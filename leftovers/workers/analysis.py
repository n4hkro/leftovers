"""AnalysisWorker – background thread worker for running analysis."""

import threading
from dataclasses import asdict
from typing import List, Set

from PySide6.QtCore import QObject, Signal

from leftovers.core.analyzer import ProcmonAnalyzer
from leftovers.core.loader import ProcmonCsvLoader
from leftovers.models.residue import ResidueCandidate
from leftovers.utils.pattern import compile_term_patterns


class AnalysisWorker(QObject):
    progress = Signal(int, str)
    finished = Signal(dict)
    failed = Signal(str)

    def __init__(self, csv_path: str, selected_terms: List[str], min_score: int):
        super().__init__()
        self.csv_path = csv_path
        self.selected_terms = selected_terms
        self.min_score = min_score
        self._cancel_event = threading.Event()

    def cancel(self):
        self._cancel_event.set()

    def is_cancelled(self) -> bool:
        return self._cancel_event.is_set()

    def _emit_phased(self, phase_start: int, phase_end: int, local_pct: int, text: str):
        local = max(0, min(100, int(local_pct)))
        global_pct = phase_start + int((phase_end - phase_start) * (local / 100.0))
        self.progress.emit(min(99, global_pct), text)

    @staticmethod
    def _dedupe_terms_case_insensitive(terms: List[str]) -> List[str]:
        unique: List[str] = []
        seen: Set[str] = set()
        for term in terms:
            key = term.strip().lower()
            if not key or key in seen:
                continue
            seen.add(key)
            unique.append(term.strip())
        return unique

    def run(self):
        try:
            self.progress.emit(1, "CSV yüklənir...")
            events = ProcmonCsvLoader.load_csv(
                self.csv_path,
                progress_cb=lambda pct, txt: self._emit_phased(0, 40, pct, txt),
                cancel_cb=self.is_cancelled,
            )
            if self.is_cancelled():
                self.failed.emit("İstifadəçi tərəfindən ləğv edildi.")
                return
            self.progress.emit(40, "CSV oxundu")

            self.progress.emit(41, "Analiz üçün indekslər hazırlanır...")
            analyzer = ProcmonAnalyzer(
                events,
                cancel_cb=self.is_cancelled,
                progress_cb=lambda pct, txt: self._emit_phased(41, 55, pct, txt),
            )
            if self.is_cancelled():
                self.failed.emit("İstifadəçi tərəfindən ləğv edildi.")
                return

            root_terms = self._dedupe_terms_case_insensitive(self.selected_terms)
            if not root_terms:
                raise RuntimeError("Proqram adı daxil edin.")
            if self.is_cancelled():
                self.failed.emit("İstifadəçi tərəfindən ləğv edildi.")
                return

            self.progress.emit(56, f"İzlər analiz olunur: {', '.join(root_terms)}")
            residues = analyzer.analyze_residue(
                root_terms=root_terms,
                cancel_cb=self.is_cancelled,
                progress_cb=lambda pct, txt: self._emit_phased(56, 95, pct, txt),
            )

            self.progress.emit(96, "Nəticələr filtr olunur...")
            weak_min_score = max(10, self.min_score - 30)
            strong_residues: List[ResidueCandidate] = []
            weak_residues: List[ResidueCandidate] = []
            for residue in residues:
                if residue.raw_score >= self.min_score:
                    strong_residues.append(residue)
                    continue
                if residue.status == "checked_only":
                    strong_residues.append(residue)
                    continue
                reason_blob = " ".join(residue.reasons).lower()
                is_field_related = (
                    residue.subtree_class in {"subtree_only", "subtree_first"}
                    or bool(residue.rename_family_id)
                    or bool(residue.installer_cluster_id)
                    or residue.cluster_membership_count >= 2
                )
                is_reason_related = any(
                    marker in reason_blob
                    for marker in (
                        "direct chain",
                        "written by chain",
                        "renamed from",
                        "guid/clsid correlation",
                        "neighborhood of confirmed residue",
                        "sibling of",
                        "created by installer descendant",
                        "live survivor expansion",
                        "registry branch sweep",
                        "vendor family proactive sweep",
                        "installer cluster",
                        "cluster bonus",
                        "firewall rule",
                        "windows installer cache",
                    )
                )
                if is_field_related or is_reason_related:
                    residue.status = "weak_but_related"
                    residue.removal_layer = "weak_but_related"
                    strong_residues.append(residue)
                    continue
                if weak_min_score <= residue.raw_score < self.min_score:
                    weak_residues.append(residue)
            residues = strong_residues

            self.progress.emit(97, "Tövsiyə olunan terminlər toplanır...")
            term_patterns = compile_term_patterns(root_terms)
            related_pids, _, _, _ = analyzer.build_related_pid_set(term_patterns)
            suggested_terms = analyzer.collect_suggested_terms(related_pids, residues, root_terms)
            if self.is_cancelled():
                self.failed.emit("İstifadəçi tərəfindən ləğv edildi.")
                return

            self.progress.emit(99, "Nəticələr hazırlanır...")
            payload = {
                "selected_terms": root_terms,
                "suggested_terms": suggested_terms,
                "residues": [asdict(x) for x in residues],
                "weak_residues": [asdict(x) for x in weak_residues],
                "summary": {
                    "events": len(events),
                    "residue_count": len(residues),
                    "weak_residue_count": len(weak_residues),
                    "safe_to_delete": sum(1 for x in residues if x.status == "safe_to_delete"),
                    "weak_but_related": sum(1 for x in residues if x.status == "weak_but_related"),
                    "review": sum(1 for x in residues if x.status == "review"),
                    "already_gone": sum(1 for x in residues if x.status == "already_gone"),
                    "ignore": sum(1 for x in residues if x.status == "ignore"),
                    "exists_check_note": (
                        "exists_now yoxlaması cari cihazda aparılır; CSV başqa mühitdən toplanıbsa nəticə fərqli ola bilər."
                    ),
                },
            }
            self.progress.emit(100, "Analiz tamamlandı")
            self.finished.emit(payload)
        except Exception as exc:
            self.failed.emit(str(exc))
