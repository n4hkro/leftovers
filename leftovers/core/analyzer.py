"""ProcmonAnalyzer – the main analysis engine for residue detection."""

import hashlib
import os
import re
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Callable, Dict, List, Optional, Set, Tuple

if os.name == "nt":
    import winreg

from leftovers.constants.operations import (
    CREATE_LIKE_OPS,
    CREATEFILE_CREATE_RE,
    HELPER_PROCESSES,
    INTERESTING_OPERATIONS,
    QUERY_ONLY_OPS,
    RELATED_CHAIN_OPS,
    STOP_AT_PARENTS,
    WRITE_OPS,
)
from leftovers.constants.paths import (
    BAM_PREFIXES,
    FIREWALL_RULES_PREFIXES,
    GUID_RE,
    KNOWN_GENERIC_DIRS,
    MUI_CACHE_PREFIXES,
    REGISTRY_EXPANSION_LIMITS,
    REGISTRY_PREFIXES,
    REGISTRY_SWEEP_PREFIXES,
    SAFE_PATH_REGEXES,
    UNINSTALL_KEY_PREFIXES,
    USERASSIST_PREFIXES,
    WINDOWS_INSTALLER_PREFIX,
    _REG_ROOT_MAP,
)
from leftovers.constants.scoring import PERSISTENCE_BONUS, SCORING_CONFIG
from leftovers.constants.trust import STOP_WORDS, TRUSTED_SIGNERS
from leftovers.models.event import ProcmonEvent
from leftovers.models.process import ProcessInfo
from leftovers.models.residue import ResidueCandidate
from leftovers.utils.path import (
    _replace_ci,
    category_from_type,
    cluster_from_path,
    detect_item_type,
    get_current_username,
    get_wow64_equivalents,
    map_sandbox_user_path,
    normalize_path,
    path_has_safe_prefix,
    path_is_low_value,
    path_looks_sandbox,
)
from leftovers.utils.pattern import (
    compile_term_patterns,
    merge_term_patterns,
    token_hit_terms,
    token_hit_weight,
    token_hits,
)
from leftovers.utils.text import (
    normalize_proc_name,
    normalize_spaces,
    parse_procmon_time_to_dt,
    rot13,
    safe_int,
    split_tokens,
)
from leftovers.utils.trust import (
    check_company_name_trusted,
    is_trusted_signed,
    read_file_version_info,
)

# Pre-computed frozenset for modification operations used in hot loops
_MODIFY_OPS = frozenset(WRITE_OPS | {"RegDeleteKey", "RegDeleteValue", "SetDispositionInformationFile"})


class ProcmonAnalyzer:
    def __init__(
        self,
        events: List[ProcmonEvent],
        cancel_cb: Optional[Callable[[], bool]] = None,
        progress_cb: Optional[Callable[[int, str], None]] = None,
        scoring_config: Optional[dict] = None,
    ):
        self.config = scoring_config or SCORING_CONFIG
        self.events = events
        self.by_pid: Dict[int, List[ProcmonEvent]] = defaultdict(list)
        self.children_by_pid: Dict[int, Set[int]] = defaultdict(set)
        self.parent_by_pid: Dict[int, int] = {}
        self.proc_names_by_pid: Dict[int, str] = {}
        self.pid_all_text: Dict[int, str] = {}
        self.process_info_by_pid: Dict[int, ProcessInfo] = {}
        self.rename_map: Dict[str, str] = {}
        self.rename_reverse_map: Dict[str, Set[str]] = defaultdict(set)
        self.rename_edges: List[Tuple[str, str, Optional[int], str]] = []
        self.path_facts: Dict[str, Dict[str, object]] = {}
        self.path_family_facts: Dict[str, Dict[str, object]] = {}
        self._index_events(cancel_cb=cancel_cb, progress_cb=progress_cb)

    def _index_events(
        self,
        cancel_cb: Optional[Callable[[], bool]] = None,
        progress_cb: Optional[Callable[[int, str], None]] = None,
    ) -> None:
        pid_unique_paths: Dict[int, Set[str]] = defaultdict(set)
        pid_parts: Dict[int, Set[str]] = defaultdict(set)
        total_events = max(1, len(self.events))

        for idx, ev in enumerate(self.events, start=1):
            if cancel_cb and idx % 5000 == 0 and cancel_cb():
                raise RuntimeError("İstifadəçi tərəfindən ləğv edildi.")
            if progress_cb and idx % 50000 == 0:
                progress = min(99, int((idx / total_events) * 100))
                progress_cb(progress, f"İndeksləmə... {idx:,}/{total_events:,}")
            if ev.pid is not None:
                self.by_pid[ev.pid].append(ev)
                info = self.process_info_by_pid.setdefault(ev.pid, ProcessInfo(pid=ev.pid))
                if ev.process_name:
                    info.proc_name = ev.process_name
                if ev.process_path:
                    info.image_path = ev.process_path
                if ev.command_line:
                    info.command_line = ev.command_line
                if not info.start_time and ev.time_of_day:
                    info.start_time = ev.time_of_day
                if ev.operation == "Process Exit" and ev.time_of_day:
                    info.end_time = ev.time_of_day

                stored_name = self.proc_names_by_pid.get(ev.pid)
                if stored_name is None:
                    if ev.process_name:
                        self.proc_names_by_pid[ev.pid] = ev.process_name
                elif ev.process_name and normalize_proc_name(ev.process_name) != normalize_proc_name(stored_name):
                    self.proc_names_by_pid[ev.pid] = ev.process_name
                    # LOGIC-1 fix: PID reuse detected — clear accumulated text for this PID
                    pid_parts[ev.pid] = set()
                    pid_unique_paths[ev.pid] = set()
                    if ev.parent_pid is not None:
                        old_parent = self.parent_by_pid.get(ev.pid)
                        if old_parent is not None and old_parent != ev.parent_pid:
                            self.children_by_pid[old_parent].discard(ev.pid)
                        self.parent_by_pid[ev.pid] = ev.parent_pid
                        self.children_by_pid[ev.parent_pid].add(ev.pid)
                if ev.parent_pid is not None and ev.pid not in self.parent_by_pid:
                    self.parent_by_pid[ev.pid] = ev.parent_pid
                    self.children_by_pid[ev.parent_pid].add(ev.pid)
                if ev.process_path:
                    pid_parts[ev.pid].add(ev.process_path.lower())
                if ev.command_line:
                    pid_parts[ev.pid].add(ev.command_line.lower())
                if ev.detail:
                    pid_parts[ev.pid].add(ev.detail.lower())
                    pid_parts[ev.pid].update(split_tokens(ev.detail))
                if ev.path:
                    pid_unique_paths[ev.pid].add(ev.path)
            if ev.operation == "Process Create":
                parent = ev.pid
                child = self._extract_child_pid(ev.detail)
                child_name = self._extract_child_name(ev.path, ev.detail)
                if parent is not None and child is not None:
                    old_parent = self.parent_by_pid.get(child)
                    if old_parent is not None and old_parent != parent:
                        self.children_by_pid[old_parent].discard(child)
                    self.children_by_pid[parent].add(child)
                    self.parent_by_pid[child] = parent
                    child_info = self.process_info_by_pid.setdefault(child, ProcessInfo(pid=child))
                    if ev.time_of_day:
                        child_info.start_time = ev.time_of_day
                    child_info.proc_name = child_name or child_info.proc_name
                    if child_name:
                        self.proc_names_by_pid[child] = child_name
            if ev.operation == "SetRenameInformationFile" and ev.path:
                target = self._extract_rename_target(ev.detail)
                if target:
                    src = ev.path
                    dst = target
                    src_id = self._canonical_path(src)
                    dst_id = self._canonical_path(dst)
                    if src_id and dst_id:
                        self.rename_map[src_id] = dst_id
                        self.rename_reverse_map[dst_id].add(src_id)
                    self.rename_edges.append((src, dst, ev.pid, ev.time_of_day))

        for pid in self.by_pid:
            parts = pid_parts.get(pid, set()).copy()
            proc = self.proc_names_by_pid.get(pid, "")
            if proc:
                parts.add(proc.lower())
            for p in pid_unique_paths.get(pid, set()):
                parts.update(seg for seg in p.lower().split("\\") if seg)
            self.pid_all_text[pid] = " ".join(parts)

        for pid, info in self.process_info_by_pid.items():
            if not info.proc_name:
                info.proc_name = self.proc_names_by_pid.get(pid, "")
        if progress_cb:
            progress_cb(100, "İndeksləmə tamamlandı")

    _PID_RE = re.compile(r"PID:\s*(\d+)", re.IGNORECASE)
    _CMD_LINE_RE = re.compile(r"Command line:\s*([^,]+)", re.IGNORECASE)
    _FILENAME_RE = re.compile(r"FileName:\s*([^,]+)", re.IGNORECASE)

    @staticmethod
    def _extract_child_pid(detail: str) -> Optional[int]:
        match = ProcmonAnalyzer._PID_RE.search(detail or "")
        if match:
            return safe_int(match.group(1))
        return None

    @staticmethod
    def _extract_child_name(path: str, detail: str) -> str:
        if path:
            base = os.path.basename(path)
            if base:
                return base
        match = ProcmonAnalyzer._CMD_LINE_RE.search(detail or "")
        if match:
            return os.path.basename(match.group(1).strip().strip('"'))
        return ""

    @staticmethod
    def _extract_rename_target(detail: str) -> str:
        match = ProcmonAnalyzer._FILENAME_RE.search(detail or "")
        if not match:
            return ""
        return normalize_path(match.group(1).strip().strip('"'))

    def canonical_artifact_key(self, path: str) -> Tuple[str, str]:
        # Identity key: normalize path shape but do not collapse rename family.
        p = normalize_path(path).lower().rstrip("\\")
        if not p:
            return "unknown", ""
        for long_root, short_root in _REG_ROOT_MAP.items():
            if p.startswith(long_root):
                p = short_root + p[len(long_root) :]
                break

        artifact_type = "registry" if p.startswith(REGISTRY_PREFIXES) else "filesystem"
        return artifact_type, p

    def _canonical_path(self, path: str) -> str:
        return self.canonical_artifact_key(path)[1]

    def _family_canonical_path(self, path: str) -> str:
        return self._family_canonical_path_from_key(self._canonical_path(path))

    def _family_canonical_path_from_key(self, canonical: str) -> str:
        """PERF-3 fix: accept a pre-computed canonical key to avoid a second
        _canonical_path() call in hot loops like _build_path_provenance_index."""
        current = canonical
        if not current:
            return ""
        visited: Set[str] = set()
        while current and current not in visited:
            visited.add(current)
            nxt = self.rename_map.get(current)
            if not nxt:
                break
            current = nxt
        return current

    def _build_path_provenance_index(
        self,
        related_pids: Set[int],
        cancel_cb: Optional[Callable[[], bool]] = None,
        progress_cb: Optional[Callable[[int, str], None]] = None,
    ) -> None:
        facts: Dict[str, Dict[str, object]] = {}
        family_facts: Dict[str, Dict[str, object]] = {}

        def ensure(key: str) -> Dict[str, object]:
            if key not in facts:
                facts[key] = {
                    "first_creator_pid": None,
                    "first_writer_pid": None,
                    "writer_pids": set(),
                    "touched_pids": set(),
                    "related_write_count": 0,
                    "non_related_write_count": 0,
                    "create_count": 0,
                    "rename_in": [],
                    "rename_out": [],
                }
            return facts[key]

        def ensure_family(key: str) -> Dict[str, object]:
            if key not in family_facts:
                family_facts[key] = {
                    "first_creator_pid": None,
                    "first_writer_pid": None,
                    "writer_pids": set(),
                    "touched_pids": set(),
                    "related_write_count": 0,
                    "non_related_write_count": 0,
                    "create_count": 0,
                    "rename_in": [],
                    "rename_out": [],
                }
            return family_facts[key]

        def apply_to_fact(item: Dict[str, object], ev: ProcmonEvent, is_creator: bool, is_writer: bool):
            if ev.pid is not None:
                cast_set = item["touched_pids"]
                if isinstance(cast_set, set):
                    cast_set.add(ev.pid)
            if is_creator:
                item["create_count"] = int(item["create_count"]) + 1
                if item["first_creator_pid"] is None:
                    item["first_creator_pid"] = ev.pid
            if is_writer:
                if ev.pid is not None:
                    writer_set = item["writer_pids"]
                    if isinstance(writer_set, set):
                        writer_set.add(ev.pid)
                if item["first_writer_pid"] is None:
                    item["first_writer_pid"] = ev.pid
                if ev.pid is not None and ev.pid in related_pids:
                    item["related_write_count"] = int(item["related_write_count"]) + 1
                else:
                    item["non_related_write_count"] = int(item["non_related_write_count"]) + 1

        total_events = max(1, len(self.events))
        for idx, ev in enumerate(self.events, start=1):
            if cancel_cb and idx % 4000 == 0 and cancel_cb():
                raise RuntimeError("İstifadəçi tərəfindən ləğv edildi.")
            if progress_cb and idx % 5000 == 0:
                progress_cb(min(99, int((idx / total_events) * 100)),
                            f"Yol indeksi qurulur... {idx:,}/{total_events:,}")
            if not ev.path:
                continue
            member_key = self._canonical_path(ev.path)
            # PERF-3 fix: reuse already-computed member_key instead of calling
            # _family_canonical_path (which would call _canonical_path a second time).
            family_key = self._family_canonical_path_from_key(member_key)
            if not member_key:
                continue
            item = ensure(member_key)
            fam_item = ensure_family(family_key or member_key)

            is_create_disposition = ev.operation == "CreateFile" and CREATEFILE_CREATE_RE.search(ev.detail or "") is not None
            is_creator = is_create_disposition or ev.operation in CREATE_LIKE_OPS
            is_writer = ev.operation in WRITE_OPS or is_create_disposition or ev.operation == "SetRenameInformationFile" or ev.operation == "SetDispositionInformationFile"

            apply_to_fact(item, ev, is_creator, is_writer)
            apply_to_fact(fam_item, ev, is_creator, is_writer)

        for src, dst, _, _ in self.rename_edges:
            src_member = self._canonical_path(src)
            dst_member = self._canonical_path(dst)
            src_family = self._family_canonical_path(src)
            dst_family = self._family_canonical_path(dst)
            if src_member:
                ensure(src_member)["rename_out"].append(normalize_path(dst))
            if dst_member:
                ensure(dst_member)["rename_in"].append(normalize_path(src))
            if src_family:
                ensure_family(src_family)["rename_out"].append(normalize_path(dst))
            if dst_family:
                ensure_family(dst_family)["rename_in"].append(normalize_path(src))

        self.path_facts = facts
        self.path_family_facts = family_facts

    def build_related_pid_set(
        self,
        term_patterns: Dict[str, List[Tuple[str, re.Pattern[str], float]]],
    ) -> Tuple[Set[int], Set[int], Set[int], Dict[int, int]]:
        roots: Set[int] = set()

        for pid in self.by_pid:
            proc_name = normalize_proc_name(self.proc_names_by_pid.get(pid, ""))
            if proc_name in STOP_AT_PARENTS:
                continue
            text = self.pid_all_text.get(pid, "")
            if token_hits(text, term_patterns):
                roots.add(pid)

        root_seed_pids = set(roots)
        for pid in list(roots):
            current = pid
            visited_up = {pid}
            while current in self.parent_by_pid:
                parent = self.parent_by_pid[current]
                if parent in visited_up:
                    break
                visited_up.add(parent)
                parent_name = normalize_proc_name(self.proc_names_by_pid.get(parent, ""))
                if parent_name in STOP_AT_PARENTS:
                    break
                if parent in roots:
                    break
                roots.add(parent)
                current = parent

        expanded = set(roots)
        depth_by_pid: Dict[int, int] = {pid: 0 for pid in roots}
        queue = deque(roots)
        while queue:
            current = queue.popleft()
            for child in self.children_by_pid.get(current, set()):
                if child not in expanded:
                    expanded.add(child)
                    depth_by_pid[child] = depth_by_pid.get(current, 0) + 1
                    queue.append(child)
        descendants_only = expanded - root_seed_pids
        return expanded, root_seed_pids, descendants_only, depth_by_pid

    _PREFETCH_PF_RE = re.compile(r"\\([^\\]+)\.exe-[0-9a-f]+\.pf$")
    _DETAIL_PATH_RE = re.compile(r"([A-Za-z]:\\[^,;\"]+)")

    def _discover_terms_and_aliases(
        self,
        term_patterns: Dict[str, List[Tuple[str, re.Pattern[str], float]]],
    ) -> Tuple[List[str], List[str]]:
        """Combined single-pass version of _discover_dynamic_terms + _extract_execution_trace_aliases."""
        discovered: Set[str] = set()
        aliases: Set[str] = set()
        for ev in self.events:
            lp = (ev.path or "").lower()
            # Dynamic term discovery from uninstall keys
            if lp.startswith(UNINSTALL_KEY_PREFIXES):
                if token_hits(ev.path or "", term_patterns) or token_hits(ev.detail or "", term_patterns):
                    value_text = ev.detail or ""
                    for match in self._DETAIL_PATH_RE.finditer(value_text):
                        extracted = normalize_path(match.group(1).strip())
                        if not extracted:
                            continue
                        if extracted.lower().endswith(".exe"):
                            extracted = normalize_path(os.path.dirname(extracted))
                        if extracted:
                            discovered.add(extracted)
            # Execution trace aliases
            if "\\prefetch\\" in lp and lp.endswith(".pf"):
                m = self._PREFETCH_PF_RE.search(lp)
                if m:
                    aliases.update(split_tokens(m.group(1)))
            if lp.startswith(USERASSIST_PREFIXES):
                decoded = rot13(ev.path or "") + " " + rot13(ev.detail or "")
                aliases.update(split_tokens(decoded))
            if lp.startswith(MUI_CACHE_PREFIXES):
                aliases.update(split_tokens(ev.detail or ""))
            if lp.startswith(BAM_PREFIXES):
                aliases.update(split_tokens(ev.path or ""))
                aliases.update(split_tokens(ev.detail or ""))
        return sorted(discovered), sorted(aliases)

    def _collect_related_guids(self, related_pids: Set[int]) -> Set[str]:
        guids: Set[str] = set()
        for ev in self.events:
            if ev.pid is None or ev.pid not in related_pids:
                continue
            # BUG-1 fix: only scan registry paths and events that have a non-empty detail
            has_registry_path = (ev.path or "").lower().startswith(REGISTRY_PREFIXES)
            has_detail = bool(ev.detail)
            if not has_registry_path and not has_detail:
                continue
            for text in [ev.path or "", ev.detail or ""]:
                for found in GUID_RE.findall(text):
                    guids.add(found.strip("{}").lower())
        return guids

    def _expand_grouped_with_guid_hits(
        self,
        grouped: Dict[Tuple[str, str], List[ProcmonEvent]],
        guid_tokens: Set[str],
        group_display_path: Optional[Dict[Tuple[str, str], str]] = None,
        cancel_cb: Optional[Callable[[], bool]] = None,
    ) -> None:
        if not guid_tokens:
            return
        # Build a single compiled regex from all GUIDs for fast matching
        guid_pattern = re.compile("|".join(re.escape(g) for g in guid_tokens))
        for idx, ev in enumerate(self.events, start=1):
            if cancel_cb and idx % 4000 == 0 and cancel_cb():
                raise RuntimeError("İstifadəçi tərəfindən ləğv edildi.")
            if not ev.path:
                continue
            sample = f"{ev.path} {ev.detail}".lower()
            if guid_pattern.search(sample):
                key = self.canonical_artifact_key(ev.path)
                if not key[1]:
                    continue
                grouped[key].append(ev)
                if group_display_path is not None:
                    group_display_path.setdefault(key, ev.path)

    def analyze_residue(
        self,
        root_terms: List[str],
        direct_boost: int = 60,
        helper_boost: int = 20,
        cancel_cb: Optional[Callable[[], bool]] = None,
        progress_cb: Optional[Callable[[int, str], None]] = None,
        enrich_file_metadata: bool = True,
    ) -> List[ResidueCandidate]:
        root_terms = [token.lower().strip() for token in root_terms if token.strip()]
        if not root_terms:
            return []

        # Sub-phase allocation within analyze_residue (progress_cb 0-100%):
        #   0-7   : term expansion
        #   7-15  : provenance index building
        #   15-16 : related path identification
        #   16-40 : event filtering
        #   40-42 : GUID expansion
        #   42-80 : group analysis
        #   80-99 : post-processing enrichment
        if progress_cb:
            progress_cb(1, "Terminlər genişləndirilir...")

        seed_patterns = compile_term_patterns(root_terms)
        dynamic_locations, exec_aliases = self._discover_terms_and_aliases(seed_patterns)
        pass1_terms = self._dedupe_terms(root_terms + dynamic_locations + exec_aliases)
        pass1_patterns = compile_term_patterns(pass1_terms)
        related_pids, _, descendants_only, depth_by_pid = self.build_related_pid_set(pass1_patterns)

        if progress_cb:
            progress_cb(3, "Əlaqəli terminlər toplanır...")

        suggested_detail = self.collect_suggested_terms_detailed(related_pids, [], pass1_terms)
        chain_terms = [x["term"] for x in suggested_detail]
        pass2_terms = self._dedupe_terms(pass1_terms + chain_terms)

        final_patterns = compile_term_patterns(pass2_terms)
        related_pids, _, descendants_only, depth_by_pid = self.build_related_pid_set(final_patterns)

        if progress_cb:
            progress_cb(5, "Termin genişləndirilməsi tamamlanır...")

        pass3_suggested_detail = self.collect_suggested_terms_detailed(related_pids, [], pass2_terms)
        trusted_terms = [item["term"] for item in pass3_suggested_detail if item.get("trust_level") == "trusted"]
        moderate_terms = [item["term"] for item in pass3_suggested_detail if item.get("trust_level") == "moderate"]
        if len(trusted_terms) + len(moderate_terms) >= 3:
            trusted_patterns = compile_term_patterns(self._dedupe_terms(pass2_terms + trusted_terms))
            moderate_patterns = compile_term_patterns(self._dedupe_terms(moderate_terms), mode_filter={"substring"})
            final_patterns = merge_term_patterns(trusted_patterns, moderate_patterns)
            related_pids, _, descendants_only, depth_by_pid = self.build_related_pid_set(final_patterns)

        if progress_cb:
            progress_cb(7, "Yol mənbə indeksi qurulur / Hadisələr süzülür...")

        session_start, session_end = self._build_session_time_window(related_pids)

        # Build related parent directories index from already-indexed by_pid
        related_parent_dirs: Set[str] = set()
        related_parent_reg: Set[str] = set()
        for pid in related_pids:
            for ev in self.by_pid.get(pid, []):
                if not ev.path:
                    continue
                _, canon = self.canonical_artifact_key(ev.path)
                if canon.startswith(REGISTRY_PREFIXES):
                    parent_reg = normalize_path(os.path.dirname(canon)).lower()
                    if parent_reg:
                        related_parent_reg.add(parent_reg)
                else:
                    parent_dir = normalize_path(os.path.dirname(canon)).lower()
                    if parent_dir:
                        related_parent_dirs.add(parent_dir)

        grouped: Dict[Tuple[str, str], List[ProcmonEvent]] = defaultdict(list)
        group_display_path: Dict[Tuple[str, str], str] = {}
        created_dirs_by_chain: Set[str] = set()

        # ── Merged pass: provenance index + event filtering ──
        # Previously these were two separate O(n) iterations over all events.
        # Combining them into a single pass halves the iteration cost.
        prov_facts: Dict[str, Dict[str, object]] = {}
        prov_family_facts: Dict[str, Dict[str, object]] = {}

        def _ensure_fact(key: str) -> Dict[str, object]:
            if key not in prov_facts:
                prov_facts[key] = {
                    "first_creator_pid": None,
                    "first_writer_pid": None,
                    "writer_pids": set(),
                    "touched_pids": set(),
                    "related_write_count": 0,
                    "non_related_write_count": 0,
                    "create_count": 0,
                    "rename_in": [],
                    "rename_out": [],
                }
            return prov_facts[key]

        def _ensure_family_fact(key: str) -> Dict[str, object]:
            if key not in prov_family_facts:
                prov_family_facts[key] = {
                    "first_creator_pid": None,
                    "first_writer_pid": None,
                    "writer_pids": set(),
                    "touched_pids": set(),
                    "related_write_count": 0,
                    "non_related_write_count": 0,
                    "create_count": 0,
                    "rename_in": [],
                    "rename_out": [],
                }
            return prov_family_facts[key]

        def _apply_provenance(item: Dict[str, object], ev: ProcmonEvent, is_creator: bool, is_writer: bool) -> None:
            if ev.pid is not None:
                cast_set = item["touched_pids"]
                if isinstance(cast_set, set):
                    cast_set.add(ev.pid)
            if is_creator:
                item["create_count"] = int(item["create_count"]) + 1
                if item["first_creator_pid"] is None:
                    item["first_creator_pid"] = ev.pid
            if is_writer:
                if ev.pid is not None:
                    writer_set = item["writer_pids"]
                    if isinstance(writer_set, set):
                        writer_set.add(ev.pid)
                if item["first_writer_pid"] is None:
                    item["first_writer_pid"] = ev.pid
                if ev.pid is not None and ev.pid in related_pids:
                    item["related_write_count"] = int(item["related_write_count"]) + 1
                else:
                    item["non_related_write_count"] = int(item["non_related_write_count"]) + 1

        # Local refs for speed in tight loop
        _interesting_ops = INTERESTING_OPERATIONS
        _related_chain_ops = RELATED_CHAIN_OPS
        _write_ops = WRITE_OPS
        _create_like_ops = CREATE_LIKE_OPS

        total_events = max(1, len(self.events))
        for idx, ev in enumerate(self.events, start=1):
            if cancel_cb and idx % 5000 == 0 and cancel_cb():
                raise RuntimeError("İstifadəçi tərəfindən ləğv edildi.")
            if progress_cb and idx % 10000 == 0:
                progress_cb(7 + min(32, int((idx / total_events) * 33)),
                            f"İndeks + süzgəc... {idx:,}/{total_events:,}")
            if not ev.path:
                continue

            # Compute canonical key once — reused by both provenance and filtering
            canonical_key = self.canonical_artifact_key(ev.path)
            member_key = canonical_key[1]
            if not member_key:
                continue

            # ── Provenance tracking (for ALL events with a path) ──
            family_key = self._family_canonical_path_from_key(member_key)
            prov_item = _ensure_fact(member_key)
            prov_fam_item = _ensure_family_fact(family_key or member_key)

            is_create_disposition = ev.operation == "CreateFile" and CREATEFILE_CREATE_RE.search(ev.detail or "") is not None
            is_creator = is_create_disposition or ev.operation in _create_like_ops
            is_prov_writer = (ev.operation in _write_ops or is_create_disposition
                              or ev.operation == "SetRenameInformationFile"
                              or ev.operation == "SetDispositionInformationFile")

            _apply_provenance(prov_item, ev, is_creator, is_prov_writer)
            _apply_provenance(prov_fam_item, ev, is_creator, is_prov_writer)

            # ── Event filtering (only for interesting operations) ──
            if ev.operation not in _interesting_ops:
                continue

            lp = member_key

            # Fast check: related-chain write gets added immediately
            is_related_write = ev.pid is not None and ev.pid in related_pids and (ev.operation in _related_chain_ops or is_create_disposition)

            if is_related_write:
                grouped[canonical_key].append(ev)
                group_display_path.setdefault(canonical_key, ev.path)
                if ev.operation == "CreateDirectory" and ev.pid is not None and ev.pid in related_pids:
                    created_dirs_by_chain.add(canonical_key[1])
                continue

            # Slower checks only when not a related write
            is_installer_path = lp.startswith(WINDOWS_INSTALLER_PREFIX)
            reg_sweep = lp.startswith(REGISTRY_SWEEP_PREFIXES)
            path_hit = bool(token_hits(lp, final_patterns, allow_rot13=False))
            detail_hit = bool(token_hits(ev.detail or "", final_patterns, allow_rot13=lp.startswith(USERASSIST_PREFIXES)))

            if not (path_has_safe_prefix(ev.path) or is_installer_path or reg_sweep or path_hit or detail_hit):
                continue
            grouped[canonical_key].append(ev)
            group_display_path.setdefault(canonical_key, ev.path)

        # Provenance: process rename edges (post-loop)
        for src, dst, _, _ in self.rename_edges:
            src_member = self._canonical_path(src)
            dst_member = self._canonical_path(dst)
            src_family = self._family_canonical_path(src)
            dst_family = self._family_canonical_path(dst)
            if src_member:
                _ensure_fact(src_member)["rename_out"].append(normalize_path(dst))
            if dst_member:
                _ensure_fact(dst_member)["rename_in"].append(normalize_path(src))
            if src_family:
                _ensure_family_fact(src_family)["rename_out"].append(normalize_path(dst))
            if dst_family:
                _ensure_family_fact(dst_family)["rename_in"].append(normalize_path(src))

        self.path_facts = prov_facts
        self.path_family_facts = prov_family_facts

        if progress_cb:
            progress_cb(40, "GUID əlaqələri yoxlanılır...")

        related_guids = self._collect_related_guids(related_pids)
        self._expand_grouped_with_guid_hits(grouped, related_guids, group_display_path=group_display_path, cancel_cb=cancel_cb)

        # ── Batch path existence checks in parallel (I/O-bound) ──
        # Pre-compute all path existence results using a thread pool so the
        # scoring loop below can look them up without blocking on I/O.
        _path_exists_cache: Dict[str, Optional[bool]] = {}
        _paths_to_check: Dict[str, str] = {}  # mapped_path -> original_path
        for group_key, evs in grouped.items():
            gpath = group_display_path.get(group_key, evs[0].path if evs else group_key[1])
            mapped = map_sandbox_user_path(gpath)
            if not path_looks_sandbox(gpath) or mapped != gpath:
                _paths_to_check[mapped] = gpath

        if _paths_to_check:
            def _check_exists(p: str) -> Tuple[str, Optional[bool]]:
                return p, self._path_exists(p)

            with ThreadPoolExecutor(max_workers=min(8, os.cpu_count() or 4)) as pool:
                for checked_path, result in pool.map(_check_exists, _paths_to_check.keys()):
                    _path_exists_cache[checked_path] = result

        if progress_cb:
            progress_cb(42, f"Qruplar analiz olunur... (0/{len(grouped):,})")

        results: List[ResidueCandidate] = []
        total_groups = max(1, len(grouped))
        for idx, (group_key, evs) in enumerate(grouped.items(), start=1):
            if cancel_cb and idx % 500 == 0 and cancel_cb():
                raise RuntimeError("İstifadəçi tərəfindən ləğv edildi.")
            if progress_cb and idx % 200 == 0:
                progress_cb(42 + min(37, int((idx / total_groups) * 38)),
                            f"Qruplar analiz olunur... {idx:,}/{total_groups:,}")

            path = group_display_path.get(group_key, evs[0].path if evs else group_key[1])
            lp = group_key[1]
            raw_score = 0
            reasons: List[str] = []
            proc_set = sorted({e.process_name for e in evs if e.process_name})
            # BUG-4 fix: renamed op_set -> op_list (sorted() returns a list, not a set)
            op_list = sorted({e.operation for e in evs if e.operation})
            first_seen = evs[0].time_of_day
            last_seen = evs[-1].time_of_day

            path_weight = token_hit_weight(lp, final_patterns)
            path_token_terms = token_hit_terms(lp, final_patterns)
            detail_match = False
            write_count = 0
            facts = self.path_facts.get(group_key[1], {})
            writer_pids: Set[int] = set(facts.get("writer_pids", set()))
            first_writer_pid: Optional[int] = facts.get("first_writer_pid")
            last_writer_pid: Optional[int] = None
            first_creator_pid: Optional[int] = facts.get("first_creator_pid")
            touched_pids: Set[int] = set(facts.get("touched_pids", set()))
            related_write_count = int(facts.get("related_write_count", 0) or 0)
            non_related_write_count = int(facts.get("non_related_write_count", 0) or 0)
            created_flag = bool(facts.get("create_count", 0))
            modified_flag = False
            read_only = True
            non_related_writer_in_window = False
            location_proximity_hit = False

            # Hoist invariant computation out of the inner event loop
            allow_rot13 = lp.startswith(USERASSIST_PREFIXES)
            has_session_window = bool(session_start and session_end)
            # Pre-compute parent_ref and location prefix check once per group
            parent_ref = normalize_path(os.path.dirname(lp)).lower() if has_session_window else ""
            lp_has_location_prefix = lp.startswith(("c:\\users\\", "c:\\programdata\\", "hkcu\\software\\"))

            for ev in evs:
                if not detail_match and token_hits(ev.detail or "", final_patterns, allow_rot13=allow_rot13):
                    detail_match = True
                is_create_disposition = ev.operation == "CreateFile" and CREATEFILE_CREATE_RE.search(ev.detail or "") is not None
                is_write = ev.operation in WRITE_OPS or is_create_disposition
                if is_write:
                    read_only = False
                    write_count += 1
                    if ev.pid is not None:
                        last_writer_pid = ev.pid
                if ev.operation in _MODIFY_OPS:
                    modified_flag = True
                if has_session_window and is_write:
                    ev_dt = parse_procmon_time_to_dt(ev.time_of_day)
                    if ev_dt and session_start <= ev_dt <= session_end:
                        if ev.pid not in related_pids:
                            non_related_writer_in_window = True
                        if lp_has_location_prefix and (
                            parent_ref in related_parent_dirs or parent_ref in related_parent_reg
                        ):
                            location_proximity_hit = True

            is_prefetch_trace = "\\prefetch\\" in lp and lp.endswith(".pf")
            is_exec_trace_prefix = lp.startswith(MUI_CACHE_PREFIXES) or lp.startswith(BAM_PREFIXES) or allow_rot13
            execution_trace_hit = is_exec_trace_prefix and (path_weight > 0 or detail_match)

            if path_is_low_value(path):
                if is_prefetch_trace and path_weight > 0:
                    raw_score += self.config["traces"]["prefetch_trace"]
                    reasons.append("prefetch execution trace")
                elif execution_trace_hit:
                    raw_score += self.config["traces"]["execution_trace"]
                    reasons.append("execution trace hit")
                else:
                    raw_score += self.config["penalties"]["low_value_area"]
                    reasons.append("low-value system area")

            if path_token_terms:
                base_add = self.config["match_scores"]["path_match_base"]
                weighted_add = int(base_add * path_weight)
                extra_max = self.config["match_scores"]["path_extra_max"]
                extra_per = self.config["match_scores"]["path_extra_per_term"]
                add = weighted_add + min(extra_max, max(0, len(path_token_terms) - 1) * extra_per)
                raw_score += add
                reasons.append(f"path match: {', '.join(path_token_terms[:4])}")

            if detail_match:
                raw_score += self.config["match_scores"]["detail_match"]
                reasons.append("token found in detail/value data")
                if allow_rot13:
                    reasons.append("UserAssist ROT13 match (decoded)")

            if lp.startswith(FIREWALL_RULES_PREFIXES) and any(token_hits(ev.detail or "", final_patterns) for ev in evs):
                raw_score += self.config["special"]["firewall_rule_reference"]
                reasons.append("firewall rule references target app")

            loc = self.config["location_scores"]
            if "\\appdata\\" in lp:
                raw_score += loc["appdata"]
            if lp.startswith("c:\\programdata\\"):
                raw_score += loc["programdata"]
            if lp.startswith("c:\\program files"):
                raw_score += loc["program_files"]
            if lp.startswith("hkcu\\software\\"):
                raw_score += loc["hkcu_software"]
            if "\\currentversion\\uninstall\\" in lp:
                raw_score += loc["uninstall_key"]
            if "\\currentversion\\run" in lp:
                raw_score += loc["current_version_run"]

            item_type = detect_item_type(path)
            cfg_persistence = self.config["persistence_bonus"]
            if item_type in cfg_persistence:
                raw_score += cfg_persistence[item_type]
                reasons.append(f"persistence type: {item_type}")

            if lp.startswith(WINDOWS_INSTALLER_PREFIX) and related_write_count > 0:
                raw_score += self.config["provenance"]["installer_cache_related"]
                reasons.append("windows installer cache touched by related chain")

            if any(guid in lp for guid in related_guids):
                raw_score += self.config["provenance"]["guid_correlation"]
                reasons.append("GUID/CLSID correlation from related chain")

            related_events = [ev for ev in evs if ev.pid is not None and ev.pid in related_pids]
            if related_events:
                first_pid_depth = 0
                first_hit = related_events[0]
                if first_hit.pid is not None:
                    first_pid_depth = depth_by_pid.get(first_hit.pid, 0)
                db = self.config["depth_boost"]
                depth_boost_val = db["depth_0_1"] if first_pid_depth <= 1 else db["depth_2_3"] if first_pid_depth <= 3 else db["depth_4_plus"]
                raw_score += depth_boost_val
                if first_hit.pid in descendants_only:
                    reasons.append(f"created by installer descendant PID {first_hit.pid} ({first_hit.process_name or '?'}) depth={first_pid_depth}")
                else:
                    reasons.append(f"direct chain: {first_hit.process_name or '?'} depth={first_pid_depth}")

            related_writer_count = sum(1 for pid in writer_pids if pid in related_pids)
            total_writer_count = max(1, len(writer_pids)) if writer_pids else 0
            subtree_class = "none"
            if touched_pids and all(pid in related_pids for pid in touched_pids) and writer_pids:
                subtree_class = "subtree_only"
            elif first_creator_pid is not None and first_creator_pid in related_pids:
                subtree_class = "subtree_first"
            elif writer_pids and (related_writer_count / total_writer_count) >= 0.7:
                subtree_class = "subtree_dominant"

            prov = self.config["provenance"]
            if first_creator_pid is not None and first_creator_pid in related_pids:
                raw_score += prov["first_creator_related"]
                reasons.append("object first created by related chain")
            elif first_writer_pid is not None and first_writer_pid in related_pids:
                raw_score += prov["first_writer_related"]
                reasons.append("object first written by related chain")

            if touched_pids and all(pid in related_pids for pid in touched_pids):
                raw_score += prov["exclusively_touched"]
                reasons.append("exclusively touched by related chain")

            if not path_token_terms and related_write_count > 0:
                raw_score += prov["written_by_chain_no_token"]
                reasons.append("written by chain without token")

            if related_write_count > 0 and non_related_write_count == 0:
                raw_score += prov["no_non_related_writes"]
                reasons.append("provenance: no non-related writes")

            helper_hit = any(
                normalize_proc_name(ev.process_name) in HELPER_PROCESSES and (bool(path_token_terms) or bool(token_hits(ev.detail or "", final_patterns)))
                for ev in evs
            )
            if helper_hit:
                raw_score += helper_boost
                reasons.append("helper-process correlation")

            act = self.config["activity"]
            if write_count == 0:
                raw_score += act["write_0"]
                reasons.append("only read/query activity")
            elif write_count <= 2:
                raw_score += act["write_1_2"]
            elif write_count <= 9:
                raw_score += act["write_3_9"]
            else:
                raw_score += act["write_10_plus"]

            if created_flag:
                raw_score += act["created"]
            if modified_flag:
                raw_score += act["modified"]
            if read_only:
                raw_score += act["read_only"]

            # BUG-3 fix: compute is_create_disposition per-event inside the loop
            for ev in evs:
                detail_kv = ev.detail_dict
                ev_is_create_disposition = ev.operation == "CreateFile" and CREATEFILE_CREATE_RE.search(ev.detail or "") is not None
                desired_access = detail_kv.get("Desired Access", "").lower()
                if ev.operation == "CreateFile" and desired_access and not ev_is_create_disposition:
                    if ("write" not in desired_access and "delete" not in desired_access
                            and "generic all" not in desired_access and "generic write" not in desired_access):
                        raw_score -= 10
                        reasons.append("read-only access (no write intent)")
                        break
                if ev.operation == "SetDispositionInformationFile":
                    if detail_kv.get("Delete", "").lower() == "true":
                        raw_score -= 15
                        reasons.append("object was deleted during session (Delete: True)")
                        break

            sess = self.config["session"]
            if non_related_writer_in_window:
                raw_score += sess["non_related_writer_window"]
                reasons.append("write occurred inside install session window")
            if location_proximity_hit:
                raw_score += sess["location_proximity"]
                reasons.append("session-window + location proximity to related subtree")

            if first_writer_pid is not None:
                reasons.append(f"first_writer={first_writer_pid}:{self.proc_names_by_pid.get(first_writer_pid, '?')}")
            if last_writer_pid is not None and last_writer_pid != first_writer_pid:
                reasons.append(f"last_writer={last_writer_pid}:{self.proc_names_by_pid.get(last_writer_pid, '?')}")

            pen = self.config["penalties"]
            if "microsoft" in lp and not path_token_terms:
                raw_score += pen["microsoft_path_no_token"]
            base_tokens = split_tokens(os.path.basename(path))
            if base_tokens and all(token in KNOWN_GENERIC_DIRS for token in base_tokens):
                raw_score += pen["generic_dir"]

            mapped = map_sandbox_user_path(path)
            exists_now = _path_exists_cache.get(mapped) if mapped in _path_exists_cache else (
                self._path_exists(mapped) if not path_looks_sandbox(path) or mapped != path else None
            )
            if path_looks_sandbox(path) and mapped == path:
                reasons.append("sandbox path could not be mapped to current user")

            for src in self._resolve_full_rename_chain(path, reverse=True)[:2]:
                if src.lower() != path.lower():
                    reasons.append(f"renamed from {src}")
            chain_forward = self._resolve_full_rename_chain(path)
            if len(chain_forward) > 1:
                reasons.append("rename chain: " + " -> ".join(chain_forward[:4]))

            checked_only = (
                bool(op_list)
                and all(op in QUERY_ONLY_OPS for op in op_list)
                and write_count == 0
                and first_creator_pid is None
                and first_writer_pid is None
                and (bool(path_token_terms) or detail_match or bool(related_events))
            )
            if checked_only:
                raw_score += self.config["special"]["checked_only_residue"]
                reasons.append("checked-only residue: installer observed preexisting artifact")

            candidate = ResidueCandidate(
                type=item_type,
                path=path,
                mapped_path=mapped,
                raw_score=raw_score,
                score=max(0, min(raw_score, 100)),
                reasons=self._unique_compact(reasons),
                first_seen=first_seen,
                last_seen=last_seen,
                processes=proc_set,
                operations=op_list,
                exists_now=exists_now,
                status=self._status_from_score(raw_score, exists_now, subtree_class, checked_only=checked_only),
                category=category_from_type(item_type),
                cluster=cluster_from_path(path),
                subtree_class=subtree_class,
            )
            if raw_score >= 10:
                results.append(candidate)

        if progress_cb:
            progress_cb(80, "Rename variantları yoxlanılır...")
        results = self._add_rename_dest_candidates(results)

        if progress_cb:
            progress_cb(82, "Ana qovluq namizədləri əlavə olunur...")
        results = self._add_parent_directory_candidates(results, created_dirs_by_chain)

        if progress_cb:
            progress_cb(84, "Vendor ailəsi yoxlanılır...")
        results = self._proactive_vendor_family_sweep(results)

        if progress_cb:
            progress_cb(86, "Təsdiqlənmiş köklərdən genişlənmə...")
        results = self._flood_fill_from_confirmed_roots(
            results, created_dirs_by_chain,
            progress_cb=progress_cb,
            cancel_cb=cancel_cb,
        )

        if progress_cb:
            progress_cb(90, "Fayl metadata-sı yoxlanılır...")
        if enrich_file_metadata:
            self._enrich_candidates_with_file_metadata(results, final_patterns)

        if progress_cb:
            progress_cb(95, "Klasterlər təyin olunur...")
        # Installer/family IDs must be assigned before cluster bonus.
        self._assign_installer_clusters(results)
        self._assign_family_clusters(results)
        self._apply_cluster_bonus(results)
        results = self._merge_by_mapped_path(results)
        self._assign_removal_layers(results)

        if progress_cb:
            progress_cb(99, "Nəticələr sıralanır...")
        results.sort(key=lambda x: (x.raw_score, x.exists_now is True), reverse=True)
        return results

    @staticmethod
    def _dedupe_terms(terms: List[str]) -> List[str]:
        out: List[str] = []
        seen: Set[str] = set()
        for term in terms:
            key = (term or "").strip().lower()
            if not key or key in seen:
                continue
            seen.add(key)
            out.append(key)
        return out

    def _resolve_full_rename_chain(self, path: str, reverse: bool = False) -> List[str]:
        current = self._canonical_path(path)
        visited: Set[str] = set()
        chain: List[str] = [normalize_path(path)]
        while current and current not in visited:
            visited.add(current)
            if reverse:
                prevs = sorted(self.rename_reverse_map.get(current, set()))
                if not prevs:
                    break
                nxt = prevs[0]
            else:
                nxt = self.rename_map.get(current)
                if not nxt:
                    break
            chain.append(normalize_path(nxt))
            current = self._canonical_path(nxt)
        return chain

    @staticmethod
    def _extension_multiplier(path: str) -> float:
        lp = (path or "").lower()
        if lp.endswith((".config", ".json", ".xml", ".yaml", ".yml", ".ini", ".db", ".sqlite")):
            return 0.7
        if lp.endswith((".dll", ".exe")):
            return 0.6
        if lp.endswith((".log", ".cache", ".tmp")):
            return 0.5
        return 0.3

    def _build_candidate_from_path(
        self,
        path: str,
        raw_score: int,
        reason: str,
        first_seen: str,
        last_seen: str,
        processes: List[str],
        operations: List[str],
    ) -> ResidueCandidate:
        mapped = map_sandbox_user_path(path)
        exists_now = self._path_exists(mapped)
        item_type = detect_item_type(path)
        return ResidueCandidate(
            type=item_type,
            path=path,
            mapped_path=mapped,
            raw_score=raw_score,
            score=max(0, min(raw_score, 100)),
            reasons=self._unique_compact([reason]),
            first_seen=first_seen,
            last_seen=last_seen,
            processes=processes,
            operations=operations,
            exists_now=exists_now,
            status=self._status_from_score(raw_score, exists_now),
            category=category_from_type(item_type),
            cluster=cluster_from_path(path),
            removal_layer=self._removal_layer_from_candidate(category_from_type(item_type), self._status_from_score(raw_score, exists_now), reason),
        )

    def _registry_to_winreg_root(self, path: str) -> Tuple[Optional[int], str]:
        raw = (path or "")
        if "\\" not in raw:
            return None, ""
        root_name, sub = raw.split("\\", 1)
        mapping = {
            "HKCU": winreg.HKEY_CURRENT_USER if os.name == "nt" else None,
            "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER if os.name == "nt" else None,
            "HKLM": winreg.HKEY_LOCAL_MACHINE if os.name == "nt" else None,
            "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE if os.name == "nt" else None,
            "HKCR": winreg.HKEY_CLASSES_ROOT if os.name == "nt" else None,
            "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT if os.name == "nt" else None,
            "HKU": winreg.HKEY_USERS if os.name == "nt" else None,
            "HKEY_USERS": winreg.HKEY_USERS if os.name == "nt" else None,
        }
        return mapping.get(root_name.upper()), sub

    def _enumerate_registry_branch(self, root_path: str, max_items: int = 600) -> List[str]:
        if os.name != "nt":
            return []
        root, sub = self._registry_to_winreg_root(root_path)
        if root is None or not sub:
            return []
        out: List[str] = []
        skipped_access_denied: List[str] = []  # CODE-4: track access-denied paths
        queue = deque([sub])
        visited: Set[str] = set()
        while queue and len(out) < max_items:
            current = queue.popleft()
            if current in visited:
                continue
            visited.add(current)
            full = f"{root_path.split(chr(92), 1)[0]}\\{current}"
            out.append(full)
            try:
                with winreg.OpenKey(root, current) as key:
                    idx = 0
                    while True:
                        try:
                            value_name, _, _ = winreg.EnumValue(key, idx)
                            out.append(f"{full}\\{value_name}")
                            idx += 1
                            if len(out) >= max_items:
                                break
                        except OSError:
                            break
                    cidx = 0
                    while True:
                        try:
                            child = winreg.EnumKey(key, cidx)
                            queue.append(f"{current}\\{child}")
                            cidx += 1
                        except OSError:
                            break
            except OSError as exc:
                # CODE-4 fix: log access-denied paths separately from not-found
                if getattr(exc, "winerror", None) == 5:  # ERROR_ACCESS_DENIED
                    skipped_access_denied.append(full)
                continue
        return out

    @staticmethod
    def _derive_vendor_root(path: str) -> str:
        p = normalize_path(path)
        parts = [x for x in p.split("\\") if x]
        if len(parts) < 3:
            return ""
        if parts[0].lower().endswith(":") and parts[1].lower() in {"programdata", "program files", "program files (x86)", "users"}:
            if parts[1].lower() == "users" and len(parts) >= 4:
                # LOGIC-5 fix: Only treat Users paths with AppData as vendor roots
                if len(parts) >= 5 and parts[3].lower() == "appdata":
                    return "\\".join(parts[:6]) if len(parts) >= 6 else "\\".join(parts[:5])
                # For other Users paths, return dirname instead
                return normalize_path(os.path.dirname(path))
            return "\\".join(parts[:3])
        return normalize_path(os.path.dirname(path))

    def _mirror_vendor_roots(self, vendor_root: str) -> List[str]:
        root = normalize_path(vendor_root)
        if not root:
            return []
        parts = [x for x in root.split("\\") if x]
        if len(parts) < 3:
            return [root]
        drive = parts[0]
        second = parts[1].lower()
        out: Set[str] = {root}

        # LOGIC-6 fix: handle Users path separately BEFORE setting vendor from parts[2]
        if second == "users" and len(parts) >= 5:
            user_name = parts[2]  # e.g. "John"
            # parts[3] = AppData, parts[4] = Local/Roaming, parts[5] = vendor
            vendor_name = parts[5] if parts[4].lower() in {"roaming", "local"} and len(parts) > 5 else parts[4]
            user_base = f"{drive}\\Users\\{user_name}"
            out.add(f"{user_base}\\AppData\\Roaming\\{vendor_name}")
            out.add(f"{user_base}\\AppData\\Local\\{vendor_name}")
            out.add(f"{drive}\\ProgramData\\{vendor_name}")
            out.add(f"{drive}\\Program Files\\{vendor_name}")
            out.add(f"{drive}\\Program Files (x86)\\{vendor_name}")
        else:
            vendor = parts[2]  # e.g. "VendorApp" under ProgramData / Program Files
            out.add(f"{drive}\\ProgramData\\{vendor}")
            out.add(f"{drive}\\Program Files\\{vendor}")
            out.add(f"{drive}\\Program Files (x86)\\{vendor}")
            users_root = f"{drive}\\Users"
            if os.path.isdir(users_root):
                try:
                    for user in os.listdir(users_root):
                        user_base = f"{users_root}\\{user}"
                        out.add(f"{user_base}\\AppData\\Roaming\\{vendor}")
                        out.add(f"{user_base}\\AppData\\Local\\{vendor}")
                except OSError:
                    pass
        return sorted({normalize_path(x) for x in out if x})

    @staticmethod
    def _walk_with_generic_reset(base_dir: str, max_depth: int = 4):
        """Walk directory tree respecting max_depth, with a grace extension for generic dirs.
        CODE-5 fix: cap extension to max 2 extra levels to prevent runaway recursion."""
        for root, dirs, files in os.walk(base_dir):
            rel = root[len(base_dir):].lstrip(os.sep)
            parts = [p for p in rel.split(os.sep) if p]
            depth = len(parts)
            if depth >= max_depth:
                generic_indices = [i for i, part in enumerate(parts) if part.lower() in KNOWN_GENERIC_DIRS]
                if generic_indices:
                    # Only extend past max_depth by at most 2 levels after the last generic dir
                    depth_after_generic = depth - (generic_indices[-1] + 1)
                    if depth_after_generic >= 2:  # was: max_depth (too permissive)
                        dirs[:] = []
                else:
                    dirs[:] = []
            yield root, dirs, files

    @staticmethod
    def _extract_vendor_token(path: str) -> str:
        parts = [p for p in normalize_path(path).split("\\") if p]
        if len(parts) >= 3 and parts[0].endswith(":") and parts[1].lower() in {"programdata", "program files", "program files (x86)"}:
            return parts[2].lower()
        if len(parts) >= 6 and parts[0].endswith(":") and parts[1].lower() == "users" and parts[3].lower() == "appdata":
            return parts[5].lower() if parts[4].lower() in {"roaming", "local"} and len(parts) > 5 else parts[4].lower()
        return ""

    def _proactive_vendor_family_sweep(self, candidates: List[ResidueCandidate]) -> List[ResidueCandidate]:
        out = list(candidates)
        seen = {(c.type, (c.mapped_path or c.path).lower()) for c in out if (c.mapped_path or c.path)}
        vendor_tokens: Set[str] = set()
        for candidate in candidates:
            token = self._extract_vendor_token(candidate.path)
            if token and token not in STOP_WORDS:
                vendor_tokens.add(token)

        users_root = "C:\\Users"
        for vendor in sorted(vendor_tokens):
            probe_paths = {
                f"C:\\ProgramData\\{vendor}",
                f"C:\\Program Files\\{vendor}",
                f"C:\\Program Files (x86)\\{vendor}",
            }
            if os.path.isdir(users_root):
                try:
                    for user in os.listdir(users_root):
                        probe_paths.add(f"{users_root}\\{user}\\AppData\\Roaming\\{vendor}")
                        probe_paths.add(f"{users_root}\\{user}\\AppData\\Local\\{vendor}")
                        probe_paths.add(f"{users_root}\\{user}\\AppData\\Local\\Programs\\{vendor}")
                except OSError:
                    pass

            for path in probe_paths:
                normalized = normalize_path(path)
                if not os.path.isdir(normalized):
                    continue
                key = ("dir", normalized.lower())
                if key in seen:
                    continue
                raw_score = 45
                candidate = self._build_candidate_from_path(
                    normalized,
                    raw_score,
                    f"vendor family proactive sweep: {vendor}",
                    "",
                    "",
                    [],
                    ["VendorFamilySweep"],
                )
                out.append(candidate)
                seen.add(key)
        return out

    def _flood_fill_from_confirmed_roots(
        self,
        candidates: List[ResidueCandidate],
        created_dirs_by_chain: Set[str],
        max_iterations: int = 3,
        progress_cb: Optional[Callable[[int, str], None]] = None,
        cancel_cb: Optional[Callable[[], bool]] = None,
    ) -> List[ResidueCandidate]:
        out = list(candidates)
        # Build a shared seen set once; expansion methods maintain it incrementally.
        seen: Set[tuple] = set()
        for c in out:
            p = (c.mapped_path or c.path)
            if p:
                seen.add((c.type, p.lower()))
        total_steps = max_iterations * 6
        step = 0
        for iteration in range(max_iterations):
            if cancel_cb and cancel_cb():
                break
            before = len(out)

            def _report(label: str) -> None:
                if progress_cb:
                    pct = 86 + (step * 4) // total_steps
                    progress_cb(pct, f"Genişlənmə ({iteration + 1}/{max_iterations}): {label}")

            _report("kök klasterlər")
            out = self._expand_confirmed_root_clusters(out)
            step += 1
            if cancel_cb and cancel_cb():
                break

            _report("qonşuluq")
            out = self._expand_neighborhood(out, seen)
            step += 1
            if cancel_cb and cancel_cb():
                break

            _report("mövcud fayllar")
            out = self._expand_survivors(out, seen)
            step += 1
            if cancel_cb and cancel_cb():
                break

            _report("registr budaqları")
            out = self._expand_confirmed_registry_branches(out, seen)
            step += 1
            if cancel_cb and cancel_cb():
                break

            _report("qardaş fayllar")
            out = self._expand_siblings(out, seen)
            step += 1
            if cancel_cb and cancel_cb():
                break

            _report("ana qovluqlar")
            out = self._add_parent_directory_candidates(out, created_dirs_by_chain)
            step += 1

            if len(out) == before:
                break
            # Rebuild seen: _add_parent_directory_candidates manages its own
            # dedup set, so new entries it added are not yet in our shared seen.
            seen = set()
            for c in out:
                p = (c.mapped_path or c.path)
                if p:
                    seen.add((c.type, p.lower()))
        return out

    def _expand_confirmed_root_clusters(self, candidates: List[ResidueCandidate]) -> List[ResidueCandidate]:
        out = list(candidates)
        by_path = {(c.mapped_path or c.path).lower(): c for c in out if (c.mapped_path or c.path)}

        # Build reverse-index maps so we can find related candidates in O(1)
        # instead of scanning all candidates for every root (was O(n²)).
        by_vendor: Dict[str, List[ResidueCandidate]] = defaultdict(list)
        by_service: Dict[str, List[ResidueCandidate]] = defaultdict(list)
        by_rename: Dict[str, List[ResidueCandidate]] = defaultdict(list)
        by_cluster: Dict[str, List[ResidueCandidate]] = defaultdict(list)
        for cand in out:
            if cand.vendor_family_id:
                by_vendor[cand.vendor_family_id].append(cand)
            if cand.service_branch_id:
                by_service[cand.service_branch_id].append(cand)
            if cand.rename_family_id:
                by_rename[cand.rename_family_id].append(cand)
            if cand.installer_cluster_id:
                by_cluster[cand.installer_cluster_id].append(cand)

        queue = deque([c for c in out if c.raw_score >= 80])
        visited: Set[str] = set()
        while queue:
            root = queue.popleft()
            root_key = (root.mapped_path or root.path).lower()
            if root_key in visited:
                continue
            visited.add(root_key)

            # Collect related candidates via reverse-index lookup (O(k) not O(n))
            related_cands: List[ResidueCandidate] = []
            if root.vendor_family_id:
                related_cands.extend(by_vendor.get(root.vendor_family_id, ()))
            if root.service_branch_id:
                related_cands.extend(by_service.get(root.service_branch_id, ()))
            if root.rename_family_id:
                related_cands.extend(by_rename.get(root.rename_family_id, ()))
            if root.installer_cluster_id:
                related_cands.extend(by_cluster.get(root.installer_cluster_id, ()))

            for cand in related_cands:
                if cand is root:
                    continue
                if cand.raw_score < 70:
                    cand.raw_score = min(100, cand.raw_score + 20)
                    cand.score = max(0, min(cand.raw_score, 100))
                    cand.reasons = self._unique_compact(cand.reasons + ["confirmed root cluster flood-fill"])
                    cand.status = self._status_from_score(cand.raw_score, cand.exists_now, cand.subtree_class)

            vendor_root = self._derive_vendor_root(root.mapped_path or root.path)
            for mirror in self._mirror_vendor_roots(vendor_root):
                m = normalize_path(mirror)
                key = m.lower()
                if not m or key in by_path:
                    continue
                if not os.path.exists(m):
                    continue
                new_candidate = self._build_candidate_from_path(
                    m,
                    55,
                    "mirrored root from confirmed cluster",
                    root.first_seen,
                    root.last_seen,
                    root.processes,
                    ["ConfirmedRootMirror"],
                )
                out.append(new_candidate)
                by_path[key] = new_candidate
                # Register new candidate in reverse indexes
                if new_candidate.vendor_family_id:
                    by_vendor[new_candidate.vendor_family_id].append(new_candidate)
                if new_candidate.service_branch_id:
                    by_service[new_candidate.service_branch_id].append(new_candidate)
                if new_candidate.rename_family_id:
                    by_rename[new_candidate.rename_family_id].append(new_candidate)
                if new_candidate.installer_cluster_id:
                    by_cluster[new_candidate.installer_cluster_id].append(new_candidate)
                queue.append(new_candidate)
        return out

    def _expand_neighborhood(self, candidates: List[ResidueCandidate], shared_seen: Optional[Set[tuple]] = None) -> List[ResidueCandidate]:
        out = list(candidates)
        seen = shared_seen if shared_seen is not None else {(c.type, (c.mapped_path or c.path).lower()) for c in out if (c.mapped_path or c.path)}

        # PERF-1 fix: build a prefix-based index of events by registry path prefix
        # to avoid full O(n) scan for every reg_key candidate
        reg_events_by_prefix: Dict[str, List] = defaultdict(list)
        for ev in self.events:
            if ev.path and ev.path.lower().startswith(REGISTRY_PREFIXES):
                lp = ev.path.lower()
                prefix = lp[:64]  # bucket by first 64 chars
                # Extract the registry root prefix for better matching
                root_end = lp.find("\\", 5)
                if root_end > 0:
                    prefix_key = lp[:root_end + 1]
                else:
                    prefix_key = prefix
                reg_events_by_prefix[prefix_key].append(ev)

        for candidate in list(candidates):
            if candidate.raw_score < 55:
                continue
            if candidate.exists_now is not True:
                continue
            if candidate.type == "reg_key":
                parent = normalize_path(os.path.dirname(candidate.path))
                if parent:
                    parent_lower = parent.lower()
                    # Use the prefix index to find matching events efficiently
                    matching_events = []
                    for prefix_key, evs in reg_events_by_prefix.items():
                        if parent_lower.startswith(prefix_key):
                            matching_events.extend(evs)
                    
                    for ev in matching_events:
                        if not ev.path or not ev.path.lower().startswith(parent_lower):
                            continue
                        t = detect_item_type(ev.path)
                        mapped = map_sandbox_user_path(ev.path)
                        key = (t, mapped.lower())
                        if key in seen:
                            continue
                        raw_score = max(30, candidate.raw_score // 2)
                        new_item = self._build_candidate_from_path(
                            ev.path,
                            raw_score,
                            f"neighborhood of confirmed residue: {parent}",
                            ev.time_of_day,
                            ev.time_of_day,
                            [ev.process_name] if ev.process_name else [],
                            [ev.operation] if ev.operation else [],
                        )
                        out.append(new_item)
                        seen.add(key)
                continue
            if candidate.type not in {"dir", "file", "config", "database", "cache", "log", "binary"}:
                continue
            root_dir = candidate.mapped_path if candidate.type == "dir" else os.path.dirname(candidate.mapped_path)
            if not root_dir:
                continue
            vendor_root = self._derive_vendor_root(root_dir)
            scan_roots = self._mirror_vendor_roots(vendor_root) if vendor_root else [root_dir]
            for scan_root in scan_roots:
                if not os.path.isdir(scan_root):
                    continue
                for base, dirs, files in self._walk_with_generic_reset(scan_root, max_depth=4):
                    for name in files:
                        fp = normalize_path(os.path.join(base, name))
                        # Skip trusted-signed system files (Təklif 3)
                        if is_trusted_signed(fp):
                            continue
                        t = detect_item_type(fp)
                        key = (t, fp.lower())
                        if key in seen:
                            continue
                        mult = self._extension_multiplier(fp)
                        raw_score = max(30, int(candidate.raw_score * mult))
                        new_item = self._build_candidate_from_path(
                            fp,
                            raw_score,
                            f"neighborhood of confirmed residue: {scan_root}",
                            candidate.first_seen,
                            candidate.last_seen,
                            candidate.processes,
                            ["NeighborhoodScan"],
                        )
                        out.append(new_item)
                        seen.add(key)
        return out

    def _expand_survivors(self, candidates: List[ResidueCandidate], shared_seen: Optional[Set[tuple]] = None) -> List[ResidueCandidate]:
        out = list(candidates)
        seen = shared_seen if shared_seen is not None else {(c.type, (c.mapped_path or c.path).lower()) for c in out if (c.mapped_path or c.path)}
        for candidate in list(candidates):
            if candidate.exists_now is not True or candidate.raw_score < 55:
                continue
            if candidate.type in {"dir", "file", "config", "database", "cache", "log", "binary"}:
                base_dir = candidate.mapped_path if candidate.type == "dir" else os.path.dirname(candidate.mapped_path)
                if not base_dir:
                    continue
                vendor_root = self._derive_vendor_root(base_dir)
                scan_roots = self._mirror_vendor_roots(vendor_root) if vendor_root else [base_dir]
                for scan_root in scan_roots:
                    if not os.path.isdir(scan_root):
                        continue
                    for root, dirs, files in self._walk_with_generic_reset(scan_root, max_depth=4):
                        for fname in files:
                            fp = normalize_path(os.path.join(root, fname))
                            # Skip trusted-signed system files (Təklif 3)
                            if is_trusted_signed(fp):
                                continue
                            t = detect_item_type(fp)
                            key = (t, fp.lower())
                            if key in seen:
                                continue
                            raw_score = max(30, int(candidate.raw_score * self._extension_multiplier(fp)))
                            out.append(
                                self._build_candidate_from_path(
                                    fp,
                                    raw_score,
                                    f"live survivor expansion: {scan_root}",
                                    candidate.first_seen,
                                    candidate.last_seen,
                                    candidate.processes,
                                    ["SurvivorScan"],
                                )
                            )
                            seen.add(key)
            elif candidate.type == "reg_key":
                for reg_path in self._enumerate_registry_branch(candidate.path):
                    t = detect_item_type(reg_path)
                    mapped = map_sandbox_user_path(reg_path)
                    key = (t, mapped.lower())
                    if key in seen:
                        continue
                    raw_score = max(30, int(candidate.raw_score * 0.5))
                    out.append(
                        self._build_candidate_from_path(
                            reg_path,
                            raw_score,
                            f"live survivor expansion: {candidate.path}",
                            candidate.first_seen,
                            candidate.last_seen,
                            candidate.processes,
                            ["RegistrySurvivorScan"],
                        )
                    )
                    seen.add(key)
        return out

    def _expand_confirmed_registry_branches(self, candidates: List[ResidueCandidate], shared_seen: Optional[Set[tuple]] = None) -> List[ResidueCandidate]:
        out = list(candidates)
        seen = shared_seen if shared_seen is not None else {(c.type, (c.mapped_path or c.path).lower()) for c in out if (c.mapped_path or c.path)}
        for candidate in list(candidates):
            if candidate.raw_score < 50:
                continue
            if candidate.type not in {"reg_key", "service", "run_entry", "clsid", "typelib", "context_menu", "shell_extension", "protocol_handler"}:
                continue
            lp = (candidate.path or "").lower()
            if not lp.startswith(REGISTRY_PREFIXES):
                continue
            max_items = 600
            for marker, limit in REGISTRY_EXPANSION_LIMITS.items():
                if marker in lp:
                    max_items = limit
                    break
            for reg_path in self._enumerate_registry_branch(candidate.path, max_items=max_items):
                item_type = detect_item_type(reg_path)
                mapped = map_sandbox_user_path(reg_path)
                key = (item_type, mapped.lower())
                if key in seen:
                    continue
                raw_score = max(35, int(candidate.raw_score * 0.55))
                out.append(
                    self._build_candidate_from_path(
                        reg_path,
                        raw_score,
                        f"registry branch sweep from confirmed residue: {candidate.path}",
                        candidate.first_seen,
                        candidate.last_seen,
                        candidate.processes,
                        ["RegistryBranchSweep"],
                    )
                )
                seen.add(key)
        return out

    def _expand_siblings(self, candidates: List[ResidueCandidate], shared_seen: Optional[Set[tuple]] = None) -> List[ResidueCandidate]:
        out = list(candidates)
        seen = shared_seen if shared_seen is not None else {(c.type, (c.mapped_path or c.path).lower()) for c in out if (c.mapped_path or c.path)}
        for candidate in list(candidates):
            if candidate.raw_score < 40:
                continue
            if candidate.type in {"file", "config", "database", "cache", "log", "binary", "shortcut"} and candidate.exists_now is True:
                folder = os.path.dirname(candidate.mapped_path)
                base = os.path.splitext(os.path.basename(candidate.mapped_path))[0].lower()
                if not folder or not base or not os.path.isdir(folder):
                    continue
                try:
                    for name in os.listdir(folder):
                        if not name.lower().startswith(base + "."):
                            continue
                        fp = normalize_path(os.path.join(folder, name))
                        t = detect_item_type(fp)
                        key = (t, fp.lower())
                        if key in seen:
                            continue
                        raw_score = max(30, int(candidate.raw_score * 0.5))
                        out.append(
                            self._build_candidate_from_path(
                                fp,
                                raw_score,
                                f"sibling of confirmed residue: {candidate.mapped_path}",
                                candidate.first_seen,
                                candidate.last_seen,
                                candidate.processes,
                                ["SiblingScan"],
                            )
                        )
                        seen.add(key)
                except OSError:
                    continue
            elif candidate.type in {"reg_key", "service", "run_entry", "clsid", "typelib", "context_menu", "shell_extension", "protocol_handler", "file_association", "firewall_rule"}:
                parent = normalize_path(os.path.dirname(candidate.path))
                if not parent:
                    continue
                for reg_path in self._enumerate_registry_branch(parent, max_items=200):
                    t = detect_item_type(reg_path)
                    mapped = map_sandbox_user_path(reg_path)
                    key = (t, mapped.lower())
                    if key in seen:
                        continue
                    raw_score = max(30, int(candidate.raw_score * 0.5))
                    out.append(
                        self._build_candidate_from_path(
                            reg_path,
                            raw_score,
                            f"sibling of confirmed residue: {candidate.path}",
                            candidate.first_seen,
                            candidate.last_seen,
                            candidate.processes,
                            ["RegistrySiblingScan"],
                        )
                    )
                    seen.add(key)
        return out

    def _assign_family_clusters(self, candidates: List[ResidueCandidate]) -> None:
        for candidate in candidates:
            vendor_token = self._extract_vendor_token(candidate.path)
            if vendor_token and vendor_token not in STOP_WORDS:
                candidate.vendor_family_id = vendor_token

            lp = (candidate.path or "").lower()
            if "\\services\\" in lp:
                candidate.service_branch_id = lp.split("\\services\\", 1)[0] + "\\services\\"

            candidate.root_family_id = candidate.vendor_family_id or candidate.service_branch_id or candidate.rename_family_id or candidate.installer_cluster_id

    def _apply_cluster_bonus(self, candidates: List[ResidueCandidate]) -> None:
        clusters: Dict[str, List[ResidueCandidate]] = defaultdict(list)
        installer_clusters: Dict[str, List[ResidueCandidate]] = defaultdict(list)
        vendor_clusters: Dict[str, List[ResidueCandidate]] = defaultdict(list)
        service_branch_clusters: Dict[str, List[ResidueCandidate]] = defaultdict(list)
        rename_family_clusters: Dict[str, List[ResidueCandidate]] = defaultdict(list)
        membership: Dict[int, Set[str]] = defaultdict(set)
        for candidate in candidates:
            parent = os.path.dirname((candidate.mapped_path or candidate.path))
            if candidate.type == "reg_key":
                parent = os.path.dirname(candidate.path)
            if parent:
                clusters[parent.lower()].append(candidate)
            if candidate.installer_cluster_id:
                installer_clusters[candidate.installer_cluster_id.lower()].append(candidate)
            if candidate.rename_family_id:
                rename_family_clusters[candidate.rename_family_id.lower()].append(candidate)
            if candidate.vendor_family_id:
                vendor_clusters[candidate.vendor_family_id.lower()].append(candidate)
            if candidate.service_branch_id:
                service_branch_clusters[candidate.service_branch_id.lower()].append(candidate)

        def apply_bonus(items: List[ResidueCandidate], reason_label: str):
            count = len(items)
            if count < 4:
                return
            cb = self.config["cluster_bonus"]
            bonus = cb["threshold_4"]
            if count >= 10:
                bonus = cb["threshold_10"]
            elif count >= 7:
                bonus = cb["threshold_7"]
            for item in items:
                item.raw_score += bonus
                item.score = max(0, min(item.raw_score, 100))
                item.reasons = self._unique_compact(item.reasons + [f"cluster bonus: {count} items in {reason_label}"])
                item.status = self._status_from_score(item.raw_score, item.exists_now, item.subtree_class)
                membership[id(item)].add(reason_label)

        for _, items in clusters.items():
            apply_bonus(items, "same directory/branch")
        for _, items in installer_clusters.items():
            apply_bonus(items, "installer cluster")
        for token, items in vendor_clusters.items():
            apply_bonus(items, f"vendor family '{token}'")
        for _, items in service_branch_clusters.items():
            apply_bonus(items, "service registry branch")
        for _, items in rename_family_clusters.items():
            apply_bonus(items, "rename family")

        for item in candidates:
            if item.subtree_class in {"subtree_only", "subtree_first"}:
                item.raw_score += self.config["subtree"]["subtree_only_or_first_bonus"]
                item.score = max(0, min(item.raw_score, 100))
                item.reasons = self._unique_compact(item.reasons + [f"subtree bonus: {item.subtree_class}"])
                item.status = self._status_from_score(item.raw_score, item.exists_now, item.subtree_class)
                membership[id(item)].add("subtree")

        fus = self.config["fusion"]
        for item in candidates:
            kinds = membership.get(id(item), set())
            item.cluster_membership_count = len(kinds)
            if len(kinds) >= 4:
                item.raw_score += fus["types_4_bonus"]
                item.status = "safe_to_delete" if item.exists_now is True else self._status_from_score(item.raw_score, item.exists_now, item.subtree_class)
                item.reasons = self._unique_compact(item.reasons + [f"multi-evidence fusion: {len(kinds)} cluster types"])
            elif len(kinds) >= 3:
                item.raw_score += fus["types_3_bonus"]
                item.status = self._status_from_score(item.raw_score, item.exists_now, item.subtree_class)
                item.reasons = self._unique_compact(item.reasons + [f"multi-evidence fusion: {len(kinds)} cluster types"])
            item.score = max(0, min(item.raw_score, 100))

    def _status_from_score(
        self,
        raw_score: int,
        exists_now: Optional[bool],
        subtree_class: str = "none",
        checked_only: bool = False,
    ) -> str:
        if checked_only:
            if exists_now is False:
                return "already_gone"
            return "checked_only"
        cfg_t = self.config["thresholds"]
        safe_threshold = cfg_t["safe_delete"]
        review_threshold = cfg_t["review"]
        if subtree_class == "subtree_only":
            safe_threshold -= 10
            review_threshold -= 10
        if raw_score >= safe_threshold:
            if exists_now is True:
                return "safe_to_delete"
            if exists_now is False:
                return "already_gone"
            return "review"
        if raw_score >= review_threshold:
            if exists_now is False:
                return "already_gone"
            return "review"
        return "ignore"

    def _build_session_time_window(self, related_pids: Set[int]) -> Tuple[Optional[datetime], Optional[datetime]]:
        starts: List[datetime] = []
        ends: List[datetime] = []
        for pid in related_pids:
            info = self.process_info_by_pid.get(pid)
            if not info:
                continue
            start_dt = parse_procmon_time_to_dt(info.start_time)
            end_dt = parse_procmon_time_to_dt(info.end_time)
            if start_dt:
                starts.append(start_dt)
            if end_dt:
                ends.append(end_dt)
            elif start_dt:
                ends.append(start_dt)
        if not starts:
            return None, None
        return min(starts), max(ends) if ends else max(starts)

    def _add_rename_dest_candidates(self, candidates: List[ResidueCandidate]) -> List[ResidueCandidate]:
        by_path = {self._canonical_path(c.path): c for c in candidates if self._canonical_path(c.path)}
        out = list(candidates)
        rename_context: Dict[str, Tuple[Optional[int], str, str]] = {}
        rename_family_by_path: Dict[str, str] = {}
        for src, dst, pid, t in self.rename_edges:
            src_k = self._canonical_path(src)
            dst_k = self._canonical_path(dst)
            rename_context[src_k] = (pid, t, normalize_path(os.path.dirname(src)).lower())
            rename_context[dst_k] = (pid, t, normalize_path(os.path.dirname(dst)).lower())

        for src in self.rename_map:
            chain = self._resolve_full_rename_chain(src)
            if not chain:
                continue
            family_id = hashlib.md5(chain[0].lower().encode("utf-8")).hexdigest()[:12]
            for item in chain:
                rename_family_by_path[self._canonical_path(item)] = family_id

        for candidate in out:
            family = rename_family_by_path.get(self._canonical_path(candidate.path))
            if family:
                candidate.rename_family_id = family

        def add_candidate_from_chain(base: ResidueCandidate, chain_item: str, step_idx: int, total_steps: int, reason: str):
            key = self._canonical_path(chain_item)
            if key in by_path:
                return
            mapped = map_sandbox_user_path(chain_item)
            exists_now = self._path_exists(mapped)
            raw_score = max(40, base.raw_score - (step_idx * 5))
            family_id = rename_family_by_path.get(key) or base.rename_family_id
            cand = ResidueCandidate(
                type=detect_item_type(chain_item),
                path=chain_item,
                mapped_path=mapped,
                raw_score=raw_score,
                score=max(0, min(raw_score, 100)),
                reasons=self._unique_compact(base.reasons + [reason, f"rename chain step {step_idx}/{total_steps}"]),
                first_seen=base.first_seen,
                last_seen=base.last_seen,
                processes=base.processes,
                operations=sorted(set(base.operations) | {"SetRenameInformationFile"}),
                exists_now=exists_now,
                status=self._status_from_score(raw_score, exists_now),
                category=category_from_type(detect_item_type(chain_item)),
                cluster=cluster_from_path(chain_item),
                rename_family_id=family_id,
            )
            out.append(cand)
            by_path[key] = cand

        def add_parent_dir(base: ResidueCandidate, item_path: str):
            parent = normalize_path(os.path.dirname(item_path))
            key = self._canonical_path(parent)
            if not parent or key in by_path:
                return
            mapped = map_sandbox_user_path(parent)
            exists_now = self._path_exists(mapped)
            raw_score = max(30, base.raw_score - 15)
            family_id = rename_family_by_path.get(self._canonical_path(item_path)) or base.rename_family_id
            cand = ResidueCandidate(
                type="dir",
                path=parent,
                mapped_path=mapped,
                raw_score=raw_score,
                score=max(0, min(raw_score, 100)),
                reasons=self._unique_compact(base.reasons + [f"rename chain parent directory: {parent}"]),
                first_seen=base.first_seen,
                last_seen=base.last_seen,
                processes=base.processes,
                operations=sorted(set(base.operations) | {"SetRenameInformationFile"}),
                exists_now=exists_now,
                status=self._status_from_score(raw_score, exists_now),
                category=category_from_type("dir"),
                cluster=cluster_from_path(parent),
                rename_family_id=family_id,
            )
            out.append(cand)
            by_path[key] = cand

        for source_lc, dest in self.rename_map.items():
            src = by_path.get(self._canonical_path(source_lc))
            if not src:
                continue
            chain = self._resolve_full_rename_chain(src.path)
            total_steps = max(1, len(chain) - 1)
            for step_idx, chain_item in enumerate(chain[1:], start=1):
                add_candidate_from_chain(src, chain_item, step_idx, total_steps, f"renamed from {src.path}")
                add_parent_dir(src, chain_item)

        for candidate in list(out):
            reverse_chain = self._resolve_full_rename_chain(candidate.path, reverse=True)
            if len(reverse_chain) <= 1:
                continue
            total_steps = max(1, len(reverse_chain) - 1)
            for step_idx, source_path in enumerate(reverse_chain[1:], start=1):
                add_candidate_from_chain(candidate, source_path, step_idx, total_steps, f"renamed to {candidate.path}")
                add_parent_dir(candidate, source_path)

        # LOGIC-4 fix: instead of O(n*m), group write events by PID and by parent dir
        # so we only look at events that are plausibly near each rename context path.
        # Build two indexes: pid -> [events], parent_dir -> [events]
        write_events_by_pid: Dict[Optional[int], List] = defaultdict(list)
        write_events_by_parent: Dict[str, List] = defaultdict(list)
        for ev in self.events:
            if ev.path and (ev.operation in WRITE_OPS or ev.operation == "CreateFile"):
                write_events_by_pid[ev.pid].append(ev)
                ev_par = normalize_path(os.path.dirname(ev.path)).lower()
                if ev_par:
                    write_events_by_parent[ev_par].append(ev)

        for path_lc, base in list(by_path.items()):
            if path_lc not in rename_context:
                continue
            pid, ts, base_parent = rename_context[path_lc]
            base_dt = parse_procmon_time_to_dt(ts)
            # Candidate events: same PID + same parent dir (union, deduped)
            candidate_evs: Dict[int, object] = {}
            if pid is not None:
                for ev in write_events_by_pid.get(pid, []):
                    candidate_evs[id(ev)] = ev
            if base_parent:
                for ev in write_events_by_parent.get(base_parent, []):
                    candidate_evs[id(ev)] = ev
            for ev in candidate_evs.values():
                ev_dt = parse_procmon_time_to_dt(ev.time_of_day)
                if base_dt and ev_dt:
                    window = 5.0 if (pid is not None and ev.pid == pid) else 3.0
                    if abs((ev_dt - base_dt).total_seconds()) > window:
                        continue
                key = self._canonical_path(ev.path)
                if key in by_path:
                    continue
                add_candidate_from_chain(base, ev.path, 1, 1, f"temporal sibling near rename by PID {pid}")
        return out

    def _add_parent_directory_candidates(self, candidates: List[ResidueCandidate], created_dirs_by_chain: Set[str]) -> List[ResidueCandidate]:
        existing = {(c.type, self._canonical_path(c.path)) for c in candidates}
        out = list(candidates)
        for candidate in list(candidates):
            parent = normalize_path(os.path.dirname(candidate.path))
            if not parent:
                continue
            key = ("dir", self._canonical_path(parent))
            if key in existing:
                continue
            if self._canonical_path(parent) not in created_dirs_by_chain:
                continue
            raw_score = 25
            mapped = map_sandbox_user_path(parent)
            exists_now = self._path_exists(mapped)
            out.append(
                ResidueCandidate(
                    type="dir",
                    path=parent,
                    mapped_path=mapped,
                    raw_score=raw_score,
                    score=max(0, min(raw_score, 100)),
                    reasons=self._unique_compact([f"parent directory of confirmed residue: {candidate.path}"]),
                    first_seen=candidate.first_seen,
                    last_seen=candidate.last_seen,
                    processes=candidate.processes,
                    operations=["CreateDirectory"],
                    exists_now=exists_now,
                    status=self._status_from_score(raw_score, exists_now),
                )
            )
            existing.add(key)
        return out

    def _enrich_candidates_with_file_metadata(
        self,
        candidates: List[ResidueCandidate],
        term_patterns: Dict[str, List[Tuple[str, re.Pattern[str], float]]],
    ) -> None:
        # Collect candidates eligible for metadata enrichment
        eligible = [
            c for c in candidates
            if c.exists_now is True and c.type in {"file", "binary"}
        ]
        if not eligible:
            return

        # Phase 1: Read metadata from disk in parallel (I/O-bound)
        def _read_meta(mapped_path: str) -> Tuple[str, Optional[bool], Optional[Dict[str, str]]]:
            """Returns (mapped_path, is_trusted, version_info)."""
            trusted = is_trusted_signed(mapped_path)
            if trusted:
                return mapped_path, True, None
            info = read_file_version_info(mapped_path)
            return mapped_path, False, info

        meta_results: Dict[str, Tuple[Optional[bool], Optional[Dict[str, str]]]] = {}
        unique_paths = list({c.mapped_path for c in eligible})
        with ThreadPoolExecutor(max_workers=min(8, os.cpu_count() or 4)) as pool:
            for path, trusted, info in pool.map(_read_meta, unique_paths):
                meta_results[path] = (trusted, info)

        # Phase 2: Apply results (single-threaded, mutates candidates)
        for candidate in eligible:
            trusted, info = meta_results.get(candidate.mapped_path, (False, None))

            if trusted:
                candidate.status = "ignore"
                candidate.raw_score = max(0, candidate.raw_score - 50)
                candidate.score = max(0, min(candidate.raw_score, 100))
                candidate.reasons = self._unique_compact(
                    candidate.reasons + ["PROTECTED: signed by trusted publisher"]
                )
                continue  # Never touch signed system files

            if not info:
                continue
            metadata_text = " ".join(v for v in [info.get("CompanyName", ""), info.get("ProductName", "")] if v)
            if not metadata_text:
                continue
            candidate.reasons = self._unique_compact(candidate.reasons + [f"metadata: {metadata_text}"])
            if token_hits(metadata_text, term_patterns):
                candidate.raw_score += 25
                candidate.score = max(0, min(candidate.raw_score, 100))
                candidate.status = self._status_from_score(candidate.raw_score, candidate.exists_now, candidate.subtree_class)

    def _assign_installer_clusters(self, candidates: List[ResidueCandidate]) -> None:
        for candidate in candidates:
            path_text = f"{candidate.path} {' '.join(candidate.reasons)}"
            match = GUID_RE.search(path_text)
            if match:
                candidate.installer_cluster_id = match.group(0).strip("{}").lower()
                continue
            lp = (candidate.path or "").lower()
            if candidate.category == "execution_trace":
                pf_match = self._PREFETCH_PF_RE.search(lp)
                if pf_match:
                    candidate.installer_cluster_id = pf_match.group(1).lower()
                    continue
                for token in split_tokens(lp):
                    if token not in STOP_WORDS:
                        candidate.installer_cluster_id = token
                        break
                if candidate.installer_cluster_id:
                    continue
            if "\\uninstall\\" in lp:
                parts = lp.split("\\uninstall\\", 1)
                if len(parts) > 1 and parts[1]:
                    candidate.installer_cluster_id = parts[1].split("\\")[0][:64]

    @staticmethod
    def _removal_layer_from_candidate(category: str, status: str, reason_blob: str) -> str:
        blob = (reason_blob or "").lower()
        if status == "safe_to_delete":
            return "confirmed_residue"
        if "live survivor expansion" in blob:
            return "live_survivor_expansion"
        if "neighborhood" in blob or "sibling of" in blob:
            return "aggressive_neighborhood"
        if status == "weak_but_related":
            return "weak_but_related"
        if category == "persistence":
            return "persistence_residue"
        if category == "installer_bookkeeping":
            return "installer_bookkeeping"
        if category == "execution_trace":
            return "execution_trace"
        if category == "user_data":
            return "user_data"
        return "review_queue"

    def _assign_removal_layers(self, candidates: List[ResidueCandidate]) -> None:
        for candidate in candidates:
            candidate.removal_layer = self._removal_layer_from_candidate(candidate.category, candidate.status, " ".join(candidate.reasons))

    def _merge_by_mapped_path(self, candidates: List[ResidueCandidate]) -> List[ResidueCandidate]:
        merged: Dict[tuple, ResidueCandidate] = {}
        merge_counts: Dict[tuple, int] = defaultdict(int)
        for candidate in candidates:
            artifact_type, canonical_path = self.canonical_artifact_key(candidate.mapped_path or candidate.path)
            key = (candidate.type, artifact_type, canonical_path)
            existing = merged.get(key)
            if existing is None:
                merged[key] = candidate
                continue
            merge_counts[key] += 1
            if candidate.raw_score > existing.raw_score:
                existing.path = candidate.path
                existing.mapped_path = candidate.mapped_path
            existing.raw_score = max(existing.raw_score, candidate.raw_score)
            existing.score = max(existing.score, candidate.score)
            existing.first_seen = min(existing.first_seen, candidate.first_seen, key=self._time_sort_key)
            existing.last_seen = max(existing.last_seen, candidate.last_seen, key=self._time_sort_key)
            if existing.exists_now is not True and candidate.exists_now is True:
                existing.exists_now = True
            elif existing.exists_now is None and candidate.exists_now is False:
                existing.exists_now = False
            existing.processes = sorted(set(existing.processes) | set(candidate.processes))
            existing.operations = sorted(set(existing.operations) | set(candidate.operations))
            existing.reasons = self._unique_compact(existing.reasons + candidate.reasons)
            if not existing.installer_cluster_id and candidate.installer_cluster_id:
                existing.installer_cluster_id = candidate.installer_cluster_id
            if existing.subtree_class == "none" and candidate.subtree_class != "none":
                existing.subtree_class = candidate.subtree_class
            if not existing.rename_family_id and candidate.rename_family_id:
                existing.rename_family_id = candidate.rename_family_id
            if not existing.vendor_family_id and candidate.vendor_family_id:
                existing.vendor_family_id = candidate.vendor_family_id
            if not existing.service_branch_id and candidate.service_branch_id:
                existing.service_branch_id = candidate.service_branch_id
            if not existing.root_family_id and candidate.root_family_id:
                existing.root_family_id = candidate.root_family_id
            existing.cluster_membership_count = max(existing.cluster_membership_count, candidate.cluster_membership_count)
            if existing.removal_layer == "review_queue" and candidate.removal_layer != "review_queue":
                existing.removal_layer = candidate.removal_layer

        for key, count in merge_counts.items():
            merged[key].reasons = self._unique_compact(merged[key].reasons + [f"merged {count + 1} entries with same canonical artifact key"])
            merged[key].status = self._status_from_score(merged[key].raw_score, merged[key].exists_now, merged[key].subtree_class)
            merged[key].score = max(0, min(merged[key].raw_score, 100))
            merged[key].removal_layer = self._removal_layer_from_candidate(merged[key].category, merged[key].status, " ".join(merged[key].reasons))
        return list(merged.values())

    @staticmethod
    def _time_sort_key(value: str) -> str:
        """Sort key for Procmon time strings. Uses datetime parse to handle 12-hour AM/PM correctly."""
        dt = parse_procmon_time_to_dt(value)
        if dt:
            return dt.strftime("%H:%M:%S.%f")
        # Fallback: raw string — pad single-digit hours so string sort works
        text = (value or "").strip()
        if not text:
            return text
        # Handle both 12-hour (e.g. "9:30:00 AM") and 24-hour (e.g. "9:30:00") raw strings
        # Convert AM/PM so that "12:xx AM" < "1:xx PM" etc.
        upper = text.upper()
        is_pm = upper.endswith(" PM")
        is_am = upper.endswith(" AM")
        if is_pm or is_am:
            time_part = text[:-3].strip()
            try:
                h, rest = time_part.split(":", 1)
                h = int(h)
                if is_am and h == 12:
                    h = 0
                elif is_pm and h != 12:
                    h += 12
                return f"{h:02d}:{rest}"
            except (ValueError, IndexError):
                pass
        # Plain 24-hour or unparseable — just zero-pad leading hour digit
        if text[0].isdigit() and ":" in text:
            hour, rest = text.split(":", 1)
            if len(hour) == 1:
                return f"0{hour}:{rest}"
        return text

    def _registry_path_exists(self, path: str) -> Optional[bool]:
        """P2 fix: Distinguish access-denied from not-found.
        Returns True if key/value exists, False if confirmed not found,
        None if access was denied or check is inconclusive."""
        if os.name != "nt":
            return None
        root, sub = self._registry_to_winreg_root(path)
        if root is None or not sub:
            return None
        sub = sub.strip("\\")
        if not sub:
            return None
        saw_access_denied = False
        saw_not_found = False
        try:
            # Try all WOW64 access modes: native, 32-bit view, 64-bit view
            for access_flag in [winreg.KEY_READ, winreg.KEY_READ | winreg.KEY_WOW64_32KEY, winreg.KEY_READ | winreg.KEY_WOW64_64KEY]:
                try:
                    with winreg.OpenKey(root, sub, 0, access_flag):
                        return True
                except OSError as exc:
                    winerr = getattr(exc, "winerror", None)
                    if winerr in (2, 3):  # ERROR_FILE_NOT_FOUND / ERROR_PATH_NOT_FOUND
                        saw_not_found = True
                    elif winerr == 5:  # ERROR_ACCESS_DENIED
                        saw_access_denied = True
                    # Other errors: continue to next access flag

            # Try as value name
            if "\\" in sub:
                parent, leaf = sub.rsplit("\\", 1)
                for access_flag in [winreg.KEY_READ, winreg.KEY_READ | winreg.KEY_WOW64_32KEY, winreg.KEY_READ | winreg.KEY_WOW64_64KEY]:
                    try:
                        with winreg.OpenKey(root, parent, 0, access_flag) as key:
                            winreg.QueryValueEx(key, leaf)
                            return True
                    except OSError as exc:
                        winerr = getattr(exc, "winerror", None)
                        if winerr in (2, 3):
                            saw_not_found = True
                        elif winerr == 5:
                            saw_access_denied = True
                        continue
            # P2 fix: if we only saw access denied (never confirmed not-found),
            # return None (unknown) instead of False (doesn't exist)
            if saw_access_denied and not saw_not_found:
                return None
            return False
        except Exception:
            return None

    def _path_exists(self, path: str) -> Optional[bool]:
        if not path:
            return None
        lp = (path or "").lower()
        try:
            if lp.startswith(REGISTRY_PREFIXES):
                result = self._registry_path_exists(path)
                if result is True:
                    return True
                # Check WOW64 equivalents for registry
                for eq_path in get_wow64_equivalents(path):
                    eq_result = self._registry_path_exists(eq_path)
                    if eq_result is True:
                        return True
                return result
            # Filesystem check
            result = os.path.exists(path)
            if result:
                return True
            # Check WOW64 equivalents for filesystem (Program Files <-> Program Files (x86))
            for eq_path in get_wow64_equivalents(path):
                if os.path.exists(eq_path):
                    return True
            return result
        except Exception:
            return None

    @staticmethod
    def _unique_compact(items: List[str]) -> List[str]:
        out = []
        seen = set()
        for item in items:
            key = item.lower().strip()
            if not key or key in seen:
                continue
            seen.add(key)
            out.append(item)
        return out[:12]  # LOGIC-4 fix: Increased from 8 to 12

    def extract_vendor_aliases(self, related_pids: Set[int], residues: List[ResidueCandidate]) -> List[str]:
        aliases: Set[str] = set()
        for residue in residues:
            token = self._extract_vendor_token(residue.path)
            if token and token not in STOP_WORDS:
                aliases.add(token)
        for pid in related_pids:
            info = self.process_info_by_pid.get(pid)
            if not info:
                continue
            for token in split_tokens(info.image_path) + split_tokens(info.command_line):
                if token not in STOP_WORDS:
                    aliases.add(token)
        for ev in self.events:
            lp = (ev.path or "").lower()
            if lp.startswith(UNINSTALL_KEY_PREFIXES):
                for token in split_tokens(ev.detail or ""):
                    if token not in STOP_WORDS:
                        aliases.add(token)
            if "\\services\\" in lp:
                service_name = lp.split("\\services\\", 1)[-1].split("\\", 1)[0]
                aliases.update(split_tokens(service_name))
                aliases.update(split_tokens(ev.detail or ""))
            token = self._extract_vendor_token(ev.path or "")
            if token and token not in STOP_WORDS:
                aliases.add(token)
        return sorted(aliases)

    def collect_suggested_terms_detailed(
        self,
        related_pids: Set[int],
        residues: List[ResidueCandidate],
        root_terms: List[str],
    ) -> List[Dict[str, object]]:
        seen = {term.lower() for term in root_terms}
        weighted: Dict[str, int] = defaultdict(int)
        term_type: Dict[str, str] = {}

        def add_token(token: str, weight: int, token_kind: str):
            tok = token.lower().strip()
            if not tok or tok in seen:
                return
            weighted[tok] += weight
            if tok not in term_type or weighted[tok] >= 20:
                term_type[tok] = token_kind

        for token in self.extract_vendor_aliases(related_pids, residues):
            add_token(token, 20, "vendor_token")

        for pid in related_pids:
            info = self.process_info_by_pid.get(pid)
            if not info:
                continue
            for token in split_tokens(info.proc_name):
                add_token(token, 14, "service_token")
            for token in split_tokens(info.image_path):
                add_token(token, 10, "product_token")
            for token in split_tokens(info.command_line):
                add_token(token, 8, "product_token")

        for residue in residues:
            for token in split_tokens(residue.path):
                add_token(token, 7, "path_token")

        for ev in self.events:
            if ev.pid is not None and ev.pid not in related_pids:
                continue
            detail_lower = (ev.detail or "").lower()
            detail_tokens = split_tokens(ev.detail)
            if "publisher" in detail_lower or "company" in detail_lower:
                for token in detail_tokens:
                    add_token(token, 18, "company_token")
            elif "displayname" in detail_lower or "uninstall" in (ev.path or "").lower():
                for token in detail_tokens:
                    add_token(token, 16, "uninstall_token")
            else:
                for token in detail_tokens:
                    add_token(token, 6, "product_token")

        typed_order = ["vendor_token", "company_token", "uninstall_token", "service_token", "product_token", "path_token"]
        output: List[str] = []
        taken: Set[str] = set()
        for kind in typed_order:
            picks = [t for t, k in term_type.items() if k == kind]
            picks.sort(key=lambda t: weighted[t], reverse=True)
            for token in picks[:2]:
                if token in taken:
                    continue
                taken.add(token)
                output.append(token)

        for token, _ in sorted(weighted.items(), key=lambda item: item[1], reverse=True):
            if token in taken:
                continue
            output.append(token)
            taken.add(token)
            if len(output) >= 20:
                break

        detailed: List[Dict[str, object]] = []
        for token in output[:20]:
            kind = term_type.get(token, "product_token")
            weight = weighted.get(token, 0)
            trust_level = "weak"
            if kind in {"vendor_token", "company_token", "service_token"} and weight >= 14:
                trust_level = "trusted"
            elif kind in {"uninstall_token", "product_token"} and weight >= 10:
                trust_level = "moderate"
            detailed.append({"term": token, "weight": weight, "kind": kind, "trust_level": trust_level})
        return detailed

    def collect_suggested_terms(
        self,
        related_pids: Set[int],
        residues: List[ResidueCandidate],
        root_terms: List[str],
    ) -> List[str]:
        return [item["term"] for item in self.collect_suggested_terms_detailed(related_pids, residues, root_terms)]

