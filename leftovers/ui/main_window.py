"""MainWindow – the main application window."""

import json
import os
import sys
from typing import Optional

from PySide6.QtCore import QModelIndex, QThread, Qt
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableView,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from leftovers.ui.table_model import GenericTableModel
from leftovers.workers.analysis import AnalysisWorker


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Procmon Residue Analyzer")
        self.resize(1450, 860)

        self.current_payload: Optional[dict] = None
        self.thread: Optional[QThread] = None
        self.worker: Optional[AnalysisWorker] = None

        self.csv_path_edit = QLineEdit()
        self.csv_path_edit.setPlaceholderText("Procmon CSV seç")
        self.browse_btn = QPushButton("CSV seç")
        self.analyze_btn = QPushButton("Analiz et")
        self.terms_edit = QLineEdit()
        self.terms_edit.setPlaceholderText("məs: verdent")
        self.min_score_spin = QSpinBox()
        self.min_score_spin.setRange(0, 100)
        self.min_score_spin.setValue(40)
        self.progress = QProgressBar()
        self.status_text = QLabel("Hazır")

        self.residue_table = QTableView()
        self.details_box = QPlainTextEdit()
        self.details_box.setReadOnly(True)
        self.log_box = QPlainTextEdit()
        self.log_box.setReadOnly(True)
        self._last_progress_log_bucket = -1

        self._build_ui()
        self._wire_events()

    def closeEvent(self, event):
        """P6 fix: Override closeEvent with safe cooperative shutdown.
        Never calls QThread.terminate() — relies on cancel event and graceful timeout."""
        if self.thread and self.thread.isRunning():
            if self.worker:
                self.worker.cancel()
            self.thread.quit()
            if not self.thread.wait(10000):  # Wait up to 10 seconds for cooperative shutdown
                # P6 fix: Do NOT call terminate() — log warning and let OS clean up on exit
                print("WARNING: Analysis thread did not stop within 10s; detaching.", file=sys.stderr)
                # Disconnect signals to prevent callbacks after window is destroyed
                try:
                    self.thread.finished.disconnect()
                except RuntimeError:
                    pass
        event.accept()

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)

        controls = QGroupBox("Giriş")
        form = QFormLayout(controls)

        csv_row = QHBoxLayout()
        csv_row.addWidget(self.csv_path_edit, 1)
        csv_row.addWidget(self.browse_btn)
        form.addRow("CSV", csv_row)
        form.addRow("Proqram adı", self.terms_edit)
        form.addRow("Minimum skor", self.min_score_spin)
        form.addRow("", self.analyze_btn)

        main_layout.addWidget(controls)
        main_layout.addWidget(self.progress)
        main_layout.addWidget(self.status_text)

        splitter = QSplitter(Qt.Horizontal)
        left = QWidget()
        left_layout = QVBoxLayout(left)
        tabs = QTabWidget()

        residues_tab = QWidget()
        residues_layout = QVBoxLayout(residues_tab)
        residues_layout.addWidget(QLabel("Tapılmış izlər"))
        residues_layout.addWidget(self.residue_table)

        logs_tab = QWidget()
        logs_layout = QVBoxLayout(logs_tab)
        logs_layout.addWidget(QLabel("İş jurnalı"))
        logs_layout.addWidget(self.log_box)

        tabs.addTab(residues_tab, "İzlər")
        tabs.addTab(logs_tab, "Log")
        left_layout.addWidget(tabs)
        splitter.addWidget(left)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.addWidget(QLabel("Seçilmiş sətrin detalları"))
        right_layout.addWidget(self.details_box)
        splitter.addWidget(right)
        splitter.setSizes([1000, 450])

        main_layout.addWidget(splitter, 1)

        menu = self.menuBar().addMenu("Fayl")
        export_json = QAction("JSON export", self)
        export_txt = QAction("TXT hesabat export", self)
        menu.addAction(export_json)
        menu.addAction(export_txt)
        export_json.triggered.connect(self.export_json)
        export_txt.triggered.connect(self.export_txt)

        # Configure residue table
        self.residue_table.setSelectionBehavior(QTableView.SelectRows)
        self.residue_table.setSelectionMode(QTableView.SingleSelection)
        self.residue_table.horizontalHeader().setStretchLastSection(True)
        self.residue_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.residue_table.setAlternatingRowColors(True)

    def _wire_events(self):
        self.browse_btn.clicked.connect(self.choose_csv)
        self.analyze_btn.clicked.connect(self.start_analysis)
        self.residue_table.clicked.connect(self.on_residue_row_clicked)

    def choose_csv(self):
        path, _ = QFileDialog.getOpenFileName(self, "Procmon CSV seç", "", "CSV Files (*.csv)")
        if path:
            self.csv_path_edit.setText(path)

    def log(self, text: str):
        self.log_box.appendPlainText(text)
        self.status_text.setText(text)

    def start_analysis(self):
        csv_path = self.csv_path_edit.text().strip()
        if not csv_path or not os.path.isfile(csv_path):
            QMessageBox.warning(self, "Səhv", "Düzgün CSV faylı seç.")
            return

        program_name = self.terms_edit.text().strip()
        if not program_name:
            QMessageBox.warning(self, "Səhv", "Bir proqram adı daxil et.")
            return
        if "," in program_name:
            QMessageBox.warning(self, "Səhv", "Yalnız 1 proqram adı yazın (vergül istifadə etməyin).")
            return

        if self.thread and self.thread.isRunning():
            if self.worker:
                self.worker.cancel()
            self.analyze_btn.setText("Ləğv edilir...")
            self.analyze_btn.setEnabled(False)
            self.log("Əvvəlki analiz ləğv edilir...")
            return

        selected_terms = [program_name]
        min_score = self.min_score_spin.value()

        self.analyze_btn.setText("Ləğv et")
        self.analyze_btn.setEnabled(True)
        self.progress.setValue(0)
        self.log_box.clear()
        self._last_progress_log_bucket = -1
        self.details_box.clear()
        self.log("Analiz başlayır...")

        self.thread = QThread(self)
        self.worker = AnalysisWorker(csv_path, selected_terms, min_score)
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self.on_progress)
        self.worker.finished.connect(self.on_finished)
        self.worker.failed.connect(self.on_failed)
        self.worker.finished.connect(self.thread.quit)
        self.worker.failed.connect(self.thread.quit)
        self.thread.finished.connect(self._on_thread_finished)
        self.thread.start()

    def _on_thread_finished(self):
        self.analyze_btn.setText("Analiz et")
        self.analyze_btn.setEnabled(True)
        app = QApplication.instance()
        if self.worker:
            if app:
                self.worker.moveToThread(app.thread())
            self.worker.deleteLater()
        if self.thread:
            self.thread.deleteLater()
        self.thread = None
        self.worker = None

    def on_progress(self, value: int, text: str):
        self.progress.setValue(value)
        self.status_text.setText(text)
        bucket = max(0, min(10, value // 10))
        if bucket != self._last_progress_log_bucket:
            self._last_progress_log_bucket = bucket
            self.log_box.appendPlainText(text)

    def on_finished(self, payload: dict):
        self.current_payload = payload
        self.progress.setValue(100)
        self.log(
            f"Hazır. Event: {payload['summary']['events']:,} | İz: {payload['summary']['residue_count']:,} | "
            f"Safe: {payload['summary']['safe_to_delete']:,} | Review: {payload['summary']['review']:,} | "
            f"Gone: {payload['summary']['already_gone']:,} | Ignore: {payload['summary'].get('ignore', 0):,} | "
            f"WeakRel: {payload['summary'].get('weak_but_related', 0):,} | Weak: {payload['summary'].get('weak_residue_count', 0):,}"
        )

        self.residue_table.setModel(
            GenericTableModel(
                payload.get("residues", []),
                [
                    "status",
                    "removal_layer",
                    "category",
                    "cluster",
                    "installer_cluster_id",
                    "raw_score",
                    "score",
                    "type",
                    "path",
                    "mapped_path",
                    "exists_now",
                    "processes",
                    "operations",
                    "reasons",
                ],
            )
        )

        selected_terms = payload.get("selected_terms", [])
        suggested_terms = payload.get("suggested_terms", [])
        note = payload.get("summary", {}).get("exists_check_note", "")
        details = "İstifadə olunan terminlər:\n- " + "\n- ".join(selected_terms)
        if suggested_terms:
            details += "\n\nTövsiyə olunan əlavə terminlər:\n- " + "\n- ".join(suggested_terms)
        details += f"\n\nQeyd: {note}"
        self.details_box.setPlainText(details)

    def on_failed(self, message: str):
        self.progress.setValue(0)
        if "ləğv edildi" in (message or "").lower():
            self.log(message)
            return
        QMessageBox.critical(self, "Xəta", message)
        self.log(f"Xəta: {message}")

    def on_residue_row_clicked(self, index: QModelIndex):
        if not self.current_payload:
            return
        row = index.row()
        items = self.current_payload.get("residues", [])
        if 0 <= row < len(items):
            item = items[row]
            self.details_box.setPlainText(json.dumps(item, ensure_ascii=False, indent=2))

    def export_json(self):
        if not self.current_payload:
            QMessageBox.information(self, "Məlumat", "Əvvəl analiz et.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "JSON saxla", "residual_candidates.json", "JSON Files (*.json)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.current_payload, f, ensure_ascii=False, indent=2)
            self.log(f"JSON saxlanıldı: {path}")
        except OSError as exc:
            QMessageBox.critical(self, "Xəta", f"Fayl yazıla bilmədi: {exc}")

    def export_txt(self):
        if not self.current_payload:
            QMessageBox.information(self, "Məlumat", "Əvvəl analiz et.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "TXT hesabat saxla", "residue_report.txt", "Text Files (*.txt)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                summary = self.current_payload["summary"]
                f.write("Procmon Residue Analyzer Report\n")
                f.write("=" * 60 + "\n")
                f.write(f"Events: {summary['events']:,}\n")
                f.write(f"Residues: {summary['residue_count']:,}\n")
                f.write(f"Safe to delete: {summary['safe_to_delete']:,}\n")
                f.write(f"Review: {summary['review']:,}\n")
                f.write(f"Already gone: {summary.get('already_gone', 0):,}\n")
                f.write(f"Ignore: {summary.get('ignore', 0):,}\n")
                f.write(f"Note: {summary.get('exists_check_note', '')}\n")
                f.write("\nSelected terms:\n")
                for token in self.current_payload.get("selected_terms", []):
                    f.write(f"- {token}\n")
                suggested = self.current_payload.get("suggested_terms", [])
                if suggested:
                    f.write("\nSuggested terms:\n")
                    for token in suggested:
                        f.write(f"- {token}\n")
                residues = self.current_payload.get("residues", [])
                normal_residues = [x for x in residues if x.get("category") != "execution_trace"]
                trace_residues = [x for x in residues if x.get("category") == "execution_trace"]

                f.write("\nResidues:\n")
                for item in normal_residues:
                    f.write("-" * 60 + "\n")
                    f.write(f"Status: {item['status']}\n")
                    f.write(f"Removal layer: {item.get('removal_layer', 'review_queue')}\n")
                    f.write(f"Raw score: {item['raw_score']}\n")
                    f.write(f"Score: {item['score']}\n")
                    f.write(f"Type: {item['type']}\n")
                    f.write(f"Category: {item.get('category', 'functional')}\n")
                    f.write(f"Cluster: {item.get('cluster', 'uncategorized')}\n")
                    f.write(f"Installer cluster: {item.get('installer_cluster_id')}\n")
                    f.write(f"Path: {item['path']}\n")
                    f.write(f"Mapped: {item['mapped_path']}\n")
                    f.write(f"Exists now: {item['exists_now']}\n")
                    f.write(f"Processes: {', '.join(item['processes'])}\n")
                    f.write(f"Operations: {', '.join(item['operations'])}\n")
                    f.write("Reasons:\n")
                    for reason in item["reasons"]:
                        f.write(f"  * {reason}\n")

                if trace_residues:
                    f.write("\nExecution traces (functional residue deyil):\n")
                    for item in trace_residues:
                        f.write("-" * 60 + "\n")
                        f.write(f"Status: {item['status']}\n")
                        f.write(f"Type: {item['type']}\n")
                        f.write(f"Path: {item['path']}\n")
                        f.write(f"Reasons: {'; '.join(item.get('reasons', []))}\n")
                weak_items = self.current_payload.get("weak_residues", [])
                if weak_items:
                    f.write("\nWeak but related residues:\n")
                    for item in weak_items:
                        f.write("-" * 60 + "\n")
                        f.write(f"Status: {item['status']}\n")
                        f.write(f"Raw score: {item['raw_score']}\n")
                        f.write(f"Type: {item['type']}\n")
                        f.write(f"Path: {item['path']}\n")
            self.log(f"TXT hesabat saxlanıldı: {path}")
        except OSError as exc:
            QMessageBox.critical(self, "Xəta", f"Fayl yazıla bilmədi: {exc}")
