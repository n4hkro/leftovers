"""Application entry point."""

import sys

from PySide6.QtWidgets import QApplication

from leftovers.ui.main_window import MainWindow


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Procmon Residue Analyzer")
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
