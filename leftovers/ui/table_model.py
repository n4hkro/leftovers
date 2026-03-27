"""GenericTableModel – Qt table model for displaying residue data."""

from typing import List

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt


class GenericTableModel(QAbstractTableModel):
    def __init__(self, rows: List[dict], headers: List[str]):
        super().__init__()
        self.rows = rows
        self.headers = headers

    def rowCount(self, parent=QModelIndex()):
        return len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return len(self.headers)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        row = self.rows[index.row()]
        key = self.headers[index.column()]
        value = row.get(key, "")
        if role == Qt.DisplayRole:
            if isinstance(value, list):
                return "; ".join(map(str, value))
            return str(value)
        if role == Qt.TextAlignmentRole:
            return int(Qt.AlignLeft | Qt.AlignVCenter)
        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Horizontal:
            return self.headers[section]
        return section + 1
