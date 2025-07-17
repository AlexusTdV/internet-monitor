import sys, os, socket, psutil, pyperclip
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QTableView,
    QHBoxLayout, QLineEdit, QPushButton, QLabel, QComboBox, QCheckBox, QMessageBox
)
from PyQt5.QtGui import QColor, QFont, QIcon, QPixmap, QPainter, QStandardItem, QStandardItemModel
from PyQt5.QtSvg import QSvgRenderer
from PyQt5.QtCore import Qt, QTimer, QSortFilterProxyModel, QModelIndex
from ping3 import ping
import geoip2.database

from PyQt5.QtWidgets import QHeaderView

def resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

FLAGS_PATH = resource_path("flags")
GEOIP_DB = resource_path("GeoLite2-Country.mmdb")

class IPFilterProxy(QSortFilterProxyModel):
    def lessThan(self, left: QModelIndex, right: QModelIndex):
        left_data = self.sourceModel().data(left, Qt.DisplayRole)
        right_data = self.sourceModel().data(right, Qt.DisplayRole)

        if left.column() == 1:
            def parse_ping(val):
                if val and "мс" in val:
                    try:
                        return int(val.replace("мс", "").strip())
                    except:
                        return 9999
                return 9999
            return parse_ping(left_data) < parse_ping(right_data)

        elif left.column() == 0:
            import ipaddress
            try:
                return ipaddress.ip_address(left_data) < ipaddress.ip_address(right_data)
            except:
                return left_data < right_data

        if left_data is None: return True
        if right_data is None: return False
        return str(left_data).lower() < str(right_data).lower()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.ip_filter = ""
        self.country_filter = ""
        self.program_filter = ""

    def setFilters(self, ip, country, program):
        self.ip_filter = ip.lower()
        self.country_filter = country.lower()
        self.program_filter = program.lower()
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row, source_parent):
        model = self.sourceModel()
        ip = model.index(source_row, 0, source_parent).data().lower()
        country = model.index(source_row, 2, source_parent).data().lower()
        program = model.index(source_row, 3, source_parent).data().lower()
        return (self.ip_filter in ip and self.country_filter in country and self.program_filter in program)

class IPMonitor(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Монитор IP-подключений by ITGoose")
        self.setWindowIcon(QIcon(resource_path("icon.ico")))
        self.resize(1100, 600)
        self.init_ui()
        self.timer = QTimer()
        self.timer.timeout.connect(self.load_data)

    def init_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)

        controls = QHBoxLayout()
        self.ip_filter = QLineEdit()
        self.ip_filter.setPlaceholderText("Фильтр IP")
        self.country_filter = QLineEdit()
        self.country_filter.setPlaceholderText("Фильтр страны")
        self.program_filter = QLineEdit()
        self.program_filter.setPlaceholderText("Фильтр процесса")
        update_btn = QPushButton("Обновить")
        update_btn.clicked.connect(self.load_data)
        self.interval_box = QComboBox()
        self.interval_box.addItems(["3", "5", "10"])
        self.auto_check = QCheckBox("Автообновление")
        self.auto_check.stateChanged.connect(self.toggle_timer)
        export_btn = QPushButton("Экспорт")
        export_btn.clicked.connect(self.export_to_txt)
        controls.addWidget(export_btn)

        for widget in [self.ip_filter, self.country_filter, self.program_filter]:
            widget.textChanged.connect(self.apply_filters)

        controls.addWidget(self.ip_filter)
        controls.addWidget(self.country_filter)
        controls.addWidget(self.program_filter)
        controls.addWidget(update_btn)
        controls.addWidget(QLabel("Интервал:"))
        controls.addWidget(self.interval_box)
        controls.addWidget(self.auto_check)
        layout.addLayout(controls)

        self.model = QStandardItemModel(0, 5)
        self.model.setHorizontalHeaderLabels(["IP", "Пинг", "Страна", "Процесс", "Путь к файлу"])
        self.proxy = IPFilterProxy()
        self.proxy.setSourceModel(self.model)

        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.doubleClicked.connect(self.copy_ip)
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setEditTriggers(QTableView.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.table)

        self.status = QLabel()
        layout.addWidget(self.status)

    def toggle_timer(self):
        if self.auto_check.isChecked():
            interval = int(self.interval_box.currentText()) * 1000
            self.timer.start(interval)
        else:
            self.timer.stop()

    def load_data(self):
        self.model.removeRows(0, self.model.rowCount())
        connections = psutil.net_connections(kind='inet')
        seen_ips = set()

        try:
            geo = geoip2.database.Reader(GEOIP_DB)
        except:
            geo = None

        for conn in connections:
            if conn.status != "ESTABLISHED" or not conn.raddr:
                continue
            ip = conn.raddr.ip
            if ip in seen_ips:
                continue
            seen_ips.add(ip)
            delay = ping(ip, timeout=1)
            delay_str = "Нет ответа" if delay is None else f"{int(delay * 1000)} мс"
            delay_ms = 9999 if delay is None else int(delay * 1000)

            try:
                info = geo.country(ip) if geo else None
                country = info.country.names.get("ru", "Страна неопределена") if info else "Страна неопределена"
                code = info.country.iso_code.lower() if info else ""
            except:
                country = "Страна неопределена"
                code = ""

            pid = conn.pid or 0
            try:
                process = psutil.Process(pid)
                program = process.exe() if process.exe() else process.name()
                process_name = process.name()
            except:
                program = "Неизвестно"
                process_name = "Неизвестно"

            row = [
                QStandardItem(ip),
                QStandardItem(delay_str),
                QStandardItem(country),
                QStandardItem(process_name),
                QStandardItem(program)
            ]

            font = QFont("Segoe UI", 10)
            for i, item in enumerate(row):
                item.setFont(font)
                if i == 1:
                    if delay_ms > 200:
                        item.setForeground(QColor("red"))
                    elif delay_ms > 100:
                        item.setForeground(QColor("orange"))
                if i == 2 and code:
                    flag_path = os.path.join(FLAGS_PATH, f"{code}.svg")
                    if os.path.exists(flag_path):
                        try:
                            renderer = QSvgRenderer(flag_path)
                            pixmap = QPixmap(32, 24)
                            pixmap.fill(Qt.transparent)
                            painter = QPainter(pixmap)
                            renderer.render(painter)
                            painter.end()
                            item.setIcon(QIcon(pixmap))
                        except:
                            pass

            self.model.appendRow(row)

        self.status.setText(f"Обновлено: {self.model.rowCount()} IP")

    def apply_filters(self):
        self.proxy.setFilters(
            self.ip_filter.text(),
            self.country_filter.text(),
            self.program_filter.text()
        )

    def export_to_txt(self):
        with open("ip_export.txt", "w", encoding="utf-8") as f:
            for row in range(self.proxy.rowCount()):
                row_data = []
                for col in range(self.proxy.columnCount()):
                    index = self.proxy.index(row, col)
                    text = self.proxy.data(index, Qt.DisplayRole)
                    row_data.append(text)
                f.write("\t".join(row_data) + "\n")
        QMessageBox.information(self, "Готово", "Список экспортирован в ip_export.txt")

    def copy_ip(self, index: QModelIndex):
        ip = self.proxy.data(self.proxy.index(index.row(), 0))
        pyperclip.copy(ip)
        self.status.setText(f"Скопировано: {ip}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = IPMonitor()
    win.show()
    sys.exit(app.exec_())
