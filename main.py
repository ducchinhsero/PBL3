import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QPushButton, QLabel, QWidget, QHBoxLayout
from PyQt5 import QtCore
from subprocess import Popen

def run_ecc_app():
    """Chạy ứng dụng ECC"""
    Popen([sys.executable, 'ecc.py'])

def run_ecdsa_app():
    """Chạy ứng dụng ECDSA"""
    Popen([sys.executable, 'ecdsa.py'])

class MainApp(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Chọn Ứng dụng")
        self.setGeometry(300, 200, 400, 200)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Tiêu đề
        title_label = QLabel("Chọn ứng dụng để khởi chạy:")
        title_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        title_label.setAlignment(QtCore.Qt.AlignCenter)
        layout.addWidget(title_label)

        button_layout = QVBoxLayout()
        button_layout.setAlignment(QtCore.Qt.AlignCenter)

        ecc_button = QPushButton("ECC")
        ecc_button.setStyleSheet("background-color: lightblue; font-size: 14px;")
        ecc_button.clicked.connect(run_ecc_app)
        button_layout.addWidget(ecc_button)

        ecdsa_button = QPushButton("ECDSA - Create and Verification Signature")
        ecdsa_button.setStyleSheet("background-color: lightgreen; font-size: 14px;")
        ecdsa_button.clicked.connect(run_ecdsa_app)
        button_layout.addWidget(ecdsa_button)

        layout.addLayout(button_layout)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_window = MainApp()
    main_window.show()
    sys.exit(app.exec_())
