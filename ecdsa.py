import os
import hashlib
from PyQt5 import QtWidgets, QtCore
from PyQt5.QtWidgets import QFileDialog, QMessageBox, QVBoxLayout, QHBoxLayout, QTextEdit, QPushButton, QLabel, QWidget
#xac nhan chuan file upload Github hehe
# Định nghĩa các hằng số cho SECP256k1
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Prime = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)

# Hàm nghịch đảo modulo
def nghich_dao_modulo(a, m):
    y1, y2 = 0, 1
    hig, low = m, a % m
    while low > 1:
        q = hig // low
        r = hig % low
        y3 = y1 - y2 * q
        y1, y2, low, hig = y2, y3, r, low
    return y2 % m

# Phép cộng điểm trên đường cong elliptic
def phan_biet(g, q):
    k = ((q[1] - g[1]) * nghich_dao_modulo(q[0] - g[0], Prime)) % Prime
    x = (k**2 - g[0] - q[0]) % Prime
    y = (k * (g[0] - x) - g[1]) % Prime
    return (x, y)

def trung_nhau(g):
    k = ((3 * g[0]**2) * nghich_dao_modulo(2 * g[1], Prime)) % Prime
    x = (k**2 - 2 * g[0]) % Prime
    y = (k * (g[0] - x) - g[1]) % Prime
    return (x, y)

def ket_hop(G, khoa_rieng):
    if khoa_rieng == 0 or khoa_rieng >= N:
        raise Exception("Khóa riêng không hợp lệ")
    khoa_rieng = '{0:b}'.format(khoa_rieng)
    Q = G
    for i in range(1, len(khoa_rieng)):
        Q = trung_nhau(Q)
        if khoa_rieng[i] == "1":
            Q = phan_biet(Q, G)
    return Q

# Tạo khóa riêng và khóa công khai
def tao_khoa():
    khoa_rieng = os.urandom(32).hex()
    khoa_rieng = int(khoa_rieng, 16)
    Qx, Qy = ket_hop(G, khoa_rieng)
    return khoa_rieng, (Qx, Qy)

# Tạo chữ ký
def tao_chu_ky_va_ky(m, khoa_rieng):
    k = int.from_bytes(os.urandom(32), byteorder='big') % N
    R = ket_hop(G, k)
    r = R[0] % N
    if r == 0:
        raise Exception("Giá trị r không hợp lệ")

    e = int(hashlib.sha256(m.encode()).hexdigest(), 16)
    s = (nghich_dao_modulo(k, N) * (e + r * khoa_rieng)) % N
    if s == 0:
        raise Exception("Giá trị s không hợp lệ")

    thong_diep_da_ky = f"{m}\nChữ ký: (r={r}, s={s})"
    return thong_diep_da_ky, (r, s)

# Xác minh chữ ký
def xac_minh_chu_ky(m, r, s, khoa_cong_khai):
    if not (1 <= r < N and 1 <= s < N):
        return False
    e = int(hashlib.sha256(m.encode()).hexdigest(), 16)
    w = nghich_dao_modulo(s, N)
    u1 = (e * w) % N
    u2 = (r * w) % N
    u1G = ket_hop(G, u1)
    u2Q = ket_hop(khoa_cong_khai, u2)
    R = phan_biet(u1G, u2Q) if u1G != u2Q else trung_nhau(u1G)
    return R[0] % N == r

# Giao diện PyQt5
class ECDSAApp(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ECDSA Application")
        self.setGeometry(200, 200, 800, 600)

        layout = QVBoxLayout()

        # Khối Create Signature
        create_signature_label = QLabel("Create Signature")
        create_signature_label.setStyleSheet("font-weight: bold; font-size: 16px;")
        layout.addWidget(create_signature_label)

        create_layout = QHBoxLayout()

        self.import_file_button = QPushButton("Import File")
        self.import_file_button.clicked.connect(self.import_file)
        create_layout.addWidget(self.import_file_button)

        self.message_box = QTextEdit()
        self.message_box.setPlaceholderText("Message content...")
        create_layout.addWidget(self.message_box)

        layout.addLayout(create_layout)

        self.sign_button = QPushButton("Sign")
        self.sign_button.setStyleSheet("background-color: red; color: white;")
        self.sign_button.clicked.connect(self.sign_message)
        layout.addWidget(self.sign_button)

        # Khối Signature Verification
        verification_label = QLabel("Signature Verification")
        verification_label.setStyleSheet("font-weight: bold; font-size: 16px;")
        layout.addWidget(verification_label)

        verification_layout = QHBoxLayout()

        self.import_signed_file_button = QPushButton("Import File")
        self.import_signed_file_button.clicked.connect(self.import_signed_file)
        verification_layout.addWidget(self.import_signed_file_button)

        self.public_key_box = QTextEdit()
        self.public_key_box.setPlaceholderText("Enter sender's public key...")
        verification_layout.addWidget(self.public_key_box)

        self.verify_button = QPushButton("Verification")
        self.verify_button.clicked.connect(self.verify_signature)
        verification_layout.addWidget(self.verify_button)

        layout.addLayout(verification_layout)

        self.result_label = QLabel("")
        layout.addWidget(self.result_label)

        self.setLayout(layout)

        # Biến lưu trạng thái
        self.message = ""
        self.signed_message = ""
        self.private_key = None
        self.public_key = None

    def import_file(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Choose file", "", "Text Files (*.txt);;All Files (*)", options=options)
        if file_path:
            with open(file_path, 'r') as file:
                self.message = file.read().strip()
            self.message_box.setText(self.message)

    def sign_message(self):
        if not self.message:
            QMessageBox.warning(self, "Error", "Please import a message first.")
            return

        self.private_key, self.public_key = tao_khoa()
        signed_message, _ = tao_chu_ky_va_ky(self.message, self.private_key)

        options = QFileDialog.Options()
        save_path, _ = QFileDialog.getSaveFileName(self, "Save signed file", "", "Text Files (*.txt);;All Files (*)", options=options)
        if save_path:
            with open(save_path, 'w') as file:
                file.write(signed_message)

            # Lưu khóa vào file
            key_path = save_path.rsplit(".", 1)[0] + "_keys.txt"
            with open(key_path, 'w') as key_file:
                key_file.write(f"Private Key: {self.private_key}\nPublic Key: {self.public_key}")

            QMessageBox.information(self, "Success", "File signed and saved successfully. Keys saved to the same folder.")


    def import_signed_file(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Choose signed file", "", "Text Files (*.txt);;All Files (*)", options=options)
        if file_path:
            with open(file_path, 'r') as file:
                self.signed_message = file.read().strip()
            self.result_label.setText(f"Imported file content:\n{self.signed_message}")

    def verify_signature(self):
        if not self.signed_message:
            QMessageBox.warning(self, "Error", "Please import a signed message first.")
            return

        if not self.public_key_box.toPlainText():
            QMessageBox.warning(self, "Error", "Please enter the sender's public key.")
            return

        try:
            public_key = eval(self.public_key_box.toPlainText())
        except:
            QMessageBox.warning(self, "Error", "Invalid public key format.")
            return

        message, signature = self.signed_message.rsplit("\nChữ ký:", 1)
        signature = signature.strip("()")
        r_str, s_str = signature.split(", s=")
        r = int(r_str.split("r=")[1])
        s = int(s_str)

        if xac_minh_chu_ky(message, r, s, public_key):
            self.result_label.setText("Success, signature correct, original text is not changed!")
        else:
            self.result_label.setText("Failure, wrong signature or data was changed content!")

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    window = ECDSAApp()
    window.show()
    sys.exit(app.exec_())
