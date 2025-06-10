import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton,
    QFileDialog, QLineEdit, QLabel, QMessageBox
)
from cryptography.fernet import Fernet
import base64
import hashlib

class FileEncryptor(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("File Encryptor/Decryptor")
        self.setGeometry(500, 300, 400, 200)
        self.file_path = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        self.label = QLabel("No file selected")
        layout.addWidget(self.label)

        self.btn_select = QPushButton("Select File")
        self.btn_select.clicked.connect(self.select_file)
        layout.addWidget(self.btn_select)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Enter password")
        layout.addWidget(self.password_input)

        self.btn_encrypt = QPushButton("Encrypt File")
        self.btn_encrypt.clicked.connect(self.encrypt_file)
        layout.addWidget(self.btn_encrypt)

        self.btn_decrypt = QPushButton("Decrypt File")
        self.btn_decrypt.clicked.connect(self.decrypt_file)
        layout.addWidget(self.btn_decrypt)

        self.setLayout(layout)

    def select_file(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, "Select File", "", "All Files (*)", options=options)
        if file_name:
            self.file_path = file_name
            self.label.setText(f"Selected: {file_name}")

    def derive_key(self, password: str) -> bytes:
        # Derive a Fernet key from the password using SHA-256 and base64
        digest = hashlib.sha256(password.encode()).digest()
        return base64.urlsafe_b64encode(digest)

    def encrypt_file(self):
        if not self.file_path:
            QMessageBox.warning(self, "Error", "Please select a file first.")
            return
        password = self.password_input.text()
        if not password:
            QMessageBox.warning(self, "Error", "Please enter a password.")
            return
        key = self.derive_key(password)
        fernet = Fernet(key)
        try:
            with open(self.file_path, "rb") as file:
                data = file.read()
            encrypted = fernet.encrypt(data)
            with open(self.file_path, "wb") as file:
                file.write(encrypted)
            QMessageBox.information(self, "Success", "File encrypted successfully.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Encryption failed:\n{str(e)}")

    def decrypt_file(self):
        if not self.file_path:
            QMessageBox.warning(self, "Error", "Please select a file first.")
            return
        password = self.password_input.text()
        if not password:
            QMessageBox.warning(self, "Error", "Please enter a password.")
            return
        key = self.derive_key(password)
        fernet = Fernet(key)
        try:
            with open(self.file_path, "rb") as file:
                data = file.read()
            decrypted = fernet.decrypt(data)
            with open(self.file_path, "wb") as file:
                file.write(decrypted)
            QMessageBox.information(self, "Success", "File decrypted successfully.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Decryption failed:\n{str(e)}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = FileEncryptor()
    window.show()
    sys.exit(app.exec_())
