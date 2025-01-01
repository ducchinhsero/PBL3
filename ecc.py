import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import hashlib
import random
from dataclasses import dataclass
import base64
import json
from datetime import datetime

@dataclass
class Point:
    """Lớp đại diện cho điểm trên đường cong Elliptic"""
    x: int
    y: int

class EllipticCurve:
    """Lớp thực hiện các phép toán trên đường cong Elliptic"""
    def __init__(self):
        # Tham số đường cong secp256k1
        self.p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        self.a = 0
        self.b = 7
        # Điểm sinh G
        self.G = Point(
            0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
            0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
        )
        # Bậc của điểm sinh
        self.n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    
    def mod_inverse(self, a, m):
        """Tính nghịch đảo modulo của a trong trường hữu hạn m"""
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y
        
        _, x, _ = extended_gcd(a, m)
        return (x % m + m) % m
    
    def add_points(self, P1: Point, P2: Point) -> Point:
        """Cộng hai điểm trên đường cong Elliptic"""
        if P1 is None or P2 is None:
            return P2 if P1 is None else P1
            
        if P1.x == P2.x and P1.y != P2.y:
            return None  # Điểm vô cực
            
        if P1.x == P2.x:
            if P1.y == 0:
                return None  # Điểm vô cực
            # Công thức tính lambda khi P1 = P2
            lam = ((3 * P1.x * P1.x + self.a) * self.mod_inverse(2 * P1.y, self.p)) % self.p
        else:
            # Công thức tính lambda khi P1 ≠ P2
            lam = ((P2.y - P1.y) * self.mod_inverse(P2.x - P1.x, self.p)) % self.p
        
        x3 = (lam * lam - P1.x - P2.x) % self.p
        y3 = (lam * (P1.x - x3) - P1.y) % self.p
        
        return Point(x3, y3)
    
    def scalar_multiply(self, k: int, P: Point) -> Point:
        """Nhân vô hướng điểm P với số k"""
        result = None
        addend = P
        
        while k:
            if k & 1:
                result = self.add_points(result, addend)
            addend = self.add_points(addend, addend)
            k >>= 1
            
        return result
    
    def generate_keypair(self):
        """Tạo cặp khóa private/public"""
        private_key = random.randrange(1, self.n)
        public_key = self.scalar_multiply(private_key, self.G)
        return private_key, public_key
    
    def point_to_string(self, P: Point) -> str:
        """Chuyển đổi điểm sang chuỗi"""
        if P is None:
            return "Point(infinity)"
        return f"Point(x={hex(P.x)}, y={hex(P.y)})"

class ECCApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Ứng dụng Mã hóa ECC")
        self.root.geometry("900x800")
        
        # Thiết lập màu nền cho cửa sổ chính
        self.root.configure(bg='#f0f5f9')  # Màu trắng xanh nhạt
        
        # Khởi tạo đường cong
        self.curve = EllipticCurve()
        
        # Style
        self.setup_styles()
        
        # Main container
        main_container = ttk.Frame(self.root, padding="10", style='Main.TFrame')
        main_container.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.setup_key_section(main_container)
        self.setup_message_section(main_container)
        self.setup_hash_section(main_container)
        self.setup_calculation_section(main_container)
        
        # Configure grid
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

    def setup_styles(self):
        style = ttk.Style()
        
        # Định nghĩa các style cho frame và button
        style.configure('Main.TFrame', background='#f0f5f9')
        style.configure('TLabelframe', background='#f0f5f9')
        style.configure('TLabelframe.Label', background='#f0f5f9')
        
        # Button styles với màu sắc tùy chỉnh
        style.configure('Red.TButton', padding=5, background='#ff6b6b')
        style.configure('Orange.TButton', padding=5, background='#ffa07a')
        style.configure('Blue.TButton', padding=5, background='#4a90e2')
        style.configure('Yellow.TButton', padding=5, background='#ffd700')
        
        style.configure('Header.TLabel', font=('Helvetica', 12, 'bold'), background='#f0f5f9')

    def setup_key_section(self, parent):
        key_frame = ttk.LabelFrame(parent, text="Quản lý Khóa ECC", padding="10")
        key_frame.grid(row=0, column=0, padx=5, pady=5, sticky=(tk.W, tk.E))
        
        # Frame cho các button
        button_frame = ttk.Frame(key_frame)
        button_frame.grid(row=0, column=0, columnspan=2, pady=10)
        button_frame.columnconfigure(0, weight=1)
        button_frame.columnconfigure(1, weight=1)
        
        # Buttons căn giữa
        generate_btn = ttk.Button(button_frame, text="Tạo Cặp Khóa Mới", 
                                command=self.generate_keys, style='Red.TButton')
        generate_btn.grid(row=0, column=0, padx=5)
        
        save_btn = ttk.Button(button_frame, text="Lưu Cặp Khóa", 
                             command=self.save_keys, style='Orange.TButton')
        save_btn.grid(row=0, column=1, padx=5)
        
        ttk.Label(key_frame, text="Private Key:", style='Header.TLabel').grid(
            row=1, column=0, padx=5, pady=2, sticky=tk.W)
        self.private_key_var = tk.StringVar()
        private_key_entry = ttk.Entry(key_frame, textvariable=self.private_key_var, 
                                    width=70, state='readonly')
        private_key_entry.grid(row=2, column=0, padx=5, pady=2, sticky=tk.W)
        
        ttk.Label(key_frame, text="Public Key:", style='Header.TLabel').grid(
            row=3, column=0, padx=5, pady=2, sticky=tk.W)
        self.public_key_var = tk.StringVar()
        public_key_entry = ttk.Entry(key_frame, textvariable=self.public_key_var, 
                                   width=70, state='readonly')
        public_key_entry.grid(row=4, column=0, padx=5, pady=2, sticky=tk.W)

    def setup_calculation_section(self, parent):
        """Thiết lập phần hiển thị các bước tính toán"""
        calc_frame = ttk.LabelFrame(parent, text="Chi tiết Tính toán ECC", padding="10")
        calc_frame.grid(row=3, column=0, padx=5, pady=5, sticky=(tk.W, tk.E))
        
        self.calc_text = tk.Text(calc_frame, height=8, width=70)
        self.calc_text.grid(row=0, column=0, padx=5, pady=5, sticky=(tk.W, tk.E))

    def setup_message_section(self, parent):
        message_frame = ttk.LabelFrame(parent, text="Nhập và Xử lý Nội dung", padding="10")
        message_frame.grid(row=1, column=0, padx=5, pady=5, sticky=(tk.W, tk.E))
        
        ttk.Label(message_frame, text="Nhập nội dung:", style='Header.TLabel').grid(
            row=0, column=0, padx=5, pady=2, sticky=tk.W)
        
        self.message_text = tk.Text(message_frame, height=6, width=70)
        self.message_text.grid(row=1, column=0, padx=5, pady=5, sticky=(tk.W, tk.E))
        
        # Button frame căn giữa
        button_frame = ttk.Frame(message_frame)
        button_frame.grid(row=2, column=0, pady=5)
        button_frame.columnconfigure(0, weight=1)
        button_frame.columnconfigure(1, weight=1)
        
        ttk.Button(button_frame, text="Import File", command=self.import_file, 
                  style='Blue.TButton').grid(row=0, column=0, padx=5)
        ttk.Button(button_frame, text="Xóa Nội dung", command=self.clear_message, 
                  style='Blue.TButton').grid(row=0, column=1, padx=5)

    def setup_hash_section(self, parent):
        hash_frame = ttk.LabelFrame(parent, text="Kết quả Hash SHA256", padding="10")
        hash_frame.grid(row=2, column=0, padx=5, pady=5, sticky=(tk.W, tk.E))
        
        control_frame = ttk.Frame(hash_frame)
        control_frame.grid(row=0, column=0, columnspan=2, pady=5)
        
        self.auto_hash_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(control_frame, text="Tự động tính hash", 
                       variable=self.auto_hash_var, 
                       command=self.toggle_auto_hash).grid(row=0, column=0, padx=5)
        
        self.hash_button = ttk.Button(control_frame, text="Tính Hash", 
                                    command=self.calculate_hash, style='Yellow.TButton')
        self.hash_button.grid(row=0, column=1, padx=5)
        
        if self.auto_hash_var.get():
            self.hash_button.state(['disabled'])
        
        ttk.Label(hash_frame, text="Giá trị Hash:", style='Header.TLabel').grid(
            row=1, column=0, padx=5, pady=2, sticky=tk.W)
        self.hash_var = tk.StringVar()
        hash_entry = ttk.Entry(hash_frame, textvariable=self.hash_var, 
                             width=70, state='readonly')
        hash_entry.grid(row=2, column=0, columnspan=2, padx=5, pady=2, sticky=tk.W)
        
        self.message_text.bind('<KeyRelease>', self.on_message_change)

    def generate_keys(self):
        try:
            # Sinh khóa và hiển thị chi tiết tính toán
            private_key, public_key = self.curve.generate_keypair()
            
            # Lưu và hiển thị khóa
            self.private_key_var.set(hex(private_key))
            self.public_key_var.set(self.curve.point_to_string(public_key))
            
            # Hiển thị chi tiết tính toán
            calc_details = (
                f"Chi tiết tính toán ECC:\n"
                f"1. Tham số đường cong secp256k1:\n"
                f"   - p (modulo) = {hex(self.curve.p)}\n"
                f"   - a = {self.curve.a}\n"
                f"   - b = {self.curve.b}\n"
                f"2. Điểm sinh G = {self.curve.point_to_string(self.curve.G)}\n"
                f"3. Private key (k) = {hex(private_key)}\n"
                f"4. Public key (K = kG) = {self.curve.point_to_string(public_key)}\n"
            )
            
            self.calc_text.delete(1.0, tk.END)
            self.calc_text.insert(tk.END, calc_details)
            
            messagebox.showinfo("Thành công", "Đã tạo cặp khóa mới!")
            
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể tạo khóa: {str(e)}")

    def save_keys(self):
        if not self.private_key_var.get() or not self.public_key_var.get():
            messagebox.showwarning("Cảnh báo", "Vui lòng tạo cặp khóa trước khi lưu!")
            return
            
        try:
            # Tạo dictionary chứa thông tin khóa
            key_data = {
                "private_key": self.private_key_var.get(),
                "public_key": self.public_key_var.get(),
                "timestamp": self.get_timestamp()
            }
            
            # Mở hộp thoại chọn nơi lưu file
            file_path = filedialog.asksaveasfilename(
                defaultextension=".ecc",
                filetypes=[("ECC Key Files", "*.ecc"), ("All Files", "*.*")],
                title="Chọn nơi lưu cặp khóa"
            )
            
            if file_path:
                with open(file_path, 'w') as f:
                    json.dump(key_data, f, indent=4)
                messagebox.showinfo("Thành công", f"Đã lưu cặp khóa vào:\n{file_path}")
        
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể lưu khóa: {str(e)}")

    def get_timestamp(self):
        """Tạo timestamp cho việc lưu khóa"""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def setup_message_section(self, parent):
        message_frame = ttk.LabelFrame(parent, text="Nhập và Xử lý Nội dung", padding="10")
        message_frame.grid(row=1, column=0, padx=5, pady=5, sticky=(tk.W, tk.E))
        
        ttk.Label(message_frame, text="Nhập nội dung:", style='Header.TLabel').grid(
            row=0, column=0, padx=5, pady=2, sticky=tk.W)
        
        self.message_text = tk.Text(message_frame, height=6, width=70)
        self.message_text.grid(row=1, column=0, padx=5, pady=5, sticky=(tk.W, tk.E))
        
        # Button frame căn giữa
        button_frame = ttk.Frame(message_frame)
        button_frame.grid(row=2, column=0, pady=5)
        button_frame.columnconfigure(0, weight=1)
        button_frame.columnconfigure(1, weight=1)
        
        ttk.Button(button_frame, text="Import File", command=self.import_file, 
                  style='Blue.TButton').grid(row=0, column=0, padx=5)
        ttk.Button(button_frame, text="Xóa Nội dung", command=self.clear_message, 
                  style='Blue.TButton').grid(row=0, column=1, padx=5)

    def setup_hash_section(self, parent):
        hash_frame = ttk.LabelFrame(parent, text="Kết quả Hash SHA256", padding="10")
        hash_frame.grid(row=2, column=0, padx=5, pady=5, sticky=(tk.W, tk.E))
        
        control_frame = ttk.Frame(hash_frame)
        control_frame.grid(row=0, column=0, columnspan=2, pady=5)
        
        self.auto_hash_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(control_frame, text="Tự động tính hash", 
                       variable=self.auto_hash_var, 
                       command=self.toggle_auto_hash).grid(row=0, column=0, padx=5)
        
        self.hash_button = ttk.Button(control_frame, text="Tính Hash", 
                                    command=self.calculate_hash, style='Yellow.TButton')
        self.hash_button.grid(row=0, column=1, padx=5)
        
        if self.auto_hash_var.get():
            self.hash_button.state(['disabled'])
        
        ttk.Label(hash_frame, text="Giá trị Hash:", style='Header.TLabel').grid(
            row=1, column=0, padx=5, pady=2, sticky=tk.W)
        self.hash_var = tk.StringVar()
        hash_entry = ttk.Entry(hash_frame, textvariable=self.hash_var, 
                             width=70, state='readonly')
        hash_entry.grid(row=2, column=0, columnspan=2, padx=5, pady=2, sticky=tk.W)
        
        self.message_text.bind('<KeyRelease>', self.on_message_change)
    def import_file(self):
        try:
            file_path = filedialog.askopenfilename()
            if file_path:
                with open(file_path, 'r', encoding='utf-8') as file:
                    content = file.read()
                    self.message_text.delete(1.0, tk.END)
                    self.message_text.insert(tk.END, content)
                    self.calculate_hash()
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể đọc file: {str(e)}")
    
    def clear_message(self):
        self.message_text.delete(1.0, tk.END)
        self.calculate_hash()
    
    def calculate_hash(self):
        try:
            message = self.message_text.get(1.0, tk.END).strip()
            if message:
                hash_object = hashlib.sha256(message.encode())
                hash_hex = hash_object.hexdigest()
                self.hash_var.set(hash_hex)
            else:
                self.hash_var.set("")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể tính hash: {str(e)}")
    
    def toggle_auto_hash(self):
        if self.auto_hash_var.get():
            self.hash_button.state(['disabled'])
            self.calculate_hash()
        else:
            self.hash_button.state(['!disabled'])
    
    def on_message_change(self, event=None):
        if self.auto_hash_var.get():
            self.calculate_hash()



if __name__ == "__main__":
    root = tk.Tk()
    app = ECCApp(root)
    root.mainloop()