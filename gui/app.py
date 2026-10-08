import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import threading
import time
import os

from gui.usb_detect import scan_for_keys

# Optional: mlcore injection
try:
    from mlcore.mlcore import MLCore
    mc = MLCore()
    import mlref.crypto
    # Inject mlcore KDF for fast Argon2
    mlref.crypto.argon2id = lambda pw, salt, m, t: mc.kdf(pw, salt, t, m, 1, 32)
except Exception as e:
    print("Warning: Could not inject mlcore crypto, falling back to python:", e)

from mlref.ops import unlock, init, lock
from mlref.vault import Credentials
from mlref.keyfile import KeyFile
from mlref.constants import PRODUCTION_POLICY

class MyLockerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        
        self.title("MyLocker - Secure USB Vault")
        self.geometry("550x450")
        self.resizable(False, False)
        
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        
        style = ttk.Style(self)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        elif "winnative" in style.theme_names():
            style.theme_use("winnative")
            
        style.configure("TFrame", background="#f0f0f0")
        style.configure("Title.TLabel", font=("Segoe UI", 16, "bold"), background="#f0f0f0")
        style.configure("Status.TLabel", font=("Segoe UI", 10), background="#f0f0f0")
        
        self.main_frame = ttk.Frame(self, style="TFrame", padding="20")
        self.main_frame.grid(row=0, column=0, sticky="nsew")
        
        self.main_frame.columnconfigure(0, weight=1)
        
        # UI Elements
        self.lbl_title = ttk.Label(self.main_frame, text="MyLocker", style="Title.TLabel")
        self.lbl_title.grid(row=0, column=0, pady=(10, 10))
        
        self.lbl_icon = ttk.Label(self.main_frame, text="🔌", font=("Segoe UI Emoji", 48), background="#f0f0f0")
        self.lbl_icon.grid(row=1, column=0, pady=5)
        
        self.lbl_status = ttk.Label(self.main_frame, text="Lütfen fiziksel USB anahtarınızı takın...", style="Status.TLabel")
        self.lbl_status.grid(row=2, column=0, pady=5)

        self.target_dir = tk.StringVar(value="Henüz bir klasör seçilmedi")
        
        self.lbl_target = ttk.Label(self.main_frame, textvariable=self.target_dir, foreground="gray", background="#f0f0f0")
        self.lbl_target.grid(row=3, column=0, pady=5)

        self.btn_select = ttk.Button(self.main_frame, text="Hedef Klasör Seç...", command=self.select_folder)
        self.btn_select.grid(row=4, column=0, pady=5)
        
        self.btn_action = ttk.Button(self.main_frame, text="Kilidi Aç / Kasa Oluştur", command=self.handle_action, state=tk.DISABLED)
        self.btn_action.grid(row=5, column=0, pady=(15, 0))

        self.btn_lock = ttk.Button(self.main_frame, text="Kasayı Kilitle", command=self.lock_current_vault, state=tk.DISABLED)
        self.btn_lock.grid(row=6, column=0, pady=5)
        
        # State
        self.found_key = None
        self.selected_folder = None
        self.unlocked_state = False
        self._stop_event = threading.Event()
        
        # Start USB monitoring thread
        self.monitor_thread = threading.Thread(target=self.monitor_usb, daemon=True)
        self.monitor_thread.start()

    def update_action_state(self):
        if self.found_key and self.selected_folder and not self.unlocked_state:
            self.btn_action.config(state=tk.NORMAL)
        else:
            self.btn_action.config(state=tk.DISABLED)

    def select_folder(self):
        folder = filedialog.askdirectory(title="MyLocker ile korunacak veya açılacak klasörü seçin")
        if folder:
            self.selected_folder = folder
            self.target_dir.set(f"Seçili Klasör: {os.path.basename(folder)}")
            self.update_action_state()

    def update_ui_detected(self, key_path):
        self.lbl_icon.config(text="🔑")
        self.lbl_status.config(text=f"USB Anahtarı bulundu!", foreground="green")
        self.update_action_state()

    def update_ui_waiting(self):
        self.lbl_icon.config(text="🔌")
        self.lbl_status.config(text="Lütfen fiziksel USB anahtarınızı takın...", foreground="black")
        self.update_action_state()
        
        # If vault was unlocked, lock it!
        if self.unlocked_state:
            self.lock_current_vault()

    def monitor_usb(self):
        while not self._stop_event.is_set():
            keys = scan_for_keys()
            if keys:
                if self.found_key != keys[0]:
                    self.found_key = keys[0]
                    self.after(0, self.update_ui_detected, keys[0])
            else:
                if self.found_key is not None:
                    self.found_key = None
                    self.after(0, self.update_ui_waiting)
            
            time.sleep(1.0)

    def handle_action(self):
        if not self.found_key or not self.selected_folder:
            return
            
        mylocker_dir = os.path.join(self.selected_folder, ".mylocker")
        is_vault = os.path.exists(mylocker_dir)
        
        pwd = simpledialog.askstring("Şifre", "Kasa şifrenizi girin:", show="*")
        if not pwd:
            return

        try:
            kf = KeyFile.load(self.found_key)
        except Exception as e:
            messagebox.showerror("Hata", f"USB Anahtarı okunamadı:\n{e}")
            return
            
        self.lbl_status.config(text="İşlem yapılıyor, lütfen bekleyin...", foreground="blue")
        self.update()
        
        try:
            from pathlib import Path
            root = Path(self.selected_folder)
            creds = Credentials(keyfiles=(kf,), password=pwd)
            
            if not is_vault:
                # Create vault
                init(root, kf, pwd, with_recovery=False)
                messagebox.showinfo("Başarılı", "Yeni Kasa oluşturuldu ve kilitlendi!")
            else:
                # Open vault
                unlock(root, creds)
                self.unlocked_state = True
                self.btn_lock.config(state=tk.NORMAL)
                self.btn_action.config(state=tk.DISABLED)
                self.lbl_icon.config(text="🔓")
                self.lbl_status.config(text="Kasa Açık (Şifreler çözüldü)!", foreground="green")
                messagebox.showinfo("Başarılı", "Kasa kilidi açıldı. Dosyalarınızı kullanabilirsiniz.")
        except Exception as e:
            self.lbl_status.config(text="USB Anahtarı bulundu!", foreground="green")
            messagebox.showerror("Hata", f"İşlem başarısız:\n{e}")

    def lock_current_vault(self):
        if not self.unlocked_state or not self.selected_folder:
            return
        try:
            self.lbl_status.config(text="Kasa kilitleniyor...", foreground="blue")
            self.update()
            
            from pathlib import Path
            root = Path(self.selected_folder)
            
            # Note: lock() re-encrypts plaintext and commits. It requires creds.
            # But wait, does lock() require password again?
            # Let's check if we can just call lock() with empty creds or we must cache it.
            # For MVP we will just call lock() and we might need password, but wait!
            # If the user unlocked it, the plaintext is there.
            # Actually, `lock()` requires `creds` to rewrite the vault.
            # I will prompt for password again for locking, or cache it.
            # For safety, let's prompt again for MVP, or just cache the creds.
            # Actually, lock() in MVP reads the plaintext and encrypts it back.
            pwd = simpledialog.askstring("Şifre", "Kasayı kilitlemek için şifrenizi girin:", show="*")
            if not pwd:
                self.lbl_status.config(text="Kasa kilitleme iptal edildi.", foreground="black")
                return
            
            kf = KeyFile.load(self.found_key)
            creds = Credentials(keyfiles=(kf,), password=pwd)
            lock(root, creds)
            
            self.unlocked_state = False
            self.btn_lock.config(state=tk.DISABLED)
            self.lbl_icon.config(text="🔑" if self.found_key else "🔌")
            self.lbl_status.config(text="Kasa kilitlendi ve şifrelendi.", foreground="black")
            self.update_action_state()
            messagebox.showinfo("Başarılı", "Kasa güvenli bir şekilde kilitlendi.")
        except Exception as e:
            messagebox.showerror("Hata", f"Kilitleme sırasında hata:\n{e}")

    def destroy(self):
        self._stop_event.set()
        super().destroy()

if __name__ == "__main__":
    import sys
    # Ensure project root is in sys.path
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    app = MyLockerApp()
    app.mainloop()
