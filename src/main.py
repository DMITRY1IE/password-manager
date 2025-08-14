import json, os, base64, hashlib, tkinter as tk
from tkinter import ttk, messagebox
from tkinter.simpledialog import askstring
from tkinter import filedialog
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from datetime import datetime
import secrets

VAULT_PATH = "vault.json" 
KDF_ITERATIONS = 200_000

def b64e(b): return base64.urlsafe_b64encode(b).decode()
def b64d(s): return base64.urlsafe_b64decode(s.encode())

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=KDF_ITERATIONS)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def new_vault(master_password: str, path: str):
    salt = secrets.token_bytes(16)
    key = derive_key(master_password, salt)
    f = Fernet(key)
    payload = {"version": 1, "items": [], "updated": datetime.utcnow().isoformat()}
    token = f.encrypt(json.dumps(payload).encode())
    blob = {"salt": b64e(salt), "kdf": {"name": "PBKDF2HMAC", "hash": "SHA256", "iter": KDF_ITERATIONS}, "data": b64e(token)}
    with open(path, "w", encoding="utf-8") as fp:
        json.dump(blob, fp, ensure_ascii=False, indent=2)

def open_vault(path: str):
    with open(path, "r", encoding="utf-8") as fp:
        return json.load(fp)

def decrypt_payload(blob, master_password: str):
    salt = b64d(blob["salt"])
    key = derive_key(master_password, salt)
    f = Fernet(key)
    try:
        data = json.loads(f.decrypt(b64d(blob["data"])).decode())
        return data, f, key
    except Exception:
        raise ValueError("Неверный мастер-пароль или повреждённый файл")

def encrypt_payload(data, fernet: Fernet):
    token = fernet.encrypt(json.dumps(data, ensure_ascii=False).encode())
    return b64e(token)

class VaultApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Менеджер паролей")
        self.geometry("780x520")
        self.resizable(True, True)
        
        # Цвета в стиле Telegram Dark
        self.bg_color = "#17212B"
        self.fg_color = "#FFFFFF"
        self.entry_bg = "#232E3C"
        self.button_bg = "#2B5278"
        self.button_active = "#3D6D99"
        self.select_color = "#2B5278"
        self.accent_color = "#5288C1"
        self.error_color = "#E15454"
        
        # Настройка темной темы
        self.configure(bg=self.bg_color)
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Конфигурация стилей
        self.style.configure('.', 
                           background=self.bg_color, 
                           foreground=self.fg_color,
                           fieldbackground=self.entry_bg,
                           insertcolor=self.fg_color)
        
        self.style.configure('TFrame', background=self.bg_color)
        self.style.configure('TLabel', 
                           background=self.bg_color, 
                           foreground=self.fg_color,
                           font=('Segoe UI', 10))
        
        self.style.configure('TEntry', 
                           fieldbackground=self.entry_bg,
                           foreground=self.fg_color,
                           insertcolor=self.fg_color,
                           bordercolor=self.entry_bg,
                           lightcolor=self.entry_bg,
                           darkcolor=self.entry_bg)
        
        self.style.configure('TButton', 
                           background=self.button_bg,
                           foreground=self.fg_color,
                           bordercolor=self.button_bg,
                           focusthickness=0,
                           focuscolor='none',
                           font=('Segoe UI', 10),
                           padding=6)
        self.style.map('TButton',
                      background=[('active', self.button_active)],
                      foreground=[('active', self.fg_color)])
        
        self.style.configure('Treeview', 
                           background=self.entry_bg,
                           foreground=self.fg_color,
                           fieldbackground=self.entry_bg,
                           rowheight=25,
                           bordercolor=self.bg_color,
                           lightcolor=self.bg_color,
                           darkcolor=self.bg_color)
        self.style.map('Treeview', 
                      background=[('selected', self.select_color)],
                      foreground=[('selected', self.fg_color)])
        
        self.style.configure('Treeview.Heading', 
                           background=self.bg_color,
                           foreground=self.fg_color,
                           relief='flat',
                           font=('Segoe UI', 10, 'bold'))
        
        self.style.configure('TScrollbar', 
                           background=self.bg_color,
                           troughcolor=self.bg_color,
                           bordercolor=self.bg_color,
                           arrowcolor=self.fg_color)
        
        self.style.configure('TMenubutton', 
                           background=self.bg_color,
                           foreground=self.fg_color)
        self.style.configure('Vertical.TScrollbar', 
                    background="#3498db",      # Цвет ползунка
                    troughcolor="#232E3C",    # Цвет фона трека
                    bordercolor="#232E3C",    # Цвет границы
                    arrowcolor="#ecf0f1",    # Цвет стрелок (если есть)
                    gripcount=0)              # Убираем стандартный "хват"
        
        self.vault_path = VAULT_PATH
        self.blob = None
        self.fernet = None
        self.key = None
        self.data = {"version": 1, "items": [], "updated": ""}

        self._build_menu()
        self._build_ui()
        self._bootstrap()

    # ---------- UI ----------
    def _build_menu(self):
        m = tk.Menu(self, 
                   bg="#2c3e50",  # Новый цвет фона
                   fg="#ecf0f1",
                   activebackground="#3498db",
                   activeforeground="#ffffff",
                   tearoff=0)
    
        filem = tk.Menu(m, 
                   bg="#2c3e50",  # Темно-синий
                   fg="#ecf0f1",
                   activebackground="#3498db",
                   activeforeground="#ffffff",
                   tearoff=0)
        filem.add_command(label="Открыть сейф…", command=self.menu_open)
        filem.add_command(label="Создать сейф…", command=self.menu_new)
        filem.add_separator()
        filem.add_command(label="Выход", command=self.destroy)
        m.add_cascade(label="Файл", menu=filem)

        toolsm = tk.Menu(m, 
                        bg=self.entry_bg,
                        fg=self.fg_color,
                        activebackground=self.select_color,
                        activeforeground=self.fg_color,
                        tearoff=0)
        toolsm.add_command(label="Сменить мастер-пароль", command=self.change_master)
        m.add_cascade(label="Инструменты", menu=toolsm)
        
        self.config(menu=m)

    def _build_ui(self):
        # Поиск
        top = ttk.Frame(self, padding=6)
        top.pack(fill="x")
        ttk.Label(top, text="Поиск:").pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self.refresh_list())
        ttk.Entry(top, textvariable=self.search_var).pack(side="left", fill="x", expand=True, padx=6)

        # Список
        mid = ttk.Frame(self, padding=(6, 0, 6, 0))
        mid.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(mid, columns=("site", "login", "updated"), show="headings", selectmode="browse")
        self.tree.heading("site", text="Сайт/Сервис")
        self.tree.heading("login", text="Логин")
        self.tree.heading("updated", text="Обновлён")
        self.tree.column("site", width=260)
        self.tree.column("login", width=180)
        self.tree.column("updated", width=120)
        self.tree.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self.on_select)

        # Форма
        form = ttk.Frame(self, padding=6)
        form.pack(fill="x")
        self.site_var = tk.StringVar()
        self.login_var = tk.StringVar()
        self.pass_var = tk.StringVar()

        g = ttk.Frame(form)
        g.pack(fill="x", pady=4)
        ttk.Label(g, text="Сайт/Сервис:").grid(row=0, column=0, sticky="w")
        ttk.Entry(g, textvariable=self.site_var).grid(row=0, column=1, sticky="we", padx=6)
        ttk.Label(g, text="Логин:").grid(row=1, column=0, sticky="w")
        ttk.Entry(g, textvariable=self.login_var).grid(row=1, column=1, sticky="we", padx=6)
        ttk.Label(g, text="Пароль:").grid(row=2, column=0, sticky="w")
        self.pass_entry = ttk.Entry(g, textvariable=self.pass_var, show="•")
        self.pass_entry.grid(row=2, column=1, sticky="we", padx=6)
        g.columnconfigure(1, weight=1)

        btns = ttk.Frame(form)
        btns.pack(fill="x", pady=6)
        ttk.Button(btns, text="Показать/скрыть", command=self.toggle_password).pack(side="left")
        ttk.Button(btns, text="Скопировать пароль", command=self.copy_password).pack(side="left", padx=6)
        ttk.Button(btns, text="Новая", command=self.action_new).pack(side="left", padx=(12, 0))
        ttk.Button(btns, text="Сохранить", command=self.action_save).pack(side="left", padx=6)
        ttk.Button(btns, text="Удалить", command=self.action_delete).pack(side="left", padx=6)

        status = ttk.Frame(self, padding=6)
        status.pack(fill="x")
        self.status_var = tk.StringVar(value="Готово")
        ttk.Label(status, textvariable=self.status_var).pack(side="left")
        sb = ttk.Scrollbar(mid, 
                  orient="vertical", 
                  command=self.tree.yview,
                  style='Vertical.TScrollbar')  # Применяем кастомный стиль
    # ---------- Boot / Vault ----------
    def _bootstrap(self):
        if not os.path.exists(self.vault_path):
            mpw = askstring("Создание сейфа", "Придумайте мастер-пароль:", show="*")
            if not mpw:
                self.destroy(); return
            new_vault(mpw, self.vault_path)
            self.status("Создан новый сейф: " + self.vault_path)
        self.load_vault(self.vault_path)

    def load_vault(self, path: str):
        try:
            blob = open_vault(path)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось открыть файл:\n{e}")
            return
        mpw = askstring("Вход", "Введите мастер-пароль:", show="*")
        if not mpw:
            self.destroy(); return
        try:
            data, f, key = decrypt_payload(blob, mpw)
        except ValueError:
            messagebox.showerror("Ошибка", "Неверный мастер-пароль.")
            self.destroy(); return
        self.vault_path, self.blob, self.fernet, self.key, self.data = path, blob, f, key, data
        self.refresh_list()
        self.status(f"Открыт: {os.path.abspath(path)}")

    def save_vault(self):
        self.data["updated"] = datetime.utcnow().isoformat()
        self.blob["data"] = encrypt_payload(self.data, self.fernet)
        with open(self.vault_path, "w", encoding="utf-8") as fp:
            json.dump(self.blob, fp, ensure_ascii=False, indent=2)

    # ---------- Actions ----------
    def action_new(self):
        self.site_var.set(""); self.login_var.set(""); self.pass_var.set("")
        self.tree.selection_remove(self.tree.selection())

    def action_save(self):
        site = self.site_var.get().strip()
        login = self.login_var.get().strip()
        pwd = self.pass_var.get()
        if not site or not login or not pwd:
            messagebox.showwarning("Внимание", "Заполните сайт, логин и пароль.")
            return
        item_id = self._selected_index()
        rec = {"site": site, "login": login, "password": pwd, "updated": datetime.utcnow().strftime("%Y-%m-%d %H:%M")}
        if item_id is None:
            self.data["items"].append(rec)
        else:
            self.data["items"][item_id] = rec
        self.save_vault()
        self.refresh_list()
        self.status("Сохранено.")

    def action_delete(self):
        idx = self._selected_index()
        if idx is None:
            messagebox.showinfo("Удаление", "Запись не выбрана.")
            return
        if messagebox.askyesno("Подтверждение", "Удалить выбранную запись?"):
            del self.data["items"][idx]
            self.save_vault()
            self.refresh_list()
            self.action_new()
            self.status("Удалено.")

    def copy_password(self):
        idx = self._selected_index()
        if idx is None:
            messagebox.showinfo("Буфер обмена", "Выберите запись.")
            return
        pwd = self.data["items"][idx]["password"]
        self.clipboard_clear(); self.clipboard_append(pwd)
        self.status("Пароль скопирован в буфер обмена.")

    def toggle_password(self):
        self.pass_entry.configure(show="" if self.pass_entry.cget("show") else "•")

    def on_select(self, _):
        idx = self._selected_index()
        if idx is None: return
        rec = self.data["items"][idx]
        self.site_var.set(rec["site"]); self.login_var.set(rec["login"]); self.pass_var.set(rec["password"])

    def refresh_list(self):
        query = self.search_var.get().lower().strip()
        for i in self.tree.get_children(): self.tree.delete(i)
        for i, rec in enumerate(self.data.get("items", [])):
            if query and query not in rec["site"].lower() and query not in rec["login"].lower():
                continue
            self.tree.insert("", "end", iid=str(i), values=(rec["site"], rec["login"], rec.get("updated","")))

    def _selected_index(self):
        sel = self.tree.selection()
        if not sel: return None
        try: return int(sel[0])
        except: return None

    def status(self, msg): self.status_var.set(msg)

    # ---------- Menu handlers ----------
    def menu_open(self):
        path = filedialog.askopenfilename(title="Открыть сейф", filetypes=[("Vault JSON","*.json"),("Все файлы","*.*")])
        if not path: return
        self.load_vault(path)

    def menu_new(self):
        path = filedialog.asksaveasfilename(title="Создать сейф", defaultextension=".json",
                                            filetypes=[("Vault JSON","*.json")])
        if not path: return
        mpw1 = askstring("Новый сейф", "Придумайте мастер-пароль:", show="*")
        if not mpw1: return
        mpw2 = askstring("Новый сейф", "Повторите мастер-пароль:", show="*")
        if mpw1 != mpw2:
            messagebox.showerror("Ошибка", "Пароли не совпадают."); return
        new_vault(mpw1, path)
        self.load_vault(path)

    def change_master(self):
        old = askstring("Смена мастер-пароля", "Текущий мастер-пароль:", show="*")
        try:
            decrypt_payload(self.blob, old)
        except Exception:
            messagebox.showerror("Ошибка", "Неверный текущий пароль."); return
        new1 = askstring("Смена мастер-пароля", "Новый мастер-пароль:", show="*")
        new2 = askstring("Смена мастер-пароля", "Повторите новый пароль:", show="*")
        if not new1 or new1 != new2:
            messagebox.showerror("Ошибка", "Пароли не совпадают."); return
        # переупаковать с новым ключом/солью
        salt = secrets.token_bytes(16)
        self.blob["salt"] = b64e(salt)
        self.key = derive_key(new1, salt)
        self.fernet = Fernet(self.key)
        self.save_vault()
        self.status("Мастер-пароль обновлён.")

if __name__ == "__main__":
    try:
        app = VaultApp()
        app.mainloop()
    except KeyboardInterrupt:
        pass