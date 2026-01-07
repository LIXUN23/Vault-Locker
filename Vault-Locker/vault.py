import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import os
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import base64
import secrets
import threading

# --- 1. THEME CONFIGURATION (The "Calm" UI) ---
BG_MAIN    = "#0b0f14"   # Deepest void
BG_PANEL   = "#111827"   # Slate panel
ACCENT     = "#22d3ee"   # Cyan highlight
ACCENT_DIM = "#0e7490"   # Muted teal (for hover)
TEXT_MAIN  = "#e5e7eb"   # Soft white
TEXT_MUTED = "#9ca3af"   # Gray
DANGER     = "#ef4444"   # Red (errors)

# --- 2. CONSTANTS ---
VAULT_HEADER = b'LIXUN_VAULT'
VERSION = b'\x01'

# --- 3. CRYPTO ENGINE ---

def derive_key(password, salt):
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def set_status(text, color=TEXT_MUTED):
    status_label.config(text=text, fg=color)
    root.update_idletasks() # Force UI to refresh immediately

def encrypt_file():
    set_status("Waiting for file...")
    filepath = filedialog.askopenfilename(title="Select File to LOCK")
    if not filepath:
        set_status("Ready")
        return

    # Fix: Bring dialogs to front
    root.attributes("-topmost", True)
    password = simpledialog.askstring("Secure Lock", "Enter Vault password:\n(Cannot be recovered)", show='*')
    root.attributes("-topmost", False)
    
    if not password:
        set_status("Action Cancelled")
        return

    root.attributes("-topmost", True)
    confirm = simpledialog.askstring("Confirm", "Re-enter Password to verify:", show='*')
    root.attributes("-topmost", False)

    if password != confirm:
        messagebox.showerror("Mismatch", "Passwords do not match")
        set_status("Error: Password Mismatch", DANGER)
        return

    try:
        set_status("Encrypting...", ACCENT)
        
        # Salt & Key
        salt = secrets.token_bytes(16)
        key = derive_key(password, salt)
        f = Fernet(key)

        # Read & Encrypt
        with open(filepath, "rb") as file:
            file_data = file.read()
        
        # Payload = [Signature] + [Data]
        payload = VAULT_HEADER + file_data
        encrypted_data = f.encrypt(payload)

        # Write: [Salt] + [Version] + [Encrypted Body]
        new_path = filepath + ".enc"
        with open(new_path, "wb") as file:
            file.write(salt + VERSION + encrypted_data)

        # Secure Delete Check
        root.attributes("-topmost", True)
        if messagebox.askyesno("Secure Delete", "Lock Successful.\n\nDelete original file?"):
            os.remove(filepath)
            set_status("Locked & Cleaned", ACCENT)
        else:
            set_status("Locked (Original Kept)", TEXT_MAIN)
        root.attributes("-topmost", False)

    except Exception as e:
        messagebox.showerror("Error", str(e))
        set_status("Encryption Failed", DANGER)

def decrypt_file():
    set_status("Select .enc file...")
    filepath = filedialog.askopenfilename(title="Select File to UNLOCK", filetypes=[("Encrypted", "*.enc")])
    if not filepath:
        set_status("Ready")
        return

    root.attributes("-topmost", True)
    password = simpledialog.askstring("Unlock", "Enter Vault password:", show='*')
    root.attributes("-topmost", False)
    
    if not password:
        set_status("Action Cancelled")
        return

    try:
        set_status("Decrypting...", ACCENT)
        with open(filepath, "rb") as file:
            full_data = file.read()

        if len(full_data) < 17: raise ValueError("Corrupted file")

        salt = full_data[:16]
        encrypted_token = full_data[17:]

        key = derive_key(password, salt)
        f = Fernet(key)
        
        decrypted_payload = f.decrypt(encrypted_token)

        if not decrypted_payload.startswith(VAULT_HEADER):
            raise ValueError("Invalid Signature")

        original_data = decrypted_payload[len(VAULT_HEADER):]

        original_path = filepath[:-4] # Remove .enc extension
        
        # 1. Restore Original File
        with open(original_path, "wb") as file:
            file.write(original_data)
        
        # 2. UPGRADE: Automatic Cleanup (No Prompt)
        # We only delete IF the write above succeeded to prevent data loss
        os.remove(filepath)
        
        set_status(f"Unlocked: {os.path.basename(original_path)}", ACCENT)
        messagebox.showinfo("Success", f"File Unlocked.\nVault file removed.")

    except InvalidToken:
        set_status("Access Denied: Wrong Password", DANGER)
        messagebox.showerror("Error", "Wrong Password!")
    except Exception as e:
        set_status("Error", DANGER)
        messagebox.showerror("Error", str(e))
        
# --- 4. UI CONSTRUCTION ---
root = tk.Tk()
root.title("LixunVault v2.0")
root.geometry("400x220")
root.configure(bg=BG_MAIN)
root.resizable(False, False)

# Title
tk.Label(
    root,
    text="AES-256 • Local File Encryption",
    font=("Consolas", 10),
    fg=TEXT_MUTED,
    bg=BG_MAIN
).pack(pady=(25, 5))

# Subtitle / Hint
tk.Label(
    root,
    text="Zero-Knowledge • Offline • Secure",
    font=("Arial", 7),
    fg="#334155", # Darker gray
    bg=BG_MAIN
).pack(pady=(0, 20))

# Button Helper
def vault_button(parent, text, command):
    return tk.Button(
        parent,
        text=text,
        command=command,
        font=("Consolas", 11, "bold"),
        bg=BG_PANEL,
        fg=TEXT_MAIN,
        activebackground=ACCENT,   # Flash bright cyan on click
        activeforeground=BG_MAIN,  # Black text on click
        relief="flat",
        bd=0,
        width=14,
        height=2,
        cursor="hand2"
    )

# Button Container
btn_frame = tk.Frame(root, bg=BG_MAIN)
btn_frame.pack(pady=5)

vault_button(btn_frame, "🔒 LOCK", encrypt_file).grid(row=0, column=0, padx=10)
vault_button(btn_frame, "🔓 UNLOCK", decrypt_file).grid(row=0, column=1, padx=10)

# Status Bar (Micro-UX)
status_label = tk.Label(
    root,
    text="Ready",
    font=("Consolas", 9),
    fg=TEXT_MUTED,
    bg=BG_MAIN
)
status_label.pack(side="bottom", pady=15)

# --- 5. LAUNCH ---
root.mainloop()