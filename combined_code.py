import os
import shutil
import datetime
import hashlib
import sqlite3
import csv
import ttkbootstrap as tb
from ttkbootstrap.constants import *
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2 import service_account
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload

# Constants
BACKUP_DIR = "backup"
RESTORE_DIR = "restored_files"  # New folder for restored files
DB_FILE = "data_recovery.db"
ENCRYPTION_KEY_FILE = "encryption.key"
SCOPES = ['https://www.googleapis.com/auth/drive']
SERVICE_ACCOUNT_FILE = 'service.json'  # Replace with your service account file
DRIVE_FOLDER_ID = '1WAxOY4DIlYKRY1x0Q4BN0wbYWtv3Pl8Z'  # Replace with your Google Drive folder ID

# Global Variables
logged_in_user = None
fernet = None

# Check if service account file exists
if not os.path.exists(SERVICE_ACCOUNT_FILE):
    messagebox.showerror("Error", f"Service account file '{SERVICE_ACCOUNT_FILE}' not found. Please ensure the file is in the correct directory.")
    exit(1)

creds = service_account.Credentials.from_service_account_file(SERVICE_ACCOUNT_FILE, scopes=SCOPES)
service = build('drive', 'v3', credentials=creds)

# Database setup
def initialize_database():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE,
                        password_hash TEXT
                      )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        action TEXT,
                        file_name TEXT,
                        timestamp TEXT,
                        checksum TEXT,
                        metadata TEXT
                      )''')
    conn.commit()
    conn.close()

# Encryption setup
def initialize_encryption():
    global fernet
    if not os.path.exists(ENCRYPTION_KEY_FILE):
        key = Fernet.generate_key()
        with open(ENCRYPTION_KEY_FILE, "wb") as key_file:
            key_file.write(key)
    else:
        with open(ENCRYPTION_KEY_FILE, "rb") as key_file:
            key = key_file.read()
    fernet = Fernet(key)

# User authentication
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def authenticate(username, password):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    if result and result[0] == hash_password(password):
        return True
    return False

def register_user(username, password):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hash_password(password)))
        conn.commit()
        messagebox.showinfo("Success", "User registered successfully.")
    except sqlite3.IntegrityError:
        messagebox.showerror("Error", "Username already exists.")
    finally:
        conn.close()

# Logging actions
def log_action(action, file_name, checksum="N/A", metadata="N/A"):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("INSERT INTO logs (action, file_name, timestamp, checksum, metadata) VALUES (?, ?, ?, ?, ?)",
                   (action, file_name, timestamp, checksum, metadata))
    conn.commit()
    conn.close()

# File metadata
def get_file_metadata(file_path):
    stats = os.stat(file_path)
    return f"Size: {stats.st_size} bytes, Created: {datetime.datetime.fromtimestamp(stats.st_ctime)}, Modified: {datetime.datetime.fromtimestamp(stats.st_mtime)}"

# Backup functions
def create_backup_dir():
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)

def create_restore_dir():
    if not os.path.exists(RESTORE_DIR):
        os.makedirs(RESTORE_DIR)

def calculate_checksum(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def encrypt_file(source_path, destination_path):
    with open(source_path, "rb") as file:
        encrypted_data = fernet.encrypt(file.read())
    with open(destination_path, "wb") as file:
        file.write(encrypted_data)

def backup_file(file_path):
    if not os.path.exists(file_path):
        messagebox.showerror("Error", f"File '{file_path}' does not exist.")
        return

    try:
        file_name = os.path.basename(file_path)
        backup_path = os.path.join(BACKUP_DIR, file_name)
        encrypt_file(file_path, backup_path)
        checksum = calculate_checksum(file_path)
        metadata = get_file_metadata(file_path)
        log_action("BACKUP", file_name, checksum, metadata)
        messagebox.showinfo("Success", f"File '{file_name}' has been backed up successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"Error backing up file: {e}")

# Restore functions
def decrypt_file(source_path, destination_path):
    with open(source_path, "rb") as file:
        decrypted_data = fernet.decrypt(file.read())
    with open(destination_path, "wb") as file:
        file.write(decrypted_data)

def restore_file(file_name):
    backup_path = os.path.join(BACKUP_DIR, file_name)

    if not os.path.exists(backup_path):
        messagebox.showerror("Error", f"Backup of '{file_name}' does not exist.")
        return

    try:
        restored_path = os.path.join(RESTORE_DIR, file_name)  # Restore to the restored_files folder
        decrypt_file(backup_path, restored_path)
        checksum = calculate_checksum(restored_path)
        log_action("RESTORE", file_name, checksum, "N/A")
        messagebox.showinfo("Success", f"File '{file_name}' has been restored successfully to '{RESTORE_DIR}'.")
    except Exception as e:
        messagebox.showerror("Error", f"Error restoring file: {e}")

# Google Drive functions
def get_drive_file(file_name, folder_id):
    try:
        query = f"'{folder_id}' in parents and name='{file_name}'"
        results = service.files().list(q=query, spaces='drive').execute()
        if results['files']:
            return results['files'][0]
        return None
    except HttpError as error:
        messagebox.showerror("Error", f"Error fetching file from Google Drive: {error}")
        return None

def upload_to_drive(file_path, folder_id):
    try:
        file_metadata = {'name': os.path.basename(file_path), 'parents': [folder_id]}
        media = MediaFileUpload(file_path, mimetype=None, resumable=True)
        file = service.files().create(body=file_metadata, media_body=media, fields='id').execute()
        messagebox.showinfo("Success", f"File uploaded to Google Drive (ID: {file.get('id')}): {file_path}")
        return file.get('id')
    except HttpError as error:
        messagebox.showerror("Error", f"Error uploading file to Google Drive: {error}")
        return None

def download_from_drive(file_id, destination_path):
    try:
        request = service.files().get_media(fileId=file_id)
        with open(destination_path, "wb") as fh:
            downloader = MediaIoBaseDownload(fh, request)
            done = False
            while done is False:
                status, done = downloader.next_chunk()
        messagebox.showinfo("Success", f"File downloaded from Google Drive: {destination_path}")
    except HttpError as error:
        messagebox.showerror("Error", f"Error downloading file from Google Drive: {error}")

def backup_to_drive():
    try:
        # Ensure the backup directory exists
        if not os.path.exists(BACKUP_DIR):
            messagebox.showerror("Error", f"Backup directory '{BACKUP_DIR}' does not exist.")
            return

        # Walk through the backup directory and upload files
        for root, _, files in os.walk(BACKUP_DIR):
            for file_name in files:
                local_file_path = os.path.join(root, file_name)
                drive_file = get_drive_file(file_name, DRIVE_FOLDER_ID)

                # If the file doesn't exist on Google Drive, upload it
                if not drive_file:
                    upload_to_drive(local_file_path, DRIVE_FOLDER_ID)
                else:
                    # Compare local and drive file modification times
                    local_modified_time = datetime.datetime.fromtimestamp(os.path.getmtime(local_file_path))
                    drive_modified_time = datetime.datetime.fromisoformat(drive_file['modifiedTime'].replace("Z", "+00:00"))

                    # If the local file is newer, upload it
                    if local_modified_time > drive_modified_time:
                        upload_to_drive(local_file_path, DRIVE_FOLDER_ID)

        messagebox.showinfo("Success", "Local backup folder backed up to Google Drive.")
    except Exception as e:
        messagebox.showerror("Error", f"Error during backup to Google Drive: {e}")

def restore_from_drive():
    try:
        query = f"'{DRIVE_FOLDER_ID}' in parents"
        results = service.files().list(q=query, spaces='drive').execute()
        if not results['files']:
            messagebox.showinfo("Restore", "No files found in Google Drive to restore.")
            return

        # Create a list of file names for the user to choose from
        file_names = [file['name'] for file in results['files']]
        selected_file = filedialog.askopenfilename(title="Select a file to restore", filetypes=[("All files", "*.*")], initialdir=BACKUP_DIR)

        if not selected_file:
            return  # User canceled the selection

        file_name = os.path.basename(selected_file)
        drive_file = get_drive_file(file_name, DRIVE_FOLDER_ID)

        if not drive_file:
            messagebox.showerror("Error", f"File '{file_name}' not found in Google Drive.")
            return

        # Download the file to the restored_files folder
        restored_path = os.path.join(RESTORE_DIR, file_name)
        download_from_drive(drive_file['id'], restored_path)

        # Restore the file
        restore_file(file_name)

        messagebox.showinfo("Success", f"File '{file_name}' has been restored from Google Drive to '{RESTORE_DIR}'.")
    except HttpError as error:
        messagebox.showerror("Error", f"Error restoring files from Google Drive: {error}")

# Export logs to CSV
def export_logs():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT action, file_name, timestamp, checksum, metadata FROM logs")
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        messagebox.showinfo("Logs", "No logs to export.")
        return

    file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
    if not file_path:
        return

    with open(file_path, "w", newline="") as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(["Action", "File Name", "Timestamp", "Checksum", "Metadata"])
        csv_writer.writerows(rows)

    messagebox.showinfo("Success", f"Logs have been exported to '{file_path}'.")

# GUI Functions
def login_prompt(root, username_label, button_frame):
    def attempt_login():
        username = username_entry.get()
        password = password_entry.get()
        if authenticate(username, password):
            global logged_in_user
            logged_in_user = username
            username_label.config(text=f"Logged in as: {username}")
            toggle_buttons(button_frame, True)
            login_window.destroy()
        else:
            messagebox.showerror("Error", "Invalid credentials.")

    login_window = tb.Toplevel(root)
    login_window.title("Login")
    login_window.geometry("300x200")

    tb.Label(login_window, text="Username:", font=("Arial", 12)).grid(row=0, column=0, padx=10, pady=10)
    tb.Label(login_window, text="Password:", font=("Arial", 12)).grid(row=1, column=0, padx=10, pady=10)

    username_entry = tb.Entry(login_window, font=("Arial", 12))
    password_entry = tb.Entry(login_window, show="*", font=("Arial", 12))

    username_entry.grid(row=0, column=1, padx=10, pady=10)
    password_entry.grid(row=1, column=1, padx=10, pady=10)

    tb.Button(login_window, text="Login", bootstyle=SUCCESS, command=attempt_login).grid(row=2, columnspan=2, pady=10)

def register_prompt(root):
    def attempt_register():
        username = username_entry.get()
        password = password_entry.get()
        if username and password:
            register_user(username, password)
            register_window.destroy()
        else:
            messagebox.showerror("Error", "Username and password cannot be empty.")

    register_window = tb.Toplevel(root)
    register_window.title("Register")
    register_window.geometry("300x200")

    tb.Label(register_window, text="Username:", font=("Arial", 12)).grid(row=0, column=0, padx=10, pady=10)
    tb.Label(register_window, text="Password:", font=("Arial", 12)).grid(row=1, column=0, padx=10, pady=10)

    username_entry = tb.Entry(register_window, font=("Arial", 12))
    password_entry = tb.Entry(register_window, show="*", font=("Arial", 12))

    username_entry.grid(row=0, column=1, padx=10, pady=10)
    password_entry.grid(row=1, column=1, padx=10, pady=10)

    tb.Button(register_window, text="Register", bootstyle=SUCCESS, command=attempt_register).grid(row=2, columnspan=2, pady=10)

def logout(username_label, button_frame):
    global logged_in_user
    logged_in_user = None
    username_label.config(text="Not logged in")
    toggle_buttons(button_frame, False)

def toggle_buttons(button_frame, logged_in):
    for widget in button_frame.winfo_children():
        widget.destroy()
    if logged_in:
        tb.Button(button_frame, text="Backup File", bootstyle=INFO,
                  command=lambda: backup_file(filedialog.askopenfilename())).grid(row=0, column=0, padx=10, pady=10)
        tb.Button(button_frame, text="Restore File", bootstyle=INFO,
                  command=lambda: restore_file(filedialog.askopenfilename())).grid(row=0, column=1, padx=10, pady=10)
        tb.Button(button_frame, text="Backup to Google Drive", bootstyle=INFO,
                  command=backup_to_drive).grid(row=1, column=0, padx=10, pady=10)
        tb.Button(button_frame, text="Restore from Google Drive", bootstyle=INFO,
                  command=restore_from_drive).grid(row=1, column=1, padx=10, pady=10)
        tb.Button(button_frame, text="Export Logs", bootstyle=PRIMARY, command=export_logs).grid(row=2, column=0, padx=10, pady=10)
        tb.Button(button_frame, text="Logout", bootstyle=DANGER, command=lambda: logout(username_label, button_frame)).grid(row=2, column=1, pady=10)
    else:
        tb.Button(button_frame, text="Login", bootstyle=PRIMARY,
                  command=lambda: login_prompt(root, username_label, button_frame)).grid(row=0, column=0, pady=10)
        tb.Button(button_frame, text="Register", bootstyle=SUCCESS, command=lambda: register_prompt(root)).grid(row=0, column=1, pady=10)

# Main GUI
if __name__ == "__main__":
    initialize_database()
    initialize_encryption()
    create_backup_dir()
    create_restore_dir()  # Create the restored_files folder

    root = tb.Window(themename="morph")
    root.title("Forensic Backup and Recovery Tool")
    root.geometry("600x400")

    username_label = tb.Label(root, text="Not logged in", font=("Arial", 14), anchor="center")
    username_label.pack(pady=20)

    button_frame = tb.Frame(root)
    button_frame.pack(pady=20)

    toggle_buttons(button_frame, False)

    root.mainloop()