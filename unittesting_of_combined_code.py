import unittest
import os
import shutil
import sqlite3
import hashlib
from cryptography.fernet import Fernet
from unittest.mock import patch, MagicMock
from combined_code import (
    initialize_database,
    initialize_encryption,
    hash_password,
    authenticate,
    register_user,
    log_action,
    get_file_metadata,
    calculate_checksum,
    encrypt_file,
    decrypt_file,
    backup_file,
    restore_file,
    DB_FILE,
    BACKUP_DIR,
    ENCRYPTION_KEY_FILE,
)

class TestForensicBackupAndRecovery(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Initialize the database and encryption for all tests
        initialize_database()
        initialize_encryption()

    def setUp(self):
        # Create a test file and backup directory
        self.test_file = "test_file.txt"
        with open(self.test_file, "w") as f:
            f.write("This is a test file.")
        if not os.path.exists(BACKUP_DIR):
            os.makedirs(BACKUP_DIR)

        # Ensure the database is initialized and tables are created
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

    def tearDown(self):
        # Clean up test files and backup directory
        if os.path.exists(self.test_file):
            os.remove(self.test_file)
        if os.path.exists(BACKUP_DIR):
            shutil.rmtree(BACKUP_DIR)
        if os.path.exists(DB_FILE):
            # Ensure all database connections are closed before deleting the file
            try:
                os.remove(DB_FILE)
            except PermissionError:
                pass  # Ignore if the file is still in use
        if os.path.exists(ENCRYPTION_KEY_FILE):
            os.remove(ENCRYPTION_KEY_FILE)

    def test_hash_password(self):
        # Test password hashing
        password = "testpassword"
        hashed = hash_password(password)
        self.assertEqual(len(hashed), 64)  # SHA-256 hash is 64 characters long

    @patch('combined_code.messagebox.showinfo')
    @patch('combined_code.messagebox.showerror')
    def test_authenticate(self, mock_showerror, mock_showinfo):
        # Test user authentication
        username = "testuser"
        password = "testpassword"
        register_user(username, password)
        self.assertTrue(authenticate(username, password))
        self.assertFalse(authenticate(username, "wrongpassword"))

    @patch('combined_code.messagebox.showinfo')
    @patch('combined_code.messagebox.showerror')
    def test_register_user(self, mock_showerror, mock_showinfo):
        # Test user registration
        username = "newuser"
        password = "newpassword"
        register_user(username, password)
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()
        self.assertIsNotNone(result)
        self.assertEqual(result[0], hash_password(password))

    @patch('combined_code.messagebox.showinfo')
    @patch('combined_code.messagebox.showerror')
    def test_log_action(self, mock_showerror, mock_showinfo):
        # Test logging actions
        action = "TEST_ACTION"
        file_name = "test_file.txt"
        log_action(action, file_name)
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT action, file_name FROM logs WHERE action = ?", (action,))
        result = cursor.fetchone()
        conn.close()
        self.assertIsNotNone(result)
        self.assertEqual(result[0], action)
        self.assertEqual(result[1], file_name)

    def test_get_file_metadata(self):
        # Test file metadata retrieval
        metadata = get_file_metadata(self.test_file)
        self.assertIn("Size:", metadata)
        self.assertIn("Created:", metadata)
        self.assertIn("Modified:", metadata)

    def test_calculate_checksum(self):
        # Test checksum calculation
        checksum = calculate_checksum(self.test_file)
        self.assertEqual(len(checksum), 64)  # SHA-256 checksum is 64 characters long

    def test_encrypt_decrypt_file(self):
        # Test file encryption and decryption
        encrypted_file = "encrypted_test_file.txt"
        decrypted_file = "decrypted_test_file.txt"
        encrypt_file(self.test_file, encrypted_file)
        self.assertTrue(os.path.exists(encrypted_file))
        decrypt_file(encrypted_file, decrypted_file)
        self.assertTrue(os.path.exists(decrypted_file))
        with open(self.test_file, "rb") as original, open(decrypted_file, "rb") as decrypted:
            self.assertEqual(original.read(), decrypted.read())
        os.remove(encrypted_file)
        os.remove(decrypted_file)

    @patch('combined_code.messagebox.showinfo')
    @patch('combined_code.messagebox.showerror')
    def test_backup_restore_file(self, mock_showerror, mock_showinfo):
        # Test file backup and restoration
        backup_file(self.test_file)
        backup_path = os.path.join(BACKUP_DIR, os.path.basename(self.test_file))
        self.assertTrue(os.path.exists(backup_path))
        restore_file(os.path.basename(self.test_file))
        restored_file = os.path.join(os.getcwd(), os.path.basename(self.test_file))
        self.assertTrue(os.path.exists(restored_file))
        with open(self.test_file, "rb") as original, open(restored_file, "rb") as restored:
            self.assertEqual(original.read(), restored.read())
        os.remove(restored_file)

if __name__ == "__main__":
    unittest.main()