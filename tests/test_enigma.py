import unittest
import sys
import os
from pathlib import Path
import tempfile
import shutil
from unittest.mock import patch, MagicMock

# Add project root to sys.path to allow importing enigma
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

from enigma import Enigma, PasswordMismatchError, main as enigma_main
from cryptography.fernet import InvalidToken

class TestEnigma(unittest.TestCase):
    def setUp(self):
        """Set up for test methods."""
        self.enigma = Enigma()
        # Create a temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        self.test_dir_path = Path(self.test_dir)

        # Create a dummy salt for consistent key generation during tests
        self.salt = b"\xa1\x1c\xbd\x13s\x90G\xe5\x17,#\x95\xd3\x86&\xe3"
        self.password = "testpassword"
        self.wrong_password = "wrongtestpassword"
        # self.key = self.enigma.gen_key_for_testing(self.password.encode(), self.salt) # Removed this

    def tearDown(self):
        """Tear down after test methods."""
        # Remove the temporary directory and its contents
        shutil.rmtree(self.test_dir)

    # Placeholder for a helper method in Enigma or direct mocking
    # For now, I'll assume gen_key will be mocked where necessary.
    # Or I can add a temporary method to Enigma for testing key generation if direct mocking is too complex for repeated use.

    @patch('getpass.getpass')
    def test_gen_key_success(self, mock_getpass):
        """Test successful key generation when passwords match."""
        mock_getpass.side_effect = [self.password, self.password]
        key = self.enigma.gen_key(salt=self.salt)
        self.assertIsNotNone(key)
        self.assertIsInstance(key, bytes)
        # Further validation could be to check if a known password + salt yields a known key
        # For now, just checking type and existence.

    @patch('getpass.getpass')
    def test_gen_key_password_mismatch(self, mock_getpass):
        """Test PasswordMismatchError when passwords do not match."""
        mock_getpass.side_effect = [self.password, self.wrong_password]
        with self.assertRaises(PasswordMismatchError):
            self.enigma.gen_key(salt=self.salt)

    @patch('getpass.getpass')
    def test_gen_key_uses_default_salt_if_none_provided(self, mock_getpass):
        """Test that gen_key uses the default salt if no salt is provided."""
        mock_getpass.side_effect = [self.password, self.password]
        # Generate key with explicit default salt
        key_with_default_salt_explicitly = self.enigma.gen_key(salt=self.enigma.default_salt)
        
        # Reset mock for the next call
        mock_getpass.side_effect = [self.password, self.password]
        # Generate key without providing salt (should use default)
        key_with_implicit_default_salt = self.enigma.gen_key()
        
        self.assertEqual(key_with_implicit_default_salt, key_with_default_salt_explicitly)

    def _create_dummy_file(self, filename="test_file.txt", content="Hello, Enigma!"):
        """Helper function to create a dummy file in the test directory."""
        file_path = self.test_dir_path / filename
        with open(file_path, "w") as f:
            f.write(content)
        return file_path

    @patch('enigma.Enigma.gen_key')
    def test_encrypt_decrypt_file_success(self, mock_gen_key):
        """Test successful file encryption and decryption."""
        original_content = "This is a secret message."
        dummy_file_path = self._create_dummy_file(content=original_content)

        # Mock gen_key to return a fixed key for testing
        test_key = Fernet.generate_key() # Generate a real Fernet key for the test
        mock_gen_key.return_value = test_key

        # Encrypt
        self.enigma.encrypt(str(dummy_file_path))
        encrypted_file_name = f"encrypted_{dummy_file_path.name}"
        encrypted_file_path = dummy_file_path.parent / encrypted_file_name
        
        self.assertTrue(encrypted_file_path.exists())
        self.assertFalse(dummy_file_path.exists()) # Original file should be deleted

        # Decrypt
        self.enigma.decrypt(str(encrypted_file_path))
        decrypted_file_path = encrypted_file_path.parent / dummy_file_path.name # Original name
        
        self.assertTrue(decrypted_file_path.exists())
        self.assertFalse(encrypted_file_path.exists()) # Encrypted file should be deleted

        with open(decrypted_file_path, "r") as f:
            decrypted_content = f.read()
        self.assertEqual(decrypted_content, original_content)

    @patch('enigma.Enigma.gen_key')
    def test_decrypt_file_incorrect_password(self, mock_gen_key):
        """Test decryption failure with an incorrect password (key)."""
        original_content = "Secret data."
        dummy_file_path = self._create_dummy_file(content=original_content)

        # Encrypt with a specific key
        correct_key = Fernet.generate_key()
        mock_gen_key.return_value = correct_key
        self.enigma.encrypt(str(dummy_file_path))
        encrypted_file_path = self.test_dir_path / f"encrypted_{dummy_file_path.name}"

        # Attempt to decrypt with a different key
        wrong_key = Fernet.generate_key()
        mock_gen_key.return_value = wrong_key # Simulate providing wrong password
        
        with self.assertRaises(InvalidToken):
            self.enigma.decrypt(str(encrypted_file_path))
        
        # Ensure original encrypted file still exists as decryption failed mid-way
        self.assertTrue(encrypted_file_path.exists())

    def test_encrypt_file_not_found(self):
        """Test encrypting a non-existent file."""
        with self.assertRaises(FileNotFoundError):
            self.enigma.encrypt(str(self.test_dir_path / "non_existent_file.txt"))

    def test_decrypt_file_not_found(self):
        """Test decrypting a non-existent file."""
        with self.assertRaises(FileNotFoundError):
            self.enigma.decrypt(str(self.test_dir_path / "non_existent_encrypted_file.txt"))

    @patch('enigma.Enigma.gen_key')
    def test_encrypt_output_file_naming(self, mock_gen_key):
        """Test the output file naming convention for encryption."""
        dummy_file_path = self._create_dummy_file(filename="test_doc.pdf")
        mock_gen_key.return_value = Fernet.generate_key()

        self.enigma.encrypt(str(dummy_file_path))
        expected_encrypted_name = f"encrypted_{dummy_file_path.name}"
        encrypted_file_path = self.test_dir_path / expected_encrypted_name
        self.assertTrue(encrypted_file_path.exists())

    @patch('enigma.Enigma.gen_key')
    def test_decrypt_output_file_naming_standard(self, mock_gen_key):
        """Test standard output file naming for decryption (encrypted_ prefix)."""
        original_filename = "my_data.xlsx"
        encrypted_filename = f"encrypted_{original_filename}"
        # Create a dummy encrypted file (content doesn't matter for this naming test)
        encrypted_file_path = self._create_dummy_file(filename=encrypted_filename, content="dummy_encrypted_data")
        
        mock_gen_key.return_value = Fernet.generate_key() # Key for decryption
        
        self.enigma.decrypt(str(encrypted_file_path))
        expected_decrypted_path = self.test_dir_path / original_filename
        self.assertTrue(expected_decrypted_path.exists())

    @patch('enigma.Enigma.gen_key')
    @patch('builtins.print') # To capture the warning print
    def test_decrypt_output_file_naming_no_prefix(self, mock_print, mock_gen_key):
        """Test output file naming for decryption when 'encrypted_' prefix is missing."""
        original_filename = "unconventional.dat"
        # Create a dummy file that doesn't follow the "encrypted_" convention
        unconventional_file_path = self._create_dummy_file(filename=original_filename, content="dummy_data")
        
        mock_gen_key.return_value = Fernet.generate_key()

        # Decrypt this unconventional file
        # We need to mock the actual fernet decryption because it would fail if the content is not encrypted
        with patch('cryptography.fernet.Fernet.decrypt') as mock_fernet_decrypt:
            mock_fernet_decrypt.return_value = b"decrypted data" # mock actual decryption
            self.enigma.decrypt(str(unconventional_file_path))

        expected_decrypted_name = f"decrypted_{original_filename}"
        decrypted_file_path = self.test_dir_path / expected_decrypted_name
        
        self.assertTrue(decrypted_file_path.exists())
        # Check if the warning was printed
        warning_found = False
        for call_args in mock_print.call_args_list:
            if f"Warning: File {unconventional_file_path} does not have 'encrypted_' prefix" in call_args[0][0]:
                warning_found = True
                break
        self.assertTrue(warning_found, "Warning about missing 'encrypted_' prefix was not printed.")

    def _create_dummy_folder_structure(self, num_files=2, subdirs=True):
        """Helper to create a dummy folder structure."""
        folder_path = self.test_dir_path / "test_folder"
        folder_path.mkdir(exist_ok=True)
        
        for i in range(num_files):
            self._create_dummy_file(filename=Path(folder_path) / f"file{i+1}.txt", content=f"Content of file {i+1}")

        if subdirs:
            subdir_path = folder_path / "subfolder"
            subdir_path.mkdir(exist_ok=True)
            self._create_dummy_file(filename=subdir_path / "subfile1.txt", content="Content of subfile1")
        return folder_path

    @patch('enigma.Enigma.gen_key')
    def test_encrypt_decrypt_folder_success(self, mock_gen_key):
        """Test successful folder encryption and decryption."""
        folder_to_process = self._create_dummy_folder_structure()
        original_files_content = {}
        original_paths = []

        for item in folder_to_process.rglob("*"):
            if item.is_file():
                original_paths.append(item.relative_to(folder_to_process))
                with open(item, 'r') as f:
                    original_files_content[item.relative_to(folder_to_process)] = f.read()
        
        self.assertTrue(len(original_files_content) > 0, "No files found in dummy folder structure.")

        test_key = Fernet.generate_key()
        mock_gen_key.return_value = test_key

        # Encrypt folder
        self.enigma.encrypt_folder(str(folder_to_process))

        # Verify encryption
        for original_relative_path in original_paths:
            original_name = original_relative_path.name
            encrypted_name = f"encrypted_{original_name}"
            encrypted_path = folder_to_process / original_relative_path.parent / encrypted_name
            original_file_path_in_folder = folder_to_process / original_relative_path
            
            self.assertTrue(encrypted_path.exists(), f"Encrypted file {encrypted_path} not found.")
            self.assertFalse(original_file_path_in_folder.exists(), f"Original file {original_file_path_in_folder} was not deleted after encryption.")

        # Decrypt folder
        self.enigma.decrypt_folder(str(folder_to_process))

        # Verify decryption
        for original_relative_path, original_content in original_files_content.items():
            decrypted_path = folder_to_process / original_relative_path
            encrypted_name = f"encrypted_{original_relative_path.name}"
            encrypted_file_path_in_folder = folder_to_process / original_relative_path.parent / encrypted_name

            self.assertTrue(decrypted_path.exists(), f"Decrypted file {decrypted_path} not found.")
            self.assertFalse(encrypted_file_path_in_folder.exists(), f"Encrypted file {encrypted_file_path_in_folder} was not deleted after decryption.")
            with open(decrypted_path, 'r') as f:
                self.assertEqual(f.read(), original_content, f"Content mismatch for {decrypted_path}.")
    
    def test_encrypt_folder_not_found(self):
        """Test encrypt_folder with a non-existent path."""
        with self.assertRaises(FileNotFoundError):
            self.enigma.encrypt_folder(str(self.test_dir_path / "non_existent_folder"))

    def test_decrypt_folder_not_found(self):
        """Test decrypt_folder with a non-existent path."""
        with self.assertRaises(FileNotFoundError):
            self.enigma.decrypt_folder(str(self.test_dir_path / "non_existent_folder"))

    def test_encrypt_folder_is_file(self):
        """Test encrypt_folder with a path that is a file, not a directory."""
        dummy_file = self._create_dummy_file(filename="iam_a_file.txt")
        with self.assertRaises(NotADirectoryError):
            self.enigma.encrypt_folder(str(dummy_file))

    def test_decrypt_folder_is_file(self):
        """Test decrypt_folder with a path that is a file, not a directory."""
        dummy_file = self._create_dummy_file(filename="iam_another_file.txt")
        with self.assertRaises(NotADirectoryError):
            self.enigma.decrypt_folder(str(dummy_file))
    
    @patch('enigma.Enigma.gen_key')
    @patch('builtins.print') # To capture print output from enigma.py for password mismatch
    def test_encrypt_folder_password_mismatch(self, mock_print, mock_gen_key):
        """Test encrypt_folder handling PasswordMismatchError."""
        folder_to_process = self._create_dummy_folder_structure(num_files=1, subdirs=False)
        mock_gen_key.side_effect = PasswordMismatchError("Passwords do not match.")
        
        self.enigma.encrypt_folder(str(folder_to_process))
        # Check that an error message was printed (as per current implementation in enigma.py)
        self.assertTrue(any("Passwords do not match." in call_args[0][0] for call_args in mock_print.call_args_list))
        # Check that original file still exists because encryption should not have proceeded
        original_file = folder_to_process / "file1.txt"
        self.assertTrue(original_file.exists())

    @patch('enigma.Enigma.gen_key')
    @patch('builtins.print')
    def test_decrypt_folder_password_mismatch(self, mock_print, mock_gen_key):
        """Test decrypt_folder handling PasswordMismatchError."""
        # Create a dummy encrypted file first (actual content doesn't matter for this test)
        folder_to_process = self.test_dir_path / "folder_with_encrypted"
        folder_to_process.mkdir()
        self._create_dummy_file(filename=folder_to_process / "encrypted_file1.txt")

        mock_gen_key.side_effect = PasswordMismatchError("Passwords do not match.")
        
        self.enigma.decrypt_folder(str(folder_to_process))
        self.assertTrue(any("Passwords do not match." in call_args[0][0] for call_args in mock_print.call_args_list))
        original_encrypted_file = folder_to_process / "encrypted_file1.txt"
        self.assertTrue(original_encrypted_file.exists()) # File should remain as is

    @patch('enigma.Enigma.gen_key')
    @patch('builtins.print') # To capture print output for "No files found"
    def test_encrypt_empty_folder(self, mock_print, mock_gen_key):
        """Test encrypting an empty folder."""
        empty_folder = self.test_dir_path / "empty_folder"
        empty_folder.mkdir()
        
        test_key = Fernet.generate_key()
        mock_gen_key.return_value = test_key
        
        self.enigma.encrypt_folder(str(empty_folder))
        # Check that "No files found" message was printed
        self.assertTrue(any("No files found" in call_args[0][0] for call_args in mock_print.call_args_list))
        self.assertEqual(len(list(empty_folder.iterdir())), 0, "Empty folder should remain empty.")

    @patch('enigma.Enigma.gen_key')
    @patch('builtins.print')
    def test_decrypt_empty_folder(self, mock_print, mock_gen_key):
        """Test decrypting an empty folder."""
        empty_folder = self.test_dir_path / "empty_folder_for_decrypt"
        empty_folder.mkdir()

        test_key = Fernet.generate_key()
        mock_gen_key.return_value = test_key

        self.enigma.decrypt_folder(str(empty_folder))
        self.assertTrue(any("No files found to decrypt" in call_args[0][0] for call_args in mock_print.call_args_list))
        self.assertEqual(len(list(empty_folder.iterdir())), 0)

    @patch('enigma.Enigma.gen_key')
    def test_encrypt_decrypt_empty_file(self, mock_gen_key):
        """Test encryption and decryption of an empty file."""
        empty_file_path = self._create_dummy_file(filename="empty_file.txt", content="")
        
        test_key = Fernet.generate_key()
        mock_gen_key.return_value = test_key

        # Encrypt
        self.enigma.encrypt(str(empty_file_path))
        encrypted_file_path = self.test_dir_path / f"encrypted_{empty_file_path.name}"
        self.assertTrue(encrypted_file_path.exists())
        with open(encrypted_file_path, 'rb') as f:
            # Encrypted content won't be empty, but it should be valid Fernet token
            self.assertTrue(len(f.read()) > 0) 

        # Decrypt
        self.enigma.decrypt(str(encrypted_file_path))
        decrypted_file_path = self.test_dir_path / empty_file_path.name
        self.assertTrue(decrypted_file_path.exists())
        with open(decrypted_file_path, 'r') as f:
            self.assertEqual(f.read(), "")

    # --- Tests for load_key_from_file ---
    def test_load_key_from_file_success(self):
        """Test successfully loading a valid key from a file."""
        valid_key = Fernet.generate_key()
        key_file_path = self.test_dir_path / "valid.key"
        with open(key_file_path, "wb") as f:
            f.write(valid_key)

        loaded_key = self.enigma.load_key_from_file(str(key_file_path))
        self.assertEqual(loaded_key, valid_key)

    def test_load_key_from_file_not_found(self):
        """Test FileNotFoundError when key file does not exist."""
        with self.assertRaises(FileNotFoundError):
            self.enigma.load_key_from_file(str(self.test_dir_path / "non_existent.key"))

    def test_load_key_from_file_empty(self):
        """Test ValueError when key file is empty."""
        key_file_path = self._create_dummy_file(filename="empty.key", content="")
        with self.assertRaisesRegex(ValueError, "Key file is empty."):
            self.enigma.load_key_from_file(str(key_file_path))
            
    def test_load_key_from_file_invalid_content_not_base64(self):
        """Test ValueError when key file content is not valid base64 for Fernet."""
        key_file_path = self._create_dummy_file(filename="invalid_content.key", content="this is not a key")
        with self.assertRaisesRegex(ValueError, "not a valid Fernet key"):
            self.enigma.load_key_from_file(str(key_file_path))

    def test_load_key_from_file_invalid_content_too_short(self):
        """Test ValueError when key file content is too short for Fernet."""
        # A valid Fernet key (base64 of 32 bytes) is 44 bytes long.
        # os.urandom(16) -> base64 is shorter.
        shorter_key = base64.urlsafe_b64encode(os.urandom(16)) # too short raw key
        key_file_path = self.test_dir_path / "short.key"
        with open(key_file_path, "wb") as f:
            f.write(shorter_key)
        
        with self.assertRaisesRegex(ValueError, "not a valid Fernet key"):
            self.enigma.load_key_from_file(str(key_file_path))

    # --- Tests for gen_key with output_key_filepath ---
    @patch('getpass.getpass')
    def test_gen_key_and_save_to_file_success(self, mock_getpass):
        """Test successful key generation and saving to an output file."""
        mock_getpass.side_effect = [self.password, self.password]
        output_key_file = self.test_dir_path / "generated.key"

        generated_key_memory = self.enigma.gen_key(salt=self.salt, output_key_filepath=str(output_key_file))
        self.assertTrue(output_key_file.exists())
        
        with open(output_key_file, "rb") as f:
            saved_key = f.read()
        self.assertEqual(saved_key, generated_key_memory)
        
        # Verify the key is valid
        self.assertIsNotNone(Fernet(generated_key_memory))

    @patch('getpass.getpass')
    @patch('builtins.print') # To capture the warning print
    def test_gen_key_save_to_file_io_error(self, mock_print, mock_getpass):
        """Test gen_key when saving to file fails due to IOError (e.g. invalid path)."""
        mock_getpass.side_effect = [self.password, self.password]
        # Path is a directory, which will cause IOError on open(..., "wb")
        invalid_output_path = str(self.test_dir_path) 

        generated_key = self.enigma.gen_key(salt=self.salt, output_key_filepath=invalid_output_path)
        self.assertIsNotNone(generated_key) # Key should still be generated and returned
        
        warning_found = False
        for call_args in mock_print.call_args_list:
            if f"Warning: Key generated, but failed to save to {invalid_output_path}" in call_args[0][0]:
                warning_found = True
                break
        self.assertTrue(warning_found, "Warning about failing to save key was not printed.")

    # --- Tests for encrypt/decrypt operations using a loaded key file ---
    def test_encrypt_decrypt_file_with_loaded_key(self):
        """Test file encryption/decryption using a key loaded from a file."""
        # 1. Generate and save a key
        key_file = self.test_dir_path / "my.key"
        with patch('getpass.getpass', side_effect=[self.password, self.password]):
            original_generated_key = self.enigma.gen_key(salt=self.salt, output_key_filepath=str(key_file))
        self.assertTrue(key_file.exists())

        # 2. Load the key
        loaded_key = self.enigma.load_key_from_file(str(key_file))
        self.assertEqual(loaded_key, original_generated_key)

        # 3. Encrypt and Decrypt file using the loaded key
        original_content = "Secret content for file, using loaded key."
        dummy_file_path = self._create_dummy_file(content=original_content)
        
        # Encrypt using loaded_key
        self.enigma.encrypt(str(dummy_file_path), key=loaded_key)
        encrypted_file_path = self.test_dir_path / f"encrypted_{dummy_file_path.name}"
        self.assertTrue(encrypted_file_path.exists())
        self.assertFalse(dummy_file_path.exists())

        # Decrypt using loaded_key
        self.enigma.decrypt(str(encrypted_file_path), key=loaded_key)
        decrypted_file_path = self.test_dir_path / dummy_file_path.name
        self.assertTrue(decrypted_file_path.exists())
        self.assertFalse(encrypted_file_path.exists())

        with open(decrypted_file_path, "r") as f:
            self.assertEqual(f.read(), original_content)

    def test_encrypt_decrypt_folder_with_loaded_key(self):
        """Test folder encryption/decryption using a key loaded from a file."""
        # 1. Generate and save a key
        key_file = self.test_dir_path / "folder_op.key"
        with patch('getpass.getpass', side_effect=[self.password, self.password]):
            original_generated_key = self.enigma.gen_key(salt=self.salt, output_key_filepath=str(key_file))
        self.assertTrue(key_file.exists())

        # 2. Load the key
        loaded_key = self.enigma.load_key_from_file(str(key_file))
        self.assertEqual(loaded_key, original_generated_key)
        
        # 3. Encrypt and Decrypt folder using the loaded key
        folder_to_process = self._create_dummy_folder_structure(num_files=2, subdirs=True)
        original_files_content = {}
        original_paths = []
        for item in folder_to_process.rglob("*"):
            if item.is_file():
                relative_path = item.relative_to(folder_to_process)
                original_paths.append(relative_path)
                with open(item, 'r') as f:
                    original_files_content[relative_path] = f.read()
        
        # Encrypt folder
        self.enigma.encrypt_folder(str(folder_to_process), key=loaded_key)
        for rel_path in original_paths:
            self.assertTrue((folder_to_process / rel_path.parent / f"encrypted_{rel_path.name}").exists())
            self.assertFalse((folder_to_process / rel_path).exists())

        # Decrypt folder
        self.enigma.decrypt_folder(str(folder_to_process), key=loaded_key)
        for rel_path, content in original_files_content.items():
            decrypted_file = folder_to_process / rel_path
            self.assertTrue(decrypted_file.exists())
            self.assertFalse((folder_to_process / rel_path.parent / f"encrypted_{rel_path.name}").exists())
            with open(decrypted_file, 'r') as f:
                self.assertEqual(f.read(), content)

    # --- Tests for CLI interactions ---
    @patch('sys.argv')
    @patch('getpass.getpass')
    @patch('builtins.print')
    def test_cli_genkey_success(self, mock_print, mock_getpass, mock_argv):
        """Test CLI 'genkey --outfile <path>' successful execution."""
        mock_getpass.side_effect = [self.password, self.password]
        key_output_path = self.test_dir_path / "cli_gen.key"
        mock_argv[:] = ['enigma.py', 'genkey', '--outfile', str(key_output_path)]

        enigma_main()

        self.assertTrue(key_output_path.exists())
        # Check if success message was printed by gen_key itself or main
        success_msg_found = False
        for call_arg in mock_print.call_args_list:
            if f"Key successfully saved to {key_output_path}" in call_arg[0][0]:
                success_msg_found = True
                break
        self.assertTrue(success_msg_found, "Success message for key saving not found.")
        
        # Optional: verify the key content
        with open(key_output_path, "rb") as f:
            key_content = f.read()
        self.assertIsNotNone(Fernet(key_content)) # Should be a valid Fernet key


    @patch('sys.argv')
    @patch('getpass.getpass') # For gen_key if --password is chosen
    @patch('builtins.print')
    def test_cli_encrypt_file_with_keyfile(self, mock_print, mock_getpass, mock_argv):
        """Test CLI 'encrypt f <path> --keyfile <key_path>'."""
        # 1. Create a key file
        key_content = Fernet.generate_key()
        key_file = self.test_dir_path / "mycli.key"
        with open(key_file, "wb") as f:
            f.write(key_content)

        # 2. Create a dummy file to encrypt
        original_data = "CLI encryption test with keyfile."
        file_to_encrypt = self._create_dummy_file(filename="cli_plain.txt", content=original_data)
        
        mock_argv[:] = ['enigma.py', 'encrypt', 'f', str(file_to_encrypt), '--keyfile', str(key_file)]
        
        enigma_main()

        encrypted_file_path = self.test_dir_path / f"encrypted_{file_to_encrypt.name}"
        self.assertTrue(encrypted_file_path.exists())
        self.assertFalse(file_to_encrypt.exists()) # Original should be gone

        # Verify print output for success (optional, but good)
        success_msg_found = False
        for call_arg in mock_print.call_args_list:
            if f"File {file_to_encrypt} encrypted successfully." in call_arg[0][0]:
                success_msg_found = True
                break
        self.assertTrue(success_msg_found, "CLI encrypt success message not found.")

        # For completeness, decrypt it (not strictly CLI test here, but ensures key worked)
        f = Fernet(key_content)
        with open(encrypted_file_path, "rb") as ef:
            decrypted_data = f.decrypt(ef.read())
        self.assertEqual(decrypted_data.decode(), original_data)


    @patch('sys.argv')
    @patch('getpass.getpass')
    @patch('builtins.print')
    def test_cli_decrypt_file_with_keyfile(self, mock_print, mock_getpass, mock_argv):
        """Test CLI 'decrypt f <path> --keyfile <key_path>'."""
        # 1. Create a key and an encrypted file
        key_content = Fernet.generate_key()
        key_file = self.test_dir_path / "myclidecrypt.key"
        with open(key_file, "wb") as f:
            f.write(key_content)

        original_data = "CLI decryption test with keyfile."
        f_encrypt = Fernet(key_content)
        encrypted_data = f_encrypt.encrypt(original_data.encode())
        
        encrypted_file_to_decrypt = self.test_dir_path / "cli_encrypted.txt"
        with open(encrypted_file_to_decrypt, "wb") as ef:
            ef.write(encrypted_data)

        # 2. Run decrypt via CLI
        mock_argv[:] = ['enigma.py', 'decrypt', 'f', str(encrypted_file_to_decrypt), '--keyfile', str(key_file)]
        enigma_main()

        decrypted_file_path = self.test_dir_path / encrypted_file_to_decrypt.name.replace("cli_encrypted", "decrypted_cli_encrypted") 
        # Based on current naming logic in enigma.py for no "encrypted_" prefix
        # If the encrypted file was named "encrypted_cli_data.txt", then the output would be "cli_data.txt"
        # Since "cli_encrypted.txt" does not start with "encrypted_", it will become "decrypted_cli_encrypted.txt"
        
        # Let's adjust the source file name to test standard decryption naming
        Path.unlink(encrypted_file_to_decrypt) # remove previous one
        encrypted_file_to_decrypt = self.test_dir_path / "encrypted_cli_for_decryption.txt"
        with open(encrypted_file_to_decrypt, "wb") as ef:
            ef.write(encrypted_data)
        
        mock_argv[:] = ['enigma.py', 'decrypt', 'f', str(encrypted_file_to_decrypt), '--keyfile', str(key_file)]
        enigma_main()
        
        # Expected name after standard decryption
        expected_decrypted_name = "cli_for_decryption.txt"
        decrypted_file_path_final = self.test_dir_path / expected_decrypted_name

        self.assertTrue(decrypted_file_path_final.exists(), f"Decrypted file {decrypted_file_path_final} not found.")
        self.assertFalse(encrypted_file_to_decrypt.exists()) # Original encrypted should be gone

        with open(decrypted_file_path_final, "r") as df:
            content = df.read()
        self.assertEqual(content, original_data)
        
        success_msg_found = False
        for call_arg in mock_print.call_args_list:
            if f"File {encrypted_file_to_decrypt} decrypted successfully." in call_arg[0][0]:
                success_msg_found = True
                break
        self.assertTrue(success_msg_found, "CLI decrypt success message not found.")


    @patch('sys.argv')
    @patch('getpass.getpass')
    @patch('builtins.print')
    def test_cli_encrypt_file_with_password(self, mock_print, mock_getpass, mock_argv):
        """Test CLI 'encrypt f <path> --password'."""
        mock_getpass.side_effect = [self.password, self.password, self.password, self.password] # For encrypt and later decrypt
        
        original_data = "CLI encryption test with password."
        file_to_encrypt = self._create_dummy_file(filename="cli_plain_pw.txt", content=original_data)
        
        mock_argv[:] = ['enigma.py', 'encrypt', 'f', str(file_to_encrypt), '--password']
        enigma_main()

        encrypted_file_path = self.test_dir_path / f"encrypted_{file_to_encrypt.name}"
        self.assertTrue(encrypted_file_path.exists())
        
        # Now try to decrypt it using the same password to verify
        mock_argv[:] = ['enigma.py', 'decrypt', 'f', str(encrypted_file_path), '--password']
        enigma_main()
        
        decrypted_file_path = self.test_dir_path / file_to_encrypt.name
        self.assertTrue(decrypted_file_path.exists())
        with open(decrypted_file_path, "r") as f:
            content = f.read()
        self.assertEqual(content, original_data)
        
        encrypt_success = any(f"File {file_to_encrypt} encrypted successfully." in call[0][0] for call in mock_print.call_args_list)
        decrypt_success = any(f"File {encrypted_file_path} decrypted successfully." in call[0][0] for call in mock_print.call_args_list)
        self.assertTrue(encrypt_success, "CLI encrypt with password success message not found.")
        self.assertTrue(decrypt_success, "CLI decrypt with password success message not found.")

    @patch('sys.argv')
    @patch('builtins.print')
    def test_cli_keyfile_and_password_mutually_exclusive(self, mock_print, mock_argv):
        """Test that providing both --keyfile and --password for encrypt/decrypt is an error."""
        key_file = self.test_dir_path / "dummy.key"
        self._create_dummy_file(path=key_file, content=Fernet.generate_key().decode()) # content as str for dummy file helper
        
        file_to_process = self._create_dummy_file(filename="somefile.txt")

        mock_argv[:] = ['enigma.py', 'encrypt', 'f', str(file_to_process), '--keyfile', str(key_file), '--password']
        
        with self.assertRaises(SystemExit): # Argparse should exit
            enigma_main()
        
        # Check stderr for the specific argparse error message
        # This is a bit tricky as SystemExit doesn't always put it on print's call_args.
        # Instead, we can rely on argparse behavior. If the test reaches here after SystemExit, it's good.
        # For more robust check, one might redirect stderr. For now, SystemExit is the key.
        
        # We can also check that no encryption happened
        self.assertFalse((self.test_dir_path / f"encrypted_{file_to_process.name}").exists())


if __name__ == '__main__':
    unittest.main()
