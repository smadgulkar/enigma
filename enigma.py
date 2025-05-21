import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from pathlib import PurePosixPath, Path
import re
import getpass
import os
from tqdm import tqdm
import argparse


class PasswordMismatchError(Exception):
    pass


class Enigma:
    def __init__(self):
        self.default_salt = b"\xa1\x1c\xbd\x13s\x90G\xe5\x17,#\x95\xd3\x86&\xe3"

    def gen_key(self, salt=None, output_key_filepath=None):
        password = getpass.getpass(prompt="Please encryption password.")
        repassword = getpass.getpass(prompt="Confirm password.")
        if password == repassword:
            password = password.encode()
            current_salt = salt if salt else self.default_salt
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=current_salt,
                iterations=100000,
                backend=default_backend(),
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))
            
            if output_key_filepath:
                try:
                    with open(output_key_filepath, "wb") as key_file:
                        key_file.write(key)
                    print(f"Key successfully saved to {output_key_filepath}")
                except IOError as e:
                    # We'll print an error but not raise, as key generation itself succeeded.
                    print(f"Warning: Key generated, but failed to save to {output_key_filepath}: {e}")
        else:
            raise PasswordMismatchError("Passwords do not match.")
        return key

    def load_key_from_file(self, key_filepath):
        try:
            with open(key_filepath, "rb") as key_file:
                key = key_file.read()
            # Validate key (must be base64 decodable and 32 bytes long after decoding)
            # Fernet keys are URL-safe base64 encoded.
            # The raw derived key is 32 bytes. urlsafe_b64encode makes it slightly longer.
            # Fernet expects the base64 encoded version.
            if not key:
                raise ValueError("Key file is empty.")
            # Attempt to decode to ensure it's valid base64 and check length if it were a raw key
            # For Fernet, the key *is* the base64 encoded string.
            # A common length for a Fernet key (base64 of 32 bytes) is 44 bytes.
            # Example: base64.urlsafe_b64encode(os.urandom(32))
            # We should ensure it can be used by Fernet. A simple way is to try to init Fernet.
            try:
                Fernet(key)
            except Exception as e: # Catches if key is invalid for Fernet
                raise ValueError(f"Key in {key_filepath} is not a valid Fernet key: {e}")
            return key
        except FileNotFoundError:
            raise FileNotFoundError(f"Key file {key_filepath} not found.")
        except IOError as e:
            raise IOError(f"Error reading key file {key_filepath}: {e}")
        except ValueError as e: # Catch our own ValueError or from base64 issues
            raise ValueError(f"Invalid key data in {key_filepath}: {e}")

    def derive_key_from_password(self, password_str, salt=None):
        if salt is None:
            salt = self.default_salt # Use the instance's default salt
        password_bytes = password_str.encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000, # Ensure this matches CLI version (it does)
            backend=default_backend(),
        )
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        return key

    def encrypt(self, input_file, key):
        if not key:
            raise ValueError("A valid key must be provided for encryption.")

        file = Path(input_file)
        if not file.exists():
            raise FileNotFoundError(f"Input file {input_file} not found.")

        name = PurePosixPath(file).stem
        suffix = PurePosixPath(file).suffix
        try:
            with open(input_file, "rb") as f:
                data = f.read()
        except IOError as e:
            raise IOError(f"Error reading input file {input_file}: {e}")

        fernet = Fernet(key)
        encrypted = fernet.encrypt(data)

        # Output file naming: prepend "encrypted_" to the original filename in the same directory
        output_file_path = file.with_name(f"encrypted_{file.name}")

        try:
            with open(output_file_path, "wb") as f:
                f.write(encrypted)
        except IOError as e:
            raise IOError(f"Error writing output file {output_file_path}: {e}")
        
        # Delete original file only after successful encryption and writing
        try:
            Path.unlink(file)
        except OSError as e:
            # Log this error or handle it more gracefully if needed
            print(f"Warning: Could not delete original file {file}: {e}")
        return output_file_path # Return the name/path of the created file


    def decrypt(self, input_file, key):
        if not key:
            raise ValueError("A valid key must be provided for decryption.")

        file = Path(input_file)
        if not file.exists():
            raise FileNotFoundError(f"Input file {input_file} not found.")

        try:
            with open(input_file, "rb") as f:
                data = f.read()
        except IOError as e:
            raise IOError(f"Error reading input file {input_file}: {e}")

        name = PurePosixPath(file).stem
        suffix = PurePosixPath(file).suffix
        fernet = Fernet(key)
        try:
            decrypted = fernet.decrypt(data)
        except InvalidToken:
            raise InvalidToken("Decryption failed. Incorrect password or corrupted file.")

        # Output file naming: remove "encrypted_" prefix if it exists.
        if name.startswith("encrypted_"):
            decrypted_name = name[len("encrypted_"):]
        else:
            # If the "encrypted_" prefix is not found, perhaps provide a default or raise an error
            # For now, let's assume it might be a file that wasn't encrypted by this script's convention
            # Or it's a file that was already decrypted.
            # To avoid data loss, let's prepend "decrypted_"
            print(f"Warning: File {input_file} does not have 'encrypted_' prefix. Outputting as 'decrypted_{file.name}'")
            decrypted_name = f"decrypted_{file.name}"

        # Ensure suffix is correctly appended if not already part of decrypted_name from slicing
        # However, file.with_name should handle this correctly.
        # Let's ensure decrypted_name does not include suffix yet if we build it manually.
        # PurePosixPath(file).stem already gives name without suffix.
        # If name was `encrypted_myfile.txt`, stem is `encrypted_myfile`, suffix is `.txt`
        # `decrypted_name` would be `myfile`.
        
        # Correctly reconstruct the output file name with its original suffix, in the same directory
        output_file_path = file.with_name(decrypted_name + suffix)


        try:
            with open(output_file_path, "wb") as f:
                f.write(decrypted)
        except IOError as e:
            raise IOError(f"Error writing output file {output_file_path}: {e}")
        
        # Delete original (encrypted) file only after successful decryption and writing
        try:
            Path.unlink(file)
        except OSError as e:
             # Log this error or handle it more gracefully if needed
            print(f"Warning: Could not delete original file {file}: {e}")
        return output_file_path # Return the name/path of the created file

    def encrypt_folder(self, path_to_folder, key):
        if not key:
            raise ValueError("A valid key must be provided for folder encryption.")
        folder = Path(path_to_folder)
        if not folder.exists():
            raise FileNotFoundError(f"Folder {path_to_folder} not found.")
        if not folder.is_dir():
            raise NotADirectoryError(f"{path_to_folder} is not a directory.")

        files_to_process = [x for x in folder.glob("**/*") if x.is_file()]
        if not files_to_process:
            print(f"No files found in {path_to_folder}.")
            return

        for file_path_obj in tqdm(files_to_process, desc="Encrypting"):
            try:
                self.encrypt(str(file_path_obj), key) # Pass the key directly
            except Exception as e:
                print(f"Failed to encrypt {file_path_obj}: {e}")


    def decrypt_folder(self, path_to_folder, key):
        if not key:
            raise ValueError("A valid key must be provided for folder decryption.")
        folder = Path(path_to_folder)
        if not folder.exists():
            raise FileNotFoundError(f"Folder {path_to_folder} not found.")
        if not folder.is_dir():
            raise NotADirectoryError(f"{path_to_folder} is not a directory.")

        files_to_process = [x for x in folder.glob("**/*") if x.is_file()]
        if not files_to_process:
            print(f"No files found to decrypt in {path_to_folder}.")
            return

        for file_path_obj in tqdm(files_to_process, desc="Decrypting"):
            try:
                self.decrypt(str(file_path_obj), key) # Pass the key directly
            except Exception as e:
                print(f"Failed to decrypt {file_path_obj}: {e}")


def main():
    parser = argparse.ArgumentParser(description="Encrypt, decrypt files/folders, or generate a key.")
    
    # Subparsers for different actions: encrypt, decrypt, genkey
    subparsers = parser.add_subparsers(dest="action", required=True, help="Action to perform")

    # --- Encrypt action ---
    parser_encrypt = subparsers.add_parser("encrypt", help="Encrypt a file or folder")
    parser_encrypt.add_argument("type", choices=['f', 'r'], help="Type: 'f' for file, 'r' for folder")
    parser_encrypt.add_argument("path", type=str, help="Full path of the file or folder to encrypt")
    group_encrypt = parser_encrypt.add_mutually_exclusive_group(required=True)
    group_encrypt.add_argument("--keyfile", type=str, help="Path to the key file")
    group_encrypt.add_argument("--password", action="store_true", help="Use password input to derive key (will prompt)")

    # --- Decrypt action ---
    parser_decrypt = subparsers.add_parser("decrypt", help="Decrypt a file or folder")
    parser_decrypt.add_argument("type", choices=['f', 'r'], help="Type: 'f' for file, 'r' for folder")
    parser_decrypt.add_argument("path", type=str, help="Full path of the file or folder to decrypt")
    group_decrypt = parser_decrypt.add_mutually_exclusive_group(required=True)
    group_decrypt.add_argument("--keyfile", type=str, help="Path to the key file")
    group_decrypt.add_argument("--password", action="store_true", help="Use password input to derive key (will prompt)")

    # --- Generate Key action ---
    parser_genkey = subparsers.add_parser("genkey", help="Generate a new encryption key")
    parser_genkey.add_argument("--outfile", type=str, required=True, help="Path to save the generated key file")

    args = parser.parse_args()
    enigma_instance = Enigma()
    key_to_use = None

    try:
        if args.action == "genkey":
            # Key generation will prompt for password internally
            enigma_instance.gen_key(output_key_filepath=args.outfile)
            # gen_key prints its own success/failure for saving, so we might not need another print here.
            # print(f"Key generated and saved to {args.outfile}") # Or let gen_key handle it

        elif args.action in ["encrypt", "decrypt"]:
            if args.keyfile:
                key_to_use = enigma_instance.load_key_from_file(args.keyfile)
            elif args.password: # This implies --password was used
                # gen_key prompts for password and returns the key
                # For encrypt/decrypt, we don't save the key unless user also uses genkey separately
                key_to_use = enigma_instance.gen_key() 
            
            if not key_to_use:
                # This case should ideally be prevented by the mutually exclusive group in argparser
                print("Error: Key not available. Provide --keyfile or use password input.")
                return

            if args.action == "encrypt":
                if args.type == "f":
                    enigma_instance.encrypt(args.path, key_to_use)
                    print(f"File {args.path} encrypted successfully.")
                elif args.type == "r":
                    enigma_instance.encrypt_folder(args.path, key_to_use)
                    print(f"Folder {args.path} encrypted successfully.")
            
            elif args.action == "decrypt":
                if args.type == "f":
                    enigma_instance.decrypt(args.path, key_to_use)
                    print(f"File {args.path} decrypted successfully.")
                elif args.type == "r":
                    enigma_instance.decrypt_folder(args.path, key_to_use)
                    print(f"Folder {args.path} decrypted successfully.")
        
    except FileNotFoundError as e:
        print(f"Error: {e}")
    except NotADirectoryError as e:
        print(f"Error: {e}")
    except NotADirectoryError as e:
        print(f"Error: {e}")
    except InvalidToken as e: # Fernet token issue (wrong key, corrupted data)
        print(f"Decryption Error: {e}")
    except PasswordMismatchError as e: # During gen_key if --password is used
        print(f"Key Generation Error: {e}")
    except ValueError as e: # Can be from load_key_from_file for invalid key data, or Enigma methods if key is None
        print(f"Error: {e}")
    except IOError as e: # File operation errors
        print(f"IOError: {e}")
    except Exception as e: # Catch-all for other unexpected errors
        print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()

