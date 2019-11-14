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


class Enigma:
    def __init__(self):
        pass

    def gen_key(self, password):
        password_provided = password  
        password = password_provided.encode()  
        salt = b"\xa1\x1c\xbd\x13s\x90G\xe5\x17,#\x95\xd3\x86&\xe3"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key

    def encrypt(self, input_file):
        password = getpass.getpass(
            prompt="Please provide a strong password for encryption."
        )
        repassword = getpass.getpass(prompt="Please type in password again to confirm.")
        if password == repassword:
            key = self.gen_key(password)
        else:
            print("Password mismatch!")
            quit()
        file = Path(input_file)
        name = PurePosixPath(file).stem
        suffix = PurePosixPath(file).suffix
        with open(input_file, "rb") as f:
            data = f.read()
        fernet = Fernet(key)
        encrypted = fernet.encrypt(data)
        output_file = "encrypted" + name + suffix
        with open(output_file, "wb") as f:
            f.write(encrypted)
        Path.unlink(file)

    def decrypt(self, input_file):
        password = getpass.getpass(prompt="Please provide a decryption password.")
        key = self.gen_key(password)
        with open(input_file, "rb") as f:
            data = f.read()
        file = Path(input_file)
        name = PurePosixPath(file).stem
        suffix = PurePosixPath(file).suffix
        fernet = Fernet(key)
        decrypted = fernet.decrypt(data)
        newname = re.sub("encrypted", "", name)
        output_file = newname + suffix
        with open(output_file, "wb") as f:
            f.write(decrypted)
        Path.unlink(file)

    def encrypt_folder(self, path_to_folder):
        p = Path(path_to_folder).glob("**/*")
        os.chdir(path_to_folder)
        files = [x for x in p if x.is_file()]
        password = getpass.getpass(
            prompt="Please provide a strong password for encryption."
        )
        repassword = getpass.getpass(prompt="Please type in password again to confirm.")
        if password == repassword:
            key = self.gen_key(password)
        else:
            print("Password mismatch!")
            quit()
        for file_name in files:
            file = Path(file_name)
            name = PurePosixPath(file).stem
            suffix = PurePosixPath(file).suffix
            with open(file_name, "rb") as f:
                data = f.read()
            fernet = Fernet(key)
            encrypted = fernet.encrypt(data)
            output_file = "encrypted" + name + suffix
            with open(output_file, "wb") as f:
                f.write(encrypted)
            Path.unlink(file)

    def decrypt_folder(self, path_to_folder):
        p = Path(path_to_folder).glob("**/*")
        os.chdir(path_to_folder)
        files = [x for x in p if x.is_file()]
        password = getpass.getpass(prompt="Please provide a decryption password.")
        key = self.gen_key(password)
        for file_name in files:
            file = Path(file_name)
            name = PurePosixPath(file).stem
            suffix = PurePosixPath(file).suffix
            with open(file_name, "rb") as f:
                data = f.read()
            fernet = Fernet(key)
            decrypted = fernet.decrypt(data)
            newname = re.sub("encrypted", "", name)
            output_file = newname + suffix
            with open(output_file, "wb") as f:
                f.write(decrypted)
            Path.unlink(file)

    def run(self):
        intfunction = input("Please choose whether you want to Encrypt (e) or Decrypt (d).\n")
        if intfunction == "e":
            dest = input("Please choose whether you want to encrypt a file (f) or folder (r).\n")
        elif intfunction == "d":
            dest = input("Please choose whether you want to decrypt a file (f) or folder (r).\n")
        else: 
            print("Please check your inputs.")
        if dest == "f":
            path = input("Please enter the full path to your file.\n")
        elif dest == "r":
            path = input("Please enter the full path to your folder.\n")

        if intfunction == "e" and dest == "f":
            self.encrypt(path)
        elif intfunction == "e" and dest == "r":
            self.encrypt_folder(path)
        elif intfunction == "d" and dest == "f":
            self.decrypt(path)
        elif intfunction == "d" and dest == "r":
            self.decrypt_folder(path)
        else:
            print("Please check you inputs.")


if __name__ == "__main__":
    Enigma().run()


        



