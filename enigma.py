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


class Enigma:
    def __init__(self):
        pass

    def gen_key(self):
        password = getpass.getpass(prompt="Please encryption password.")
        repassword = getpass.getpass(prompt="Confirm password.")
        if password == repassword:
            password = password.encode()
            salt = b"\xa1\x1c\xbd\x13s\x90G\xe5\x17,#\x95\xd3\x86&\xe3"
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend(),
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))
        else:
            print("Password mismatch!")
            quit()
        return key

    def encrypt(self, input_file, **kwargs):
        k = kwargs.get("key", None)
        if k:
            key = k
        else:
            key = self.gen_key()
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

    def decrypt(self, input_file, **kwargs):
        k = kwargs.get("key", None)
        if k:
            key = k
        else:
            key = self.gen_key()
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
        key = self.gen_key()
        for file_name in tqdm(files, desc="Encrypting"):
            self.encrypt(file_name, key=key)

    def decrypt_folder(self, path_to_folder):
        p = Path(path_to_folder).glob("**/*")
        os.chdir(path_to_folder)
        files = [x for x in p if x.is_file()]
        key = self.gen_key()
        for file_name in tqdm(files, desc="Decrypting"):
            self.decrypt(file_name, key=key)


parser = argparse.ArgumentParser(description="Encrypt and decrypt files or folders")
parser.add_argument("function", type=str, help="Type e to encrypt and d to decrypt")
parser.add_argument(
    "type", type=str, help="Type f in case of a file and r in case of folder"
)
parser.add_argument("path", type=str, help="Full path of file or folder")

args = parser.parse_args()
intfunction = args.function
dest = args.type
path = args.path

if intfunction == "e" and dest == "f":
    Enigma().encrypt(path)
elif intfunction == "e" and dest == "r":
    Enigma().encrypt_folder(path)
elif intfunction == "d" and dest == "f":
    Enigma().decrypt(path)
elif intfunction == "d" and dest == "r":
    Enigma().decrypt_folder(path)
else:
    print("Please check you inputs.")

