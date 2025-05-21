# Enigma
A simple python script to encrypt/decrypt files and folders using python's Fernet implementation.

## Command-Line Interface (CLI)

The original Enigma script can be used via the command line.

### Features
- Encrypt or decrypt individual files.
- Encrypt or decrypt entire folders recursively.
- Password-based key derivation.
- Option to use a pre-generated key file.
- Option to save a generated key to a file.

### Setup (CLI)
1.  Ensure you have Python 3 installed.
2.  Install cryptography: `pip install cryptography tqdm` (tqdm is used for progress bars in folder operations).

### Basic Usage (CLI)

The script uses `argparse` for command-line arguments.

**Actions:**
*   `encrypt`: To encrypt a file or folder.
*   `decrypt`: To decrypt a file or folder.
*   `genkey`: To generate a new key and save it to a file.

**Common Arguments:**
*   `type`: Specify 'f' for a single file or 'r' for a folder (recursive).
*   `path`: The full path to the file or folder.
*   `--keyfile <path>`: Path to a file containing the encryption/decryption key.
*   `--password`: Use a password prompt to derive the key (this is the default if no keyfile is provided for encrypt/decrypt).

**Examples (CLI):**

1.  **Generate a key and save it:**
    ```bash
    python enigma.py genkey --outfile mykey.key
    ```
    (You will be prompted to enter and confirm a password.)

2.  **Encrypt a file using a password:**
    ```bash
    python enigma.py encrypt f /path/to/your/document.txt --password
    ```
    (You will be prompted to enter and confirm a password.)

3.  **Decrypt a file using a password:**
    ```bash
    python enigma.py decrypt f /path/to/your/encrypted_document.txt --password
    ```

4.  **Encrypt a file using a key file:**
    ```bash
    python enigma.py encrypt f /path/to/your/document.txt --keyfile mykey.key
    ```

5.  **Decrypt a file using a key file:**
    ```bash
    python enigma.py decrypt f /path/to/your/encrypted_document.txt --keyfile mykey.key
    ```

6.  **Encrypt an entire folder using a password:**
    ```bash
    python enigma.py encrypt r /path/to/your/folder --password
    ```

7.  **Decrypt an entire folder using a key file:**
    ```bash
    python enigma.py decrypt r /path/to/your/encrypted_folder --keyfile mykey.key
    ```

## Web Interface

A simple Flask web application provides a graphical interface for Enigma's encryption and decryption functionalities.

### Setup (Web Interface)

1.  **Python 3:** Ensure you have Python 3 installed on your system.
2.  **Install Dependencies:** Navigate to the project root directory (where `requirements.txt` is located) and run the following command to install the necessary Python packages:
    ```bash
    pip install -r requirements.txt
    ```
    This will install Flask and other dependencies (like cryptography, which is also used by Enigma CLI).

### Running the Web Application

1.  **Start the Server:** Open your terminal, navigate to the project root directory, and run:
    ```bash
    python app.py
    ```
2.  **Access the Application:** Open your web browser and go to the following URL:
    ```
    http://127.0.0.1:5000/
    ```
    (This is the default address for the Flask development server).

### Basic Usage (Web Interface)

The web interface allows for a simple workflow to process your files:

1.  **Navigate to the Main Page:** The home page will welcome you.
2.  **Upload File:** Click on the "Upload a file for Encryption/Decryption" link.
3.  **Select and Upload:** On the upload page, choose a file from your computer and click "Upload".
4.  **Choose Action:** After a successful upload, you will be presented with options to either "Encrypt this file" or "Decrypt this file". Click on your desired action.
5.  **Enter Password:** You will be prompted to enter a password. This password will be used to derive the key for the encryption or decryption operation.
6.  **Process and Download:** After submitting the password, the file will be processed. You will then be taken to a results page where you can:
    *   See the name of the original file.
    *   See the action performed.
    *   See the name of the output file (e.g., `encrypted_yourfile.txt` or `decrypted_yourfile.txt`).
    *   Click a link to download the processed file.

### Important Notes (Web Interface)

*   **Development Server:** The command `python app.py` runs Flask's built-in development server. This server is convenient for local development and testing but is **not suitable for production environments**. For deployment, you should use a production-grade WSGI server (e.g., Gunicorn, uWSGI).
*   **File Storage:** Uploaded files are temporarily stored in the `uploads/` directory within the project structure. Processed files also reside in this directory before download. The `uploads/` directory includes a `.gitignore` file to prevent accidental versioning of these temporary files.
*   **Security:** The application uses password-based key derivation for each operation. Ensure you use strong, unique passwords for sensitive files.

---

For details on the underlying encryption mechanisms, refer to the Fernet (cryptography) documentation.I have updated the `README.md` file. I added a basic "Command-Line Interface (CLI)" section using some of the information from the CLI part of `enigma.py` to provide context before introducing the "Web Interface" section.

The new "Web Interface" section includes:
*   Setup instructions (Python 3, `pip install -r requirements.txt`).
*   How to run the application (`python app.py` and the default URL).
*   A step-by-step basic usage guide for the web workflow.
*   Important notes about the development server and file storage.

The formatting should be consistent with Markdown.

**Deliverables Check:**
*   Modified `README.md` file with the new section detailing how to set up and run the web interface. (Done)

I believe this fulfills the requirements of the subtask.
