import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory # Added send_from_directory
from werkzeug.utils import secure_filename
from enigma import Enigma, PasswordMismatchError, InvalidToken # Ensure all are imported
from pathlib import Path # Added Path

app = Flask(__name__)
# It's good practice to use a strong, randomly generated secret key.
# For development, this is fine. For production, consider environment variables.
app.secret_key = os.urandom(24)
app.config['UPLOAD_FOLDER'] = 'uploads/'
# Ensure the upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

enigma_instance = Enigma() # Instantiate Enigma

@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')

# Allowed extensions (optional, can be expanded)
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'docx', 'xlsx', 'pptx', 'enc'} # Added 'enc' for encrypted files

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['GET', 'POST'])
def upload_file_route(): # Renamed function for clarity
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename): # Using allowed_file check
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            try:
                file.save(filepath)
                flash(f"File '{filename}' uploaded successfully. Ready for processing.")
                session['uploaded_filename'] = filename # Store filename in session
                # session['original_filepath'] = filepath # Store full path for processing - not strictly needed if we reconstruct
                flash(f"File '{filename}' uploaded. Choose an action.")
                return redirect(url_for('show_actions', filename=filename))
            except Exception as e:
                flash(f"Error saving file: {e}")
                return redirect(request.url)
        else:
            flash('File type not allowed or no file selected.')
            return redirect(request.url)
    # For GET request
    return render_template('upload.html')

@app.route('/actions/<filename>')
def show_actions(filename):
    # Check if file exists in upload folder to prevent arbitrary path exploits, though filename is from session/secure_filename
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(filename)) # Re-secure just in case
    if not os.path.exists(filepath):
        flash(f"File {filename} not found for actions. Please upload again.")
        return redirect(url_for('upload_file_route'))
    return render_template('actions.html', filename=filename)

@app.route('/process/<action>/<filename>', methods=['GET', 'POST'])
def process_file(action, filename):
    # Validate action
    if action not in ['encrypt', 'decrypt']:
        flash("Invalid action.")
        return redirect(url_for('index'))

    # Secure filename and construct path to the original uploaded file
    s_filename = secure_filename(filename)
    input_filepath = os.path.join(app.config['UPLOAD_FOLDER'], s_filename)

    if not os.path.exists(input_filepath):
        flash(f"File {s_filename} not found. Please upload again.")
        return redirect(url_for('upload_file_route'))

    if request.method == 'POST':
        password = request.form.get('password')
        if not password:
            flash("Password is required.")
            return render_template('process_form.html', action=action, filename=s_filename)

        try:
            # Use the new derive_key_from_password method
            key = enigma_instance.derive_key_from_password(password)
            
            processed_filepath = None
            if action == 'encrypt':
                processed_filepath = enigma_instance.encrypt(input_filepath, key=key)
                flash(f"File '{s_filename}' encrypted successfully!")
            elif action == 'decrypt':
                processed_filepath = enigma_instance.decrypt(input_filepath, key=key)
                flash(f"File '{s_filename}' decrypted successfully!")
            
            if processed_filepath:
                # Store the name of the processed file for download link
                session['processed_filename'] = Path(processed_filepath).name
                # The original file is deleted by encrypt/decrypt.
                session['processed_filename'] = Path(processed_filepath).name # Keep this for potential direct download link on index if user navigates away
                
                # Pass necessary info to the result page
                return render_template('result.html', 
                                       original_filename=s_filename, 
                                       action_performed=action, 
                                       processed_filename=Path(processed_filepath).name)
            else:
                flash("Error processing file: Output path not determined.")
                # If s_filename (original) still exists, go to its actions, else to upload
                if os.path.exists(input_filepath):
                    return redirect(url_for('show_actions', filename=s_filename))
                else:
                    return redirect(url_for('upload_file_route'))

        except InvalidToken:
            flash("Decryption failed: Incorrect password or corrupted file.")
        except PasswordMismatchError: # Should not happen with derive_key_from_password
            flash("Key generation failed: Password mismatch (this should not occur here).")
        except FileNotFoundError: # If the input file was somehow deleted between checks
            flash(f"Error: File {s_filename} vanished during processing.")
            return redirect(url_for('upload_file_route'))
        except Exception as e:
            flash(f"An unexpected error occurred: {str(e)}")
        
        # If any error occurred, redirect back to the process form or actions page
        return redirect(url_for('process_file', action=action, filename=s_filename))

    # For GET request to /process/...
    return render_template('process_form.html', action=action, filename=s_filename)

@app.route('/download/<filename>')
def download_file(filename):
    # Secure the filename again just to be safe, though it should be secure from session
    s_filename = secure_filename(filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], s_filename)
    
    if not os.path.exists(filepath):
        flash(f"Error: File {s_filename} not found for download.")
        return redirect(url_for('index'))
        # Alternatively, return abort(404)
        
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], s_filename, as_attachment=True)
    except Exception as e:
        flash(f"Error sending file: {e}")
        app.logger.error(f"Error sending file {s_filename}: {e}") # Log the error
        return redirect(url_for('index'))


if __name__ == '__main__':
    # from pathlib import Path # Moved to top-level imports
    app.run(debug=True)
