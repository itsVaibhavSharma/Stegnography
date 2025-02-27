import os
import secrets
import uuid
from flask import Flask, request, render_template_string, send_file, redirect, url_for, flash, session
from PIL import Image
import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from io import BytesIO
import base64

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['UPLOAD_FOLDER'] = 'temp_uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload size

# Create upload folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# -------------------- Steganography Functions --------------------

def encrypt_text(text, key):
    """Encrypt text using AES encryption"""
    # Convert to bytes
    text_bytes = text.encode('utf-8')
    key_bytes = key.encode('utf-8')
    
    # Pad key to 32 bytes (256 bits)
    if len(key_bytes) < 32:
        key_bytes = key_bytes + b'\0' * (32 - len(key_bytes))
    else:
        key_bytes = key_bytes[:32]
    
    # Pad the data
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(text_bytes) + padder.finalize()
    
    # Generate a random IV
    iv = os.urandom(16)
    
    # Create the cipher
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Encrypt the data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # Return IV and encrypted data
    return iv + encrypted_data

def decrypt_text(encrypted_data, key):
    """Decrypt text using AES encryption"""
    try:
        # Extract IV and encrypted data
        iv = encrypted_data[:16]
        actual_encrypted_data = encrypted_data[16:]
        
        # Convert key to bytes and pad to 32 bytes
        key_bytes = key.encode('utf-8')
        if len(key_bytes) < 32:
            key_bytes = key_bytes + b'\0' * (32 - len(key_bytes))
        else:
            key_bytes = key_bytes[:32]
        
        # Create the cipher
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Decrypt the data
        padded_data = decryptor.update(actual_encrypted_data) + decryptor.finalize()
        
        # Unpad the data
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        
        # Return the decrypted text
        return data.decode('utf-8')
    except Exception as e:
        print(f"Decryption error: {e}")
        return None

def hide_data_in_image(image, data):
    """Hide encrypted data in image using LSB steganography"""
    # Convert image to numpy array
    img_array = np.array(image)
    
    # Flatten the array
    flat_img = img_array.flatten()
    
    # Convert data to binary
    binary_data = ''.join(format(byte, '08b') for byte in data)
    binary_data += '0' * 8  # Add null terminator
    
    # Check if image is large enough
    if len(binary_data) > len(flat_img):
        raise ValueError("Image too small to hide the data")
    
    # Modify LSB of each pixel
    for i in range(len(binary_data)):
        flat_img[i] = (flat_img[i] & ~1) | int(binary_data[i])
    
    # Reshape back to original image dimensions
    stego_img = flat_img.reshape(img_array.shape)
    
    return Image.fromarray(stego_img.astype(np.uint8))

def extract_data_from_image(image):
    """Extract hidden data from image"""
    # Convert image to numpy array
    img_array = np.array(image)
    
    # Flatten the array
    flat_img = img_array.flatten()
    
    # Extract LSB from each pixel
    binary_data = ''
    for pixel in flat_img:
        binary_data += str(pixel & 1)
        
        # Check if we've reached the null terminator (8 zeros)
        if len(binary_data) % 8 == 0:
            byte = binary_data[-8:]
            if byte == '00000000':
                binary_data = binary_data[:-8]  # Remove null terminator
                break
    
    # Convert binary to bytes
    extracted_data = bytearray()
    for i in range(0, len(binary_data), 8):
        if i + 8 <= len(binary_data):
            byte = binary_data[i:i+8]
            extracted_data.append(int(byte, 2))
    
    return bytes(extracted_data)

# -------------------- File Storage Functions --------------------

def save_temp_image(image):
    """Save image to a temporary file and return the filename"""
    filename = f"{uuid.uuid4()}.png"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    image.save(filepath, format='PNG')
    return filename

def get_temp_image_path(filename):
    """Get the full path for a temporary image file"""
    return os.path.join(app.config['UPLOAD_FOLDER'], filename)

# -------------------- Flask Routes --------------------

@app.route('/')
def index():
    return render_template_string(INDEX_TEMPLATE)

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    if request.method == 'POST':
        # Check if the required fields are present
        if 'image' not in request.files or not request.form.get('secret_text') or not request.form.get('secret_key'):
            flash('Please fill in all fields')
            return redirect(request.url)
        
        image_file = request.files['image']
        secret_text = request.form['secret_text']
        secret_key = request.form['secret_key']
        
        # Validate the image
        if image_file.filename == '':
            flash('No image selected')
            return redirect(request.url)
        
        try:
            # Open and process the image
            image = Image.open(image_file)
            
            # Ensure image is in RGB mode (not RGBA or other)
            if image.mode != 'RGB':
                image = image.convert('RGB')
            
            # Encrypt the text
            encrypted_data = encrypt_text(secret_text, secret_key)
            
            # Hide data in image
            stego_image = hide_data_in_image(image, encrypted_data)
            
            # Save the image to a temporary file
            filename = save_temp_image(stego_image)
            
            # Store the filename in session for download
            session['stego_image_filename'] = filename
            
            # Create preview for display
            preview_io = BytesIO()
            stego_image.save(preview_io, format='PNG')
            preview_io.seek(0)
            preview_str = base64.b64encode(preview_io.getvalue()).decode()
            preview = f"data:image/png;base64,{preview_str}"
            
            # Pass to template
            return render_template_string(
                RESULT_TEMPLATE,
                mode="encryption",
                preview=preview,
                download_url=url_for('download_image')
            )
            
        except Exception as e:
            flash(f'Error: {str(e)}')
            return redirect(request.url)
    
    return render_template_string(ENCRYPT_TEMPLATE)

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'POST':
        # Check if the required fields are present
        if 'stego_image' not in request.files or not request.form.get('secret_key'):
            flash('Please fill in all fields')
            return redirect(request.url)
        
        image_file = request.files['stego_image']
        secret_key = request.form['secret_key']
        
        # Validate the image
        if image_file.filename == '':
            flash('No image selected')
            return redirect(request.url)
        
        try:
            # Open and process the image
            image = Image.open(image_file)
            
            # Extract data from image
            extracted_data = extract_data_from_image(image)
            
            # Decrypt the data
            decrypted_text = decrypt_text(extracted_data, secret_key)
            
            if decrypted_text:
                return render_template_string(
                    DECRYPT_RESULT_TEMPLATE,
                    decrypted_text=decrypted_text
                )
            else:
                flash('Failed to decrypt. Incorrect key or the image does not contain hidden data.')
                return redirect(request.url)
            
        except Exception as e:
            flash(f'Error: {str(e)}')
            return redirect(request.url)
    
    return render_template_string(DECRYPT_TEMPLATE)

@app.route('/download-image')
def download_image():
    # Get the stego image filename from session
    filename = session.get('stego_image_filename')
    
    if filename:
        filepath = get_temp_image_path(filename)
        
        if os.path.exists(filepath):
            try:
                return send_file(
                    filepath,
                    mimetype='image/png',
                    as_attachment=True,
                    download_name='stego_image.png'
                )
            except Exception as e:
                flash(f'Error downloading file: {str(e)}')
                return redirect(url_for('index'))
    
    flash('No image found or image expired')
    return redirect(url_for('index'))

@app.route('/about')
def about():
    return render_template_string(ABOUT_TEMPLATE)

# -------------------- HTML Templates --------------------

INDEX_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Image Steganography</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <style>
        :root {
            --primary-color: #3498db;
            --primary-dark: #2980b9;
            --secondary-color: #2c3e50;
            --light-color: #ecf0f1;
            --success-color: #2ecc71;
            --warning-color: #f39c12;
            --error-color: #e74c3c;
            --card-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
            --transition: all 0.3s ease;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
            background-image: linear-gradient(120deg, #f5f7fa 0%, #c3cfe2 100%);
            background-attachment: fixed;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .card {
            background-color: white;
            border-radius: 15px;
            box-shadow: var(--card-shadow);
            padding: 30px;
            margin-bottom: 30px;
            transition: var(--transition);
        }
        
        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 30px rgba(0, 0, 0, 0.15);
        }
        
        h1, h2, h3 {
            color: var(--secondary-color);
        }
        
        h1 {
            margin-bottom: 10px;
            font-size: 2.5rem;
        }
        
        header {
            text-align: center;
            margin-bottom: 30px;
        }
        
        header p {
            font-size: 1.1rem;
            color: #666;
            max-width: 700px;
            margin: 0 auto;
        }
        
        .nav {
            display: flex;
            justify-content: center;
            flex-wrap: wrap;
            gap: 15px;
            margin-bottom: 30px;
        }
        
        .nav a {
            color: var(--primary-color);
            text-decoration: none;
            padding: 8px 16px;
            border-radius: 30px;
            font-weight: 500;
            transition: var(--transition);
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .nav a:hover {
            background-color: var(--light-color);
            color: var(--primary-dark);
            transform: translateY(-3px);
        }
        
        .features {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 25px;
            margin-top: 40px;
        }
        
        .feature-card {
            background-color: white;
            border-radius: 12px;
            padding: 25px;
            text-align: center;
            transition: var(--transition);
            height: 100%;
            border: 1px solid rgba(0, 0, 0, 0.05);
            display: flex;
            flex-direction: column;
            justify-content: center;
        }
        
        .feature-card:hover {
            transform: translateY(-10px);
            box-shadow: var(--card-shadow);
        }
        
        .feature-icon {
            font-size: 2.5rem;
            margin-bottom: 15px;
            color: var(--primary-color);
        }
        
        .cta-buttons {
            display: flex;
            justify-content: center;
            flex-wrap: wrap;
            gap: 20px;
            margin-top: 40px;
        }
        
        .btn {
            display: inline-flex;
            align-items: center;
            gap: 10px;
            background-color: var(--primary-color);
            color: white;
            padding: 12px 24px;
            border-radius: 30px;
            text-decoration: none;
            font-weight: bold;
            transition: var(--transition);
            border: none;
            cursor: pointer;
        }
        
        .btn:hover {
            background-color: var(--primary-dark);
            transform: translateY(-3px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
        }
        
        footer {
            text-align: center;
            margin-top: 50px;
            padding: 20px;
            color: #7f8c8d;
            font-size: 0.9rem;
            border-top: 1px solid rgba(0, 0, 0, 0.1);
        }
        
        .developer-info {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            margin-top: 10px;
        }
        
        .dev-social a {
            color: #7f8c8d;
            margin: 0 5px;
            transition: var(--transition);
        }
        
        .dev-social a:hover {
            color: var(--primary-color);
        }
        
        /* Media Queries */
        @media (max-width: 768px) {
            .features {
                grid-template-columns: 1fr;
            }
            
            .cta-buttons {
                flex-direction: column;
                align-items: center;
            }
            
            .btn {
                width: 100%;
                max-width: 300px;
                justify-content: center;
            }
            
            h1 {
                font-size: 2rem;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <header>
                <h1>Secure Data Hiding in Images</h1>
                <p>Hide your confidential messages within images using advanced steganography and encryption techniques</p>
            </header>
            
            <div class="nav">
                <a href="/"><i class="fas fa-home"></i> Home</a>
                <a href="/encrypt"><i class="fas fa-lock"></i> Encrypt</a>
                <a href="/decrypt"><i class="fas fa-unlock"></i> Decrypt</a>
                <a href="/about"><i class="fas fa-info-circle"></i> About</a>
            </div>
            
            <div class="features">
                <div class="feature-card">
                    <div class="feature-icon"><i class="fas fa-shield-alt"></i></div>
                    <h3>Advanced Encryption</h3>
                    <p>Your messages are secured with AES-256 encryption before being hidden in the image</p>
                </div>
                <div class="feature-card">
                    <div class="feature-icon"><i class="fas fa-image"></i></div>
                    <h3>LSB Steganography</h3>
                    <p>Data is hidden in the least significant bits of the image, making it invisible to the naked eye</p>
                </div>
                <div class="feature-card">
                    <div class="feature-icon"><i class="fas fa-user-check"></i></div>
                    <h3>Easy to Use</h3>
                    <p>Simple interface for both hiding data and extracting hidden messages from images</p>
                </div>
            </div>
            
            <div class="cta-buttons">
                <a href="/encrypt" class="btn"><i class="fas fa-lock"></i> Hide Secret Message</a>
                <a href="/decrypt" class="btn"><i class="fas fa-unlock"></i> Extract Hidden Message</a>
            </div>
        </div>
    </div>
    
    <footer>
        <p>Secure Image Steganography Application &copy; 2025</p>
        <div class="developer-info">
            <p>Developed with <i class="fas fa-heart" style="color: #e74c3c;"></i> by Vaibhav Sharma</p>
            <div class="dev-social">
                <a href="#" title="GitHub"><i class="fab fa-github"></i></a>
                <a href="#" title="LinkedIn"><i class="fab fa-linkedin"></i></a>
                <a href="#" title="Twitter"><i class="fab fa-twitter"></i></a>
            </div>
        </div>
    </footer>
</body>
</html>
'''

ENCRYPT_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Encrypt Message - Image Steganography</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <style>
        :root {
            --primary-color: #3498db;
            --primary-dark: #2980b9;
            --secondary-color: #2c3e50;
            --light-color: #ecf0f1;
            --success-color: #2ecc71;
            --warning-color: #f39c12;
            --error-color: #e74c3c;
            --card-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
            --transition: all 0.3s ease;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
            background-image: linear-gradient(120deg, #f5f7fa 0%, #c3cfe2 100%);
            background-attachment: fixed;
        }
        
        .container {
            max-width: 900px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .card {
            background-color: white;
            border-radius: 15px;
            box-shadow: var(--card-shadow);
            padding: 30px;
            margin-bottom: 30px;
            transition: var(--transition);
        }
        
        h1, h2, h3 {
            color: var(--secondary-color);
        }
        
        .form-group {
            margin-bottom: 25px;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: var(--secondary-color);
        }
        
        input[type="text"],
        input[type="password"],
        textarea,
        input[type="file"] {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 8px;
            font-size: 1rem;
            transition: var(--transition);
        }
        
        input[type="text"]:focus,
        input[type="password"]:focus,
        textarea:focus {
            border-color: var(--primary-color);
            box-shadow: 0 0 0 3px rgba(52, 152, 219, 0.2);
            outline: none;
        }
        
        textarea {
            min-height: 150px;
            resize: vertical;
        }
        
        .btn {
            display: inline-flex;
            align-items: center;
            gap: 10px;
            background-color: var(--primary-color);
            color: white;
            padding: 12px 24px;
            border: none;
            border-radius: 30px;
            cursor: pointer;
            font-weight: bold;
            font-size: 1rem;
            transition: var(--transition);
        }
        
        .btn:hover {
            background-color: var(--primary-dark);
            transform: translateY(-3px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
        }
        
        .nav {
            display: flex;
            justify-content: center;
            flex-wrap: wrap;
            gap: 15px;
            margin-bottom: 30px;
        }
        
        .nav a {
            color: var(--primary-color);
            text-decoration: none;
            padding: 8px 16px;
            border-radius: 30px;
            font-weight: 500;
            transition: var(--transition);
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .nav a:hover {
            background-color: var(--light-color);
            color: var(--primary-dark);
            transform: translateY(-3px);
        }
        
        .flash-messages {
            background-color: #f8d7da;
            color: #721c24;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 8px;
            display: {{ 'block' if get_flashed_messages() else 'none' }};
            animation: fadeIn 0.3s ease;
        }
        
        .flash-messages ul {
            margin-bottom: 0;
            padding-left: 20px;
        }
        
        .tips {
            background-color: #e8f4fd;
            padding: 20px;
            border-radius: 8px;
            margin-top: 30px;
            border-left: 4px solid var(--primary-color);
        }
        
        .tips h3 {
            color: var(--primary-color);
            margin-bottom: 10px;
        }
        
        .tips ul {
            padding-left: 20px;
        }
        
        .tips li {
            margin-bottom: 8px;
        }
        
        small {
            display: block;
            color: #666;
            margin-top: 5px;
        }
        
        footer {
            text-align: center;
            margin-top: 50px;
            padding: 20px;
            color: #7f8c8d;
            font-size: 0.9rem;
            border-top: 1px solid rgba(0, 0, 0, 0.1);
        }
        
        .developer-info {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            margin-top: 10px;
        }
        
        .dev-social a {
            color: #7f8c8d;
            margin: 0 5px;
            transition: var(--transition);
        }
        
        .dev-social a:hover {
            color: var(--primary-color);
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .file-input-wrapper {
            position: relative;
            overflow: hidden;
            display: inline-block;
            cursor: pointer;
        }
        
        .file-input-wrapper input[type="file"] {
            position: absolute;
            left: 0;
            top: 0;
            opacity: 0;
            cursor: pointer;
        }
        
        .file-input-button {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background-color: #f0f0f0;
            border: 1px dashed #ccc;
            border-radius: 8px;
            padding: 15px;
            text-align: center;
            transition: var(--transition);
            width: 100%;
            cursor: pointer;
        }
        
        .file-input-button:hover {
            background-color: #e9ecef;
            border-color: #adb5bd;
        }
        
        #file-name {
            margin-top: 10px;
            font-size: 0.9rem;
            color: #666;
        }
        
        /* Media Queries */
        @media (max-width: 768px) {
            .card {
                padding: 20px;
            }
            
            .container {
                padding: 10px;
            }
            
            h1 {
                font-size: 1.8rem;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <h1><i class="fas fa-lock"></i> Hide Secret Message in Image</h1>
            
            <div class="nav">
                <a href="/"><i class="fas fa-home"></i> Home</a>
                <a href="/encrypt"><i class="fas fa-lock"></i> Encrypt</a>
                <a href="/decrypt"><i class="fas fa-unlock"></i> Decrypt</a>
                <a href="/about"><i class="fas fa-info-circle"></i> About</a>
            </div>
            
            <div class="flash-messages">
                {% with messages = get_flashed_messages() %}
                    {% if messages %}
                        <ul>
                        {% for message in messages %}
                            <li>{{ message }}</li>
                        {% endfor %}
                        </ul>
                    {% endif %}
                {% endwith %}
            </div>
            
            <form method="POST" enctype="multipart/form-data">
                <div class="form-group">
                    <label for="image">Select Image:</label>
                    <div class="file-input-wrapper">
                        <div class="file-input-button">
                            <i class="fas fa-image fa-2x"></i>
                            <div>
                                <strong>Choose an image</strong><br>
                                <span>or drag and drop it here</span>
                            </div>
                        </div>
                        <input type="file" id="image" name="image" accept="image/*" required onchange="updateFileName(this)">
                    </div>
                    <div id="file-name"></div>
                    <small>Recommended: Use PNG images for best quality results</small>
                </div>
                
                <div class="form-group">
                    <label for="secret_text"><i class="fas fa-comment-dots"></i> Your Secret Message:</label>
                    <textarea id="secret_text" name="secret_text" placeholder="Enter the secret message you want to hide..." required></textarea>
                </div>
                
                <div class="form-group">
                    <label for="secret_key"><i class="fas fa-key"></i> Encryption Key:</label>
                    <input type="password" id="secret_key" name="secret_key" placeholder="Enter a strong encryption key..." required>
                    <small>Remember this key! You'll need it to decrypt the message later.</small>
                </div>
                
                <button type="submit" class="btn"><i class="fas fa-lock"></i> Hide Message in Image</button>
            </form>
            
            <div class="tips">
                <h3>Tips for Better Security:</h3>
                <ul>
                    <li>Use a strong, unique password that includes letters, numbers, and special characters</li>
                    <li>Larger images can hide more data without visible degradation</li>
                    <li>PNG format is recommended as it uses lossless compression</li>
                    <li>Don't upload the original image anywhere - it can be used for comparison</li>
                </ul>
            </div>
        </div>
    </div>
    
    <footer>
        <p>Secure Image Steganography Application &copy; 2025</p>
        <div class="developer-info">
            <p>Developed with <i class="fas fa-heart" style="color: #e74c3c;"></i> by Vaibhav Sharma</p>
            <div class="dev-social">
                <a href="#" title="GitHub"><i class="fab fa-github"></i></a>
                <a href="#" title="LinkedIn"><i class="fab fa-linkedin"></i></a>
                <a href="#" title="Twitter"><i class="fab fa-twitter"></i></a>
            </div>
        </div>
    </footer>
    
    <script>
        function updateFileName(input) {
            const fileNameElement = document.getElementById('file-name');
            if (input.files.length > 0) {
                fileNameElement.textContent = 'Selected file: ' + input.files[0].name;
            } else {
                fileNameElement.textContent = '';
            }
        }
    </script>
</body>
</html>
'''

RESULT_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ mode|title }} Complete - Image Steganography</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <style>
        :root {
            --primary-color: #3498db;
            --primary-dark: #2980b9;
            --secondary-color: #2c3e50;
            --light-color: #ecf0f1;
            --success-color: #2ecc71;
            --warning-color: #f39c12;
            --error-color: #e74c3c;
            --card-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
            --transition: all 0.3s ease;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
            background-image: linear-gradient(120deg, #f5f7fa 0%, #c3cfe2 100%);
            background-attachment: fixed;
        }
        
        .container {
            max-width: 900px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .card {
            background-color: white;
            border-radius: 15px;
            box-shadow: var(--card-shadow);
            padding: 30px;
            margin-bottom: 30px;
            transition: var(--transition);
        }
        
        h1, h2, h3 {
            color: var(--secondary-color);
        }
        
        .success-message {
            text-align: center;
            padding: 25px;
            background-color: #d4edda;
            border-radius: 10px;
            margin-bottom: 30px;
            color: #155724;
            animation: fadeIn 0.5s ease;
            border-left: 5px solid var(--success-color);
        }
        
        .success-message h2 {
            color: #155724;
            margin-bottom: 10px;
        }
        
        .btn {
            display: inline-flex;
            align-items: center;
            gap: 10px;
            background-color: var(--primary-color);
            color: white;
            padding: 14px 28px;
            border: none;
            border-radius: 30px;
            text-decoration: none;
            cursor: pointer;
            font-weight: bold;
            font-size: 1rem;
            transition: var(--transition);
        }
        
        .btn:hover {
            background-color: var(--primary-dark);
            transform: translateY(-3px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
        }
        
        .btn-group {
            display: flex;
            justify-content: center;
            flex-wrap: wrap;
            gap: 15px;
            margin-top: 30px;
        }
        
        .image-preview {
            max-width: 100%;
            margin: 30px auto;
            text-align: center;
        }
        
        .image-preview img {
            max-width: 100%;
            max-height: 500px;
            border: 1px solid #ddd;
            border-radius: 10px;
            box-shadow: 0 3px 15px rgba(0, 0, 0, 0.1);
            transition: var(--transition);
        }
        
        .image-preview img:hover {
            transform: scale(1.02);
            box-shadow: 0 5px 20px rgba(0, 0, 0, 0.15);
        }
        
        .nav {
            display: flex;
            justify-content: center;
            flex-wrap: wrap;
            gap: 15px;
            margin-bottom: 30px;
        }
        
        .nav a {
            color: var(--primary-color);
            text-decoration: none;
            padding: 8px 16px;
            border-radius: 30px;
            font-weight: 500;
            transition: var(--transition);
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .nav a:hover {
            background-color: var(--light-color);
            color: var(--primary-dark);
            transform: translateY(-3px);
        }
        
        .security-notice {
            background-color: #fff3cd;
            border-left: 5px solid var(--warning-color);
            color: #856404;
            padding: 20px;
            border-radius: 10px;
            margin-top: 30px;
        }
        
        .security-notice h3 {
            color: #856404;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .security-notice ul {
            padding-left: 20px;
        }
        
        .security-notice li {
            margin-bottom: 8px;
        }
        
        footer {
            text-align: center;
            margin-top: 50px;
            padding: 20px;
            color: #7f8c8d;
            font-size: 0.9rem;
            border-top: 1px solid rgba(0, 0, 0, 0.1);
        }
        
        .developer-info {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            margin-top: 10px;
        }
        
        .dev-social a {
            color: #7f8c8d;
            margin: 0 5px;
            transition: var(--transition);
        }
        
        .dev-social a:hover {
            color: var(--primary-color);
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .confetti {
            position: fixed;
            width: 10px;
            height: 10px;
            background-color: #f0f;
            position: absolute;
            top: -10px;
            z-index: 999;
        }
        
        /* Media Queries */
        @media (max-width: 768px) {
            .card {
                padding: 20px;
            }
            
            .container {
                padding: 10px;
            }
            
            h1 {
                font-size: 1.8rem;
            }
            
            .btn-group {
                flex-direction: column;
                align-items: center;
            }
            
            .btn {
                width: 100%;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <h1><i class="fas fa-check-circle" style="color: var(--success-color);"></i> {{ mode|title }} Complete</h1>
            
            <div class="nav">
                <a href="/"><i class="fas fa-home"></i> Home</a>
                <a href="/encrypt"><i class="fas fa-lock"></i> Encrypt</a>
                <a href="/decrypt"><i class="fas fa-unlock"></i> Decrypt</a>
                <a href="/about"><i class="fas fa-info-circle"></i> About</a>
            </div>
            
            <div class="success-message">
                <h2><i class="fas fa-check-circle"></i> Success!</h2>
                <p>Your message has been successfully hidden in the image. The image appears normal but contains your encrypted secret message.</p>
            </div>
            
            <div class="image-preview">
                <h3>Preview of your stego-image:</h3>
                <img src="{{ preview }}" alt="Steganographic image with hidden message" id="preview-image">
            </div>
            
            <div class="btn-group">
                <a href="{{ download_url }}" class="btn" id="download-btn"><i class="fas fa-download"></i> Download Image</a>
                <a href="/encrypt" class="btn"><i class="fas fa-plus-circle"></i> Hide Another Message</a>
            </div>
            
            <div class="security-notice">
                <h3><i class="fas fa-shield-alt"></i> Important Security Notes:</h3>
                <ul>
                    <li><strong>Remember your encryption key!</strong> Without it, the message cannot be recovered.</li>
                    <li>This image looks normal but contains your hidden data. Share it carefully.</li>
                    <li>Some social media platforms may compress the image and destroy the hidden data.</li>
                    <li>For maximum security, only transfer the image directly through secure channels.</li>
                </ul>
            </div>
        </div>
    </div>
    
    <footer>
        <p>Secure Image Steganography Application &copy; 2025</p>
        <div class="developer-info">
            <p>Developed with <i class="fas fa-heart" style="color: #e74c3c;"></i> by Vaibhav Sharma</p>
            <div class="dev-social">
                <a href="#" title="GitHub"><i class="fab fa-github"></i></a>
                <a href="#" title="LinkedIn"><i class="fab fa-linkedin"></i></a>
                <a href="#" title="Twitter"><i class="fab fa-twitter"></i></a>
            </div>
        </div>
    </footer>
    
    <script>
        // Add a small confetti effect for success
        function createConfetti() {
            const colors = ['#3498db', '#2ecc71', '#e74c3c', '#f39c12', '#9b59b6'];
            const confettiCount = 100;
            
            for (let i = 0; i < confettiCount; i++) {
                const confetti = document.createElement('div');
                confetti.className = 'confetti';
                
                // Random position
                confetti.style.left = Math.random() * 100 + 'vw';
                
                // Random color
                confetti.style.backgroundColor = colors[Math.floor(Math.random() * colors.length)];
                
                // Random size
                const size = Math.random() * 10 + 5;
                confetti.style.width = size + 'px';
                confetti.style.height = size + 'px';
                
                // Random rotation
                confetti.style.transform = 'rotate(' + Math.random() * 360 + 'deg)';
                
                // Append to body
                document.body.appendChild(confetti);
                
                // Animate falling
                const duration = Math.random() * 3 + 2;
                confetti.style.transition = 'all ' + duration + 's ease-out';
                
                setTimeout(() => {
                    confetti.style.transform = 'translateY(' + (window.innerHeight + 100) + 'px) rotate(' + Math.random() * 360 + 'deg)';
                    confetti.style.opacity = '0';
                }, 10);
                
                // Remove after animation
                setTimeout(() => {
                    confetti.remove();
                }, duration * 1000);
            }
        }
        
        // Create confetti when the page loads
        window.addEventListener('load', createConfetti);
        
        // Add download tracking
        document.getElementById('download-btn').addEventListener('click', function() {
            console.log('Download initiated');
            // You could add analytics tracking here
        });
    </script>
</body>
</html>
'''

DECRYPT_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Decrypt Message - Image Steganography</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <style>
        :root {
            --primary-color: #3498db;
            --primary-dark: #2980b9;
            --secondary-color: #2c3e50;
            --light-color: #ecf0f1;
            --success-color: #2ecc71;
            --warning-color: #f39c12;
            --error-color: #e74c3c;
            --card-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
            --transition: all 0.3s ease;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
            background-image: linear-gradient(120deg, #f5f7fa 0%, #c3cfe2 100%);
            background-attachment: fixed;
        }
        
        .container {
            max-width: 900px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .card {
            background-color: white;
            border-radius: 15px;
            box-shadow: var(--card-shadow);
            padding: 30px;
            margin-bottom: 30px;
            transition: var(--transition);
        }
        
        h1, h2, h3 {
            color: var(--secondary-color);
        }
        
        .form-group {
            margin-bottom: 25px;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: var(--secondary-color);
        }
        
        input[type="text"],
        input[type="password"],
        input[type="file"] {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 8px;
            font-size: 1rem;
            transition: var(--transition);
        }
        
        input[type="text"]:focus,
        input[type="password"]:focus {
            border-color: var(--primary-color);
            box-shadow: 0 0 0 3px rgba(52, 152, 219, 0.2);
            outline: none;
        }
        
        .btn {
            display: inline-flex;
            align-items: center;
            gap: 10px;
            background-color: var(--primary-color);
            color: white;
            padding: 12px 24px;
            border: none;
            border-radius: 30px;
            cursor: pointer;
            font-weight: bold;
            font-size: 1rem;
            transition: var(--transition);
        }
        
        .btn:hover {
            background-color: var(--primary-dark);
            transform: translateY(-3px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
        }
        
        .nav {
            display: flex;
            justify-content: center;
            flex-wrap: wrap;
            gap: 15px;
            margin-bottom: 30px;
        }
        
        .nav a {
            color: var(--primary-color);
            text-decoration: none;
            padding: 8px 16px;
            border-radius: 30px;
            font-weight: 500;
            transition: var(--transition);
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .nav a:hover {
            background-color: var(--light-color);
            color: var(--primary-dark);
            transform: translateY(-3px);
        }
        
        .flash-messages {
            background-color: #f8d7da;
            color: #721c24;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 8px;
            display: {{ 'block' if get_flashed_messages() else 'none' }};
            animation: fadeIn 0.3s ease;
            border-left: 4px solid var(--error-color);
        }
        
        .tips {
            background-color: #e8f4fd;
            padding: 20px;
            border-radius: 8px;
            margin-top: 30px;
            border-left: 4px solid var(--primary-color);
        }
        
        .tips h3 {
            color: var(--primary-color);
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .tips ul {
            padding-left: 20px;
        }
        
        .tips li {
            margin-bottom: 8px;
        }
        
        footer {
            text-align: center;
            margin-top: 50px;
            padding: 20px;
            color: #7f8c8d;
            font-size: 0.9rem;
            border-top: 1px solid rgba(0, 0, 0, 0.1);
        }
        
        .developer-info {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            margin-top: 10px;
        }
        
        .dev-social a {
            color: #7f8c8d;
            margin: 0 5px;
            transition: var(--transition);
        }
        
        .dev-social a:hover {
            color: var(--primary-color);
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .file-input-wrapper {
            position: relative;
            overflow: hidden;
            display: inline-block;
            cursor: pointer;
        }
        
        .file-input-wrapper input[type="file"] {
            position: absolute;
            left: 0;
            top: 0;
            opacity: 0;
            cursor: pointer;
        }
        
        .file-input-button {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background-color: #f0f0f0;
            border: 1px dashed #ccc;
            border-radius: 8px;
            padding: 15px;
            text-align: center;
            transition: var(--transition);
            width: 100%;
            cursor: pointer;
        }
        
        .file-input-button:hover {
            background-color: #e9ecef;
            border-color: #adb5bd;
        }
        
        #file-name {
            margin-top: 10px;
            font-size: 0.9rem;
            color: #666;
        }
        
        /* Media Queries */
        @media (max-width: 768px) {
            .card {
                padding: 20px;
            }
            
            .container {
                padding: 10px;
            }
            
            h1 {
                font-size: 1.8rem;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <h1><i class="fas fa-unlock"></i> Reveal Hidden Message from Image</h1>
            
            <div class="nav">
                <a href="/"><i class="fas fa-home"></i> Home</a>
                <a href="/encrypt"><i class="fas fa-lock"></i> Encrypt</a>
                <a href="/decrypt"><i class="fas fa-unlock"></i> Decrypt</a>
                <a href="/about"><i class="fas fa-info-circle"></i> About</a>
            </div>
            
            <div class="flash-messages">
                {% with messages = get_flashed_messages() %}
                    {% if messages %}
                        <ul>
                        {% for message in messages %}
                            <li>{{ message }}</li>
                        {% endfor %}
                        </ul>
                    {% endif %}
                {% endwith %}
            </div>
            
            <form method="POST" enctype="multipart/form-data">
                <div class="form-group">
                    <label for="stego_image"><i class="fas fa-image"></i> Select Steganographic Image:</label>
                    <div class="file-input-wrapper">
                        <div class="file-input-button">
                            <i class="fas fa-image fa-2x"></i>
                            <div>
                                <strong>Choose the image with hidden data</strong><br>
                                <span>or drag and drop it here</span>
                            </div>
                        </div>
                        <input type="file" id="stego_image" name="stego_image" accept="image/*" required onchange="updateFileName(this)">
                    </div>
                    <div id="file-name"></div>
                </div>
                
                <div class="form-group">
                    <label for="secret_key"><i class="fas fa-key"></i> Decryption Key:</label>
                    <input type="password" id="secret_key" name="secret_key" placeholder="Enter the key that was used for encryption..." required>
                </div>
                
                <button type="submit" class="btn"><i class="fas fa-unlock-alt"></i> Extract Hidden Message</button>
            </form>
            
            <div class="tips">
                <h3><i class="fas fa-info-circle"></i> Important Notes:</h3>
                <ul>
                    <li>You must use the exact same key that was used for encryption</li>
                    <li>If the image was compressed (e.g., by social media), the hidden data may be corrupted</li>
                    <li>Always use the original steganographic image for best results</li>
                    <li>The encryption key is case-sensitive</li>
                </ul>
            </div>
        </div>
    </div>
    
    <footer>
        <p>Secure Image Steganography Application &copy; 2025</p>
        <div class="developer-info">
            <p>Developed with <i class="fas fa-heart" style="color: #e74c3c;"></i> by Vaibhav Sharma</p>
            <div class="dev-social">
                <a href="#" title="GitHub"><i class="fab fa-github"></i></a>
                <a href="#" title="LinkedIn"><i class="fab fa-linkedin"></i></a>
                <a href="#" title="Twitter"><i class="fab fa-twitter"></i></a>
            </div>
        </div>
    </footer>
    
    <script>
        function updateFileName(input) {
            const fileNameElement = document.getElementById('file-name');
            if (input.files.length > 0) {
                fileNameElement.textContent = 'Selected file: ' + input.files[0].name;
            } else {
                fileNameElement.textContent = '';
            }
        }
    </script>
</body>
</html>
'''

DECRYPT_RESULT_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Message Revealed - Image Steganography</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <style>
        :root {
            --primary-color: #3498db;
            --primary-dark: #2980b9;
            --secondary-color: #2c3e50;
            --light-color: #ecf0f1;
            --success-color: #2ecc71;
            --warning-color: #f39c12;
            --error-color: #e74c3c;
            --card-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
            --transition: all 0.3s ease;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
            background-image: linear-gradient(120deg, #f5f7fa 0%, #c3cfe2 100%);
            background-attachment: fixed;
        }
        
        .container {
            max-width: 900px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .card {
            background-color: white;
            border-radius: 15px;
            box-shadow: var(--card-shadow);
            padding: 30px;
            margin-bottom: 30px;
            transition: var(--transition);
        }
        
        h1, h2, h3 {
            color: var(--secondary-color);
        }
        
        .success-message {
            text-align: center;
            padding: 25px;
            background-color: #d4edda;
            border-radius: 10px;
            margin-bottom: 30px;
            color: #155724;
            animation: fadeIn 0.5s ease;
            border-left: 5px solid var(--success-color);
        }
        
        .success-message h2 {
            color: #155724;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 10px;
            justify-content: center;
        }
        
        .btn {
            display: inline-flex;
            align-items: center;
            gap: 10px;
            background-color: var(--primary-color);
            color: white;
            padding: 14px 28px;
            border: none;
            border-radius: 30px;
            text-decoration: none;
            cursor: pointer;
            font-weight: bold;
            font-size: 1rem;
            transition: var(--transition);
        }
        
        .btn:hover {
            background-color: var(--primary-dark);
            transform: translateY(-3px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
        }
        
        .btn-group {
            display: flex;
            justify-content: center;
            flex-wrap: wrap;
            gap: 15px;
            margin-top: 30px;
        }
        
        .message-container {
            background-color: #f8f9fa;
            border: 1px solid #ddd;
            border-radius: 10px;
            padding: 25px;
            margin: 25px 0;
            overflow-wrap: break-word;
            animation: fadeIn 0.5s ease;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.05);
            position: relative;
        }
        
        .message-container pre {
            white-space: pre-wrap;
            font-family: inherit;
            margin: 0;
            line-height: 1.7;
        }
        
        .message-container:before {
            content: '\\201C';
            font-size: 60px;
            color: rgba(52, 152, 219, 0.2);
            position: absolute;
            top: -10px;
            left: 10px;
        }
        
        .message-container:after {
            content: '\\201D';
            font-size: 60px;
            color: rgba(52, 152, 219, 0.2);
            position: absolute;
            bottom: -40px;
            right: 10px;
        }
        
        .nav {
            display: flex;
            justify-content: center;
            flex-wrap: wrap;
            gap: 15px;
            margin-bottom: 30px;
        }
        
        .nav a {
            color: var(--primary-color);
            text-decoration: none;
            padding: 8px 16px;
            border-radius: 30px;
            font-weight: 500;
            transition: var(--transition);
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .nav a:hover {
            background-color: var(--light-color);
            color: var(--primary-dark);
            transform: translateY(-3px);
        }
        
        footer {
            text-align: center;
            margin-top: 50px;
            padding: 20px;
            color: #7f8c8d;
            font-size: 0.9rem;
            border-top: 1px solid rgba(0, 0, 0, 0.1);
        }
        
        .developer-info {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            margin-top: 10px;
        }
        
        .dev-social a {
            color: #7f8c8d;
            margin: 0 5px;
            transition: var(--transition);
        }
        
        .dev-social a:hover {
            color: var(--primary-color);
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .message-actions {
            display: flex;
            justify-content: flex-end;
            margin-top: 15px;
        }
        
        .message-actions button {
            background: none;
            border: none;
            cursor: pointer;
            color: var(--primary-color);
            font-size: 1rem;
            display: flex;
            align-items: center;
            gap: 5px;
            transition: var(--transition);
        }
        
        .message-actions button:hover {
            color: var(--primary-dark);
        }
        
        /* Media Queries */
        @media (max-width: 768px) {
            .card {
                padding: 20px;
            }
            
            .container {
                padding: 10px;
            }
            
            h1 {
                font-size: 1.8rem;
            }
            
            .btn-group {
                flex-direction: column;
                align-items: center;
            }
            
            .btn {
                width: 100%;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <h1><i class="fas fa-unlock-alt" style="color: var(--success-color);"></i> Hidden Message Revealed</h1>
            
            <div class="nav">
                <a href="/"><i class="fas fa-home"></i> Home</a>
                <a href="/encrypt"><i class="fas fa-lock"></i> Encrypt</a>
                <a href="/decrypt"><i class="fas fa-unlock"></i> Decrypt</a>
                <a href="/about"><i class="fas fa-info-circle"></i> About</a>
            </div>
            
            <div class="success-message">
                <h2><i class="fas fa-check-circle"></i> Success!</h2>
                <p>The hidden message has been successfully recovered from the image and decrypted.</p>
            </div>
            
            <h3><i class="fas fa-comment-dots"></i> The Hidden Message:</h3>
            <div class="message-container">
                <pre id="decrypted-text">{{ decrypted_text }}</pre>
                <div class="message-actions">
                    <button onclick="copyToClipboard()"><i class="fas fa-copy"></i> Copy Text</button>
                </div>
            </div>
            
            <div class="btn-group">
                <a href="/decrypt" class="btn"><i class="fas fa-unlock-alt"></i> Decrypt Another Image</a>
                <a href="/encrypt" class="btn"><i class="fas fa-lock"></i> Hide New Message</a>
            </div>
        </div>
    </div>
    
    <footer>
        <p>Secure Image Steganography Application &copy; 2025</p>
        <div class="developer-info">
            <p>Developed with <i class="fas fa-heart" style="color: #e74c3c;"></i> by Vaibhav Sharma</p>
            <div class="dev-social">
                <a href="#" title="GitHub"><i class="fab fa-github"></i></a>
                <a href="#" title="LinkedIn"><i class="fab fa-linkedin"></i></a>
                <a href="#" title="Twitter"><i class="fab fa-twitter"></i></a>
            </div>
        </div>
    </footer>
    
    <script>
        function copyToClipboard() {
            const text = document.getElementById('decrypted-text').innerText;
            navigator.clipboard.writeText(text).then(function() {
                // Show a temporary "Copied!" message
                const button = document.querySelector('.message-actions button');
                const originalText = button.innerHTML;
                button.innerHTML = '<i class="fas fa-check"></i> Copied!';
                
                setTimeout(function() {
                    button.innerHTML = originalText;
                }, 2000);
            });
        }
        
        // Add a small celebration effect for success
        function celebrate() {
            const colors = ['#3498db', '#2ecc71', '#e74c3c', '#f39c12', '#9b59b6'];
            const messageContainer = document.querySelector('.message-container');
            
            // Add a subtle animation to the message
            messageContainer.style.transition = 'transform 0.5s ease';
            messageContainer.style.transform = 'scale(1.02)';
            
            setTimeout(() => {
                messageContainer.style.transform = 'scale(1)';
            }, 500);
        }
        
        // Celebrate when the page loads
        window.addEventListener('load', celebrate);
    </script>
</body>
</html>
'''

ABOUT_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>About - Image Steganography</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <style>
        :root {
            --primary-color: #3498db;
            --primary-dark: #2980b9;
            --secondary-color: #2c3e50;
            --light-color: #ecf0f1;
            --success-color: #2ecc71;
            --warning-color: #f39c12;
            --error-color: #e74c3c;
            --card-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
            --transition: all 0.3s ease;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
            background-image: linear-gradient(120deg, #f5f7fa 0%, #c3cfe2 100%);
            background-attachment: fixed;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .card {
            background-color: white;
            border-radius: 15px;
            box-shadow: var(--card-shadow);
            padding: 30px;
            margin-bottom: 30px;
            transition: var(--transition);
        }
        
        h1, h2, h3 {
            color: var(--secondary-color);
        }
        
        h1 {
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .nav {
            display: flex;
            justify-content: center;
            flex-wrap: wrap;
            gap: 15px;
            margin-bottom: 30px;
        }
        
        .nav a {
            color: var(--primary-color);
            text-decoration: none;
            padding: 8px 16px;
            border-radius: 30px;
            font-weight: 500;
            transition: var(--transition);
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .nav a:hover {
            background-color: var(--light-color);
            color: var(--primary-dark);
            transform: translateY(-3px);
        }
        
        .section {
            margin-bottom: 40px;
            animation: fadeIn 0.5s ease;
        }
        
        .technique-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 25px;
            margin-top: 25px;
        }
        
        .technique-card {
            background-color: #f8f9fa;
            border: 1px solid #ddd;
            border-radius: 10px;
            padding: 20px;
            transition: var(--transition);
            height: 100%;
            display: flex;
            flex-direction: column;
        }
        
        .technique-card:hover {
            transform: translateY(-5px);
            box-shadow: var(--card-shadow);
        }
        
        .technique-card h3 {
            margin-bottom: 15px;
            color: var(--primary-color);
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        footer {
            text-align: center;
            margin-top: 50px;
            padding: 20px;
            color: #7f8c8d;
            font-size: 0.9rem;
            border-top: 1px solid rgba(0, 0, 0, 0.1);
        }
        
        .security-tips {
            background-color: #e8f4fd;
            padding: 25px;
            border-radius: 10px;
            margin-top: 30px;
            border-left: 5px solid var(--primary-color);
        }
        
        .security-tips h2 {
            color: var(--primary-color);
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .security-tips ul {
            padding-left: 20px;
        }
        
        .security-tips li {
            margin-bottom: 10px;
        }
        
        .developer-profile {
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 30px;
            background-color: #f8f9fa;
            border-radius: 10px;
            margin: 40px 0;
            text-align: center;
            border-top: 5px solid var(--primary-color);
        }
        
        .developer-img {
            width: 150px;
            height: 150px;
            border-radius: 50%;
            object-fit: cover;
            margin-bottom: 20px;
            border: 5px solid white;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
        }
        
        .social-links {
            display: flex;
            gap: 15px;
            margin-top: 20px;
        }
        
        .social-links a {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background-color: var(--light-color);
            color: var(--primary-color);
            text-decoration: none;
            transition: var(--transition);
        }
        
        .social-links a:hover {
            background-color: var(--primary-color);
            color: white;
            transform: translateY(-3px);
        }
        
        .developer-bio {
            max-width: 600px;
            margin: 0 auto;
        }
        
        .developer-info {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            margin-top: 10px;
        }
        
        .dev-social a {
            color: #7f8c8d;
            margin: 0 5px;
            transition: var(--transition);
        }
        
        .dev-social a:hover {
            color: var(--primary-color);
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        /* Media Queries */
        @media (max-width: 768px) {
            .technique-grid {
                grid-template-columns: 1fr;
            }
            
            .card {
                padding: 20px;
            }
            
            .container {
                padding: 10px;
            }
            
            h1 {
                font-size: 1.8rem;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <h1><i class="fas fa-info-circle"></i> About Image Steganography</h1>
            
            <div class="nav">
                <a href="/"><i class="fas fa-home"></i> Home</a>
                <a href="/encrypt"><i class="fas fa-lock"></i> Encrypt</a>
                <a href="/decrypt"><i class="fas fa-unlock"></i> Decrypt</a>
                <a href="/about"><i class="fas fa-info-circle"></i> About</a>
            </div>
            
            <div class="section">
                <h2><i class="fas fa-question-circle"></i> What is Steganography?</h2>
                <p>Steganography is the practice of concealing a message, file, image, or video within another file, image, or video. The word steganography combines the Greek words "steganos" (meaning "covered or concealed") and "graphe" (meaning "writing").</p>
                <p>Unlike cryptography, which focuses on keeping the contents of a message secret, steganography focuses on keeping the existence of the message secret. An outside observer should not be able to distinguish between ordinary content and content containing hidden information.</p>
            </div>
            
            <div class="developer-profile">
                <div class="developer-img">
                    <i class="fas fa-user" style="font-size: 80px; color: #3498db;"></i>
                </div>
                <h2>Vaibhav Sharma</h2>
                <h3>Developer & Cybersecurity Enthusiast</h3>
                <div class="developer-bio">
                    <p>Hi there! I'm Vaibhav Sharma, a passionate developer with expertise in cryptography, web development, and information security. I created this steganography application to demonstrate how data can be securely hidden within digital images.</p>
                    <p>My work focuses on creating innovative solutions that merge security with user-friendly interfaces. I believe that privacy tools should be accessible to everyone, not just security experts.</p>
                </div>
                <div class="social-links">
                    <a href="#" title="GitHub"><i class="fab fa-github"></i></a>
                    <a href="#" title="LinkedIn"><i class="fab fa-linkedin-in"></i></a>
                    <a href="#" title="Twitter"><i class="fab fa-twitter"></i></a>
                    <a href="#" title="Email"><i class="fas fa-envelope"></i></a>
                </div>
            </div>
            
            <div class="section">
                <h2><i class="fas fa-cogs"></i> How This Application Works</h2>
                <p>This application uses two main techniques to secure your data:</p>
                
                <div class="technique-grid">
                    <div class="technique-card">
                        <h3><i class="fas fa-shield-alt"></i> AES-256 Encryption</h3>
                        <p>Before hiding your message, we encrypt it using the Advanced Encryption Standard (AES) with a 256-bit key derived from your password. This ensures that even if someone knows there's hidden data in the image, they cannot read it without your key.</p>
                        <p>AES is one of the most secure encryption algorithms available today, used by governments and organizations worldwide to protect sensitive data.</p>
                    </div>
                    
                    <div class="technique-card">
                        <h3><i class="fas fa-mask"></i> LSB Steganography</h3>
                        <p>After encryption, we use the Least Significant Bit (LSB) technique to hide the encrypted data. This works by replacing the least significant bit of each pixel's color values with bits from our encrypted message.</p>
                        <p>Since changing the LSB has minimal impact on the image's appearance, the modified image looks virtually identical to the original to the human eye.</p>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2><i class="fas fa-lightbulb"></i> Use Cases for Steganography</h2>
                <ul>
                    <li><strong>Private Communication:</strong> Share sensitive information without raising suspicion</li>
                    <li><strong>Digital Watermarking:</strong> Embed copyright information or ownership details in media</li>
                    <li><strong>Data Authentication:</strong> Verify the integrity and authenticity of files</li>
                    <li><strong>Secure Storage:</strong> Store sensitive data in plain sight</li>
                    <li><strong>Whistleblowing:</strong> Securely transmit evidence or sensitive information</li>
                    <li><strong>Two-Factor Authentication:</strong> Use steganographic images as part of multi-factor authentication</li>
                </ul>
            </div>
            
            <div class="security-tips">
                <h2><i class="fas fa-shield-alt"></i> Security Best Practices</h2>
                <ul>
                    <li>Use strong, unique passwords for encryption</li>
                    <li>Don't share the original cover image alongside the steganographic image</li>
                    <li>Avoid using the same cover image multiple times</li>
                    <li>Remember that some image processing, compression, or format conversions may destroy hidden data</li>
                    <li>For maximum security, combine steganography with other security measures</li>
                    <li>Be cautious about how and where you share steganographic images</li>
                    <li>Use secure, end-to-end encrypted channels for transmission when possible</li>
                </ul>
            </div>
        </div>
    </div>
    
    <footer>
        <p>Secure Image Steganography Application &copy; 2025</p>
        <div class="developer-info">
            <p>Developed with <i class="fas fa-heart" style="color: #e74c3c;"></i> by Vaibhav Sharma</p>
            <div class="dev-social">
                <a href="#" title="GitHub"><i class="fab fa-github"></i></a>
                <a href="#" title="LinkedIn"><i class="fab fa-linkedin"></i></a>
                <a href="#" title="Twitter"><i class="fab fa-twitter"></i></a>
            </div>
        </div>
    </footer>
</body>
</html>
'''

if __name__ == '__main__':
    app.run(debug=True)