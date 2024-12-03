# Import required modules for AES encryption and decryption
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64  # For encoding and decoding the data
import os      # For generating random initialization vectors (IVs)

# Function to pad the text to a multiple of 16 bytes (required by AES)
def pad(text):
    """Pads the text to make it a multiple of 16 bytes."""
    return text + ' ' * (16 - len(text) % 16)  # Add spaces to the text to make it a multiple of 16

# Function to remove padding (spaces) after decryption
def unpad(text):
    """Removes padding from the text."""
    return text.rstrip()  # Removes trailing spaces

# Function to encrypt the given text using AES algorithm with a key
def encrypt(text, key):
    """Encrypts the text using the AES algorithm and the provided key."""
    # Ensure the key is 32 bytes long (either pad or truncate to fit AES-256)
    key = key.encode().ljust(32, b'\0')[:32]  
    iv = os.urandom(16)  # Generate a random 16-byte initialization vector (IV)
    
    # Create the AES cipher object using the key, mode (CFB), and IV
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    
    # Create an encryptor object for encryption
    encryptor = cipher.encryptor()
    
    # Pad the text to make it a multiple of 16 bytes and encode it to bytes
    padded_text = pad(text).encode()
    
    # Encrypt the padded text and concatenate IV with the encrypted text
    encrypted = iv + encryptor.update(padded_text) + encryptor.finalize()
    
    # Base64 encode the result (this is to make the output printable and easy to store)
    return base64.b64encode(encrypted).decode()

# Function to decrypt the encrypted text using AES algorithm and a key
def decrypt(encrypted_text, key):
    """Decrypts the encrypted text using the AES algorithm and the provided key."""
    # Ensure the key is 32 bytes long (either pad or truncate to fit AES-256)
    key = key.encode().ljust(32, b'\0')[:32]
    
    # Decode the encrypted base64 text back to raw bytes
    encrypted_data = base64.b64decode(encrypted_text)
    
    # Extract the first 16 bytes as the IV
    iv = encrypted_data[:16]
    
    # Create the AES cipher object using the key, mode (CFB), and IV
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    
    # Create a decryptor object for decryption
    decryptor = cipher.decryptor()
    
    # Decrypt the data and remove the padding
    decrypted = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
    
    # Remove any trailing spaces that were used for padding during encryption
    return unpad(decrypted.decode())

# Main function that displays the menu and lets the user choose between encryption, decryption, or exit
def main():
    while True:
        # Display the menu to the user
        print("\nAES Encryption/Decryption Program")
        print("1. Encrypt Text")
        print("2. Decrypt Text")
        print("3. Exit")
        
        # Get the user's choice
        choice = input("Enter your choice (1/2/3): ").strip()

        if choice == '1':
            # If user chooses to encrypt, ask for the text and key
            text = input("Enter the text to encrypt: ").strip()
            key = input("Enter the key: ").strip()
            
            # Encrypt the text and display the encrypted result
            encrypted_text = encrypt(text, key)
            print(f"Encrypted Text: {encrypted_text}")
        
        elif choice == '2':
            # If user chooses to decrypt, ask for the encrypted text and key
            encrypted_text = input("Enter the text to decrypt: ").strip()
            key = input("Enter the key: ").strip()
            
            try:
                # Decrypt the text and display the decrypted result
                decrypted_text = decrypt(encrypted_text, key)
                print(f"Decrypted Text: ** {decrypted_text} **")
            except Exception as e:
                # If decryption fails (e.g., wrong key or corrupted data), show an error message
                print("Decryption failed. Please check your key and encrypted text.")
        
        elif choice == '3':
            # Exit the program if the user chooses option 3
            print("Exiting the program.")
            break
        
        else:
            # Handle invalid choice
            print("Invalid choice. Please try again.")

# This checks if the script is being run directly and starts the main function
if __name__ == "__main__":
    main()
