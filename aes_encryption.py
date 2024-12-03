from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os

def pad(text):
    """Pads the text to make it a multiple of 16 bytes."""
    return text + ' ' * (16 - len(text) % 16)

def unpad(text):
    """Removes padding from the text."""
    return text.rstrip()

def encrypt(text, key):
    """Encrypts the text using the AES algorithm and the provided key."""
    key = key.encode().ljust(32, b'\0')[:32]  
    iv = os.urandom(16)  
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_text = pad(text).encode()
    encrypted = iv + encryptor.update(padded_text) + encryptor.finalize()
    return base64.b64encode(encrypted).decode()

def decrypt(encrypted_text, key):
    """Decrypts the encrypted text using the AES algorithm and the provided key."""
    key = key.encode().ljust(32, b'\0')[:32]  
    encrypted_data = base64.b64decode(encrypted_text)
    iv = encrypted_data[:16]  
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
    return unpad(decrypted.decode())

def main():
    while True:
        print("\nAES Encryption/Decryption Program")
        print("1. Encrypt Text")
        print("2. Decrypt Text")
        print("3. Exit")
        choice = input("Enter your choice (1/2/3): ").strip()

        if choice == '1':
            text = input("Enter the text to encrypt: ").strip()
            key = input("Enter the key: ").strip()
            encrypted_text = encrypt(text, key)
            print(f"Encrypted Text: {encrypted_text}")
        elif choice == '2':
            encrypted_text = input("Enter the text to decrypt: ").strip()
            key = input("Enter the key: ").strip()
            try:
                decrypted_text = decrypt(encrypted_text, key)
                print(f"Decrypted Text: ** {decrypted_text} **")
            except Exception as e:
                print("Decryption failed. Please check your key and encrypted text.")
        elif choice == '3':
            print("Exiting the program.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
