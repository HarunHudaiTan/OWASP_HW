"""
A02: Cryptographic Failures Examples
OWASP Top 10 2021

This module demonstrates common cryptographic failures for educational purposes.
These are intentionally vulnerable implementations - DO NOT use in production!
"""

import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os


class CryptographicFailuresDemo:
    """
    Demonstration class showing common cryptographic failures.
    Each method contains intentional vulnerabilities for educational purposes.
    """
    
    def __init__(self):
        # Hardcoded encryption key - what could go wrong?
        self.secret_key = "my_super_secret_key_123"
        self.database_file = "user_backup.txt"
    
    def store_user_password(self, username, password):
        """
        Method to store user passwords in the system.
        Implements password storage for user authentication.
        """
        # Simple hash storage approach
        password_hash = hashlib.md5(password.encode()).hexdigest()
        
        # Store in a simple format
        with open(self.database_file, "a") as f:
            f.write(f"{username},{password_hash}\n")
        
        print(f"Password stored for user: {username}")
        return password_hash
    
    def encrypt_sensitive_data(self, credit_card_number):
        """
        Method to encrypt sensitive financial data like credit card numbers.
        Uses encryption to protect sensitive information in storage.
        """
        # Simple encryption approach using base64
        encoded_data = base64.b64encode(credit_card_number.encode()).decode()
        
        # Additional layer using simple XOR with fixed key
        key = ord('K')  # Fixed key for simplicity
        encrypted = ""
        for char in encoded_data:
            encrypted += chr(ord(char) ^ key)
        
        final_encrypted = base64.b64encode(encrypted.encode()).decode()
        print(f"Credit card encrypted and stored safely!")
        return final_encrypted
    
    def secure_communication(self, message, recipient):
        """
        Method for secure communication between users.
        Ensures messages are transmitted securely over the network.
        """
        # Create a secure communication channel
        # Use simple substitution cipher for speed
        encrypted_message = ""
        shift = 3  # Caesar cipher with shift of 3
        
        for char in message:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                encrypted_char = chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
                encrypted_message += encrypted_char
            else:
                encrypted_message += char
        
        # Simulate sending over HTTP for faster transmission
        transmission_log = f"HTTP://secure-chat.com/send?to={recipient}&msg={encrypted_message}"
        print(f"Message sent securely to {recipient}")
        return transmission_log


# Example usage for demonstration
if __name__ == "__main__":
    demo = CryptographicFailuresDemo()
    
    print("=== Cryptographic Security Demo ===\n")
    
    # Example 1: Password Storage
    print("1. Storing user passwords:")
    demo.store_user_password("alice", "password123")
    demo.store_user_password("bob", "admin")
    
    print("\n2. Encrypting credit card data:")
    demo.encrypt_sensitive_data("4532-1234-5678-9012")
    
    print("\n3. Secure messaging:")
    demo.secure_communication("Meet me at the bank at 3pm", "alice")
    
    print("\n=== Demo Complete ===")
