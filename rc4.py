#!/usr/bin/env python3
"""
ECRYP-RC4: Implementation of RC4 cipher with a console user menu
Authors: Ulad Shuhayeu
         Yermukhamed Islam
"""

def ksa(key_bytes):
    """
    Key-Scheduling Algorithm.
    :param key_bytes: The encryption/decryption key in bytes
    :return: The initialized array S (permutation of 0..255)
    """
    S = list(range(256))
    j = 0
    key_len = len(key_bytes)
    for i in range(256):
        j = (j + S[i] + key_bytes[i % key_len]) % 256
        S[i], S[j] = S[j], S[i]
    return S

def prga(S, data_length):
    """
    Pseudo-Random Generation Algorithm.
    :param S: The state array from KSA
    :param data_length: How many bytes of keystream to generate
    :return: A list of keystream bytes
    """
    i = 0
    j = 0
    keystream = []
    for _ in range(data_length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        keystream.append(K)
    return keystream

def rc4(key, data):
    """
    Encrypt/Decrypt data using RC4 with the given key.
    :param key: The key (string or bytes)
    :param data: The plaintext or ciphertext (as bytes)
    :return: Resulting bytes (encrypted or decrypted)
    """
    if isinstance(key, str):
        key = key.encode('utf-8')  # convert ASCII string to bytes

    S = ksa(key)
    keystream = prga(S, len(data))
    result = bytes([d ^ k for d, k in zip(data, keystream)])
    return result

def user_menu():
    """
    Provides a simple console-based user menu:
    1) Encrypt
    2) Decrypt
    3) Exit
    """
    while True:
        print("\n====== ECRYP-RC4 User Menu ======")
        print("1) Encrypt")
        print("2) Decrypt")
        print("3) Run tests")
        print("4) Exit")
        choice = input("Choose an option (1/2/3/4): ").strip()

        if choice == '1':
            key = input("Enter your key (ASCII text): ")
            plaintext = input("Enter your plaintext (ASCII text): ")
            # Convert plaintext to bytes
            plaintext_bytes = plaintext.encode('utf-8')
            # Encrypt
            ciphertext = rc4(key, plaintext_bytes)
            # Show ciphertext in hex format
            print(f"Ciphertext (hex): {ciphertext.hex()}")

        elif choice == '2':
            key = input("Enter your key (ASCII text): ")
            ciphertext_hex = input("Enter your ciphertext (hex-encoded): ")
            try:
                ciphertext = bytes.fromhex(ciphertext_hex)
            except ValueError:
                print("Error: Invalid hex string.")
                continue
            # Decrypt
            decrypted_bytes = rc4(key, ciphertext)
            # Attempt to convert back to ASCII
            try:
                decrypted_text = decrypted_bytes.decode('utf-8')
                print(f"Decrypted text: {decrypted_text}")
            except UnicodeDecodeError:
                print("Decrypted data is not valid UTF-8 text.")
                print(f"Raw bytes: {decrypted_bytes}")
        elif choice == '3':
            # Run tests
            import pytest
            pytest.main(["-x", "test.py"])
        elif choice == '4':
            print("Exiting the application.")
            break
        else:
            print("Invalid choice. Please try again.")

def main():
    """
    Main entry point. Calls the user menu.
    """
    user_menu()

if __name__ == "__main__":
    main()
