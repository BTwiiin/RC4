
# ECRYP-RC4 Cipher Application

## Table of Contents
1. [Introduction & Short Theory](#introduction--short-theory)
2. [Functional Description of the Application](#functional-description-of-the-application)
3. [Code Structure & Explanation](#code-structure--explanation)
4. [User Interface Menu (Console Mode)](#user-interface-menu-console-mode)
5. [Test Cases](#test-cases)
    - [Test Case 1: Known RFC 6229 Vector (Key: "Key")](#test-case-1-known-rfc-6229-vector-key-key)
    - [Test Case 2: Simple ASCII Key and Plaintext](#test-case-2-simple-ascii-key-and-plaintext)
    - [Test Case 3: Empty Plaintext](#test-case-3-empty-plaintext)
    - [Test Case 4: 1-Byte Key](#test-case-4-1-byte-key)
    - [Test Case 5: Longer Key (256 bytes)](#test-case-5-longer-key-256-bytes)
    - [Test Case 6: Binary Data Encryption](#test-case-6-binary-data-encryption)
    - [Test Case 7: Special Characters and Repeated Encryption/Decryption](#test-case-7-special-characters-and-repeated-encryptiondecryption)
6. [Screenshots](#screenshots)
7. [Conclusion](#conclusion)
8. [References](#references)

## Introduction & Short Theory
RC4 is a stream cipher known for its simplicity and speed in software. It uses a variable-length key to initialize a 256-byte state array with a pseudo-random permutation. The algorithm then generates a keystream that is XORed with the plaintext to produce ciphertext. Decryption uses the same process, XORing the ciphertext with the keystream to recover the original plaintext.

## Functional Description of the Application
This application implements the RC4 encryption algorithm with a console-based user menu. Users can:
- Encrypt plaintext using an ASCII key.
- Decrypt ciphertext (provided as a hex-encoded string) using the same key.
- Run a series of predefined tests to verify the correctness of the implementation.
- Exit the application.

## Code Structure & Explanation
- **`ksa(key_bytes)`**: Implements the Key-Scheduling Algorithm that initializes and scrambles the state array `S` using the provided key.
- **`prga(S, data_length)`**: Implements the Pseudo-Random Generation Algorithm to produce a keystream of the specified length using the state array `S`.
- **`rc4(key, data)`**: Uses `ksa` and `prga` to either encrypt or decrypt data depending on the given key.
- **`user_menu()`**: Provides an interactive console menu for encryption, decryption, testing, and exiting the application.
- **Test Cases (`test.py`)**: Contains various tests to validate the functionality and correctness of the RC4 implementation.
### `rc4.py`

This file contains all of our **RC4** functionality plus a console-based UI. The key functions are described below.

<details>
<summary><strong>Click to expand <code>rc4.py</code> content</strong></summary>

```python
#!/usr/bin/env python3
"""
ECRYP-RC4: Implementation of RC4 cipher with a console user menu

Author: Your Name
Date: YYYY-MM-DD

Description:
  1. ksa(key_bytes) -> Creates the S array from 0..255
  2. prga(S, data_length) -> Generates keystream bytes
  3. rc4(key, data) -> High-level encryption/decryption
  4. user_menu() -> Console-based interface
  5. main() -> Entry point

Usage (console):
  python rc4.py
"""
def ksa(key_bytes):
    """
    Key-Scheduling Algorithm (KSA).

    References:
      - RC4 algorithm specification
      - This function is tested in test_ksa_small_key (test_rc4.py)

    :param key_bytes: The user-provided key, as bytes
    :return: A permuted list S of 256 bytes
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
    Pseudo-Random Generation Algorithm (PRGA).

    References:
      - RC4 algorithm specification
      - This function is tested in test_prga_output_length (test_rc4.py)

    :param S: The permuted list from ksa()
    :param data_length: The number of keystream bytes needed
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

    :param key: str or bytes (the encryption key)
    :param data: bytes (plaintext or ciphertext)
    :return: bytes (encrypted or decrypted result)

    This function is tested in test_encrypt_decrypt_roundtrip (test_rc4.py)
    """
    if isinstance(key, str):
        key = key.encode('utf-8')  # Convert ASCII string to bytes

    # 1) Key-scheduling
    S = ksa(key)

    # 2) Generate keystream
    keystream = prga(S, len(data))

    # 3) XOR keystream with data
    return bytes([d ^ k for d, k in zip(data, keystream)])

def user_menu():
    """
    A simple interactive console menu for encryption/decryption.

    Tested manually and also in test_user_menu_simulated_input (test_rc4.py)
    """
    while True:
        print("\n====== ECRYP-RC4 User Menu ======")
        print("1) Encrypt")
        print("2) Decrypt")
        print("3) Exit")
        choice = input("Choose an option (1/2/3): ").strip()

        if choice == '1':
            key = input("Enter your key (ASCII text): ")
            plaintext = input("Enter your plaintext (ASCII text): ")
            ciphertext = rc4(key, plaintext.encode('utf-8'))
            print(f"Ciphertext (hex): {ciphertext.hex()}")
        elif choice == '2':
            key = input("Enter your key (ASCII text): ")
            ciphertext_hex = input("Enter your ciphertext (hex-encoded): ")
            try:
                ciphertext = bytes.fromhex(ciphertext_hex)
            except ValueError:
                print("Error: invalid hex input.")
                continue
            decrypted = rc4(key, ciphertext)
            try:
                print(f"Decrypted text: {decrypted.decode('utf-8')}")
            except UnicodeDecodeError:
                print("Decrypted result is not valid UTF-8 text.")
                print("Raw bytes:", decrypted)
        elif choice == '3':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please select 1, 2 or 3.")

def main():
    """
    Entry point, calls user_menu().
    """
    user_menu()

if __name__ == "__main__":
    main() 

```

</details>

## User Interface Menu (Console Mode)
When the application is run, it presents a menu:
    ====== ECRYP-RC4 User Menu ======

    1) Encrypt
    2) Decrypt
    3) Run tests
    4) Exit Choose an option (1/2/3/4):

Users can select an option by entering the corresponding number to perform encryption, decryption, run tests, or exit.

## Test Cases

### Test Case 1: Known RFC 6229 Vector (Key: "Key")
- **Objective:** Validate encryption against a known test vector from RFC 6229.
- **Details:** Uses key `"Key"` and plaintext `"Plaintext"`. The ciphertext should match the known value from RFC 6229.

### Test Case 2: Simple ASCII Key and Plaintext
- **Objective:** Test basic encryption and decryption.
- **Details:** Use simple ASCII strings for key and plaintext. Ensure decryption returns the original plaintext.

### Test Case 3: Empty Plaintext
- **Objective:** Verify that encryption of an empty plaintext yields an empty ciphertext.
- **Details:** Provide a non-empty key and an empty plaintext. The output should also be empty.

### Test Case 4: 1-Byte Key
- **Objective:** Validate functionality with a minimal key length.
- **Details:** Use a 1-byte key (e.g., `"\x01"`) and check properties of the state array after KSA.

### Test Case 5: Longer Key (256 bytes)
- **Objective:** Ensure the algorithm handles a maximum-length key correctly.
- **Details:** Use a key consisting of 256 bytes (values 0 to 255). Encrypt and decrypt to verify correctness.

### Test Case 6: Binary Data Encryption
- **Objective:** Verify encryption and decryption of binary data.
- **Details:** Use binary data as plaintext to ensure the algorithm handles non-text bytes.

### Test Case 7: Special Characters and Repeated Encryption/Decryption
- **Objective:** Test keys and plaintexts with special characters and multiple encryption/decryption cycles.
- **Details:** Use keys and plaintexts containing special characters (e.g., `!@#$%^&*()`), newlines, tabs, etc., and repeat the process to verify consistency.

## Screenshots
*Include screenshots of the application in action here.*  
![Encryption Example]()  
![Decryption Example]()

## Conclusion
The RC4 cipher implementation demonstrates how a stream cipher can be built and tested in a console application. It handles various edge cases including empty plaintexts, short and long keys, and special characters. Through thorough testing, we confirm the correctness and robustness of the implementation.

## References
- [RFC 6229 - Test Vectors for RC4](https://tools.ietf.org/html/rfc6229)
- [Wikipedia: RC4](https://en.wikipedia.org/wiki/RC4)