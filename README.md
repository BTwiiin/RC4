
# ✨ ECRYP-RC4 Cipher Application ✨

---

## 📚 Table of Contents
1. [Introduction & Short Theory](#introduction--short-theory)
2. [Functional Description of the Application](#functional-description-of-the-application)
3. [Code Structure & Explanation](#code-structure--explanation)
4. [User Interface Menu (Console Mode)](#user-interface-menu-console-mode)
5. [Test Cases](#test-cases)
    - [Test Case 1: Compare with Library Implementation](#test-case-1-compare-with-library-implementation)
    - [Test Case 2: Simple ASCII Key and Plaintext](#test-case-2-simple-ascii-key-and-plaintext)
    - [Test Case 3: Empty Plaintext](#test-case-3-empty-plaintext)
    - [Test Case 4: 1-Byte Key](#test-case-4-1-byte-key)
    - [Test Case 5: Longer Key (256 bytes)](#test-case-5-longer-key-256-bytes)
    - [Test Case 6: Binary Data Encryption](#test-case-6-binary-data-encryption)
    - [Test Case 7: Special Characters and Repeated Encryption/Decryption](#test-case-7-special-characters-and-repeated-encryptiondecryption)
6. [Screenshots](#screenshots)
7. [Conclusion](#conclusion)
8. [References](#references)

---

## 🎓 Introduction & Short Theory
What is RC4? <br>
RC4 (Rivest Cipher 4) is a stream cipher designed by Ron Rivest in 1987. It is simple in design and was widely used due to its speed and simplicity, though it is now considered deprecated for many secure applications because of discovered vulnerabilities in certain usage modes. However, it remains an instructive example for learning stream cipher fundamentals.

Overview of the Algorithm <br>
RC4 generates a keystream of pseudo-random bytes, which is then XORed with the plaintext to produce ciphertext. Decryption is the same operation: ciphertext XOR the same keystream recovers the plaintext.

RC4 has two major phases: <br>
1. Key-Scheduling Algorithm (KSA): <br>
    - Input: user-provided key (of length L bytes). <br>
    - Output: an initial permutation of integers 𝑆 (values 0 to 255). <br>
    - Process (pseudocode): 
    ```python
        S = [0, 1, 2, ..., 255]
        j = 0
        for i in range(0..255):
            j = (j + S[i] + key[i mod L]) mod 256
            swap(S[i], S[j])
            
    ```
2. Pseudo-Random Generation Algorithm (PRGA)
    - Input: the array 𝑆 produced by KSA. <br>
    - Output: a keystream of bytes. <br>
    - Process (pseudocode): 
    ```python
        i = 0
        j = 0
        while more bytes needed:
            i = (i + 1) mod 256
            j = (j + S[i]) mod 256
            swap(S[i], S[j])
            K = S[(S[i] + S[j]) mod 256]
            output K
    ```

Encryption/Decryption is simply: <br>

    Ciphertext = Plaintext ⊕ Keystream 

    Plaintext = Ciphertext ⊕ Keystream

---

## ⚙️ Functional Description of the Application
This application implements the RC4 encryption algorithm with a console-based user menu. Users can:
- 🔐 Encrypt plaintext using an ASCII key.
- 🔓 Decrypt ciphertext (provided as a hex-encoded string) using the same key.
- 🧪 Run a series of predefined tests to verify the correctness of the implementation.
- 🚪 Exit the application.

---

## 🛠️ Code Structure & Explanation
- **`ksa(key_bytes)`**: Implements the Key-Scheduling Algorithm that initializes and scrambles the state array `S` using the provided key.
```python
def ksa(key_bytes):
    S = list(range(256))
    j = 0
    
    if (len(key_bytes) == 0):
        print("Key cannot be empty")
        key_bytes = input("Enter your key (ASCII text) again: ")

    key_len = len(key_bytes)

    for i in range(256):
        j = (j + S[i] + key_bytes[i % key_len]) % 256
        S[i], S[j] = S[j], S[i]
    return S
```
- **`prga(S, data_length)`**: Implements the Pseudo-Random Generation Algorithm to produce a keystream of the specified length using the state array `S`.
```python
def prga(S, data_length):
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
```
- **`rc4(key, data)`**: Uses `ksa` and `prga` to either encrypt or decrypt data depending on the given key.
```python
def rc4(key, data):
    if isinstance(key, str):
        key = key.encode('utf-8')
    S = ksa(key)
    keystream = prga(S, len(data))
    result = bytes([d ^ k for d, k in zip(data, keystream)])
    return result
```
- **`user_menu()`**: Provides an interactive console menu for encryption, decryption, testing, and exiting the application.
- **Test Cases (`test.py`)**: Contains various tests to validate the functionality and correctness of the RC4 implementation.
### `rc4.py`

This file contains all of our **RC4** functionality plus a console-based UI. The key functions are described below.

<details>
<summary><strong>Click to expand <code>rc4.py</code> content</strong></summary>

```python
def ksa(key_bytes):
    S = list(range(256))
    j = 0
    
    if (len(key_bytes) == 0):
        print("Key cannot be empty")
        key_bytes = input("Enter your key (ASCII text) again: ")

    key_len = len(key_bytes)

    for i in range(256):
        j = (j + S[i] + key_bytes[i % key_len]) % 256
        S[i], S[j] = S[j], S[i]
    return S

def prga(S, data_length):
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
    if isinstance(key, str):
        key = key.encode('utf-8')
    S = ksa(key)
    keystream = prga(S, len(data))
    result = bytes([d ^ k for d, k in zip(data, keystream)])
    return result

```

</details>

## 💻 User Interface Menu (Console Mode)
When the application is run, it presents a menu:

![Menu Example](img\Menu.png)

Users can select an option by selection the corresponding option to perform encryption, decryption, run tests, or exit using arrows.

## 🧪 Test Cases

Click the badge below to view and manually trigger the test workflow:

[![Run Tests](https://github.com/BTwiiin/RC4/actions/workflows/run-test.yml/badge.svg)](https://github.com/BTwiiin/RC4/actions/workflows/run-test.yml)

### Test Case 1: Compare with Library Implementation
- **Objective:** Validate encryption against a known library implementation.
- **Details:** Encrypt a plaintext message using the RC4 implementation and compare the output with the ciphertext produced by the `ARC4` function from the `Crypto.Cipher` module. This ensures that our implementation is consistent with a well-established library.
```python
def test_compare_with_library():
    key = b"SecretKey"
    plaintext = b"This is a test message for RC4."

    our_ciphertext = rc4(key, plaintext)

    cipher = ARC4.new(key)
    library_ciphertext = cipher.encrypt(plaintext)

    assert our_ciphertext == library_ciphertext, "Our RC4 output differs from ARC4 library output"
```

### Test Case 2: Simple ASCII Key and Plaintext
- **Objective:** Test basic encryption and decryption.
- **Details:** Use simple ASCII strings for key and plaintext. Ensure decryption returns the original plaintext.
```python
def test_encrypt_decrypt_roundtrip():
    key = "secret"
    plaintext = b"Hello World!"
    ciphertext = rc4(key, plaintext)
    decrypted = rc4(key, ciphertext)
    assert decrypted == plaintext
```

### Test Case 3: Empty Plaintext
- **Objective:** Verify that encryption of an empty plaintext yields an empty ciphertext.
- **Details:** Provide a non-empty key and an empty plaintext. The output should also be empty.
```python
def test_empty_plaintext():
    key = "empty"
    plaintext = b""
    ciphertext = rc4(key, plaintext)
    assert ciphertext == b""
```

### Test Case 4: 1-Byte Key
- **Objective:** Validate functionality with a minimal key length.
- **Details:** Use a 1-byte key (e.g., `"\x01"`) and check properties of the state array after KSA.
```python
def test_ksa_small_key():
    key = b"\x01"
    S = ksa(key)
    assert len(S) == 256
    assert sorted(S) == list(range(256))
```

### Test Case 5: Longer Key (256 bytes)
- **Objective:** Ensure the algorithm handles a maximum-length key correctly.
- **Details:** Use a key consisting of 256 bytes (values 0 to 255). Encrypt and decrypt to verify correctness.
```python
def test_large_key():
    key = bytes(range(256))
    plaintext = b"Test with large key"
    ciphertext = rc4(key, plaintext)
    decrypted = rc4(key, ciphertext)
    assert decrypted == plaintext
```

### Test Case 6: Binary Data Encryption
- **Objective:** Verify encryption and decryption of binary data.
- **Details:** Use binary data as plaintext to ensure the algorithm handles non-text bytes.
```python
def test_binary_data_encryption():
    key = b"binarykey"
    plaintext = bytes(range(256))
    ciphertext = rc4(key, plaintext)
    decrypted = rc4(key, ciphertext)
    assert decrypted == plaintext
```

### Test Case 7: Special Characters and Repeated Encryption/Decryption
- **Objective:** Test keys and plaintexts with special characters and multiple encryption/decryption cycles.
- **Details:** Use keys and plaintexts containing special characters (e.g., `!@#$%^&*()`), newlines, tabs, etc., and repeat the process to verify consistency.
```python
def test_special_chars():
    key = "!@#$%^&*()"
    original_plaintext = b"Line1\nLine2\r\n\tTabbed"
    
    cycles = 5
    plaintext = original_plaintext
    for _ in range(cycles):
        ciphertext = rc4(key, plaintext)
        plaintext = rc4(key, ciphertext)
        assert plaintext == original_plaintext, "Decrypted text does not match original"
```

## 📸 Screenshots
Encryption:

![Encryption Example](img\Encrypt.png)  

Decryption:

![Decryption Example](img\Decrypt.png)

Simulation:

![Decryption Example](img\Simulation.png)
## 📚 References
- [Wikipedia: RC4](https://en.wikipedia.org/wiki/RC4)