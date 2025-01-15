def ksa(key_bytes):
    """
    Key Scheduling Algorithm (KSA) for RC4 stream cipher.
    This function initializes the permutation in the array `S` using the provided key.

    Args:
        key_bytes (bytes): The key to be used for the RC4 algorithm. It should be a sequence of bytes.

    Returns:
        list: A list of 256 integers representing the initial permutation of `S`.
    """

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
    """
    Pseudo-Random Generation Algorithm (PRGA) for RC4 stream cipher.

    Args:
        S (list): The permutation array of 256 bytes.
        data_length (int): The length of the keystream to generate.

    Returns:
        list: The generated keystream of bytes.
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
    Encrypts or decrypts data using the RC4 algorithm.

    Args:
        key (str or bytes): The encryption key. If a string is provided, it will be encoded to bytes using UTF-8.
        data (bytes): The data to be encrypted or decrypted.

    Returns:
        bytes: The encrypted or decrypted data.

    Note:
        This function uses the Key Scheduling Algorithm (KSA) and the Pseudo-Random Generation Algorithm (PRGA) 
        to generate a keystream which is then XORed with the input data to produce the output.
    """

    if isinstance(key, str):
        key = key.encode('utf-8')
    S = ksa(key)
    keystream = prga(S, len(data))
    result = bytes([d ^ k for d, k in zip(data, keystream)])
    return result