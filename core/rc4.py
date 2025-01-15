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