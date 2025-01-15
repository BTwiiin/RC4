import queue
import threading
import pytest
from core.rc4 import ksa, prga, rc4
from core.threads import user1_encrypt, user2_decrypt
from Crypto.Cipher import ARC4

def test_ksa_small_key():
    """
    Test the KSA function with a small key.
    """
    key = b"\x01"
    S = ksa(key)
    # Check the length of S
    assert len(S) == 256
    # Check that S is a permutation of 0..255
    assert sorted(S) == list(range(256))


def test_binary_data_encryption():
    """
    Test encryption and decryption of binary data.
    """
    key = b"binarykey"
    plaintext = bytes(range(256))  # Binary data from 0x00 to 0xFF
    ciphertext = rc4(key, plaintext)
    decrypted = rc4(key, ciphertext)
    assert decrypted == plaintext


def test_encrypt_decrypt_roundtrip():
    """
    Tests rc4() encryption and decryption in a round-trip manner.
    Ensures that decrypted text matches the original plaintext.
    """
    key = "secret"
    plaintext = b"Hello World!"
    ciphertext = rc4(key, plaintext)
    decrypted = rc4(key, ciphertext)
    assert decrypted == plaintext


def test_compare_with_library():
    """	
    Compare our RC4 implementation with PyCryptodome's ARC4.	
    """	
    key = b"SecretKey"
    plaintext = b"This is a test message for RC4."

    our_ciphertext = rc4(key, plaintext)

    cipher = ARC4.new(key)
    library_ciphertext = cipher.encrypt(plaintext)

    assert our_ciphertext == library_ciphertext, "Our RC4 output differs from ARC4 library output"



def test_empty_plaintext():
    """
    Encryption of an empty plaintext should yield empty ciphertext.
    """
    key = "empty"
    plaintext = b""
    ciphertext = rc4(key, plaintext)
    assert ciphertext == b""


def test_large_key():
    """
    Test encryption with a 256-byte key (0..255).
    Ensures code handles max key length properly.
    """
    key = bytes(range(256))
    plaintext = b"Test with large key"
    ciphertext = rc4(key, plaintext)
    # Just check that we can decrypt it back
    decrypted = rc4(key, ciphertext)
    assert decrypted == plaintext


def test_special_chars():
    """
    Special characters in both key and plaintext with repeated encryption/decryption cycles.
    """
    key = "!@#$%^&*()"
    original_plaintext = b"Line1\nLine2\r\n\tTabbed"
    
    # Perform multiple encryption and decryption cycles
    cycles = 5  # Number of repeated cycles
    plaintext = original_plaintext
    for _ in range(cycles):
        ciphertext = rc4(key, plaintext)
        plaintext = rc4(key, ciphertext)  # Decrypt back to original
        # After decryption, plaintext should match original
        assert plaintext == original_plaintext, "Decrypted text does not match original"



@pytest.mark.parametrize("key, plaintext", [
    ("secret", b"Hello, User2 from queue!"),
    ("short", b"abc"),
    ("longkey", b"Some random text to test queue-based flow"),
])
def test_queue_communication(key, plaintext):
    """
    Tests the queue-based communication between User1 and User2.
    Checks that the decrypted text matches the original plaintext.
    """
    message_queue = queue.Queue()
    result_queue = queue.Queue()

    # Spawn threads
    t1 = threading.Thread(target=user1_encrypt, args=(key, plaintext, message_queue))
    t2 = threading.Thread(target=user2_decrypt, args=(key, message_queue, result_queue))

    # Start threads
    t1.start()
    t2.start()

    # Wait for threads to finish
    t1.join()
    t2.join()

    # Verify the result
    decrypted = result_queue.get()
    assert decrypted == plaintext, (
        f"Decrypted text ({decrypted}) does not match original ({plaintext})."
    )