import pytest
from rc4 import ksa, prga, rc4

def test_ksa_small_key():
    key = b"\x01"
    S = ksa(key)
    # Check the length of S
    assert len(S) == 256
    # Check that S is a permutation of 0..255
    assert sorted(S) == list(range(256))



def test_prga_output_length():
    """
    Test the PRGA function to ensure it returns the correct number of bytes in the keystream.
    """
    key = b"testkey"
    S = ksa(key)
    output_len = 32
    stream = prga(S, output_len)
    assert len(stream) == output_len


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


def test_known_vector_rfc6229():
    """
    Compares to a known RC4 test vector from RFC 6229 or external reference.
    Key = "Key", Plaintext = "Plaintext".
    """
    key = "Key"
    plaintext = b"Plaintext"
    # This known ciphertext is from a reference in RFC 6229 or another known source.
    # You should confirm the exact bytes for your reference.
    known_ciphertext_hex = "bbf316e8d940af0ad3"  # Example placeholder
    ciphertext = rc4(key, plaintext)
    assert ciphertext.hex() == known_ciphertext_hex.lower()


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
    Special characters in both key and plaintext.
    """
    key = "!@#$%^&*()"
    plaintext = b"Line1\nLine2\r\n\tTabbed"
    ciphertext = rc4(key, plaintext)
    # Decrypt
    decrypted = rc4(key, ciphertext)
    assert decrypted == plaintext


# OPTIONAL: Testing the user menu with simulated input (example approach)
def test_user_menu_simulated_input(monkeypatch):
    """
    Demonstrates how you might test user_menu() with Pytest monkeypatch.
    """
    from io import StringIO
    from rc4 import user_menu

    # Sequence of inputs: first "3" to trigger tests, then "4" to exit the menu.
    simulated_inputs = StringIO("3\n4\n")
    monkeypatch.setattr('sys.stdin', simulated_inputs)

    # Run user_menu() - It should handle the inputs without error.
    user_menu()

