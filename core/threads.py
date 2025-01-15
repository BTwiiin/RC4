"""
Threaded RC4 Encryption/Decryption Demo

This script demonstrates how two 'users' can communicate using RC4 encryption/decryption
in separate threads. User1 encrypts a message, and User2 decrypts the shared ciphertext.
A threading.Event is used to properly synchronize access to the shared ciphertext without
busy-waiting.
"""

import queue
import threading
import pytest
from core.rc4 import rc4  # Make sure rc4.py is in the same directory or properly installed.

def user1_encrypt(key, plaintext, message_queue):
    """
    User1 encrypts the plaintext using RC4 and places the ciphertext
    into the message_queue.
    """
    ciphertext = rc4(key, plaintext)
    print(f"[User1] Encrypted and sent: {ciphertext.hex()}")
    message_queue.put(ciphertext)

def user2_decrypt(key, message_queue, result_queue):
    """
    User2 waits to receive ciphertext from message_queue, decrypts it,
    and puts the decrypted result in result_queue.
    """
    print("[User2] Waiting for ciphertext...")
    ciphertext = message_queue.get()  # Blocks until something is available
    decrypted = rc4(key, ciphertext)
    print(f"[User2] Received and decrypted: {decrypted.decode('utf-8')}")
    result_queue.put(decrypted)  # For verification by the test/demo

def demo_communication(key, plaintext):
    """
    Demonstrates single-pass communication:
    - User1 encrypts a message and sends it via queue.
    - User2 decrypts it and returns the result via another queue.
    """
    message_queue = queue.Queue()
    result_queue = queue.Queue()

    # Create and start threads
    t1 = threading.Thread(target=user1_encrypt, args=(key, plaintext, message_queue))
    t2 = threading.Thread(target=user2_decrypt, args=(key, message_queue, result_queue))

    t1.start()
    t2.start()

    t1.join()
    t2.join()

    # Get the decrypted result (for demonstration)
    decrypted = result_queue.get()
    print("[Main] Final Decrypted Message:", decrypted.decode("utf-8"))


