import os
import shutil
import readchar
import readchar.key

from core.rc4 import rc4

def get_key():
    return readchar.readkey()

def user_menu():
    options = ["Encrypt", "Decrypt", "Run tests", "Run simulation", "Exit"]
    selected = 0

    while True:
        # Clear screen
        os.system('clear' if os.name == 'posix' else 'cls')

        # Get terminal width for centering
        terminal_width = shutil.get_terminal_size().columns

        # Print centered header
        header = "====== ECRYP-RC4 User Menu ======"
        print("\n" + header.center(terminal_width))

        # Print centered menu options
        for i, option in enumerate(options):
            prefix = "> " if i == selected else "  "
            line = f"{prefix}{option}"
            print(line.center(terminal_width))

        key = get_key()
        if key == readchar.key.UP:
            selected = (selected - 1) % len(options)
        elif key == readchar.key.DOWN:
            selected = (selected + 1) % len(options)
        elif key in ('\r', '\n'):  # Enter key
            if selected == 0:
                key_input = input("Enter your key (ASCII text): ")
                plaintext = input("Enter your plaintext (ASCII text): ")
                plaintext_bytes = plaintext.encode('utf-8')
                ciphertext = rc4(key_input, plaintext_bytes)
                print(f"Ciphertext (hex): {ciphertext.hex()}")
            elif selected == 1:
                key_input = input("Enter your key (ASCII text): ")
                ciphertext_hex = input("Enter your ciphertext (hex-encoded): ")
                try:
                    ciphertext = bytes.fromhex(ciphertext_hex)
                except ValueError:
                    print("Error: Invalid hex string.")
                    input("Press Enter to continue...")
                    continue
                decrypted_bytes = rc4(key_input, ciphertext)
                try:
                    decrypted_text = decrypted_bytes.decode('utf-8')
                    print(f"Decrypted text: {decrypted_text}")
                except UnicodeDecodeError:
                    print("Decrypted data is not valid UTF-8 text.")
                    print(f"Raw bytes: {decrypted_bytes}")
            elif selected == 2:
                import pytest
                pytest.main(["-x", "test_rc4.py"])
            elif selected == 3:
                from core.threads import demo_communication
                key_input = input("Enter your key (ASCII text): ")
                plaintext = input("Enter your plaintext (ASCII text): ")
                plaintext_bytes = plaintext.encode('utf-8')
                demo_communication(key_input, plaintext_bytes)
            elif selected == 4:
                print("Exiting the application.")
                break
            input("Press Enter to continue...")
