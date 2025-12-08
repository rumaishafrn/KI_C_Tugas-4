import socket
import json
from helper import (
    generate_keypair,
    rsa_encrypt,
    rsa_decrypt,
    generate_random_des_key,
    encrypt_list_to_string,
    string_to_encrypted_list,
    des_encrypt,
    des_decrypt,
    rsa_sign,
    rsa_verify
)


def is_hex_string(s):
    """Cek apakah string valid hex."""
    if not s:
        return False
    try:
        bytes.fromhex(s)
        return True
    except ValueError:
        return False


def receive_all_data(sock):
    """Menerima data dari socket sampai menemukan karakter newline (\n)."""
    buffer = bytearray()
    while True:
        try:
            # Meningkatkan buffer agar data besar (termasuk signature) dapat diterima
            chunk = sock.recv(16384) 
            if not chunk:
                # Koneksi terputus
                return None 

            buffer.extend(chunk)
            
            # Cek apakah newline (\n) sudah ada di buffer
            if b'\n' in buffer:
                # Pisahkan data hingga newline pertama (satu pesan lengkap)
                full_data = buffer.split(b'\n', 1)[0]
                return full_data.decode('utf-8').strip()
                
        except socket.timeout:
            return None
        except Exception as e:
            print(f"[Socket Receive Error]: {e}")
            return None


def main():
    print("=" * 50)
    print("--- SERVER (Device 1) with RSA Key Exchange & Digital Signature ---")
    print("=" * 50)

    HOST = "0.0.0.0"
    PORT = 8888

    print("\n[Generating RSA key pair for Server...]")
    public_key, private_key = generate_keypair(bits=1024)
    e, n = public_key
    print("[Server Public Key Generated]")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)

    print(f"\n[Server listening on {HOST}:{PORT}]")
    print("Waiting for Device 2 (Client) to connect...")
    conn, addr = server_socket.accept()
    print(f"\n[Device 2 connected from {addr}]")

    with conn:
        # ----- PUBLIC KEY EXCHANGE -----
        print("\n[Exchanging public keys...]")

        # Send server public key
        server_pubkey_data = json.dumps({"e": e, "n": n})
        conn.sendall((server_pubkey_data + "\n").encode())
        print("[Server public key sent to Client]")

        # Receive client public key (menggunakan fungsi baru)
        client_pubkey_json = receive_all_data(conn)
        if client_pubkey_json is None:
            print("[Connection closed or error during key exchange.]")
            return
            
        client_pubkey = json.loads(client_pubkey_json)
        client_public_key = (client_pubkey["e"], client_pubkey["n"])
        print("[Client public key received]")

        print("\n" + "=" * 50)
        print("[Key exchange complete! Ready for secure communication]")
        print("=" * 50)

        # ----- MAIN MENU LOOP -----
        while True:
            print("\n" + "-" * 50)
            print("Please choose an option:")
            print("  1. Encrypt and Send a message (auto-generate DES key) + SIGN")
            print("  2. Receive and Decrypt a message + VERIFY")
            print("  3. Exit")
            print("-" * 50)

            choice = input("Enter your choice (1, 2, or 3): ")

            # =====================================================
            # 1. SEND MESSAGE (ENCRYPT + SIGN)
            # =====================================================
            if choice == "1":
                plaintext = input("\nEnter the message to encrypt: ")

                try:
                    des_key = generate_random_des_key()
                    print(f"\n[Auto-generated DES key: '{des_key}']")

                    ciphertext_hex = des_encrypt(des_key, plaintext)
                    print(f"[DES encrypted message: {ciphertext_hex}]")

                    encrypted_key = rsa_encrypt(client_public_key, des_key)
                    encrypted_key_str = encrypt_list_to_string(encrypted_key)

                    print(f"[RSA encrypted DES key (first 5 values): {encrypted_key[:5]}...]")

                    # --- DIGITAL SIGNATURE STEP ---
                    data_to_sign = encrypted_key_str + ciphertext_hex
                    signature_list = rsa_sign(private_key, data_to_sign)
                    signature_str = encrypt_list_to_string(signature_list)

                    print("[✓ Message signed with Server Private Key]")

                    package = json.dumps({
                        "encrypted_key": encrypted_key_str,
                        "encrypted_message": ciphertext_hex,
                        "signature": signature_str 
                    })

                    conn.sendall((package + "\n").encode())
                    print("\n[✓ Message sent successfully! (Includes Digital Signature)]")

                except Exception as e:
                    print(f"\n[✗ Error during encryption/signing: {e}]")

            # =====================================================
            # 2. RECEIVE MESSAGE (DECRYPT + VERIFY)
            # =====================================================
            elif choice == "2":
                print("\n[Waiting to receive message from Device 2...]")

                try:
                    # Menerima data menggunakan fungsi baru
                    received = receive_all_data(conn)
                    if received is None:
                        print("[Connection closed by client or error during receive.]")
                        break

                    data = json.loads(received)
                    encrypted_key_str = data["encrypted_key"]
                    encrypted_message_hex = data["encrypted_message"]
                    client_signature_str = data["signature"]

                    print("[Received encrypted DES key, message, and Digital Signature]")

                    # --- DECRYPTION STEP ---
                    encrypted_key_list = string_to_encrypted_list(encrypted_key_str)
                    des_key = rsa_decrypt(private_key, encrypted_key_list)

                    print(f"[Decrypted DES key: '{des_key}']")
                    
                    if not is_hex_string(encrypted_message_hex):
                        print("  Error: Received data is not valid hex. Cannot decrypt.")
                        continue
                        
                    decrypted_text = des_decrypt(des_key, encrypted_message_hex)
                    
                    # --- VERIFICATION STEP ---
                    data_to_verify = encrypted_key_str + encrypted_message_hex
                    client_signature_list = string_to_encrypted_list(client_signature_str)
                    
                    is_valid = rsa_verify(client_public_key, data_to_verify, client_signature_list)

                    if is_valid:
                        print("\n[✓ Digital Signature verified successfully! (Sender is Client)]")
                        print("\n[✓ Message decrypted successfully!]")
                        print(f"  Decrypted message: '{decrypted_text}'")
                    else:
                        print("\n[✗ WARNING: Digital Signature failed verification! (Sender NOT verified)]")
                        print(f"  Decrypted message (POTENSIAL TAMPERING): '{decrypted_text}'")

                except json.JSONDecodeError as e:
                    print(f"\n[✗ Error during JSON decoding (data probably incomplete): {e}]")
                    print(f"   Received raw data (start): {received[:200]}...")
                except Exception as e:
                    print(f"\n[✗ Error during decryption/verification: {e}]")

            # =====================================================
            # 3. EXIT
            # =====================================================
            elif choice == "3":
                print("\n[Exiting program...]")
                break
            else:
                print("\n[Invalid choice. Please enter 1, 2, or 3.]")

    server_socket.close()
    print("\n[Server socket closed. Goodbye!]")


if __name__ == "__main__":
    main()