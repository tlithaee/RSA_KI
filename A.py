import socket
import math

def generate_rsa_keys():
    # RSA key generation code (same as provided)
    p = 11
    q = 13
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 2
    while e < phi:
        if math.gcd(e, phi) == 1:
            break
        else:
            e += 1
    d = pow(e, -1, phi)  # Fix: use modular inverse to calculate d
    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key

def encrypt(message, public_key):
    # RSA encryption code with modulo parameter
    e, n = public_key
    C = pow(message, e, n)
    return C

def decrypt(ciphertext, private_key):
    # RSA decryption code with modulo parameter
    d, n = private_key
    M = pow(ciphertext, d, n)
    return M

def main():
    # Set up socket connection
    server_address = ('localhost', 12345)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(server_address)

    # Generate RSA keys
    public_key, private_key = generate_rsa_keys()
    print(f'Public key: {public_key}')
    print(f'Private key: {private_key}\n')

    # Send public key to server
    client_socket.send(str(public_key).encode())

    # Receive server's public key
    server_public_key = eval(client_socket.recv(1024).decode())
    print(f"Received server's public key: {server_public_key}\n")

    # Get user input
    message_n1 = int(input("Enter N1 message to send:"))

    # Encrypt and send N1 using server's public key
    encrypted_message_n1 = encrypt(message_n1, server_public_key)
    print(f'Encrypted message (using PUB B): {encrypted_message_n1}')
    client_socket.send(str(encrypted_message_n1).encode())

    print('(1) N1 sent ...\n')

    # Receive and decrypt N2 using client's private key
    encrypted_message_n2 = client_socket.recv(1024).decode()
    if encrypted_message_n2:
        decrypted_message_n2 = decrypt(int(encrypted_message_n2), private_key)
        print(f'(2) N2 Decrypted message (using private key A): {decrypted_message_n2}')

        # Send the decrypted N2 message back to the server (clientB.py)
        encrypted_message_n2 = encrypt(decrypted_message_n2, server_public_key)
        print(f'Encrypted message (using PUB B): {encrypted_message_n2}')
        client_socket.send(str(encrypted_message_n2).encode())
        print('\n(3) N2 sent ...\n')

        # Receive and reconstruct the 16-bit session key
        session_key_chunks = []
        print('(4) Receiving Session Key...')
        for _ in range(8):  # Receive 8 chunks to reconstruct 16 bits
            encrypted_chunk = int(client_socket.recv(1024).decode())
            decrypted_chunk = decrypt(encrypted_chunk, private_key)
            session_key_chunks.append(decrypted_chunk)

            print(f'received\t: {encrypted_chunk}')
            print(f'decrypted\t: {decrypted_chunk}\n')

        # Corrected code to concatenate the 2-bit chunks
        reconstructed_session_key = sum((chunk << (i * 2)) for i, chunk in enumerate(session_key_chunks[::-1]))
        print(f'(5) Decrypted Session Key (using private key A): {reconstructed_session_key:016b}')

    # Close the connection
    client_socket.close()

if __name__ == "__main__":
    main()
