import socket
import math

def generate_rsa_keys():
    # RSA key generation code (same as provided)
    p = 13
    q = 17
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
    message_n1 = int(input("Enter N1 message to send: "))

    # Encrypt and send message
    encrypted_message_n1 = encrypt(message_n1, server_public_key)
    print(f'Encrypted message (using PUB B): {encrypted_message_n1}')
    client_socket.send(str(encrypted_message_n1).encode())

    print('(1) N1 || ID_A sent ...\n')

     # Receive and decrypt message (N1)
    received_message_n1 = int(client_socket.recv(1024).decode())
    decrypted_message_n1 = decrypt(received_message_n1, private_key)
    print(f'(2) N1 Decrypted message (using private key A): {decrypted_message_n1}')

    # Receive and decrypt message (N2)
    received_message_n2 = int(client_socket.recv(1024).decode())
    decrypted_message_n2 = decrypt(received_message_n2, private_key)
    print(f'N2 Decrypted message (using private key A): {decrypted_message_n2}\n')

    # Send the decrypted N2 message back to server (clientB.py)
    encrypted_message_n2 = encrypt(decrypted_message_n2, server_public_key)
    client_socket.send(str(encrypted_message_n2).encode())
    print('(3) N2 sent ...\n')

    # Close the connection
    client_socket.close()

if __name__ == "__main__":
    main()
