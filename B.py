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
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(server_address)
    server_socket.listen(1)

    print("Waiting for connection...\n")
    client_socket, client_address = server_socket.accept()
    print(f"Connection established with {client_address}\n")

    # Generate RSA keys
    public_key, private_key = generate_rsa_keys()
    print(f'Public key: {public_key}')
    print(f'Private key: {private_key}\n')

    # Receive client's public key
    client_public_key = eval(client_socket.recv(1024).decode())
    print(f"Received client's public key: {client_public_key}\n")

    # Send public key to client
    client_socket.send(str(public_key).encode())

    # Receive and decrypt first message (N1)
    encrypted_message_n1 = int(client_socket.recv(1024).decode())
    decrypted_message_n1 = decrypt(encrypted_message_n1, private_key)
    print(f'(1) N1 Decrypted message (using private key B): {decrypted_message_n1}\n')

    message_n2 = int(input("Enter N2 message to send: "))

    # Encrypt both N1 and N2 using clientA.py's public key
    encrypted_message_n1 = encrypt(decrypted_message_n1, client_public_key)
    encrypted_message_n2 = encrypt(message_n2, client_public_key)

    # Send both encrypted messages back to clientA.py
    client_socket.send(str(encrypted_message_n1).encode())
    client_socket.send(str(encrypted_message_n2).encode())
    print('(2) N1 || N2 sent ...\n')

    # Receive and decrypt second message (N2)
    encrypted_message_n2 = int(client_socket.recv(1024).decode())
    decrypted_message_n2 = decrypt(encrypted_message_n2, private_key)
    print(f'(3) N2 Decrypted message (using private key B): {decrypted_message_n2}\n')

    # Close the connection
    client_socket.close()
    server_socket.close()

if __name__ == "__main__":
    main()
