import socket
import math
import time

def generate_rsa_keys():
    p = 17
    q = 19
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 2
    while e < phi:
        if math.gcd(e, phi) == 1:
            break
        else:
            e += 1
    d = pow(e, -1, phi) 
    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key

def encrypt(message, public_key):
    e, n = public_key
    C = pow(message, e, n)
    return C

def decrypt(ciphertext, private_key):
    d, n = private_key
    M = pow(ciphertext, d, n)
    return M

def main():
    public_key, private_key = generate_rsa_keys()

    server_address = ('localhost', 12345)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(server_address)
    server_socket.listen(1)

    print("Waiting for connection . . .\n")
    client_socket, client_address = server_socket.accept()
    print(f"Connection established with {client_address}\n")

    print(f'Public key: {public_key}')
    print(f'Private key: {private_key}\n')

    # Send server's public key to the client
    client_socket.send(str(public_key).encode())

    # Receive client's public key from the client
    client_public_key = eval(client_socket.recv(1024).decode())
    print(f"Received client's public key: {client_public_key}\n")

    # Receive encrypted N1 message from client
    encrypted_message_n1 = int(client_socket.recv(1024).decode())
    print(f'(1) N1 Encrypted message: {encrypted_message_n1}')

    # Decrypt N1 using the server's private key
    decrypted_message_n1 = decrypt(encrypted_message_n1, private_key)
    print(f'N1 Decrypted message (using private key B): {decrypted_message_n1}\n')

    message_n2 = int(input("Enter N2 message to send: "))

    # Encrypt N2 using the client's public key
    encrypted_message_n2 = encrypt(message_n2, client_public_key)
    print(f'Encrypted message (using PUB A): {encrypted_message_n2}')

    # Send encrypted N2 message back to clientA.py
    client_socket.send(str(encrypted_message_n2).encode())
    print('(2) N2 sent . . .\n')

    # Receive and decrypt N2 using the server's private key
    encrypted_message_n2 = int(client_socket.recv(1024).decode())
    decrypted_message_n2 = decrypt(encrypted_message_n2, private_key)
    print(f'(3) N2 Decrypted message (using private key B): {decrypted_message_n2}\n')

    # Encrypt and send each 2-bit chunk to A.py
    print('(4) Sending Session Key . . .')
    session_key = '1234567890987612'
    
    session_key_chunks = [session_key[i:i+2] for i in range(0, len(session_key), 2)]

    print(f'Session Key\t: {session_key_chunks}')
    for chunk in session_key_chunks:
        encrypted_chunk = encrypt(int(chunk), client_public_key)
        print(f'sending\t\t: {chunk}')
        print(f'encrypted\t: {encrypted_chunk}\n')
        client_socket.send(str(encrypted_chunk).encode())
        time.sleep(0.5)
    
    print('(5) Session Key sent . . .\n')

    client_socket.close()
    server_socket.close()

if __name__ == "__main__":
    main()
