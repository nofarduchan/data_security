import socket
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import os

# Function to generate an elliptic curve key pair (private and public keys)
def generate_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

# Function to derive a shared secret using Elliptic Curve Diffie-Hellman (ECDH)
def derive_shared_secret(private_key, peer_public_key, salt):
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"ECDH Key Agreement"
    ).derive(shared_secret)

    return derived_key

# Function to serialize a public key into PEM format
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("localhost", 65432))  # Listen on port 65432
    server_socket.listen(1)

    print("Server is waiting for a connection...")

    conn, addr = server_socket.accept()
    print(f"Connected to {addr}")

    # Generate key pair for the server
    server_private, server_public = generate_key_pair()

    # Generate a random salt for session
    salt = os.urandom(16)

    # Display the public key of the server
    print("\n--- Server's Public Key ---")
    print(serialize_public_key(server_public).decode())

    # Send public key and salt to the client
    print("\nSending Server's public key and salt to the client...")
    conn.sendall(serialize_public_key(server_public) + salt)

    # Receive public key from client
    print("\nWaiting for client's public key...")
    client_public_key_pem = conn.recv(1024)
    client_public_key = serialization.load_pem_public_key(client_public_key_pem)

    print("\nClient's Public Key:")
    print(client_public_key_pem.decode())

    # Derive shared secret using the client's public key and the shared salt
    print("\n--- Deriving Shared Secret ---")
    server_shared_key = derive_shared_secret(server_private, client_public_key, salt)
    print(f"Server's derived shared key: {server_shared_key.hex()}")

    # Send the derived key to the client for comparison
    conn.sendall(server_shared_key)

    # Receive the client's derived shared key for comparison
    client_shared_key_received = conn.recv(1024)
    if client_shared_key_received == server_shared_key:
        print("\nShared secret match: The shared key is identical.")
    else:
        print("\nShared secret mismatch: The keys do not match.")

    # Close connection
    conn.close()



if __name__ == "__main__":
    start_server()
