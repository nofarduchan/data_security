import socket
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import os

def generate_key_pair():
    """
    Generate an elliptic curve key pair (private and public keys).

    Returns:
        tuple: A tuple containing the private key and public key.
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def derive_shared_secret(private_key, peer_public_key, salt):
    """
    Derive a shared secret using Elliptic Curve Diffie-Hellman (ECDH).

    Args:
        private_key (PrivateKey): The private key of the local party.
        peer_public_key (PublicKey): The public key of the remote party.
        salt (bytes): A random salt for key derivation.

    Returns:
        bytes: A derived shared secret.
    """
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"ECDH Key Agreement"
    ).derive(shared_secret)

    return derived_key


def serialize_public_key(public_key):
    """
    Serialize a public key into PEM format.

    Args:
        public_key (PublicKey): The public key to be serialized.

    Returns:
        bytes: The PEM-encoded public key.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def start_client():
    """
    Start the client that connects to the server, performs the
    ECDH key exchange, and verifies the shared secret.
    """
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("localhost", 65432))  # Connect to the server

    # Generate key pair for the client
    client_private, client_public = generate_key_pair()

    # Display the public key of the client
    print("\n--- Client's Public Key ---")
    print(serialize_public_key(client_public).decode())

    # Receive public key and salt from server
    print("\nWaiting for server's public key and salt...")
    server_data = client_socket.recv(1024)
    server_public_key_pem = server_data[:-16]  # Extract server's public key
    salt = server_data[-16:]  # Extract salt

    server_public_key = serialization.load_pem_public_key(server_public_key_pem)

    print("\nServer's Public Key:")
    print(server_public_key_pem.decode())

    print("\nReceived salt:")
    print(salt.hex())

    # Send client's public key to the server
    print("\nSending Client's public key to the server...")
    client_socket.sendall(serialize_public_key(client_public))

    # Derive shared secret using the server's public key and the shared salt
    print("\n--- Deriving Shared Secret ---")
    client_shared_key = derive_shared_secret(client_private, server_public_key, salt)
    print(f"Client's derived shared key: {client_shared_key.hex()}")

    # Receive the server's derived shared key for comparison
    client_socket.sendall(client_shared_key)  # Send the derived key to the server

    # Receive the server's derived shared key for comparison
    server_shared_key_received = client_socket.recv(1024)

    if server_shared_key_received == client_shared_key:
        print("\nShared secret match: The shared key is identical.")
    else:
        print("\nShared secret mismatch: The keys do not match.")

    # Close connection
    client_socket.close()


if __name__ == "__main__":
    start_client()
