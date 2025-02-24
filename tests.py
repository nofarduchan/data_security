import unittest
from cryptography.hazmat.primitives import serialization
import os
from client_ecdh import generate_key_pair, derive_shared_secret, serialize_public_key

class TestECDH(unittest.TestCase):

    def setUp(self):
        """Set up the test environment by generating client and server key pairs."""
        # Generate client and server key pairs for testing
        self.client_private, self.client_public = generate_key_pair()
        self.server_private, self.server_public = generate_key_pair()

        # Random salt for testing
        self.salt = os.urandom(16)

    def test_generate_key_pair(self):
        """Test the key pair generation functionality."""
        print("\nTesting key pair generation...")

        # Testing client key pair generation
        client_private, client_public = generate_key_pair()
        self.assertIsNotNone(client_private)
        self.assertIsNotNone(client_public)

        # Testing server key pair generation
        server_private, server_public = generate_key_pair()
        self.assertIsNotNone(server_private)
        self.assertIsNotNone(server_public)

        print("Generated key pair successfully for both client and server.")

    def test_shared_secret(self):
        """Test the shared secret derivation using ECDH."""
        print("\nTesting shared secret derivation...")

        # Serialize public keys
        client_public_pem = serialize_public_key(self.client_public)
        server_public_pem = serialize_public_key(self.server_public)

        # Simulate key exchange by deserializing the keys
        client_received_public = serialization.load_pem_public_key(server_public_pem)
        server_received_public = serialization.load_pem_public_key(client_public_pem)

        # Deriving shared secrets
        client_shared_key = derive_shared_secret(self.client_private, client_received_public, self.salt)
        server_shared_key = derive_shared_secret(self.server_private, server_received_public, self.salt)

        # Print out both shared keys for debugging
        print(f"Client's derived shared key: {client_shared_key.hex()}")
        print(f"Server's derived shared key: {server_shared_key.hex()}")

        # The derived keys should match
        self.assertEqual(client_shared_key, server_shared_key)
        print("Derived shared secret successfully for both client and server.")

    def test_shared_secret_mismatch(self):
        """Test if shared secrets mismatch when using incorrect keys."""
        print("\nTesting shared secret mismatch...")

        # Serialize public keys and use the same private key for both sides
        wrong_client_private, wrong_client_public = generate_key_pair()
        wrong_server_private, wrong_server_public = generate_key_pair()

        # Deriving shared secrets
        wrong_client_shared_key = derive_shared_secret(wrong_client_private, self.server_public, self.salt)
        wrong_server_shared_key = derive_shared_secret(wrong_server_private, self.client_public, self.salt)

        # The derived keys should NOT match
        self.assertNotEqual(wrong_client_shared_key, wrong_server_shared_key)
        print("Shared secret mismatch test passed: The keys do not match when incorrect keys are used.")

    def test_invalid_key(self):
        """Test if invalid keys are handled correctly."""
        print("\nTesting invalid key deserialization...")
        with self.assertRaises(ValueError):
            # Trying to deserialize an invalid public key
            serialization.load_pem_public_key(b"invalid_key")
        print("Invalid key deserialization test passed.")


if __name__ == "__main__":
    unittest.main()
