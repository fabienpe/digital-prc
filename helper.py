from cryptography.hazmat.primitives import serialization, hashes
import binascii


def get_ec_private_key_fingerprint(key_pem, password=None):
    # Load the private key from the PEM file
    private_key = serialization.load_pem_private_key(
        key_pem, password)

    # Get the private key bytes
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Compute the SHA-256 hash of the private key bytes
    digest = hashes.Hash(hashes.SHA256())
    digest.update(private_key_bytes)
    fingerprint = digest.finalize()

    # Convert the fingerprint to a hex-encoded string
    hex_fingerprint = binascii.hexlify(fingerprint).decode('utf-8')

    return hex_fingerprint
