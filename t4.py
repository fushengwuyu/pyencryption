# author: sunshine
# datetime:2024/1/4 上午11:46
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()

plaintext = b"Hello, RSA encryption!"

# Encryption
signature = private_key.sign(
    data=plaintext,
    padding=padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    algorithm=hashes.SHA256()
)

# Decryption
decrypted_text = public_key.verify(
    signature=signature,
    data=plaintext,
    padding=padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    algorithm=hashes.SHA256()
)
print(decrypted_text)
