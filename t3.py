# !/usr/bin/env python

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64


def generate_keys():
    modulus_length = 1024

    key = RSA.generate(modulus_length)
    # print (key.exportKey())

    pub_key = key.publickey()
    # print (pub_key.exportKey())

    return key, pub_key


def encrypt_private_key(a_message, private_key):
    encryptor = PKCS1_OAEP.new(private_key)
    encrypted_msg = encryptor.encrypt(a_message)
    print(encrypted_msg)
    encoded_encrypted_msg = base64.b64encode(encrypted_msg)
    print(encoded_encrypted_msg)
    return encoded_encrypted_msg


def decrypt_public_key(encoded_encrypted_msg, public_key):
    encryptor = PKCS1_OAEP.new(public_key)
    decoded_encrypted_msg = base64.b64decode(encoded_encrypted_msg)
    print(decoded_encrypted_msg)
    decoded_decrypted_msg = encryptor.decrypt(decoded_encrypted_msg)
    print(decoded_decrypted_msg)
    # return decoded_decrypted_msg


def main():
    private, public = generate_keys()
    print(private)
    message = b'Hello world'
    encoded = encrypt_private_key(message, public)
    decrypt_public_key(encoded, private)


if __name__ == "__main__":
    main()
