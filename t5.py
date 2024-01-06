# author: sunshine
# datetime:2024/1/4 下午2:12v
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import cryptography


def sign_license(private_key, license_data):
    # 使用私钥签名
    signature = private_key.sign(
        license_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_license(public_key, license_data, signature):
    # 使用公钥验证签名
    try:
        public_key.verify(
            signature,
            license_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except cryptography.exceptions.InvalidSignature:
        return False


def encrypt_sensitive_info(public_key, sensitive_info):
    # 使用公钥加密敏感信息
    ciphertext = public_key.encrypt(
        sensitive_info.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def decrypt_sensitive_info(private_key, ciphertext):
    # 使用私钥解密敏感信息
    decrypted_info = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_info.decode('utf-8')


# 示例用法
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

license_data = b"Valid until 2025-01-01; MAC:00:11:22:33:44:55"
signature = sign_license(private_key, license_data)

# 将敏感信息加密并附加到许可证中
sensitive_info = "Some sensitive information"
encrypted_info = encrypt_sensitive_info(public_key, sensitive_info)

# 将签名和加密后的信息组合成许可证
license_data_with_signature = license_data + b"; Signature:" + signature + b"; EncryptedInfo:" + encrypted_info

# 在验证许可证时，先提取签名和加密后的信息，再进行验证
start_signature = license_data_with_signature.find(b"; Signature:") + len(b"; Signature:")
end_signature = license_data_with_signature.find(b"; EncryptedInfo:")
start_encrypted_info = end_signature + len(b"; EncryptedInfo:")

extracted_signature = license_data_with_signature[start_signature:end_signature]
extracted_encrypted_info = license_data_with_signature[start_encrypted_info:]

# 验证签名
if verify_license(public_key, license_data, extracted_signature):
    # 如果签名验证通过，则解密敏感信息并进行逻辑判断
    decrypted_info = decrypt_sensitive_info(private_key, extracted_encrypted_info)
    print("Decrypted Info:", decrypted_info)
else:
    print("Invalid license signature")
