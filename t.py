import base64
import json

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA


def rsa_pri_encrypt(data):
    """
    rsa加密
    :param data: 明文
    :return:
    """
    # 请替换为你的私钥路径
    private_key_path = "rsa_private.key"
    with open(private_key_path, "rb") as f:
        private_key = RSA.import_key(f.read())

    cipher = PKCS1_OAEP.new(private_key)

    rsa_info = cipher.encrypt(data)
    return base64.b64encode(rsa_info).decode('utf-8')


def rsa_pub_decrypt(data):
    """
    用公钥对密文解密
    :param data: 密文
    :return:
    """
    data = base64.b64decode(data)
    public_key_path = "rsa_public.key"  # 使用公钥路径
    with open(public_key_path, "rb") as f:
        public_key = RSA.import_key(f.read())

    cipher = PKCS1_OAEP.new(public_key)
    rsa_info = cipher.decrypt(data)
    return rsa_info


text = json.dumps({"StartTime": "2022-01-01T00:00:00", "ExpiredTime": "2104-02-21T00:00:00", "AppId": "knowlage"}).encode('utf-8')
cipher_text = rsa_pri_encrypt(text)
print(cipher_text)
text1 = rsa_pub_decrypt(cipher_text)
print(text1)
