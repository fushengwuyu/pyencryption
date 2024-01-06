import json
import base64
import random
import string
import struct
import binascii
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA
from Crypto.Util.Padding import pad
BASE_TIME_FORMAT = "2006-01-02"


def get_license(start, days, plat):
    l = {"dddd": '的冯绍峰'}
    # 加密
    info_b = json.dumps(l).encode('utf-8')
    aes_key = rand_string(16)
    aes_iv = rand_string(16)

    aes_info, _ = aes_128_encrypt_pkcs7_unpadding(info_b, aes_key.encode('utf-8'), aes_iv.encode('utf-8'))

    rsa_before = aes_key.encode('utf-8') + aes_iv.encode('utf-8') + sha1(aes_info)

    rsa_info, _ = rsa_pri_encrypt(rsa_before)

    res_byte = struct.pack('>H', len(rsa_info)) + rsa_info
    res_byte += struct.pack('>H', len(aes_info)) + aes_info

    return base64.b64encode(res_byte).decode('utf-8')


def rand_string(length):
    # 实现随机字符串生成，这里简化为只包含字母和数字
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for i in range(length))


def aes_128_encrypt_pkcs7_unpadding(data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(data, AES.block_size))
    return encrypted_data, None


def sha1(data):
    h = SHA.new()
    h.update(data)
    return h.digest()


def rsa_pri_encrypt(data):
    # 请将这里替换为你的私钥路径
    private_key_path = "rsa_private.key"
    with open(private_key_path, 'rb') as key_file:
        private_key = RSA.import_key(key_file.read())
    cipher_text = pkcs1_15.new(private_key).sign(SHA.new(data))
    return cipher_text, None


# 示例用法
start_date = "2022-01-01"
days_valid = 30
platform = "example_platform"

license = get_license(start_date, days_valid, platform)
print(license)
