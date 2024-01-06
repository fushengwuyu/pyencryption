# author: sunshine
# datetime:2024/1/4 上午10:02
import json
import base64
import struct
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad
import hashlib
import random
from datetime import datetime, timedelta

from Cryptodome.Util.Padding import unpad

BASE_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"


def get_license(start, days, plat):
    start_date = datetime.strptime(start, BASE_TIME_FORMAT)
    expired_date = start_date + timedelta(days=days)

    l = dict(StartTime=start,
             ExpiredTime=expired_date.strftime(BASE_TIME_FORMAT),
             AppId=plat)
    # 加密
    info_b = json.dumps(l).encode('utf-8')
    aes_key = rand_string(16)
    aes_iv = rand_string(16)

    aes_info, err = aes_128_encrypt_pkcs7_unpadding(info_b, aes_key, aes_iv)
    if err:
        print("AES encrypt error:", err)
        return None

    aes_info_len = len(aes_info)

    rsa_before = aes_key.encode('utf-8') + aes_iv.encode('utf-8') + aes_info
    rsa_info, err = rsa_pri_encrypt(rsa_before)
    if err:
        print("RSA private encrypt error:", err)
        return None

    rsa_info_len = len(rsa_info)

    res_byte = struct.pack('>H', rsa_info_len) + rsa_info + struct.pack('>H', aes_info_len) + aes_info

    return base64.b64encode(res_byte).decode('utf-8')


def aes_128_encrypt_pkcs7_unpadding(data, key, iv):
    print(key.encode('utf-8'), iv.encode('utf-8'))
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv.encode('utf-8'))
    encrypted_data = cipher.encrypt(pad(data, AES.block_size))
    return encrypted_data, None


def rsa_pri_encrypt(data):
    # 请替换为你的私钥路径
    private_key_path = "rsa_private.key"
    with open(private_key_path, "rb") as f:
        private_key = RSA.import_key(f.read())

    cipher = PKCS1_OAEP.new(private_key)
    rsa_info = cipher.encrypt(data)

    return rsa_info, None


def rsa_pri_encrypt_v1(data):
    from rsa import transform, core
    import rsa
    with open('rsa_private.key', 'rb') as rd:
        pri_key = rd.read()
    key = rsa.PrivateKey.load_pkcs1(pri_key)
    d = key.e
    n = key.n
    num = transform.bytes2int(data)
    encrypto = core.encrypt_int(num, d, n)
    out = transform.int2bytes(encrypto)
    # sep_idx = out.index(b"\x00", 2)
    # out = out[sep_idx + 1:]
    return out, None


def rand_string(length):
    return ''.join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=length))


def sha1(data):
    return hashlib.sha1(data).digest()


def aes_enc():
    info_b = 'hello world'.encode('utf-8')
    aes_key, aes_iv = 'k' * 16, 'v' * 16
    aes_info, err = aes_128_encrypt_pkcs7_unpadding(info_b, aes_key, aes_iv)
    aes_info_len = len(aes_info)
    res_byte = struct.pack('>H', aes_info_len) + aes_info
    return base64.b64encode(res_byte).decode('utf-8')


def aes_dec(license_text):
    li_byte = base64.b64decode(license_text)

    offset = 0
    aes_len_byte = li_byte[offset:offset + 2]
    offset += 2
    aes_len = struct.unpack('>H', aes_len_byte)[0]
    aes_info_byte = li_byte[offset: offset+aes_len]
    key = aes_info_byte[:16]
    iv = aes_info_byte[16:32]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    res = unpad(cipher.decrypt(aes_info_byte), AES.block_size)
    print(res.decode())



# # 示例用法
start_time = "2022-01-01T00:00:00"
license_days = 30000
app_id = "knowlage"

license_string = get_license(start_time, license_days, app_id)
print("Generated License:", license_string)

# print(aes_enc())
# print(aes_dec(aes_enc()))

