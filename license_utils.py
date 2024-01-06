# author: sunshine
# datetime:2024/1/3 下午4:25

import datetime
import base64
import json
import struct
import requests
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from pydantic import BaseModel
import rsa
from rsa import transform, core


class LicenseService(BaseModel):
    public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn2rbggIJ7sJang/g85oc
FaejgZqYGGVYCQNB5piFHB7S1b0ZQx+lLTTwlttzGrplJ5/EiNcJLJzUi4LbMBUb
zGcUUMjr6NGUp/9qB+S9LefUN98o8iKuVnPDQvUwZla4ujFcZ2kz1NCrssKFDW9i
u4IkTG1SOA3D286JEY+lnBc4QXGNcXAC7YwFm7NUJwPzz/MkwpfkSVcua+nykz2Z
L4omIXp3sl+S0EHVcKx2QCf+KKVniOL/aFo4VUegMryPi7tARmH8LXuNtNnWN2m9
3+zrkWKlDrj+LENMkt6EstsvkJALIz+LepCteNRaYa/FsPnGILPq0HRtfs8mVLR1
TwIDAQAB
-----END PUBLIC KEY-----"""

    plat = "knowlage"
    license_server_url = ''

    def check_license(self, license_text):
        # 1. 解密license
        sens = self.decode_license(license_text)
        sens = json.loads(sens)
        expired_time = datetime.strptime(sens['expired'], "%Y-%m-%d %H:%M:%S")
        start_time = datetime.strptime(sens['start'], "%Y-%m-%d %H:%M:%S")
        now = datetime.now()
        if start_time > now or now > expired_time:
            raise Exception('证书失效，请联系服务商获取最新的证书！')

        if sens['app'] != self.plat:
            raise Exception('请获取正确平台的证书！')

        mac = self.get_mac()
        if mac != sens['feature']:
            raise Exception('证书验证失败，请使用授权的服务器！')
        return sens['expired']

    def get_mac(self):
        try:
            response = requests.get(self.license_server_url)
            if response.status_code != 200:
                raise Exception('证书服务器链接失败！')
            rsa_info = self.rsa_decrypt(base64.b64decode(response.content))
            return rsa_info.decode()
        except Exception as e:
            raise Exception(f'证书服务器链接失败！ {e}')

    def decode_license(self, license_text):
        # struct.pack('>H', rsa_info_len) + rsa_info + struct.pack('>H', aes_info_len) + aes_info
        li_byte = base64.b64decode(license_text)

        offset = 0
        rsa_len_byte = li_byte[offset:offset + 2]

        offset += 2
        rsa_len = struct.unpack('>H', rsa_len_byte)[0]

        rsa_info_byte = li_byte[offset:offset + rsa_len]
        offset += rsa_len
        rsa_info = self.rsa_decrypt(rsa_info_byte)
        aes_len_byte = li_byte[offset:offset + 2]
        aes_len = struct.unpack('>H', aes_len_byte)[0]

        offset += 2
        aes_info_byte = li_byte[offset:]

        if aes_len != len(aes_info_byte):
            raise ValueError("数据长度错误")

        key, iv = self.check_hash(rsa_info, aes_info_byte)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        res = unpad(cipher.decrypt(aes_info_byte), AES.block_size)
        return res.decode()

    def check_hash(self, rsa_info, aes_info_byte):
        # 实现你的checkHash函数逻辑，返回key和iv
        # 示例：假设checkHash的逻辑为简单地截取前16个字节作为key，后16个字节作为iv
        key = rsa_info[:16]
        iv = rsa_info[16:32]
        return key, iv

    def rsa_decrypt(self, encrypt_text):

        key = rsa.PublicKey.load_pkcs1_openssl_pem(self.public_key.encode('utf-8'))
        d = key.e
        n = key.n
        num = transform.bytes2int(encrypt_text)
        decrypto = core.decrypt_int(num, d, n)
        out = transform.int2bytes(decrypto)

        sep_idx = out.index(b"\x00", 2)
        out = out[sep_idx + 1:]
        return out


if __name__ == '__main__':
    cipher_text = 'AQCBlcAa5lDpffqw4kOleFhZGSMK8tbgxcoEJ9exUQfI0X9S4EQGDeR4QzzLrAYt8GtFVFicLpqRNzPbL132ZknWedaf8R25IBVGB64SRhfRgW4EUNu3SCrah0siYohkhR7+55aWMH0Fr/lpCOIbgEnwgwmVwNLbDXLrZOWSlY66kUTJ8mYShESz/hnYIPfsmxPkLFgU3MBH3B66mZ7Z7TK4Uvx9bevYKCu78Lv7ajXmO3mXUpqhJ8Srm7ahCdyxRPhRfzapOwvPqyUTfKbGqzQ2Ubt5m5eIQ+ZnBuNwdYeq1BhqnMUZShNQ4uQlGJodaiNni/rKQm44+hSl9G5/eK/cAGDSSXJHfv/hz/OcGVRYt1rAUmAMDKKB+KjyHOIrQlhujOj7e0LLg/pxCBNvXa8rOhNinUgmLPy4gcyp1EL7NhM2Fd44lsL0HgG2E5YKdq9S3VjBMYZYeIbktOLvnBFjzWU='

    t_cipher_text = 'AQAkb4ZzUnZ1JwDINKD9Pf5eocpco0qANbncRbqkyne6ib8iO+UuAHSQpV3HqHDBY4F9ne7Nmg79sedA7PHoGwEJgISDLxrzi+7QE31dkWWKq3DCHcCD+07sD+khBNfQTZ+1XVlRvtJC7gDfAG9nWc+RRynCYphvccV9ySL6uz8+RSjl3S4mbCgW2L/ee0y0ucOZUaUC5ITrSyi5Q7HshXeXoW890iQVecbyPQqu9EIOkj329+uorDlF+VPtqESC9xnqFemi/cWyCs3zXbS2pd2mBVEqtwYq7vKvD3kUETDYN2j09EQ0Rr3DFwULONgny+JdZ6yuR20NuTsHBksybsJLAJAhTRTJRdeEHfosNWLa592Bctbeze+0oFJ2efodRWI8bcBLZJdnlsxuxH6MMIIvR+R1VFjEexQL+pNWho69sc3ncmLIIcxvhOSUrY4/mZQ1wwofNdxDEeyAkZPXoCMxJxnazc80b6mM3aeDocmoq/eb05i94Uz9qQhLODzXw0xokNmF1W3IPbDb2CyzO4PRKmU='
    LicenseService(license_server_url='http://192.168.16.7:34567/license/feature').check_license(cipher_text)

    text = b'hello world'


    def enc():
        with open('rsa_private.key', 'rb') as rd:
            pri_key = rd.read()
        key = rsa.PrivateKey.load_pkcs1(pri_key)
        d = key.e
        n = key.n
        num = transform.bytes2int(text)
        encrypto = core.encrypt_int(num, d, n)
        out = transform.int2bytes(encrypto)
        # sep_idx = out.index(b"\x00", 2)
        # out = out[sep_idx + 1:]
        print(out)
        return out


    def dec(encrypt_text):
        with open('rsa_public.key', 'rb') as rd:
            pub_key = rd.read()
        key = rsa.PublicKey.load_pkcs1_openssl_pem(pub_key)
        d = key.e
        n = key.n
        num = transform.bytes2int(encrypt_text)
        decrypto = core.decrypt_int(num, d, n)
        out = transform.int2bytes(decrypto)
        sep_idx = out.index(b"\x00", 2)
        out = out[sep_idx + 1:]
        return out.decode()

    # cipher_text = enc()
    # print(dec(cipher_text))
