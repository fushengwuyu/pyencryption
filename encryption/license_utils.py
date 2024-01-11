# author: sunshine
# datetime:2024/1/3 下午4:25

import datetime
import base64
import json
import random
import struct
import requests
from datetime import datetime, timedelta
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from pydantic import BaseModel
import M2Crypto.RSA

import subprocess


class CompressFeature:
    def system_info(self):
        command = ["lshw", "-class", "system", "-json"]
        try:
            output = subprocess.check_output(command)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Command execution failed with error: {e}")

        result = json.loads(output.decode("utf-8"))

        if isinstance(result, list):
            infos = []
            for item in result:
                node_id = item.get("id", "")
                uuid = item.get("configuration", {}).get("uuid", "")
                infos.extend([node_id, uuid])
            system_feature = "-".join(infos)
        else:
            node_id = result.get("id", "")
            uuid = result.get("configuration", {}).get("uuid", "")
            system_feature = f"{node_id}-{uuid}"

        return system_feature

    def disk_info(self):
        command = ["lshw", "-class", "disk", "-json"]
        try:
            output = subprocess.check_output(command)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Command execution failed with error: {e}")

        result = json.loads(output.decode("utf-8"))

        if isinstance(result, list):
            infos = [item.get("serial", "") for item in result]
            disk_feature = "-".join(infos)
        else:
            disk_feature = result.get("serial", "")

        return disk_feature

    def network_info(self):
        command = ["lshw", "-class", "network", "-json"]
        try:
            output = subprocess.check_output(command)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Command execution failed with error: {e}")

        result = json.loads(output.decode("utf-8"))

        if isinstance(result, list):
            infos = []
            for item in result:
                serial = item.get("serial", "")
                ip = item.get("configuration", {}).get("ip", "")
                infos.extend([serial, ip])
            net_feature = "-".join(infos)
        else:
            serial = result.get("serial", "")
            ip = result.get("configuration", {}).get("ip", "")
            net_feature = f"{serial}-{ip}"

        return net_feature

    def get_feature(self):
        ...


class LicenseService(BaseModel):
    plat = "knowlage"
    license_server_url = ''
    time_format = "%Y-%m-%d %H:%M:%S"
    public_key: bytes = None

    def set_public_key(self, public_key: str = None, public_file: str = None):
        if public_key is not None:
            self.public_key = public_file.encode()
        elif public_file is not None:
            with open(public_file, 'rb') as rd:
                public_key = rd.read()
            self.public_key = public_key

    def check_license(self, license_text):

        # 1. 解密license
        sens = self.decode_license(license_text)
        sens = json.loads(sens)
        expired_time = datetime.strptime(sens['expired'], self.time_format)
        start_time = datetime.strptime(sens['start'], self.time_format)
        now = datetime.now()
        if start_time > now or now > expired_time:
            raise Exception('证书失效，请联系服务商获取最新的证书！')

        if sens['app'] != self.plat:
            raise Exception('请获取正确平台的证书！')

        mac = self.get_mac()
        if mac != sens['feature']:
            raise Exception('证书验证失败，请使用授权的服务器！')
        return sens['expired']

    def get_license(self, start, days, plat, private_file):
        start_date = datetime.strptime(start, self.time_format)
        expired_date = start_date + timedelta(days=days)

        l = dict(start=start,
                 expired=expired_date.strftime(self.time_format),
                 app=plat)
        # 加密
        info_b = json.dumps(l).encode('utf-8')
        aes_key = self.rand_string(16)
        aes_iv = self.rand_string(16)

        aes_info, err = self.aes_128_encrypt_pkcs7_unpadding(info_b, aes_key, aes_iv)
        if err:
            print("AES encrypt error:", err)
            return None

        aes_info_len = len(aes_info)

        rsa_before = aes_key.encode('utf-8') + aes_iv.encode('utf-8') + aes_info
        rsa_info, err = self.rsa_pri_encrypt(rsa_before, private_file)
        if err:
            print("RSA private encrypt error:", err)
            return None

        rsa_info_len = len(rsa_info)

        res_byte = struct.pack('>H', rsa_info_len) + rsa_info + struct.pack('>H', aes_info_len) + aes_info

        return base64.b64encode(res_byte).decode('utf-8')

    def rsa_pri_encrypt(self, data, private_file):

        rsa_pri = M2Crypto.RSA.load_key(private_file)
        rsa_info = rsa_pri.private_encrypt(data, M2Crypto.RSA.pkcs1_padding)
        return rsa_info, None

    def aes_128_encrypt_pkcs7_unpadding(self, data, key, iv):
        cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv.encode('utf-8'))
        encrypted_data = cipher.encrypt(pad(data, AES.block_size))
        return encrypted_data, None

    def rand_string(self, length):
        return ''.join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=length))

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
        import M2Crypto.BIO
        import M2Crypto.RSA
        bio = M2Crypto.BIO.MemoryBuffer(self.public_key)
        rsa_pub = M2Crypto.RSA.load_pub_key_bio(bio)

        return rsa_pub.public_decrypt(encrypt_text, M2Crypto.RSA.pkcs1_padding)


if __name__ == '__main__':
    # res = CompressFeature().network_info()
    # print(res)
    license_client = LicenseService(license_server_url='http://192.168.16.7:34567/license/feature')
    # # %Y-%m-%d %H:%M:%S
    start_time = "2022-01-01 00:00:00"
    license_days = 9999
    app_id = "knowlage"
    license_client.set_public_key(public_file='rsa_public.key')
    primsg = license_client.get_license(start=start_time, days=license_days, plat=app_id,
                                        private_file='rsa_private.key')
    print(primsg)
    # license_client.check_license(primsg)
    # # LicenseService(license_server_url='http://192.168.16.7:34567/license/feature').check_license(t_cipher_text)
