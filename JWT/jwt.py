import requests
import json
import base64
import sys
from typing import Tuple
from google.protobuf.json_format import MessageToDict,ParseDict
from Crypto.Cipher import AES
from .jwt_pb2 import LoginReq, LoginRes

MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB50"


def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    padding = bytes([padding_length] * padding_length)
    return text + padding

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = pad(plaintext)
    return aes.encrypt(padded_plaintext)

def getAccess_Token(uid: str, password: str) -> Tuple[str, str]:
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = (
        f"uid={uid}&password={password}"
        "&response_type=token&client_type=2"
        "&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
        "&client_id=100067"
    )
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/x-www-form-urlencoded"
    }

    response = requests.post(url, data=payload, headers=headers)
    data = response.json()
    return data.get("access_token", "0"), data.get("open_id", "0")


def get_auth_data(uid: int, password: str) -> Tuple[str, str, str]:
    access_token, open_id = getAccess_Token(uid, password)
    if access_token == "0":
        raise ValueError("Failed to obtain access token.")

    data = {
      "open_id": open_id,
      "open_id_type": "4",
      "login_token": access_token,
      "orign_platform_type": "4"
    }
    proto = LoginReq()
    ParseDict(data,proto)
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto.SerializeToString())

    url = "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION
    }

    response = requests.post(url, data=payload, headers=headers)
    proto = LoginRes()
    proto.ParseFromString(response.content)
    message_dict = data = MessageToDict(proto, preserving_proto_field_name=True)
    message_dict['open_id'] = open_id
    message_dict['access_token'] = access_token
    return message_dict

if __name__ == "__main__":
    uid = "4202089370"
    password = "BDB6E27AB0A34D966E241EDDD7E5C177B9A3D94CD316ED8E0660B6F50C3B2BE3"
    print(json.dumps(get_auth_data(uid,password),indent=4))
