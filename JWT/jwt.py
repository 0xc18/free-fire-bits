import requests
import json
import base64
import sys
from typing import Tuple
from google.protobuf import json_format, message
from Crypto.Cipher import AES
import jwt_pb2

MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB50"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"

def json_to_proto(json_data: str, proto_message: message.Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    padding = bytes([padding_length] * padding_length)
    return text + padding

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = pad(plaintext)
    return aes.encrypt(padded_plaintext)

def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    message_instance = message_type()
    message_instance.ParseFromString(encoded_data)
    return message_instance

def getAccess_Token(uid: str, password: str) -> Tuple[str, str]:
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = (
        f"uid={uid}&password={password}"
        "&response_type=token&client_type=2"
        "&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
        "&client_id=100067"
    )
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/x-www-form-urlencoded"
    }

    response = requests.post(url, data=payload, headers=headers)
    data = response.json()
    print (data)
    return data.get("access_token", "0"), data.get("open_id", "0")


def create_jwt(uid: int, password: str) -> Tuple[str, str, str]:
    access_token, open_id = getAccess_Token(uid, password)
    print(access_token, open_id)
    if access_token == "0":
        raise ValueError("Failed to obtain access token.")

    json_data = json.dumps({
      "open_id": open_id,
      "open_id_type": "4",
      "login_token": access_token,
      "orign_platform_type": "4"
    })

    encoded_result = json_to_proto(json_data, jwt_pb2.LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, encoded_result)

    url = "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION
    }

    response = requests.post(url, data=payload, headers=headers)
    response_content = response.content
    message_obj = decode_protobuf(response_content, jwt_pb2.LoginRes)
    message_dict = json.loads(json_format.MessageToJson(message_obj))
    token = message_dict.get("token", "0")
    region = message_dict.get("lockRegion", "0")
    serverUrl = message_dict.get("serverUrl", "0")

    if token == "0":
        raise ValueError("Failed to obtain JWT.")

    return token, region, serverUrl

def main():
    print("\n--- Free Fire JWT Generator ---")

    uid = "4202089370"
    password = "BDB6E27AB0A34D966E241EDDD7E5C177B9A3D94CD316ED8E0660B6F50C3B2BE3"

    try:
        print("Generating JWT...")
        token, lock_region, server_url = create_jwt(uid, password)
        print("--- JWT Created Successfully ---")
        print(f"Token: {token}")
        print(f"Region: {lock_region}")
        print(f"Server URL: {server_url}")

    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    main()
