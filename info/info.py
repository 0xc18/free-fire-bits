import json
import base64
import requests
from google.protobuf import json_format, message
from Crypto.Cipher import AES
from proto import main_pb2, AccountPersonalShow_pb2

# === Settings ===
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB50"

# === AES Utils ===
def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance

def json_to_proto(json_data: str, proto_message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

# === Synchronous GetAccountInformation ===
def GetAccountInformation(uid, JWT):
    payload = json_to_proto(json.dumps({'a': uid, 'b': 7}), main_pb2.GetPlayerPersonalShow())
    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)

    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'Authorization': f"Bearer {JWT}",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION
    }

    resp = requests.post("https://clientbp.ggblueshark.com/GetPlayerPersonalShow", data=data_enc, headers=headers)
    msg = decode_protobuf(resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)
    return json.loads(json_format.MessageToJson(msg))


print(GetAccountInformation('1923696445','eyJhbGciOiJIUzI1NiIsInN2ciI6IjEiLCJ0eXAiOiJKV1QifQ.eyJhY2NvdW50X2lkIjoxMzQ3Mjc0ODM5OCwibmlja25hbWUiOiIweGMxOCIsIm5vdGlfcmVnaW9uIjoiQkQiLCJsb2NrX3JlZ2lvbiI6IkJEIiwiZXh0ZXJuYWxfaWQiOiIwZWUyZDVjYTBiZWVhZmJiZjRiM2UzYzQ2MThjMDhmNSIsImV4dGVybmFsX3R5cGUiOjQsInBsYXRfaWQiOjAsImNsaWVudF92ZXJzaW9uIjoiIiwiZW11bGF0b3Jfc2NvcmUiOjEwMCwiaXNfZW11bGF0b3IiOnRydWUsImNvdW50cnlfY29kZSI6IkJEIiwiZXh0ZXJuYWxfdWlkIjo0MjAyMDg5MzcwLCJyZWdfYXZhdGFyIjoxMDIwMDAwMDcsInNvdXJjZSI6MCwibG9ja19yZWdpb25fdGltZSI6MTc1OTUxMTE5NywiY2xpZW50X3R5cGUiOjEsInNpZ25hdHVyZV9tZDUiOiIiLCJ1c2luZ192ZXJzaW9uIjowLCJyZWxlYXNlX2NoYW5uZWwiOiIiLCJyZWxlYXNlX3ZlcnNpb24iOiJPQjUwIiwiZXhwIjoxNzU5NTQ5NjU1fQ.jjCJhfY6U7VMcwN7rQdDg5kUxtas86bKcm9N7Q5un1g'))
