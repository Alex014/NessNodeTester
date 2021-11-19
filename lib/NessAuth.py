from base64 import b64encode
from base64 import b64decode
from base64 import b32encode
from base64 import b32decode
from nacl.signing import SigningKey
from nacl.signing import VerifyKey
from nacl.public import PrivateKey, PublicKey, SealedBox
import json
import urllib.parse
import requests


class NessAuth:
    def get_by_auth_id(self, node_full_url: str, user_private_key: str, node_url: str, node_nonce: str, username: str,
                       user_nonce: str):
        auth_id = self.auth_id(user_private_key, node_url, node_nonce, username, user_nonce)
        url = node_full_url + "/" + username + "/" + urllib.parse.quote_plus(auth_id)

        return json.loads(requests.get(url).text)

    def get_by_two_way_encryption(self, node_full_url: str, data: str, node_public_key: str, user_private_key: str,
                                  username: str):
        encrypted_data = self.encrypt(data, node_public_key)
        signature = self.sign(user_private_key, encrypted_data)

        url = node_full_url
        # print(requests.post(url, {'data': encrypted_data, 'sig': signature, 'username': username}).text)
        return json.loads(
            requests.post(url, {'data': encrypted_data, 'sig': signature, 'username': username}).text
        )

    def verify_two_way_result(self, node_verify_key: str, result: dict):
        return self.verify(node_verify_key, result['data'], result['sig'])

    def decrypt_two_way_result(self, result: dict, node_private_key: str):
        return self.decrypt(b64decode(result['data']), node_private_key)

    def auth_id(self, private_key: str, node_url, node_nonce: str, username: str, user_nonce: str):
        message = node_url + "-" + node_nonce + "-" + username + '-' + user_nonce
        return self.sign(private_key, message)

    def sign(self, private_key: str, data: str):
        signing_key = SigningKey(b64decode(private_key))
        signed = signing_key.sign(data.encode('utf-8'))
        return b32encode(signed.signature).decode('utf-8')

    def verify(self, verify_key: str, data: str, sig: str):
        # print(verify_key, data, sig)
        verify_key = VerifyKey(b64decode(verify_key))
        return verify_key.verify(data.encode('utf-8'), b32decode(sig))

    def encrypt(self, data: str, public_key: str):
        public_key = PublicKey(b64decode(public_key))
        box = SealedBox(public_key)
        return b64encode(box.encrypt(data.encode('utf-8'))).decode('utf-8')

    def decrypt(self, encrypted_data: str, private_key: str):
        private_key = PrivateKey(b64decode(private_key))
        sb = SealedBox(private_key)
        text = sb.decrypt(encrypted_data)
        return text.decode('utf-8')