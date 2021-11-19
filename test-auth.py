import json
import sys
import urllib.parse
from lib.NessAuth import NessAuth


class AuthTester:

    data_user = {}
    data_node = {}

    def __init__(self):
        return

    def loadUser(self, username: str):
        filename = username + ".key.json"
        f = open("out/keys/user/" + filename, "r")
        return json.loads(f.read())

    def loadNode(self, url: str):
        filename = urllib.parse.quote_plus(url) + ".key.json"
        f = open("out/keys/node/" + filename, "r")
        return json.loads(f.read())

    def test(self, username: str, node_url: str):
        ness_auth = NessAuth()
        user = self.loadUser(username)
        node = self.loadNode(node_url)

        user_private_key = user['keys']["private"][user['keys']['current']]

        result = ness_auth.get_by_auth_id(node_url + "/node/test/auth", user_private_key, node_url, node["nonce"], username,
                                          user["nonce"])

        if result['result'] == 'error':
            print(" ~~~ TEST #1 Auth ID FAILED ~~~ ")
            print(result['error'])
        else:
            print(" *** TEST #1 Auth ID OK !!! *** ")
            print(result['message'])

        test_string = 'The state calls its own violence law, but that of the individual, crime.'
        url = node_url + "/node/test/auth"

        result = ness_auth.get_by_two_way_encryption(url, test_string, node['public'], user_private_key, username)

        if result['result'] == 'error':
            print(" ~~~ TEST #2 Two way encryption FAILED ~~~ ")
            print(result['error'])
        else:
            if ness_auth.verify_two_way_result(node['verify'], result):
                print(" *** TEST #2 Two way encryption OK !!! *** ")
                print(ness_auth.decrypt_two_way_result(result, user_private_key))
            else:
                print(" ~~~ TEST #2 Two way encryption FAILED ~~~ ")
                print(" Verifying signature failed ")

        return True


print('Tester')

if len(sys.argv) == 3:
    tester = AuthTester()
    tester.test(sys.argv[1], sys.argv[2])
else:
    print('Usage: python test-auth.py <username> <node URL>')
