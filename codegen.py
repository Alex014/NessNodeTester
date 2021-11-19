import os
import sys
from base64 import b64encode
from base64 import b64decode
import json
import urllib.parse
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from nacl.signing import SigningKey, VerifyKey
from nacl.public import PrivateKey, PublicKey
from nacl.encoding import Base64Encoder
import validators
import lxml.etree as etree


# Codegen
class Codegen:

    data = {}

    def __init__(self):
        return

    def show_node(self, url: str):
        filename = urllib.parse.quote_plus(url) + ".key.json"
        f = open("out/keys/node/" + filename, "r")
        node_json = json.loads(f.read())
        print(json.dumps(node_json, indent=4, sort_keys=True))
        f.close()

    def show_user(self, username: str):
        filename = urllib.parse.quote_plus(username) + ".key.json"
        f = open("out/keys/user/" + filename, "r")
        user_json = json.loads(f.read())
        print(json.dumps(user_json, indent=4, sort_keys=True))
        f.close()

    def show_user_worm(self, username: str):
        filename = urllib.parse.quote_plus(username) + ".key.json"
        f = open("out/keys/user/" + filename, "r")
        user_json = json.loads(f.read())
        print(user_json['worm'])
        worm = etree.XML(user_json['worm'])
        etree.tostring(worm, pretty_print=True)
        f.close()

    def show_node_worm(self, url: str):
        filename = urllib.parse.quote_plus(url) + ".key.json"
        f = open("out/keys/node/" + filename, "r")
        node_json = json.loads(f.read())
        print(node_json['worm'])
        worm = etree.XML(node_json['worm'])
        etree.tostring(worm, pretty_print=True)
        f.close()

    def generate_node(self, url, tags: str):
        if not os.path.exists('out'):
            os.mkdir('out')

        if not os.path.exists('out/config'):
            os.mkdir('out/config')

        if not os.path.exists('out/keys'):
            os.mkdir('out/keys')

        if not os.path.exists('out/keys/node'):
            os.mkdir('out/keys/node')

        keypair = self.__keypair()

        node = {
            'url': url,
            'tags': tags,
            'private': keypair[0],
            'verify': keypair[1],
            'public': keypair[2],
            'nonce': b64encode(get_random_bytes(16)).decode('utf-8')
        }

        node['worm'] = self.__worm_node(node)

        # Node keys
        filename = urllib.parse.quote_plus(url) + ".key.json"
        f = open("out/keys/node/" + filename, "w")
        f.write(json.dumps(node, indent=4, sort_keys=True))
        f.close()
        print("Output file is: out/keys/node/" + filename)
        # Node config

        # Emercoin config

        # Prng config

    def generate_user(self, username: str, keypair_cnt: int, keys: tuple, tags: str):
        if not os.path.exists('out'):
            os.mkdir('out')

        if not os.path.exists('out/config'):
            os.mkdir('out/config')

        if not os.path.exists('out/keys'):
            os.mkdir('out/keys')

        if not os.path.exists('out/keys/user'):
            os.mkdir('out/keys/user')

        key_pairs = self.__keypairs(keypair_cnt)
        singles = {}

        for single in keys:
            if str(single[1]).lower() == 'aes':
                singles.update(self.__aes(int(single[0]), int(single[2])))
            elif str(single[1]).lower() == 'blowfish':
                singles.update(self.__blowfish(int(single[0]), int(single[2])))

        user = {
            'application': {'name': 'Codegen', 'ver': '0.1'},
            'keys': {
                'private': key_pairs['private'],
                'verify': key_pairs['verify'],
                'public': key_pairs['public'],
                'current': key_pairs['current'],
                'single': singles
            },
            'nonce': b64encode(get_random_bytes(16)).decode('utf-8'),
            'tags': tags
        }

        user['worm'] = self.__worm_user(user)

        filename = urllib.parse.quote_plus(username) + ".key.json"
        f = open("out/keys/user/" + filename, "w")
        f.write(json.dumps(user, indent=4, sort_keys=True))
        f.close()

        print("Output file is: out/keys/user/" + filename)

    def __worm_node(self, node: dict):
        linesep = '\n'
        tab = '\t'
        tab2 = '\t\t'

        worm = "<worm>"+linesep+\
            tab + "<node type=\"ness\" url=\"" + node["url"] + "\" nonce=\"" + node["nonce"] + "\"   " + \
            " verify=\"" + node["verify"] + "\" public=\"" + node["public"] + "\" tags=\"" + \
            node["tags"] + "\">" + linesep + \
            tab2 + "<!-- Here tags may be different for each type of node or each node -->" + linesep + \
            tab + "</node>" + linesep + \
            "</worm>"

        return worm

    def __worm_user(self, user: dict):
        linesep = '\n'
        tab = '\t'
        tab2 = '\t\t'
        tab3 = '\t\t\t'

        current = user["keys"]["current"]

        keys = linesep

        for i in range(0, len(user["keys"]["public"]) - 1):
            if current == i:
                cc = " current=\"current\" "
            else:
                cc = ''

            keys += tab3 + "<key public=\"" + user["keys"]["public"][i] + "\"  verify=\"" + user["keys"]["verify"][i] \
                + "\"" + cc + "/>" + linesep

        worm = "<worm>" + linesep + \
            tab + "<user type=\"ness\" nonce=\"" + user["nonce"] + "\" tags=\"" \
               + user["tags"] + "\">" + linesep + \
            tab2 + "<keys>" + keys + \
            tab2 + "</keys>" + linesep + \
            tab2 + "<!-- Here tags may be different for each type of user -->" + linesep + \
            tab + "</user>" + linesep + \
            "</worm>"

        return worm

    def __key(self, byte: int = 32):
        key = get_random_bytes(byte)
        return b64encode(key).decode('utf-8')

    def __aes(self, count: int, _bytes: int = 32):
        ciphers = []
        for i in range(0, count):
            _key = self.__key(_bytes)
            h = SHA256.new()
            h.update(_key.encode('utf-8'))
            ciphers.append({h.hexdigest(): _key})
        return {'aes': ciphers}

    def __blowfish(self, count: int, _bytes: int = 32):
        ciphers = []
        for i in range(0, count):
            _key = self.__key(_bytes)
            h = SHA256.new()
            h.update(_key.encode('utf-8'))
            ciphers.append({h.hexdigest(): _key})
        return {'blowfish': ciphers}

    def __keypair(self):
        signing_key = SigningKey.generate()
        signing__key = signing_key.encode(encoder=Base64Encoder).decode('utf-8')
        private_key = PrivateKey(b64decode(signing__key))
        verify__key = signing_key.verify_key.encode(encoder=Base64Encoder).decode('utf-8')
        public__key = private_key.public_key.encode(encoder=Base64Encoder).decode('utf-8')
        return [signing__key, verify__key, public__key]

    def __keypairs(self, count: int):
        private_list = []
        verify_list = []
        public_list = []

        for i in range(0, count):
            keypair = self.__keypair()
            private_list.append(keypair[0])
            verify_list.append(keypair[1])
            public_list.append(keypair[2])

        return {'private': private_list, 'public': public_list, 'verify': verify_list, 'current': 0}

class Terminal:
    def __is_integer(self, n):
        try:
            int(n)
        except ValueError:
            return False
        else:
            return True

    def __is_cipher(self, _cipher: str):
        return _cipher.lower() == 'aes' or _cipher.lower() == 'blowfish'

    def __manual(self):
        print("# Code generator for Ness nodes")
        print("### DESCRIPTION:")
        print("  Generates ciphers for NESS nodes and NESS node clients")
        print("  Works on ed25519 for keypairs and Blowfish or AES for symmetrical ciphers")
        print("### DIRECTORIES:")
        print(" 'out/keys/node/*.key.json' - generated nodes")
        print(" 'out/keys/user/*.key.json' - generated users")
        print("### USAGE:")
        print("#### Generate user")
        print("python codegen.py -ug username 10 \"1,blowfish,16;1,aes,8\" \"Hello World,test\"")
        print("python codegen.py --user-generate username 10 \"1,blowfish,16;1,aes,8\" \"Hello World,test\"")
        print("  Generates user with username 'username' with 10 keypairs")
        print("  1,blowfish,16 - generate 1 Blowfish cipher 16 bytes long")
        print("  1,aes,8 - generate 1 AES cipher 8 bytes long")
        print("  \"Hello World,test\" - coma separated tags")
        print("#### Show generated user")
        print("python codegen.py -us username")
        print("python codegen.py --user-show username")
        print("#### Show <WORM> part of generated user")
        print("python codegen.py -usw username")
        print("python codegen.py --user-show-worm username")
        print("#### Generate node")
        print("python codegen.py -ng http://my-ness-node.net \"Test,My test node,Hello world\"")
        print("python codegen.py --node-generate http://my-ness-node.net \"Test,My test node,Hello world\"")
        print("  \"Test,My test node,Hello world\" - coma separated tags")
        print("#### Show generated node")
        print("python codegen.py -ns http://my-ness-node.net")
        print("python codegen.py --node-show http://my-ness-node.net")
        print("#### Show <WORM> part of generated node")
        print("python codegen.py -nsw http://my-ness-node.net")
        print("python codegen.py --node-show-worm http://my-ness-node.net")
        print("#### Show version")
        print("python codegen.py -v")
        print("python codegen.py --version")
        print("#### Show this manual")
        print("python codegen.py -h")
        print("python codegen.py --help")

    def __node_show(self, url: str):
        codegen = Codegen()
        codegen.show_node(url)

    def __user_show(self, username: str):
        codegen = Codegen()
        codegen.show_user(username)

    def __node_show_worm(self, url: str):
        codegen = Codegen()
        codegen.show_node_worm(url)

    def __user_show_worm(self, username: str):
        codegen = Codegen()
        codegen.show_user_worm(username)

    def __node_generate(self, url: str, tags: str):
        if validators.url(url):
            # print(url)
            codegen = Codegen()
            codegen.generate_node(url, tags)
            print("Node '" + url + "' generated OK")
            return True
        else:
            print("Node URL '" + url + "' is not valid")
            return False

    def __user_generate(self, username: str, keys_count: int, keys: str, tags: str):
        keys_list = keys.split(';')
        final_keys = []

        for key_full in keys_list:
            key_full_list = key_full.split(',')
            if len(key_full_list) == 3:
                if self.__is_integer(key_full_list[0]) \
                  and self.__is_cipher(key_full_list[1]) \
                  and self.__is_integer(key_full_list[2]):
                    final_keys.append(key_full_list)
                else:
                    print("Ciphers_Count(1+),Cipher_Name(blowfish or aes),Cipher_Bytes; ... ")
                    return False

        # print(username, keys_count, final_keys)
        codegen = Codegen()
        codegen.generate_user(username, keys_count, final_keys, tags)
        print("User '" + username + "' generated OK")

        return True

    def process(self):
        if len(sys.argv) >= 2:
            mode = sys.argv[1].lower()
            if len(sys.argv) == 4 and (mode == '-ng' or mode == '--node-generate'):
                url = sys.argv[2]
                tags = sys.argv[3]

                if not self.__node_generate(url, tags):
                    self.__manual()

            elif len(sys.argv) == 6 and (mode == '-ug' or mode == '--user-generate'):
                username = sys.argv[2]

                if self.__is_integer(sys.argv[3]):
                    keys_count = int(sys.argv[3])
                else:
                    self.__manual()
                    return False

                keys = sys.argv[4]
                tags = sys.argv[5]

                if not self.__user_generate(username, keys_count, keys, tags):
                    self.__manual()
            elif len(sys.argv) == 3 and (mode == '-us' or mode == '--user-show'):
                username = sys.argv[2]
                self.__user_show(username)
            elif len(sys.argv) == 3 and (mode == '-ns' or mode == '--node-show'):
                url = sys.argv[2]
                self.__node_show(url)
            elif len(sys.argv) == 3 and (mode == '-usw' or mode == '--user-show-worm'):
                username = sys.argv[2]
                self.__user_show_worm(username)
            elif len(sys.argv) == 3 and (mode == '-nsw' or mode == '--node-show-worm'):
                url = sys.argv[2]
                self.__node_show_worm(url)
            elif len(sys.argv) == 2 and (mode == '-v' or mode == '--version'):
                print('Codegen V-0.1')
            elif len(sys.argv) == 2 and (mode == '-h' or mode == '--help'):
                self.__manual()
            else:
                self.__manual()
        else:
            self.__manual()

t = Terminal()
t.process()
