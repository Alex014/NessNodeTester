import json
import sys
import urllib.parse

print('Configen')
print('Generates node config from previously generated node by Codegen')


class Configen:

    def loadNode(node_url: str):
        filename = urllib.parse.quote_plus(node_url) + ".key.json"
        f = open("out/keys/node/" + filename, "r")
        return json.loads(f.read())

    def saveNode(node_url: str):
        node = Configen.loadNode(node_url)

        config_node = {
            "nonce": node["nonce"],
            "private": node["private"],
            "public": node["public"],
            "url": node["url"],
            "verify": node["verify"]
        }

        filename = "out/config/node.json"
        f = open(filename, "w")
        f.write(json.dumps(config_node, indent=4, sort_keys=True))

        config_emer = {
            "host": "localhost",
            "port": 8332,
            "user": "user",
            "password": "password"
        }

        filename = "out/config/emer.json"
        f = open(filename, "w")
        f.write(json.dumps(config_emer, indent=4, sort_keys=True))

        config_prng = {
            "seed": "/tmp/seed.txt",
            "seed-big": "/tmp/seed-big.txt",
            "numbers": "/tmp/numbers.json",
            "numbers-big": "/tmp/numbers-big.json"
        }

        filename = "out/config/prng.json"
        f = open(filename, "w")
        f.write(json.dumps(config_prng, indent=4, sort_keys=True))


if len(sys.argv) == 2:
    node_url = sys.argv[1]
    Configen.saveNode(node_url)
    print('Config generated !')
    print('Move all generated *.json files from "out/config/*.json" to ~/.ness/*.json')
else:
    print('Usage: python configen.py <node URL>')