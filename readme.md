# NESS Node Tester - test suit for NESS nodes
* codegen.py

 Private and public code generation for user (client) and node

 Usage:
```
# Code generator for Ness nodes
### DESCRIPTION:
  Generates ciphers for NESS nodes and NESS node clients
  Works on ed25519 for keypairs and Blowfish or AES for symmetrical ciphers
### DIRECTORIES:
 'out/keys/node/*.key.json' - generated nodes
 'out/keys/user/*.key.json' - generated users
### USAGE:
#### Generate user
python codegen.py -ug username 10 "1,blowfish,16;1,aes,8" "Hello World,test"
python codegen.py --user-generate username 10 "1,blowfish,16;1,aes,8" "Hello World,test"
  Generates user with username 'username' with 10 keypairs
  1,blowfish,16 - generate 1 Blowfish cipher 16 bytes long
  1,aes,8 - generate 1 AES cipher 8 bytes long
  "Hello World,test" - coma separated tags
#### Show generated user
python codegen.py -us username
python codegen.py --user-show username
#### Show <WORM> part of generated user
python codegen.py -usw username
python codegen.py --user-show-worm username
#### Generate node
python codegen.py -ng http://my-ness-node.net "Test,My test node,Hello world"
python codegen.py --node-generate http://my-ness-node.net "Test,My test node,Hello world"
  "Test,My test node,Hello world" - coma separated tags
#### Show generated node
python codegen.py -ns http://my-ness-node.net
python codegen.py --node-show http://my-ness-node.net
#### Show <WORM> part of generated node
python codegen.py -nsw http://my-ness-node.net
python codegen.py --node-show-worm http://my-ness-node.net
#### Show version
python codegen.py -v
python codegen.py --version
#### Show this manual
python codegen.py -h
python codegen.py --help
```
* configen.py

 Configuration generation for node
 
 Usage: `python configen.py <node URL>`
* test-auth.py

 Authentication testing

 Run after codegen.py
 
 Usage: `python test-auth.py <username> <node URL>`

## Instalation
`pip install requests, nacl, pynacl, pycryptodome, validators, lxml`