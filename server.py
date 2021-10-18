# server.py
# By Gargi Chaurasia 2019059
import time
import socket
import sys
import pickle
from util.HashAlgo import HashAlgo
from util.Operations import Operations
from util.RSA import RSA
from util.SAES import SAES


class Server:

    def __init__(self):
        print("[STARTING] Server is starting...")
        self.PORT = 5050
        # Local IP Addess of the host
        self.SERVER_IP = socket.gethostbyname(socket.gethostname())
        self.ADDR = (self.SERVER_IP, self.PORT)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(self.ADDR)

    def listen(self):
        print(f'[LISTENING] Server listening on {self.SERVER_IP}...')
        self.server_socket.listen()
        self.conn, self.addr = self.server_socket.accept()

        return self.conn, self.addr

    def inputKeyParameters(self):
        print("Enter the space seperated key parameters p, q and e:")
        self.p, self.q, self.e = map(int, input().split())

    def generateServerKeys(self):
        self.private_key, self.public_key = RSA.generateKeys(
            self.p, self.q, self.e)

    def recieveMsg(self):
        msg = self.conn.recv(1024)
        msg = pickle.loads(msg)
        return msg

    def sendMsg(self, data):
        data = pickle.dumps(data)
        self.conn.send(data)

    def workFlow(self):

        # Recieving data send by the client
        data = self.recieveMsg()
        client_public_key = data['client_public_key']
        ciphertext = data['ciphertext']
        client_signature = data['client_signature']
        encrypted_secret_key = data['secret_key']
        SAES.is_padded = data['padded']

        # Decrypt secret key using server's private key
        decrypted_secret_key = int(RSA.decrypt(
            self.private_key, encrypted_secret_key))
        print("\nDecrypted secret key:", decrypted_secret_key)
        print("\n[Server] Decrypting client's message...")
        subkeys = SAES.generate_subkeys(decrypted_secret_key)

        # Reverse the keys
        subkeys[0], subkeys[4] = subkeys[4], subkeys[0]
        subkeys[1], subkeys[5] = subkeys[5], subkeys[1]

        plaintext = SAES.decrypt(ciphertext, subkeys)
        print("Decrypted plaintext:", plaintext)

        if SAES.is_padded:
            plaintext = plaintext[:-1]

        # Generating digest
        hash_code = HashAlgo.generateHashCode(message=plaintext)
        print(f"\nMessage digest: {hash_code}")

        # Verifying client signature
        is_verified = RSA.verify(
            client_public_key, hash_code=hash_code, client_sign=client_signature)
        print("Signature verified:", is_verified)

        self.server_socket.close()


server_obj = Server()
conn, add = server_obj.listen()
print("[Connected] Connection created with IP: {} on PORT: {}".format(add[0], add[1]))
print("\n--------------Code by Gargi Chaurasia (2019059)--------------\n")

server_obj.inputKeyParameters()

# Now verify key parameters
is_verified = RSA.verifyParameters(server_obj.p, server_obj.q, server_obj.e)
if not is_verified:
    server_obj.inputKeyParameters()

# Generate public and private key
server_obj.generateServerKeys()

# Recieving client's request
msg = server_obj.recieveMsg()
if msg == 'Y':

    # Sending public key on client's request
    server_obj.sendMsg(server_obj.public_key)
    print(f'[Sending] Public key to {server_obj.ADDR} (Client)...')

    ############################################################################

    # Workflow
    server_obj.workFlow()

else:
    print("[Sever] Closing the connection...")
    server_obj.server_socket.close()
