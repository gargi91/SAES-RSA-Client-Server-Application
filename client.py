# client.py
# By Gargi Chaurasia 2019059
import socket
import sys
import pickle
from util.HashAlgo import HashAlgo
from util.Operations import Operations
from util.RSA import RSA
from util.SAES import SAES


class Client:
    def __init__(self):
        print("[STARTING] Client is starting...")
        self.PORT = 5050
        # Local IP Addess of the host
        self.SERVER_IP = socket.gethostbyname(socket.gethostname())
        self.ADDR = (self.SERVER_IP, self.PORT)
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self):
        print(f'[Connecting] Client trying to connect {self.SERVER_IP}...')
        self.client_socket.connect(self.ADDR)

        print(f'[Connected] Secure connection established with server.')

    def inputMessage(self):
        print("Enter your message to be send to the server:")
        self.message = input()

    def inputKey(self):
        print("Enter the secret key. Value should be in range 0 to {} as the key size is {}:".format(
            2 ** SAES.key_size - 1, SAES.key_size))
        self.key = int(input())
        if (self.key < 0) or (self.key > (2 ** SAES.key_size - 1)):
            print("Follow the rules for the key")
            exit(1)

    def inputKeyParameters(self):
        print("Enter the space seperated key parameters p, q and e:")
        self.p, self.q, self.e = map(int, input().split())

    def generateClientKeys(self):
        self.private_key, self.public_key = RSA.generateKeys(
            self.p, self.q, self.e)

    def recieveMsg(self):
        msg = self.client_socket.recv(1024)
        msg = pickle.loads(msg)
        return msg

    def sendMsg(self, data):
        data = pickle.dumps(data)
        self.client_socket.send(data)

    def _ciphertextHex(self, ciphertext):
        ciphertext_hex = []
        for i in ciphertext:
            ciphertext_hex.append("{:04x}".format(int(i, 2)))
        return ciphertext_hex

    def workFlow(self):
        # Encrypting secret key
        encrypted_secret_key = RSA.encrypt(
            self.server_public_key, str(self.key))
        print("\nEncrypted secret key:", RSA.printHexList(encrypted_secret_key))

        # Creating ciphertext
        print("\n[Client] Encrypting...")
        subkeys = SAES.generate_subkeys(self.key)
        ciphertext = SAES.encrypt(self.message, subkeys)
        ciphertext_hex = self._ciphertextHex(ciphertext)
        print('Ciphertext:', ''.join(ciphertext_hex))

        # Generating digest
        hash_code = HashAlgo.generateHashCode(message=self.message)
        print(f"\nMessage digest: {hash_code}")

        # Creating digital signature using hash code
        client_sign = RSA.sign(self.private_key, hash_code)
        print("Client signature:", RSA.printHexList(client_sign))

        # arranging datas to be send to server
        data = {'secret_key': encrypted_secret_key, 'ciphertext': ciphertext_hex,
                'client_signature': client_sign, 'client_public_key': self.public_key, 'padded': SAES.is_padded}

        # Sending data to server
        self.sendMsg(data)

        self.client_socket.close()


client_obj = Client()
client_obj.connect()
print("\n--------------Code by Gargi Chaurasia (2019059)--------------\n")

client_obj.inputMessage()
client_obj.inputKey()
client_obj.inputKeyParameters()

# Now verify key parameters
is_verified = RSA.verifyParameters(client_obj.p, client_obj.q, client_obj.e)
if not is_verified:
    client_obj.inputKeyParameters()

# Generate public and private keys
client_obj.generateClientKeys()

print("Do you want to request server for it's public key? Y or N")
res = input()
if res.lower() == 'y':
    # Requesting server for it's public key
    print("[Requesting] Server's public key...")
    client_obj.sendMsg("Y")

    # Recieving server's public key
    client_obj.server_public_key = client_obj.recieveMsg()

    print("Server's public key recieved!")

    ##############################################################################

    # Workflow
    client_obj.workFlow()

else:
    print("[Client] Closing the connection...")
    client_obj.client_socket.close()
