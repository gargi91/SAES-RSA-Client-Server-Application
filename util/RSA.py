# By Gargi Chaurasia 2019059
from util.Operations import Operations


class RSA:

    @classmethod
    def verifyParameters(self, p, q, e):
        '''
        Verify p and q as primes and e as valid number
        Parameters:
        p,q (int): Long prime number
        e (int): Derived number from p*q, 1 < e <= Φ(p*q) and gcd(e,Φ(p*q)) = 1
        Return:
        bool: Returns True if verified else False
        '''

        # Verifying if p and q are primes
        if not Operations.isPrime(p):
            print("Sorry! Invalid prime p.")
            return False
        if not Operations.isPrime(q):
            print("Sorry! Invalid prime q.")
            return False

        # Calculating Φ of N using Euler's Totient function
        phiN = (p-1)*(q-1)

        # Verify if e is valid, e should be coprime with p*q
        if (not (1 < e <= phiN)) or (not Operations.isCoPrime(phiN, e)):
            print(
                f"Sorry! Invalid input for e. e should be in range (1,{phiN}] and should be coprimes.")
            return False

        return True

    @classmethod
    def generateKeys(self, p, q, e):
        '''
        RSA key generation algorithm implementation
        Parameters:
        p,q (int): Long prime number
        e (int): Derived number from p*q, 1 < e <= Φ(p*q) and gcd(e,Φ(p*q)) = 1
        Return:
        list: List containing two tuples - private and public key
        '''
        N = p * q  # RSA modulus

        # Calculating Φ of N using Euler's Totient function
        phiN = (p-1)*(q-1)

        # Calculating d for private key
        # d is mod inv of e with respect to phiN, e * d (mod phiN) = 1
        d = Operations.modInverse(e, phiN)

        private_key = (d, N)
        publick_key = (e, N)

        return [private_key, publick_key]

    @classmethod
    def encrypt(self, key, msg):
        '''
        RSA encryption algorithm implementation
        Parameters:
        key (tuple): Tuple containing public exponent e and modulus N
        msg (str): Message to be encrypted
        Return:
        list: List of cipher values of each character of msg
        '''
        cipher = []
        e, N = key[0], key[1]

        for ch in msg:
            m = ord(ch)  # to convet into ASCII value ,e.g a = 97
            c = pow(m, e, N)  # c = m ^ e mod n
            cipher.append(pow(m, e, N))

        return cipher

    @classmethod
    def decrypt(self, key, cipher):
        '''
        RSA decryption algorithm implementation
        Parameters:
        key (tuple): Tuple containing secret exponent d and modulus N
        cipher (list): cipher list of int values to be decrypted to original text
        Return:
        msg: Decrypted original text message
        '''
        msg = ""
        d, N = key[0], key[1]
        for part in cipher:
            if part:
                c = int(part)
                msg += chr(pow(c, d, N))

        return msg

    @classmethod
    def sign(self, key, digest):
        '''
        RSA document signing algorithm implementation
        Parameters:
        key (tuple): Tuple containing secret exponent d and modulus N
        digest (str): Message digest generated from hash function
        Return:
        str: Client signature of message digest
        '''
        client_sign = []
        d, N = key[0], key[1]

        for ch in digest:
            m = ord(ch)  # to convet into ASCII value ,e.g a = 97
            c = pow(m, d, N)  # c = m ^ e mod n
            client_sign.append(pow(m, d, N))

        return client_sign

    @classmethod
    def verify(self, key, hash_code, client_sign):
        '''
        RSA client signature verification algorithm implementation
        Parameters:
        key (tuple): Tuple containing public exponent e and modulus N
        client_sign (list): Client signature to be verified
        hash_code (str): Message digest generated from decrypted plaintext by server
        Return:
        bool: if decrypted client_sign equals generated signature return True else False
        '''

        # Decrypting the client signature using client's public key
        generated_sign = ""
        e, N = key[0], key[1]
        for part in client_sign:
            if part:
                c = int(part)
                generated_sign += chr(pow(c, e, N))

        print("Intermediate verification code:", generated_sign)
        return hash_code == generated_sign

    @classmethod
    def printHexList(self, intList):
        '''
        Convert ciphertext list into hex form 
        Parameters:
        intList (list): List of cipher values of each character of msg
        Return:
        str: Hexadedimal format of cipherText list
        '''
        output = ""
        for index, elem in enumerate(intList):
            output += "{:02x}".format(elem)

        return output
