# By Gargi Chaurasia 2019059
import hashlib


class DigitalSignature:

    @classmethod
    def generateHashCode(self, message):
        '''
        Generates hash code using md5 hash algorithm.
        Parameters:
        message (str): Message to be hashed
        Return:
        str : string representation of hexadecimal message digest
        '''

        # Creating object of md5
        hash_obj = hashlib.md5()

        # Feeding the encoded message string in the hash_obj
        hash_obj.update(message.encode())

        # Generating message digest in hexadecimal format
        msg_digest = hash_obj.hexdigest()

        return msg_digest
