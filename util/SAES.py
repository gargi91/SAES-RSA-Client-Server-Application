# By Gargi Chaurasia 2019059
from util.Operations import Operations


class SAES:

    plaintext_block_size = 16
    key_size = 16
    no_of_rounds = 2
    substitution_box = {
        '0000': '1001',
        '0001': '0100',
        '0010': '1010',
        '0011': '1011',
        '0100': '1101',
        '0101': '0001',
        '0110': '1000',
        '0111': '0101',
        '1000': '0110',
        '1001': '0010',
        '1010': '0000',
        '1011': '0011',
        '1100': '1100',
        '1101': '1110',
        '1110': '1111',
        '1111': '0111',
    }
    inv_substitution_box = {
        '1001': '0000',
        '0100': '0001',
        '1010': '0010',
        '1011': '0011',
        '1101': '0100',
        '0001': '0101',
        '1000': '0110',
        '0101': '0111',
        '0110': '1000',
        '0010': '1001',
        '0000': '1010',
        '0011': '1011',
        '1100': '1100',
        '1110': '1101',
        '1111': '1110',
        '0111': '1111',
    }

    mix_column_table = {
        '2': '02468ACE3175B9FD',
        '4': '048C37BF62EA51D9',
        '9': '09182B3A4D5C6F7E'
    }

    mix_column_matrix = [[1, 4], [4, 1]]
    inv_mix_column_matrix = [[9, 2], [2, 9]]

    round_constants = ['80', '30']  # hex numbers of [1000 0000, 0011 0000]
    is_padded = False

    @classmethod
    def __perform_substitution(self, data, substitution_box):
        """
        Nibble substitution (S-Boxes) from the given substitution box
        Parameters:
        data (int): Intermediary data in the number form 
        substitution_box (dict): Dictionary of nibble as key and its substitution nibble as value
        Returns: 
        int: substituted data
        """

        # Converting the integer form into 8 bit binary string
        binary_rep = "{:08b}".format(data)

        # Substituting the two nibbles formed in the above conversion
        ans = self.substitution_box[binary_rep[:4]] + \
            self.substitution_box[binary_rep[4:]]
        return int(ans, 2)

    @classmethod
    def generate_subkeys(self, key):
        """
        Generating subkeys from the given secret key
        key (int): 16 bit secret key in the range of (1, 2^16-1)
        Returns: 
        list[int]: 3 pairs of subkeys generated (w0,w1, w2,w3, w4,w5)
        """

        # Converting the secret key form into 16 bit binary string
        binary_rep = "{:016b}".format(key)

        subkeys = []

        # Splitting the key into 2 words w0 and w1 to generate the first sub key
        subkeys.append(int(binary_rep[:8], 2))
        subkeys.append(int(binary_rep[8:], 2))

        # Generating the other two sub keys
        for i in range(self.no_of_rounds):

            # Rotating nibbles
            temp = Operations.circular_left_shift(subkeys[-1], 4)

            # apply S-Box substitution on nibbles using encryption S-box
            temp = self.__perform_substitution(temp, self.substitution_box)

            # xor with round constant '1000 0000'
            temp = Operations.xor_operation(
                temp, int(self.round_constants[i], 16))

            # xor with previous sub key 8 bit word
            key1 = Operations.xor_operation(temp, subkeys[-2])

            # appending next subkey's 8 bit word
            subkeys.append(key1)

            # again xor with above created word of the same subkey
            key2 = Operations.xor_operation(subkeys[-2], subkeys[-1])

            # appending next subkey's last 8 bit word
            subkeys.append(key2)

        return subkeys

    @classmethod
    def __formatKey(self, keys):
        """ For printing subkeys in 16 bit binary format from it's decimal representation """
        binary_rep = "{:08b}".format(keys[0]) + "{:08b}".format(keys[1])

        return binary_rep

    @classmethod
    def __initial_round(self, text_blocks, keys):
        """
        Add round key implementation before round 1
        Parameters:
        text_blocks (list): ciphertext or plaintext block (pair wise blocks of the entire text e.g ok!! => ['ok', '!!'])
        keys (list): sub keys 8 bit words list
        Returns: 
        list: returns the xored value of text blocks with sub key
        """

        # forming 16 bit sub key from it's int representation of two 8 bit words
        joint_key = int("{:08b}".format(keys[0]) + "{:08b}".format(keys[1]), 2)

        result_blocks = []

        # Looping through all the pairs of the characters (binary representation)
        for i in text_blocks:

            # xor the block i with the 16 bit subkey
            xored = Operations.xor_operation(int(i, 2), joint_key)

            # convert the int form of the xored value into 16 bit binary string
            xored = "{:016b}".format(xored)

            # append in the result block
            result_blocks.append(xored)

        return result_blocks

    @classmethod
    def __convert_into_matrix(self, plaintext_blocks):
        """
        converting the plaintext into matrix form 
        Parameters:
        plain_blocks (list): plaintext block (pair wise blocks of the entire text e.g ok!! => ['ok', '!!'])
        Returns: 
        list: list of all the plain text blocks in their matrix form
        """

        plaintext_matrix = []
        for i in range(len(plaintext_blocks)):
            plaintext_matrix.append([[0, 0], [0, 0]])
        for i in range(len(plaintext_blocks)):
            plaintext_matrix[i][0][0] = plaintext_blocks[i][:4]
            plaintext_matrix[i][1][0] = plaintext_blocks[i][4:8]
            plaintext_matrix[i][0][1] = plaintext_blocks[i][8:12]
            plaintext_matrix[i][1][1] = plaintext_blocks[i][12:]
        return plaintext_matrix

    @classmethod
    def __formatPlaintextMatrix(self, plaintext_matrix, binary=False):
        """ Utility function to return the linear plaintext block from plaintext matrix form """

        plaintext_blocks = []
        for i in range(len(plaintext_matrix)):
            plaintext_block = []

            # If the matrix of the blocks are in int form
            if not binary:
                plaintext_block.append(
                    '{:04b}'.format(plaintext_matrix[i][0][0]))
                plaintext_block.append(
                    '{:04b}'.format(plaintext_matrix[i][1][0]))
                plaintext_block.append(
                    '{:04b}'.format(plaintext_matrix[i][0][1]))
                plaintext_block.append(
                    '{:04b}'.format(plaintext_matrix[i][1][1]))

            # If the matrix of the blocks are in binary form
            else:
                plaintext_block.append(plaintext_matrix[i][0][0])
                plaintext_block.append(plaintext_matrix[i][1][0])
                plaintext_block.append(plaintext_matrix[i][0][1])
                plaintext_block.append(plaintext_matrix[i][1][1])

            plaintext_blocks.append(''.join(plaintext_block))

        return plaintext_blocks

    @classmethod
    def __perform_encryption_round(self, plaintext_blocks, keys, round_number):
        """
        To perform 2 round of encryption 
        Parameters:
        plaintext_blocks (list): List of plaintext block (pair wise blocks of the entire text e.g ok!! => ['ok', '!!'])
        keys (list): sub keys 8 bit words list
        round_number (int): Current round number
        Returns: 
        list: Return the operated plaintext blocks list 
        """

        # Splitting the subkey's words into 4 nibbles
        k1 = '{:08b}'.format(keys[0])
        k2 = '{:08b}'.format(keys[1])
        b0 = int(k1[:4], 2)  # nibble 1
        b1 = int(k1[4:], 2)  # nibble 2
        b2 = int(k2[:4], 2)  # nibble 3
        b3 = int(k2[4:], 2)  # nibble 4

        # Each of the below procees if for each of the 4 nibbles of every plaintext block

        # Subsituting nibbles
        for i in range(len(plaintext_blocks)):
            # substitution
            plaintext_blocks[i][0][0] = int(
                self.substitution_box[plaintext_blocks[i][0][0]], 2)
            plaintext_blocks[i][1][0] = int(
                self.substitution_box[plaintext_blocks[i][1][0]], 2)
            plaintext_blocks[i][0][1] = int(
                self.substitution_box[plaintext_blocks[i][0][1]], 2)
            plaintext_blocks[i][1][1] = int(
                self.substitution_box[plaintext_blocks[i][1][1]], 2)

        print(f"Round {round_number} Substitute nibbles:", ' '.join(self.__formatPlaintextMatrix(plaintext_blocks))
              )

        # Shift Rows
        for i in range(len(plaintext_blocks)):
            # Swap 2nd and 4th nibble
            plaintext_blocks[i][1][0], plaintext_blocks[i][1][1] = \
                plaintext_blocks[i][1][1], plaintext_blocks[i][1][0]

        print(f"Round {round_number} Shift rows:", ' '.join(self.__formatPlaintextMatrix(plaintext_blocks))
              )

        # Mix columns
        if round_number == 1:
            for i in range(len(plaintext_blocks)):
                # for nibble 1 => nibble1 * 1 xor nibble2 * 4
                first_operand = plaintext_blocks[i][0][0]
                second_operand = int(
                    self.mix_column_table['4'][plaintext_blocks[i][1][0]], 16)
                val1 = Operations.xor_operation(first_operand, second_operand)

                # for nibble 3 => nibble3 * 1 xor nibble4 * 4
                first_operand = plaintext_blocks[i][0][1]
                second_operand = int(
                    self.mix_column_table['4'][plaintext_blocks[i][1][1]], 16)
                val2 = Operations.xor_operation(first_operand, second_operand)

                # for nibble 2 => nibble1 * 4 xor nibble2 * 1
                first_operand = int(
                    self.mix_column_table['4'][plaintext_blocks[i][0][0]], 16)
                second_operand = plaintext_blocks[i][1][0]
                val3 = Operations.xor_operation(first_operand, second_operand)

                # for nibble 4 => nibble3 * 4 xor nibble4 * 1
                first_operand = int(
                    self.mix_column_table['4'][plaintext_blocks[i][0][1]], 16)
                second_operand = plaintext_blocks[i][1][1]
                val4 = Operations.xor_operation(first_operand, second_operand)

                plaintext_blocks[i][0][0] = val1
                plaintext_blocks[i][0][1] = val2
                plaintext_blocks[i][1][0] = val3
                plaintext_blocks[i][1][1] = val4

            print(f"Round {round_number} mix columns:", ' '.join(self.__formatPlaintextMatrix(plaintext_blocks))
                  )

        # Add round key
        for i in range(len(plaintext_blocks)):
            plaintext_blocks[i][0][0] = "{:04b}".format(Operations.xor_operation(
                plaintext_blocks[i][0][0], b0))
            plaintext_blocks[i][1][0] = "{:04b}".format(Operations.xor_operation(
                plaintext_blocks[i][1][0], b1))
            plaintext_blocks[i][0][1] = "{:04b}".format(Operations.xor_operation(
                plaintext_blocks[i][0][1], b2))
            plaintext_blocks[i][1][1] = "{:04b}".format(Operations.xor_operation(
                plaintext_blocks[i][1][1], b3))

        print(f"Round {round_number} Add round key:",
              ' '.join(self.__formatPlaintextMatrix(
                  plaintext_blocks, binary=True)))

        return plaintext_blocks

    @classmethod
    def encrypt(self, plaintext, keys):
        """
        Simplified AES encryption algorithm implementation 
        Parameters:
        plaintext (string): Text message input from the user
        keys (list): sub keys 8 bit words list 3 pairs
        Returns: 
        list: Return the encrypted ciphertext blocks of plaintext 
        """

        print("Cipher text intermediate computation process:")
        if len(plaintext) % 2:
            # if length is odd then to form pairs of each char add padding char '0'
            plaintext = plaintext + '0'
            self.is_padded = True

        # Creating blocks of 16 bit chars pair of the plaintext e.g ok!! => ['ok', '!!']
        plaintext_blocks = []
        for i in range(0, len(plaintext), 2):
            temp = "{:08b}".format(
                ord(plaintext[i])) + "{:08b}".format(ord(plaintext[i + 1]))
            plaintext_blocks.append(temp)

        print("Starting bitArray of message:", ' '.join(plaintext_blocks))

        # Perform the Initial round of adding key 0
        plaintext_blocks = self.__initial_round(plaintext_blocks, keys[0:2])

        print("After pre-round transformation:", ' '.join(plaintext_blocks))

        print(f'Round Key0: {self.__formatKey(keys[0:2])}\n')

        # Converting plaintext blocks list into list of matrix of each block
        plaintext_matrix = self.__convert_into_matrix(plaintext_blocks)

        # Performing the encryption round 1 with key 1
        plaintext_matrix = self.__perform_encryption_round(
            plaintext_matrix, keys[2:4], 1)

        print(f'Round Key1: {self.__formatKey(keys[2:4])}\n')

        # Performing the encryption round 2 with key 2
        plaintext_matrix = self.__perform_encryption_round(
            plaintext_matrix, keys[4:], 2)

        print(f'Round Key2: {self.__formatKey(keys[4:])}\n')

        # Creating ciphertext blocks list from the ciphertext matrix list
        ciphertext = []
        for i in plaintext_matrix:
            x = i[0][0] + i[1][0] + i[0][1] + i[1][1]
            ciphertext.append(x)
        return ciphertext

    @classmethod
    def __perform_decryption_round(self, ciphertext_matrix, keys, round_number):
        """
        To perform 2 rounds of decryption 
        Parameters:
        ciphertext_blocks (list): List of ciphertext block 
        keys (list): sub keys 8 bit words list
        round_number (int): Current round number
        Returns: 
        list: Return the operated ciphertext blocks list 
        """

        # Splitting the subkey's words into 4 nibbles
        k1 = '{:08b}'.format(keys[0])
        k2 = '{:08b}'.format(keys[1])
        b0 = int(k1[:4], 2)
        b1 = int(k1[4:], 2)
        b2 = int(k2[:4], 2)
        b3 = int(k2[4:], 2)

        # Inverse shift rows
        for i in range(len(ciphertext_matrix)):
            ciphertext_matrix[i][1][0], ciphertext_matrix[i][1][1] = \
                ciphertext_matrix[i][1][1], ciphertext_matrix[i][1][0]

        print(f"Round {round_number} Inverse shift rows:", ' '.join(self.__formatPlaintextMatrix(ciphertext_matrix, binary=True))
              )

        # Inverse Substitution
        for i in range(len(ciphertext_matrix)):
            ciphertext_matrix[i][0][0] = int(
                self.inv_substitution_box[ciphertext_matrix[i][0][0]], 2)
            ciphertext_matrix[i][1][0] = int(
                self.inv_substitution_box[ciphertext_matrix[i][1][0]], 2)
            ciphertext_matrix[i][0][1] = int(
                self.inv_substitution_box[ciphertext_matrix[i][0][1]], 2)
            ciphertext_matrix[i][1][1] = int(
                self.inv_substitution_box[ciphertext_matrix[i][1][1]], 2)

        print(f"Round {round_number} Inverse substitution:", ' '.join(
            self.__formatPlaintextMatrix(ciphertext_matrix, binary=False)))

        # Add round key
        for i in range(len(ciphertext_matrix)):
            ciphertext_matrix[i][0][0] = Operations.xor_operation(
                ciphertext_matrix[i][0][0], b0)
            ciphertext_matrix[i][1][0] = Operations.xor_operation(
                ciphertext_matrix[i][1][0], b1)
            ciphertext_matrix[i][0][1] = Operations.xor_operation(
                ciphertext_matrix[i][0][1], b2)
            ciphertext_matrix[i][1][1] = Operations.xor_operation(
                ciphertext_matrix[i][1][1], b3)

        print(f"Round {round_number} Add round key:", ' '.join(
            self.__formatPlaintextMatrix(ciphertext_matrix, binary=False)))

        # Inverse mix columns
        if round_number == 1:
            for i in range(len(ciphertext_matrix)):
                first_operand = int(
                    self.mix_column_table['9'][ciphertext_matrix[i][0][0]], 16)
                second_operand = int(
                    self.mix_column_table['2'][ciphertext_matrix[i][1][0]], 16)
                val1 = Operations.xor_operation(first_operand, second_operand)

                first_operand = int(
                    self.mix_column_table['9'][ciphertext_matrix[i][0][1]], 16)
                second_operand = int(
                    self.mix_column_table['2'][ciphertext_matrix[i][1][1]], 16)
                val2 = Operations.xor_operation(first_operand, second_operand)

                first_operand = int(
                    self.mix_column_table['2'][ciphertext_matrix[i][0][0]], 16)
                second_operand = int(
                    self.mix_column_table['9'][ciphertext_matrix[i][1][0]], 16)
                val3 = Operations.xor_operation(first_operand, second_operand)

                first_operand = int(
                    self.mix_column_table['2'][ciphertext_matrix[i][0][1]], 16)
                second_operand = int(
                    self.mix_column_table['9'][ciphertext_matrix[i][1][1]], 16)
                val4 = Operations.xor_operation(first_operand, second_operand)

                ciphertext_matrix[i][0][0] = val1
                ciphertext_matrix[i][0][1] = val2
                ciphertext_matrix[i][1][0] = val3
                ciphertext_matrix[i][1][1] = val4

            print(f"Round {round_number} Mix column:", ' '.join(
                self.__formatPlaintextMatrix(ciphertext_matrix, binary=False)))

        for i in range(len(ciphertext_matrix)):
            ciphertext_matrix[i][0][0] = "{:04b}".format(
                ciphertext_matrix[i][0][0])
            ciphertext_matrix[i][1][0] = "{:04b}".format(
                ciphertext_matrix[i][1][0])
            ciphertext_matrix[i][0][1] = "{:04b}".format(
                ciphertext_matrix[i][0][1])
            ciphertext_matrix[i][1][1] = "{:04b}".format(
                ciphertext_matrix[i][1][1])

        return ciphertext_matrix

    @classmethod
    def decrypt(self, ciphertext, keys):
        """
        Simplified AES decryption algorithm implementation 
        Parameters:
        ciphertext (list): ciphertext in hex form for each plain text block
        keys (list): sub keys 8 bit words list 3 pairs
        Returns: 
        str: Return the decrypted plaintext of the given ciphertext list 
        """

        print("Decryption Intermediate process:")

        # Converting each ciphertext block into 16 bit binary form from hex form
        ciphertext_blocks = []
        for i in ciphertext:
            ciphertext_blocks.append("{:016b}".format(int(i, 16)))

        print("Ciphertext bitArray:", ' '.join(ciphertext_blocks))

        # Initial round of adding round key 2
        ciphertext_blocks = SAES.__initial_round(ciphertext_blocks, keys[0:2])
        print("After pre-round transformation:", ' '.join(ciphertext_blocks))

        print(f'Round Key2: {self.__formatKey(keys[0:2])}\n')

        # converting ciphertext blocks list into ciphertext matrix list
        ciphertext_matrix = SAES.__convert_into_matrix(ciphertext_blocks)

        # Performing round 1 of decryption with round key 1
        ciphertext_matrix = SAES.__perform_decryption_round(
            ciphertext_matrix, keys[2:4], 1)

        print(f'Round Key1: {self.__formatKey(keys[2:4])}\n')

        # Performing decryption round 2 with round key 0
        plaintext_matrix = SAES.__perform_decryption_round(
            ciphertext_matrix, keys[4:], 2)

        print(f'Round Key0: {self.__formatKey(keys[4:])}\n')

        # Converting plaintext block matrix into linear list
        plaintext_blocks = []
        for i in plaintext_matrix:
            x = i[0][0] + i[1][0] + i[0][1] + i[1][1]
            plaintext_blocks.append(x)

        # If the plaintext was padded remove the last character from it
        if self.is_padded:
            plaintext_blocks[-1] = plaintext_blocks[-1][:-7]

        # Join all the block to form the final decrypted message
        plaintext = []
        for i in plaintext_blocks:
            plaintext.append(chr(int(i[:8], 2)))
            plaintext.append(chr(int(i[8:], 2)))

        plaintext = "".join(plaintext)

        return plaintext
