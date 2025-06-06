import numpy as np

# from diffie_hellman import Diffie_Hellman


class AES:

    '''

    def test(self):

        print("Enter message:")
        plaintext = input()

        key = self.generate_key()

        encrypted = self.encrypt(plaintext, key)

        print(self.decrypt(encrypted, key))

    '''

    def encrypt(self, plaintext, key):

        # create s-box
        s_box = [
            [int('63', 16), int('7c', 16), int('77', 16), int('7b', 16), int('f2', 16), int('6b', 16), int('6f', 16), int('c5', 16),
             int('30', 16), int('01', 16), int('67', 16), int('2b', 16), int('fe', 16), int('d7', 16), int('ab', 16), int('76', 16)],
            [int('ca', 16), int('82', 16), int('c9', 16), int('7d', 16), int('fa', 16), int('59', 16), int('47', 16), int('f0', 16),
             int('ad', 16), int('d4', 16), int('a2', 16), int('af', 16), int('9c', 16), int('a4', 16), int('72', 16), int('c0', 16)],
            [int('b7', 16), int('fd', 16), int('93', 16), int('26', 16), int('36', 16), int('3f', 16), int('f7', 16), int('cc', 16),
             int('34', 16), int('a5', 16), int('e5', 16), int('f1', 16), int('71', 16), int('d8', 16), int('31', 16), int('15', 16)],
            [int('04', 16), int('c7', 16), int('23', 16), int('c3', 16), int('18', 16), int('96', 16), int('05', 16), int('9a', 16),
             int('07', 16), int('12', 16), int('80', 16), int('e2', 16), int('eb', 16), int('27', 16), int('b2', 16), int('75', 16)],
            [int('09', 16), int('83', 16), int('2c', 16), int('1a', 16), int('1b', 16), int('6e', 16), int('5a', 16), int('a0', 16),
             int('52', 16), int('3b', 16), int('d6', 16), int('b3', 16), int('29', 16), int('e3', 16), int('2f', 16), int('84', 16)],
            [int('53', 16), int('d1', 16), int('00', 16), int('ed', 16), int('20', 16), int('fc', 16), int('b1', 16), int('5b', 16),
             int('6a', 16), int('cb', 16), int('be', 16), int('39', 16), int('4a', 16), int('4c', 16), int('58', 16), int('cf', 16)],
            [int('d0', 16), int('ef', 16), int('aa', 16), int('fb', 16), int('43', 16), int('4d', 16), int('33', 16), int('85', 16),
             int('45', 16), int('f9', 16), int('02', 16), int('7f', 16), int('50', 16), int('3c', 16), int('9f', 16), int('a8', 16)],
            [int('51', 16), int('a3', 16), int('40', 16), int('8f', 16), int('92', 16), int('9d', 16), int('38', 16), int('f5', 16),
             int('bc', 16), int('b6', 16), int('da', 16), int('21', 16), int('10', 16), int('ff', 16), int('f3', 16), int('d2', 16)],
            [int('cd', 16), int('0c', 16), int('13', 16), int('ec', 16), int('5f', 16), int('97', 16), int('44', 16), int('17', 16),
             int('c4', 16), int('a7', 16), int('7e', 16), int('3d', 16), int('64', 16), int('5d', 16), int('19', 16), int('73', 16)],
            [int('60', 16), int('81', 16), int('4f', 16), int('dc', 16), int('22', 16), int('2a', 16), int('90', 16), int('88', 16),
             int('46', 16), int('ee', 16), int('b8', 16), int('14', 16), int('de', 16), int('5e', 16), int('0b', 16), int('db', 16)],
            [int('e0', 16), int('32', 16), int('3a', 16), int('0a', 16), int('49', 16), int('06', 16), int('24', 16), int('5c', 16),
             int('c2', 16), int('d3', 16), int('ac', 16), int('62', 16), int('91', 16), int('95', 16), int('e4', 16), int('79', 16)],
            [int('e7', 16), int('c8', 16), int('37', 16), int('6d', 16), int('8d', 16), int('d5', 16), int('4e', 16), int('a9', 16),
             int('6c', 16), int('56', 16), int('f4', 16), int('ea', 16), int('65', 16), int('7a', 16), int('ae', 16), int('08', 16)],
            [int('ba', 16), int('78', 16), int('25', 16), int('2e', 16), int('1c', 16), int('a6', 16), int('b4', 16), int('c6', 16),
             int('e8', 16), int('dd', 16), int('74', 16), int('1f', 16), int('4b', 16), int('bd', 16), int('8b', 16), int('8a', 16)],
            [int('70', 16), int('3e', 16), int('b5', 16), int('66', 16), int('48', 16), int('03', 16), int('f6', 16), int('0e', 16),
             int('61', 16), int('35', 16), int('57', 16), int('b9', 16), int('86', 16), int('c1', 16), int('1d', 16), int('9e', 16)],
            [int('e1', 16), int('f8', 16), int('98', 16), int('11', 16), int('69', 16), int('d9', 16), int('8e', 16), int('94', 16),
             int('9b', 16), int('1e', 16), int('87', 16), int('e9', 16), int('ce', 16), int('55', 16), int('28', 16), int('df', 16)],
            [int('8c', 16), int('a1', 16), int('89', 16), int('0d', 16), int('bf', 16), int('e6', 16), int('42', 16), int('68', 16),
             int('41', 16), int('99', 16), int('2d', 16), int('0f', 16), int('b0', 16), int('54', 16), int('bb', 16), int('16', 16)]
        ]

        # convert plaintext into blocks of binary bytes
        msg_blocks = self.convert_message(plaintext)

        # calculate keys to be used for each round
        round_keys = self.calculate_key_schedule(key)

        # initialise array
        encrypted_message = []

        # for each 16 byte block
        for m in msg_blocks:

            # ~~~ add round key ~~~

            block = self.add_round_key(m, round_keys[0])

            # ~~~ 9 rounds of sub bytes, shift rows, mix columns, add round key ~~~

            for x in range(0, 9):

                subbed_bytes = self.sub_bytes(block, s_box)

                shifted_rows = self.shift_rows(subbed_bytes)

                mixed_columns = self.mix_columns(shifted_rows)

                block = self.add_round_key(mixed_columns, round_keys[x + 1])

            # ~~~ last round of sub bytes, shift rows, add round key ~~~

            subbed_bytes = self.sub_bytes(block, s_box)

            shifted_rows = self.shift_rows(subbed_bytes)

            block = self.add_round_key(shifted_rows, round_keys[10])

            # append block to encrypted message
            encrypted_message.append(block)

        # return encrypted message
        return encrypted_message

    def decrypt(self, msg_blocks, key):

        # create inverse s-box
        inverse_s_box = [
            [int('52', 16), int('09', 16), int('6a', 16), int('d5', 16), int('30', 16), int('36', 16), int('a5', 16), int('38', 16),
             int('bf', 16), int('40', 16), int('a3', 16), int('9e', 16), int('81', 16), int('f3', 16), int('d7', 16), int('fb', 16)],
            [int('7c', 16), int('e3', 16), int('39', 16), int('82', 16), int('9b', 16), int('2f', 16), int('ff', 16), int('87', 16),
             int('34', 16), int('8e', 16), int('43', 16), int('44', 16), int('c4', 16), int('de', 16), int('e9', 16), int('cb', 16)],
            [int('54', 16), int('7b', 16), int('94', 16), int('32', 16), int('a6', 16), int('c2', 16), int('23', 16), int('3d', 16),
             int('ee', 16), int('4c', 16), int('95', 16), int('0b', 16), int('42', 16), int('fa', 16), int('c3', 16), int('4e', 16)],
            [int('08', 16), int('2e', 16), int('a1', 16), int('66', 16), int('28', 16), int('d9', 16), int('24', 16), int('b2', 16),
             int('76', 16), int('5b', 16), int('a2', 16), int('49', 16), int('6d', 16), int('8b', 16), int('d1', 16), int('25', 16)],
            [int('72', 16), int('f8', 16), int('f6', 16), int('64', 16), int('86', 16), int('68', 16), int('98', 16), int('16', 16),
             int('d4', 16), int('a4', 16), int('5c', 16), int('cc', 16), int('5d', 16), int('65', 16), int('b6', 16), int('92', 16)],
            [int('6c', 16), int('70', 16), int('48', 16), int('50', 16), int('fd', 16), int('ed', 16), int('b9', 16), int('da', 16),
             int('5e', 16), int('15', 16), int('46', 16), int('57', 16), int('a7', 16), int('8d', 16), int('9d', 16), int('84', 16)],
            [int('90', 16), int('d8', 16), int('ab', 16), int('00', 16), int('8c', 16), int('bc', 16), int('d3', 16), int('0a', 16),
             int('f7', 16), int('e4', 16), int('58', 16), int('05', 16), int('b8', 16), int('b3', 16), int('45', 16), int('06', 16)],
            [int('d0', 16), int('2c', 16), int('1e', 16), int('8f', 16), int('ca', 16), int('3f', 16), int('0f', 16), int('02', 16),
             int('c1', 16), int('af', 16), int('bd', 16), int('03', 16), int('01', 16), int('13', 16), int('8a', 16), int('6b', 16)],
            [int('3a', 16), int('91', 16), int('11', 16), int('41', 16), int('4f', 16), int('67', 16), int('dc', 16), int('ea', 16),
             int('97', 16), int('f2', 16), int('cf', 16), int('ce', 16), int('f0', 16), int('b4', 16), int('e6', 16), int('73', 16)],
            [int('96', 16), int('ac', 16), int('74', 16), int('22', 16), int('e7', 16), int('ad', 16), int('35', 16), int('85', 16),
             int('e2', 16), int('f9', 16), int('37', 16), int('e8', 16), int('1c', 16), int('75', 16), int('df', 16), int('6e', 16)],
            [int('47', 16), int('f1', 16), int('1a', 16), int('71', 16), int('1d', 16), int('29', 16), int('c5', 16), int('89', 16),
             int('6f', 16), int('b7', 16), int('62', 16), int('0e', 16), int('aa', 16), int('18', 16), int('be', 16), int('1b', 16)],
            [int('fc', 16), int('56', 16), int('3e', 16), int('4b', 16), int('c6', 16), int('d2', 16), int('79', 16), int('20', 16),
             int('9a', 16), int('db', 16), int('c0', 16), int('fe', 16), int('78', 16), int('cd', 16), int('5a', 16), int('f4', 16)],
            [int('1f', 16), int('dd', 16), int('a8', 16), int('33', 16), int('88', 16), int('07', 16), int('c7', 16), int('31', 16),
             int('b1', 16), int('12', 16), int('10', 16), int('59', 16), int('27', 16), int('80', 16), int('ec', 16), int('5f', 16)],
            [int('60', 16), int('51', 16), int('7f', 16), int('a9', 16), int('19', 16), int('b5', 16), int('4a', 16), int('0d', 16),
             int('2d', 16), int('e5', 16), int('7a', 16), int('9f', 16), int('93', 16), int('c9', 16), int('9c', 16), int('ef', 16)],
            [int('a0', 16), int('e0', 16), int('3b', 16), int('4d', 16), int('ae', 16), int('2a', 16), int('f5', 16), int('b0', 16),
             int('c8', 16), int('eb', 16), int('bb', 16), int('3c', 16), int('83', 16), int('53', 16), int('99', 16), int('61', 16)],
            [int('17', 16), int('2b', 16), int('04', 16), int('7e', 16), int('ba', 16), int('77', 16), int('d6', 16), int('26', 16),
             int('e1', 16), int('69', 16), int('14', 16), int('63', 16), int('55', 16), int('21', 16), int('0c', 16), int('7d', 16)]
        ]

        # calculate keys to be used for each round
        round_keys = self.calculate_key_schedule(key)

        # initialise array
        decrypted_message = []

        # for each 16 byte block
        for m in msg_blocks:

            # ~~~ add round key ~~~

            block = self.add_round_key(m, round_keys[10])

            # ~~~ 9 rounds of inverse shift rows, inverse sub bytes, add round key, inverse mix columns ~~~

            for x in range(0, 9):

                shifted_rows = self.inverse_shift_rows(block)

                subbed_bytes = self.sub_bytes(shifted_rows, inverse_s_box)

                added_key = self.add_round_key(subbed_bytes, round_keys[9 - x])

                block = self.inverse_mix_columns(added_key)

            # ~~~ last round of inverse shift rows, inverse sub bytes, add round key ~~~

            shifted_rows = self.inverse_shift_rows(block)

            subbed_bytes = self.sub_bytes(shifted_rows, inverse_s_box)

            block = self.add_round_key(subbed_bytes, round_keys[0])

            # append block to decrypted message
            decrypted_message.append(block)

        # join blocks to create string of binary of decrypted message
        decrypted_bin = self.join_blocks(decrypted_message)

        # return decrypted message converted to string
        return self.bin_to_string(decrypted_bin)

    def convert_message(self, message):

        # add extra characters until message can be divided into equal blocks of 16 bytes
        while len(message) % 16 != 0:
            message += "-"

        # convert message to binary
        msg_bin = self.string_to_bin(message)

        # divide binary string into blocks of 128 bits (16 bytes)
        blocks = self.split(msg_bin, 128)

        # initialise array
        organised_blocks = []

        # for each block of 128 bits
        for b in blocks:

            # organise block into 2d array of columns and append to array
            organised_blocks.append(self.organise_block(b))

        # return 2d array of blocks
        return organised_blocks

    def organise_block(self, b):

        # divide block into columns of 32 bits (4 bytes)
        column = self.split(b, 32)

        # initialise array
        byte_blocks = []

        # for each column in block
        for c in column:

            # divide column into individual bytes and append to array
            byte_blocks.append(self.split(c, 8))

        # return 2d array of blocks
        return byte_blocks

    def join_blocks(self, array):

        # initialise string
        string = ""

        # for each 16 byte block in message
        for a in array:
            # for each 4 byte column in block
            for b in a:
                # for each byte in column
                for c in b:
                    # add byte to end of string
                    string = string + c

        # return string of joined blocks
        return string

    def string_to_bin(self, string):
        # https://stackoverflow.com/questions/18815820/how-to-convert-string-to-binary

        binary = ''.join(format(ord(i), '08b') for i in string)

        return binary

    def bin_to_string(self, binary):
        # https://stackoverflow.com/questions/40557335/binary-to-string-text-in-python

        string = ''.join(chr(int(binary[i*8:i*8+8], 2)) for i in range(len(binary)//8))

        return string

    def split(self, string, block_length):
        # https://stackoverflow.com/questions/21351275/split-a-string-to-even-sized-chunks

        blocks = [string[i:i+block_length] for i in range(0, len(string), block_length)]

        return blocks

    def calculate_key_schedule(self, key):

        '''
        rconi = [rci 00 00 00]

        n = 4
        r = 11
        k0 - k3 = 32 bit words of original key
        w0 - w43 = 32 bit words of expanded key

        rotword = 1 byte left circular shift
        subword = application of s box to each 4 bytes of word

        if i < n:
            wi = ki
        if i >= n and i = 0 mod n
            wi = wi-n xor subword(rotword(wi-1)) xor rconi/n
        else
            wi = wi-n xor wi-1
        '''

        # create s-box
        s_box = [
            [int('63', 16), int('7c', 16), int('77', 16), int('7b', 16), int('f2', 16), int('6b', 16), int('6f', 16), int('c5', 16),
             int('30', 16), int('01', 16), int('67', 16), int('2b', 16), int('fe', 16), int('d7', 16), int('ab', 16), int('76', 16)],
            [int('ca', 16), int('82', 16), int('c9', 16), int('7d', 16), int('fa', 16), int('59', 16), int('47', 16), int('f0', 16),
             int('ad', 16), int('d4', 16), int('a2', 16), int('af', 16), int('9c', 16), int('a4', 16), int('72', 16), int('c0', 16)],
            [int('b7', 16), int('fd', 16), int('93', 16), int('26', 16), int('36', 16), int('3f', 16), int('f7', 16), int('cc', 16),
             int('34', 16), int('a5', 16), int('e5', 16), int('f1', 16), int('71', 16), int('d8', 16), int('31', 16), int('15', 16)],
            [int('04', 16), int('c7', 16), int('23', 16), int('c3', 16), int('18', 16), int('96', 16), int('05', 16), int('9a', 16),
             int('07', 16), int('12', 16), int('80', 16), int('e2', 16), int('eb', 16), int('27', 16), int('b2', 16), int('75', 16)],
            [int('09', 16), int('83', 16), int('2c', 16), int('1a', 16), int('1b', 16), int('6e', 16), int('5a', 16), int('a0', 16),
             int('52', 16), int('3b', 16), int('d6', 16), int('b3', 16), int('29', 16), int('e3', 16), int('2f', 16), int('84', 16)],
            [int('53', 16), int('d1', 16), int('00', 16), int('ed', 16), int('20', 16), int('fc', 16), int('b1', 16), int('5b', 16),
             int('6a', 16), int('cb', 16), int('be', 16), int('39', 16), int('4a', 16), int('4c', 16), int('58', 16), int('cf', 16)],
            [int('d0', 16), int('ef', 16), int('aa', 16), int('fb', 16), int('43', 16), int('4d', 16), int('33', 16), int('85', 16),
             int('45', 16), int('f9', 16), int('02', 16), int('7f', 16), int('50', 16), int('3c', 16), int('9f', 16), int('a8', 16)],
            [int('51', 16), int('a3', 16), int('40', 16), int('8f', 16), int('92', 16), int('9d', 16), int('38', 16), int('f5', 16),
             int('bc', 16), int('b6', 16), int('da', 16), int('21', 16), int('10', 16), int('ff', 16), int('f3', 16), int('d2', 16)],
            [int('cd', 16), int('0c', 16), int('13', 16), int('ec', 16), int('5f', 16), int('97', 16), int('44', 16), int('17', 16),
             int('c4', 16), int('a7', 16), int('7e', 16), int('3d', 16), int('64', 16), int('5d', 16), int('19', 16), int('73', 16)],
            [int('60', 16), int('81', 16), int('4f', 16), int('dc', 16), int('22', 16), int('2a', 16), int('90', 16), int('88', 16),
             int('46', 16), int('ee', 16), int('b8', 16), int('14', 16), int('de', 16), int('5e', 16), int('0b', 16), int('db', 16)],
            [int('e0', 16), int('32', 16), int('3a', 16), int('0a', 16), int('49', 16), int('06', 16), int('24', 16), int('5c', 16),
             int('c2', 16), int('d3', 16), int('ac', 16), int('62', 16), int('91', 16), int('95', 16), int('e4', 16), int('79', 16)],
            [int('e7', 16), int('c8', 16), int('37', 16), int('6d', 16), int('8d', 16), int('d5', 16), int('4e', 16), int('a9', 16),
             int('6c', 16), int('56', 16), int('f4', 16), int('ea', 16), int('65', 16), int('7a', 16), int('ae', 16), int('08', 16)],
            [int('ba', 16), int('78', 16), int('25', 16), int('2e', 16), int('1c', 16), int('a6', 16), int('b4', 16), int('c6', 16),
             int('e8', 16), int('dd', 16), int('74', 16), int('1f', 16), int('4b', 16), int('bd', 16), int('8b', 16), int('8a', 16)],
            [int('70', 16), int('3e', 16), int('b5', 16), int('66', 16), int('48', 16), int('03', 16), int('f6', 16), int('0e', 16),
             int('61', 16), int('35', 16), int('57', 16), int('b9', 16), int('86', 16), int('c1', 16), int('1d', 16), int('9e', 16)],
            [int('e1', 16), int('f8', 16), int('98', 16), int('11', 16), int('69', 16), int('d9', 16), int('8e', 16), int('94', 16),
             int('9b', 16), int('1e', 16), int('87', 16), int('e9', 16), int('ce', 16), int('55', 16), int('28', 16), int('df', 16)],
            [int('8c', 16), int('a1', 16), int('89', 16), int('0d', 16), int('bf', 16), int('e6', 16), int('42', 16), int('68', 16),
             int('41', 16), int('99', 16), int('2d', 16), int('0f', 16), int('b0', 16), int('54', 16), int('bb', 16), int('16', 16)]
        ]

        # create table of rcon values
        rcon = [
            int('01000000', 16), int('02000000', 16), int('04000000', 16), int('08000000', 16), int('10000000', 16),
            int('20000000', 16), int('40000000', 16), int('80000000', 16), int('1B000000', 16), int('36000000', 16)
            ]

        # divide key into blocks of 32 bits
        k = self.split(key, 32)

        # initialise list
        w = []

        # n is the number of 32-bit words per round key (four for 128-bit key)

        # create four 32-bit words per round key needed (eleven rounds for 128-bit key)
        for i in range(0, 44):

            # if i is less than n
            if i < 4:
                # next word of expanded key is next word of original key
                w.append(k[i])

            # if i is more than n and a multiple of n
            elif (i >= 4) and (i % 4 == 0):

                # divide last 32-bit word calculated into bytes
                split = self.split(w[i - 1], 8)

                # initialise list
                rotword = []

                # rotate bytes in last 32-bit word calculated left by one place
                rotword.append(split[1:] + split[:1])

                # substitute rotated bytes according to s-box
                subword = self.sub_bytes(rotword, s_box)

                # convert substituted byte to 32-bit binary string and append to expanded key
                w.append(self.xor(self.xor(w[i - 4], ''.join(subword[0])), str('{0:032b}'.format(rcon[(i // 4) - 1]))))

            # otherwise
            else:
                # xor last 32-bit word calculated with word[i-n] and append to expanded key
                w.append(self.xor(w[i - 4], w[i - 1]))

        # initialise list
        round_keys = []

        # initialise string
        round_key = ""

        # for each 32-bit word of expanded key
        for j in range(0, 44):

            # add word to end of string
            round_key = round_key + w[j]

            # if string is a full round key
            if j % 4 == 3:

                # organise string into 2d array of columns and append to list of round keys
                round_keys.append(self.organise_block(round_key))

                # clear string
                round_key = ""

        # return list of round keys
        return round_keys

    def xor(self, a, b):

        # initialise string
        xor = ""

        # for each bit
        for i in range(len(a)):

            if a[i] == b[i]:
                # if bit in a and bit in b are the same, add 0 to end of string
                xor = xor + "0"
            else:
                # if bit in a and bit in b are different, add 1 to end of string
                xor = xor + "1"

        # return string
        return xor

    def add_round_key(self, m, k):

        # initialise array
        block = []

        # for each column in block
        for x in range(0, 4):

            # initialise list
            column = []

            # for each byte in column
            for y in range(0, 4):

                # new byte is original byte xor key byte
                xor = self.xor(m[x][y], k[x][y])

                # append byte to column
                column.append(xor)

            # append column to block
            block.append(column)

        # return block
        return block

    def sub_bytes(self, block, table):

        # initialise array
        subbed_block = []

        # for each column in block
        for column in block:

            # initialise list
            subbed_column = []

            # for each byte in column
            for byte in column:

                # divide byte into nibbles
                nibbles = self.split(byte, 4)

                # substitute byte according to given table (either s-box or inverse s-box)
                subbed_byte = table[int(nibbles[0], 2)][int(nibbles[1], 2)]

                # convert substituted byte to 8-bit binary string and append to column
                subbed_column.append('{0:08b}'.format(subbed_byte))

            # append column to block
            subbed_block.append(subbed_column)

        # return substituted block
        return subbed_block

    def shift_rows(self, block):

        # convert block to numpy array
        block_array = np.asarray(block)

        # swap columns and rows
        rows_block = block_array.T.tolist()

        # set number of places to rotate by to zero
        x = 0

        # initialise list
        rot_rows = []

        # for each row in block
        for rows in rows_block:

            # rotate values in row left by x places
            rot_rows.append(rows[x:] + rows[:x])

            # increase number of places to rotate by by one
            x += 1

        # convert block of rotated rows to numpy array
        block_array = np.asarray(rot_rows)

        # swap rows and columns
        columns_block = block_array.T.tolist()

        # return block of rotated rows
        return columns_block

    def inverse_shift_rows(self, block):

        # convert block to numpy array
        block_array = np.asarray(block)

        # swap columns and rows
        rows_block = block_array.T.tolist()

        # set number of places to rotate by to zero
        x = 0

        # initialise list
        rot_rows = []

        # for each row in block
        for rows in rows_block:

            # shift values in row right by x places
            rot_rows.append(rows[-x:] + rows[:-x])

            # increase number of places to shift by by one
            x += 1

        # convert block of rotated rows to numpy array
        block_array = np.asarray(rot_rows)

        # swap rows and columns
        columns_block = block_array.T.tolist()

        # return block of rotated rows
        return columns_block

    def mix_columns(self, block):

        '''

        for each column

            result[0] = ([0] * 2) xor ([1] * 3) xor [2] xor [3]
            result[1] = [0] xor ([1] * 2) xor ([2] * 3) xor [3]
            result[2] = [0] xor [1] xor ([2] * 2) xor ([3] * 3)
            result[3] = ([0] * 3) xor [1] xor [2] xor ([3] * 2)

        mult_by_two

            if [x][0] == 1
                result = ([x] << 1) xor 1b
            else
                result = [x] << 1

        mult_by_three

            result = mult_by_two([x]) xor [x]

        '''

        # initialise array
        result_block = []

        # for each column in block
        for column in block:

            # initialise list
            result = []

            # multiply first byte in column by two
            two_result = self.mult_by_two(column[0])
            # multiply second byte in column by three
            three_result = self.xor(self.mult_by_two(column[1]), column[1])

            # add first byte multiplied by two, second byte multiplied by three, third byte, and fourth byte, and append to result column
            result.append(self.xor(self.xor(two_result, three_result), self.xor(column[2], column[3])))

            # multiply second byte in column by two
            two_result = self.mult_by_two(column[1])
            # multiply third byte in column by three
            three_result = self.xor(self.mult_by_two(column[2]), column[2])

            # add first byte, second byte multiplied by two, third byte multiplied by three, and fourth byte, and append to result column
            result.append(self.xor(self.xor(two_result, three_result), self.xor(column[0], column[3])))

            # multiply third byte in column by two
            two_result = self.mult_by_two(column[2])
            # multiply fourth byte in column by three
            three_result = self.xor(self.mult_by_two(column[3]), column[3])

            # add first byte, second byte, third byte multiplied by two, and fourth byte multiplied by three, and append to result column
            result.append(self.xor(self.xor(two_result, three_result), self.xor(column[0], column[1])))

            # multiply fourth byte in column by two
            two_result = self.mult_by_two(column[3])
            # multiply first byte in column by three
            three_result = self.xor(self.mult_by_two(column[0]), column[0])

            # add first byte multiplied by three, second byte, third byte, and fourth byte multiplied by two, and append to result column
            result.append(self.xor(self.xor(two_result, three_result), self.xor(column[1], column[2])))

            # append result column to result block
            result_block.append(result)

        # return result block
        return result_block

    def inverse_mix_columns(self, block):

        '''

        [ 14  11  13  9  ]
        | 9   14  11  13 |
        | 13  9   14  11 |
        [ 11  13  9   14 ]

        x×9=(((x×2)×2)×2)+x
        x×11=((((x×2)×2)+x)×2)+x
        x×13=((((x×2)+x)×2)×2)+x
        x×14=((((x×2)+x)×2)+x)×2

        '''

        # initialise array
        result_block = []

        # for each column in block
        for column in block:

            # initialise list
            result = []

            # multiply first byte in column by fourteen
            first = self.mult_by_two(self.xor(self.mult_by_two(self.xor(self.mult_by_two(column[0]), column[0])), column[0]))
            # multiply second byte in column by eleven
            second = self.xor(self.mult_by_two(self.xor(self.mult_by_two(self.mult_by_two(column[1])), column[1])), column[1])
            # multiply third byte in column by thirteen
            third = self.xor(self.mult_by_two(self.mult_by_two(self.xor(self.mult_by_two(column[2]), column[2]))), column[2])
            # multiply forth byte in column by nine
            fourth = self.xor(self.mult_by_two(self.mult_by_two(self.mult_by_two(column[3]))), column[3])

            # add multiplied first byte, second byte, third byte, and fourth byte, and append to result column
            result.append(self.xor(self.xor(first, second), self.xor(third, fourth)))

            # multiply first byte in column by nine
            first = self.xor(self.mult_by_two(self.mult_by_two(self.mult_by_two(column[0]))), column[0])
            # multiply second byte in column by fourteen
            second = self.mult_by_two(self.xor(self.mult_by_two(self.xor(self.mult_by_two(column[1]), column[1])), column[1]))
            # multiply third byte in column by eleven
            third = self.xor(self.mult_by_two(self.xor(self.mult_by_two(self.mult_by_two(column[2])), column[2])), column[2])
            # multiply fourth byte in column by thirteen
            fourth = self.xor(self.mult_by_two(self.mult_by_two(self.xor(self.mult_by_two(column[3]), column[3]))), column[3])

            # add multiplied first byte, second byte, third byte, and fourth byte, and append to result column
            result.append(self.xor(self.xor(first, second), self.xor(third, fourth)))

            # multiply first byte in column by thirteen
            first = self.xor(self.mult_by_two(self.mult_by_two(self.xor(self.mult_by_two(column[0]), column[0]))), column[0])
            # multiply second byte in column by nine
            second = self.xor(self.mult_by_two(self.mult_by_two(self.mult_by_two(column[1]))), column[1])
            # multiply third byte in column by fourteen
            third = self.mult_by_two(self.xor(self.mult_by_two(self.xor(self.mult_by_two(column[2]), column[2])), column[2]))
            # multiply fourth byte in column by eleven
            fourth = self.xor(self.mult_by_two(self.xor(self.mult_by_two(self.mult_by_two(column[3])), column[3])), column[3])

            # add multiplied first byte, second byte, third byte, and fourth byte, and append to result column
            result.append(self.xor(self.xor(first, second), self.xor(third, fourth)))

            # multiply first byte in column by eleven
            first = self.xor(self.mult_by_two(self.xor(self.mult_by_two(self.mult_by_two(column[0])), column[0])), column[0])
            # multiply second byte in column by thirteen
            second = self.xor(self.mult_by_two(self.mult_by_two(self.xor(self.mult_by_two(column[1]), column[1]))), column[1])
            # multiply third byte in column by nine
            third = self.xor(self.mult_by_two(self.mult_by_two(self.mult_by_two(column[2]))), column[2])
            # multiply fourth byte in column by fourteen
            fourth = self.mult_by_two(self.xor(self.mult_by_two(self.xor(self.mult_by_two(column[3]), column[3])), column[3]))

            # add multiplied first byte, second byte, third byte, and fourth byte, and append to result column
            result.append(self.xor(self.xor(first, second), self.xor(third, fourth)))

            # append result column to result block
            result_block.append(result)

        # return result block
        return result_block

    def mult_by_two(self, binary):

        # shift binary left by one place
        shifted = binary[1:] + '0'

        if binary[0] == '1':
            # if first bit is one, result is shifted byte xor 00011011
            result = self.xor(shifted, '00011011')
        else:
            # if first bit is zero, result is shifted byte
            result = shifted

        # return result
        return result

    '''
    def generate_key(self):

        x = 0
        key = ""

        # for speed calculating 16 separate keys and adding them together
        # would be more efficient to calculate as 1 long key
        while x < 16:

            p, g, a, A = Diffie_Hellman().alice()
            b, B = Diffie_Hellman().bob(p, g)

            ka = Diffie_Hellman().calculate_key(a, B, p)
            kb = Diffie_Hellman().calculate_key(b, A, p)

            if ka == kb:
                key = key + str('{0:08b}'.format(ka))
                x += 1
            else:
                print("Error")

        return key
    '''


'''
if __name__ == '__main__':

    go = AES()
'''
