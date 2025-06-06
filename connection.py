from diffie_hellman import Diffie_Hellman
from aes import AES
from tokenisation import Tokenisation
from authenticate import Authenticate


# ~~~ merchant ~~~

# initialise string
merch_details = ""

# cardholder name given to merchant by customer
print("Cardholder name: ", end="")
merch_name = input()

# card details given to merchant by customer

print("Card number: ", end="")
merch_details = merch_details + input()

print("Issue date: ", end="")
merch_details = merch_details + input()

print("Expiry date: ", end="")
merch_details = merch_details + input()

print("Security code: ", end="")
merch_details = merch_details + input()

print()

# create merchant Tokenisation object
merch_tokenise = Tokenisation()

# create token from card details
merch_token = merch_tokenise.get_token(merch_details)

# plaintext to be sent by merchant is cardholder name and card details token
merch_plaintext = merch_name + "-" + merch_token

# create merchant Diffie-Hellman object
merch_dh = Diffie_Hellman()

# initialise lists
p_list = []
g_list = []

a_list = []
A_list = []

# generate information for sixteen keys using Diffie-Hellman
for w in range(0, 16):

    # generate p, g, Alice's secret integer, and Alice's integer to send
    p, g, a, A = merch_dh.alice()

    # append values to corresponding lists
    p_list.append(p)
    g_list.append(g)
    a_list.append(a)
    A_list.append(A)

# merchant sends p_list, g_list and A_list to bank


# ~~~ bank ~~~

# create bank Diffie-Hellman object
bank_dh = Diffie_Hellman()

# initialise lists
b_list = []
B_list = []

# generate information for sixteen keys using Diffie-Hellman
for x in range(0, 16):

    # generate Bob's secret integer, and Bob's integer to send
    b, B = bank_dh.bob(p_list[x], g_list[x])

    # append values to corresponding lists
    b_list.append(b)
    B_list.append(B)

# bank sends B_list to merchant


# ~~~ merchant ~~~

# initialise string
merch_key = ""

# for each of sixteen keys
for y in range(0, 16):

    # calculate shared secret key value, convert to 8-bit binary string, and add to end of merchant key string
    merch_key = merch_key + str('{0:08b}'.format(merch_dh.calculate_key(a_list[y], B_list[y], p_list[y])))


# ~~~ bank ~~~

# initialise string
bank_key = ""

# for each of sixteen keys
for z in range(0, 16):

    # calculate shared secret key value, convert to 8-bit binary string, and add to end of bank key string
    bank_key = bank_key + str('{0:08b}'.format(bank_dh.calculate_key(b_list[z], A_list[z], p_list[z])))

# create bank Authenticate object
bank_auth = Authenticate()

# generate bank's public and private keys
# (this line can be commented out after the first time the program runs)
bank_auth.generate_keys()

# generate bank signature using ID 12345
bank_signature = bank_auth.create_signature("bank_keys/private_key.txt", 12345)

# create bank AES object
bank_aes = AES()

# encrypt bank signature with AES using bank's Diffie-Hellman generated key
encrypted = bank_aes.encrypt(bank_signature, bank_key)

# bank sends encrypted to merchant


# ~~~ merchant ~~~

# create merchant AES object
merch_aes = AES()

# decrypt bank signature with AES using merchant's Diffie-Hellman generated key
decrypted = merch_aes.decrypt(encrypted, merch_key).split("-")

# create merchant Authenticate object
merch_auth = Authenticate()

# verify bank signature gives ID 12345
if merch_auth.check_signature(decrypted[0], "bank_keys/public_key.txt", 12345):
    # if bank signature is valid, print confirmation message
    print("Bank signature valid")
else:
    # if bank signature is not valid, print error message
    print("Bank signature not valid")

    # do not send card details to unverified bank
    merch_plaintext = "0"

print()

# encrypt cardholder name and card details token with AES using merchant's Diffie-Hellman generated key
encrypted = merch_aes.encrypt(merch_plaintext, merch_key)

# merchant sends encrypted to bank


# ~~~ bank ~~~

# # decrypt cardholder name and card details with AES using bank's Diffie-Hellman generated key
decrypted = bank_aes.decrypt(encrypted, bank_key)

# split cardholder name and card details
bank_received = decrypted.split("-")

# initialise string
details = ""

# open file containing account information and read first line
accounts = open("accounts.txt", "r")
line = accounts.readline().strip().split(",")

# while not at the end of the file
while line[0] != "END":

    # if cardholder name received from merchant same as account holder name in file
    if bank_received[0] == line[0]:

        # join card details into one string
        details = ''.join(line[1:])

    # read next line
    line = accounts.readline().strip().split(",")

# close file containing account information
accounts.close()

# create bank Tokenisation object
bank_tokenise = Tokenisation()

# create token from card details from file
bank_token = bank_tokenise.get_token(details)

if bank_token == bank_received[1]:
    # if token from card details from file is same as token received from merchant, send confirmation message
    bank_plaintext = "Card details valid"
else:
    # if token from card details from file is different from token received from merchant, send error message
    bank_plaintext = "Card details not valid"

# encrypt message with AES using bank's Diffie-Hellman generated key
encrypted = bank_aes.encrypt(bank_plaintext, bank_key)

# bank sends encrypted to merchant


# ~~~ merchant ~~~

# decrypt message with AES using merchant's Diffie-Hellman generated key
decrypted = merch_aes.decrypt(encrypted, merch_key).split("-")

# print message received from bank
print(decrypted[0])
