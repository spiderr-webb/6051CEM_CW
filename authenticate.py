from math import lcm, gcd


class Authenticate:

    '''

    def test(self):

        signature = self.create_signature()

        print(signature)

        print(self.check_signature(signature, 'bank_keys/public_key.pem'))

    '''

    def generate_keys(self):

        # generate prime numbers p and q
        p, q = self.generate_p_q()

        # calculate n
        n = p * q

        # calculate Carmichael function of n
        c = lcm(p-1, q-1)

        # generate e
        e = self.generate_e(c)

        # calculate modular multiplicative inverse of e mod c
        d = pow(e, -1, c)

        # write n and e values to public key file
        public_key = open("bank_keys/public_key.txt", "w")
        public_key.write(str(n) + "\n")
        public_key.write(str(e) + "\n")
        public_key.close()

        # write n and d values to private key file
        private_key = open("bank_keys/private_key.txt", "w")
        private_key.write(str(n) + "\n")
        private_key.write(str(d) + "\n")
        private_key.close()

    def generate_p_q(self):

        # initialise list
        primes = []

        # create list of prime numbers between 10 and 2000
        for x in range(10, 2000):
            if sympy.isprime(x):
                primes.append(x)

        # choose random value from prime number list
        p = random.choice(primes)

        # clear list
        primes = []

        # create list of prime numbers between 2000 and 5000
        for y in range(2000, 5000):
            if sympy.isprime(y):
                primes.append(y)

        # choose random value from prime number list
        q = random.choice(primes)

        # return chosen prime number values
        return p, q

    def generate_e(self, c):

        # initialise list
        coprimes = []

        # create list of coprimes of c
        for x in range(2, c):
            if gcd(x, c) == 1:
                coprimes.append(x)

        # choose random value from coprimes list
        e = random.choice(coprimes)

        # return chosen coprime value
        return e

    def create_signature(self, keypath, bank_id):

        # read n and d values from private key file
        private_key = open(keypath, "r")
        n = private_key.readline().strip()
        d = private_key.readline().strip()
        private_key.close()

        # calculate digital signature value
        signature = pow(bank_id, int(d)) % int(n)

        # return signature as string
        return str(signature)

    def check_signature(self, signature, keypath, bank_id):

        # read n and e values from public key file
        public_key = open(keypath, "r")
        n = public_key.readline().strip()
        e = public_key.readline().strip()
        public_key.close()

        # calculate decrypted value
        decrypted = pow(int(signature), int(e)) % int(n)

        if decrypted == bank_id:
            # if decrypted value is expected value for bank return true
            return True
        else:
            # if decrypted value is not expected value for bank return false
            return False






'''
if __name__ == '__main__':

    go = Authenticate()
'''
