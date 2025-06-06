# generate random number
# check if prime
# if no generate again
# if yes generate smaller random number

import random

import sympy
from math import gcd


class Diffie_Hellman:

    '''

    def test(self):

        p = self.generate_p()
        g = self.generate_g(p)

        a = self.generate_s(p)
        b = self.generate_s(p)

        print(f"Alice secret key: {a}")
        print(f"Bob secret key: {b}")
        print()

        A = self.calculate_send_value(g, a, p)
        B = self.calculate_send_value(g, b, p)

        ka = self.calculate_key(a, B, p)
        kb = self.calculate_key(b, A, p)

        print(f"Alice key calculated: {ka}")
        print(f"Bob key calculated: {kb}")
        print()

        if ka == kb:
            key = ka
        else:
            print("Error")
            key = -1

        return key

    def test_2(self):

        p, g, a, A = self.alice()

        b, B = self.bob(p, g)

        ka = self.calculate_key(a, B, p)
        kb = self.calculate_key(b, A, p)

        print(f"Alice key calculated: {ka}")
        print(f"Bob key calculated: {kb}")
        print()

        if ka == kb:
            key = ka
        else:
            print("Error")
            key = -1

        return key

    '''

    def alice(self):

        # generate prime number p
        p = self.generate_p()

        # generate base g
        g = self.generate_g(p)

        # generate Alice's secret integer
        a = self.generate_s(p)

        # generate integer to send to Bob
        A = self.calculate_send_value(g, a, p)

        # return generated values
        return p, g, a, A

    def bob(self, p, g):

        # generate Bob's secret integer
        b = self.generate_s(p)

        # generate integer to send to Alice
        B = self.calculate_send_value(g, b, p)

        # return generated values
        return b, B

    def generate_p(self):

        # initialise list
        primes = []

        # create list of 8-bit prime numbers
        for x in range(0, 255):
            if sympy.isprime(x):
                primes.append(x)

        # choose random value from prime number list
        p = random.choice(primes)

        # return chosen value
        return p

    def generate_g(self, p):

        # get list of primitive roots modulo p
        prim_roots = self.primRoots(p)

        # choose random value from primitive roots list
        g = random.choice(prim_roots)

        # return chosen value
        return g

    def primRoots(self, modulo):
        # https://math.stackexchange.com/questions/4143148/how-can-i-use-python-to-find-all-the-primitive-roots-of-a-number-for-which-it-ex

        required_set = {num for num in range(1, modulo) if gcd(num, modulo)}
        return [g for g in range(1, modulo) if required_set == {pow(g, powers, modulo) for powers in range(1, modulo)}]

    def generate_s(self, p):

        # generate random integer between 1 and p-1
        s = random.randint(1, p-1)

        # return generated value
        return s

    def calculate_send_value(self, g, s, p):

        # calculate value to send to other party
        S = (pow(g, s)) % p

        # return calculated value
        return S

    def calculate_key(self, s, S, p):

        # calculate shared secret key
        k = (pow(S, s) % p)

        # return key
        return k


'''
if __name__ == '__main__':

    key = Diffie_Hellman().test_2()

    print(f"Value of key returned: {key}")
'''
