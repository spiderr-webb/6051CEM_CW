import hashlib


class Tokenisation:

    def get_token(self, details):

        # calculate hash value from details
        encoded = details.encode()
        result = hashlib.sha256(encoded)
        token = result.hexdigest()

        # return hash value
        return token
