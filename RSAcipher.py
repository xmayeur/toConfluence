from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from base64 import b64encode, b64decode


class RSAcipher:

    def __init__(self, certfile=None, key=None):
        try:
            if key is not None:
                self.key = RSA.importKey(key)

            elif certfile is not None:
                self.key = RSA.importKey(open(certfile).read())

            else:
                self.key = RSA.generate(2048)

            _pubkey = self.key.publickey()
            self.pubkey = _pubkey.exportKey()
            self.privkey = self.key.exportKey('PEM')
            self.rsa = PKCS1_OAEP.new(self.key)

        except Exception as e:
            print('Error initializing RSAcipher : ' + e.message)
            self.key = None

    def create_keyset(self, name='key'):
        self.key = RSA.generate(2048)
        with open(name + '.key', 'wb') as f:
            f.write(self.key.exportKey('PEM'))
        self.pubkey = self.key.publickey()
        with open(name + '.pub', 'wb') as f:
            f.write(self.pubkey.exportKey())
        return self.key

    def encrypt(self, text):
        return b64encode(self.rsa.encrypt(text.encode())).decode()

    def decrypt(self, msg):
        try:
            return self.rsa.decrypt(b64decode(msg)).decode()
        except Exception as e:
            return None


def main():
    rsa = RSAcipher()
    rsa.create_keyset('H:/.ssh/XY56RE')


if __name__ == "__main__":
    main()
