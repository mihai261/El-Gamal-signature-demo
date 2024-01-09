import argparse
import binascii
from Crypto.Util import number
from Crypto.Random import get_random_bytes

# init
bits = 256

parser = argparse.ArgumentParser(prog="ElGamal Signature Test",
                                description="This is a basic implementation of the El Gamal signature scheme")
parser.add_argument('--mode', default='sign')
parser.add_argument('--keypair', nargs='+', type=int, default=[32, 211])
parser.add_argument('--message')
parser.add_argument('--signature', nargs='+', type=int)
args = parser.parse_args()

def sign(message, a, N):
    x = number.getPrime(bits, randfunc=get_random_bytes)
    p = pow(a, x, N)
    k = number.getPrime(bits, randfunc=get_random_bytes)
    S1 = pow(a, k, N)
    S2 = (pow(k, -1, N-1) * (message - S1*x)) % (N-1)
    return (p, S1, S2)


def verify(message, a, N, signature):
    (p, S1, S2) = signature
    V = (pow(p, S1) * pow(S1, S2)) % N
    W = pow(a, message, N)
    return V == W


def main():
    converted_message = int(binascii.hexlify(args.message.encode()), 16)
    if(args.mode == 'sign'):
        print(sign(converted_message, args.keypair[0], args.keypair[1]))
    elif(args.mode == 'verify'):
        if verify(converted_message, args.keypair[0], args.keypair[1], tuple(args.signature)):
            print('Signature is valid')
        else:
            print('Signature is not valid')

if __name__ == '__main__':
    main()
