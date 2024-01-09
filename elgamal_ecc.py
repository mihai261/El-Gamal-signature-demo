import argparse
import binascii
import base64
import sys
import hashlib
from ecpy.curves import Curve, Point
from Crypto.Util import number
from Crypto.Random import get_random_bytes
from random import randint


# argument parsing
parser = argparse.ArgumentParser(prog="ElGamal Signature with EC",
                                description="This is a basic implementation of the El Gamal signature scheme using elliptic curves")
parser.add_argument('--mode')
parser.add_argument('--identity')
parser.add_argument('--keysize', type=int)
parser.add_argument('--message')
parser.add_argument('--signature')
parser.add_argument('--curve', default='NIST-P256')
args = parser.parse_args()


# curve setup
curve = Curve.get_curve(args.curve)
if curve == None:
    print(f'Unknown curve {args.curve}', file=sys.stderr)
    exit()
G = curve.generator
n = curve.order


# signing
def sign(message, kA):
    k = randint(1, n)
    R = curve.mul_point(k, G)
    r = R.x % n
    s = (pow(k, -1, n) * (message + kA*r)) % n
    return R.x, R.y, s


# verification
def verify(message, signature, A):
    (R, s) = signature
    V1 = curve.mul_point(s, R)
    V2 = curve.mul_point(message, G) + curve.mul_point(R.x, A)
    if(V1 == V2):
        print('Signature is valid')
    else:
        print('Signature is NOT valid')


def main():
    if args.mode == 'sign':
        data = args.message.encode()
        hash = hashlib.sha256(data).hexdigest()
        converted_message = int(binascii.hexlify(hash.encode()), 16)
        private_key = None

        with open('store.txt', 'r') as identity_store:
            while True:
                line = identity_store.readline()
                if not line: break

                tokens = line.split(' ')
                if len(tokens) != 3: continue
                identity = tokens[0]

                if identity == args.identity:
                    private_key = tokens[1]
                    break
        
        if private_key == None:
            print(f'No keys found for identity {args.identity}', file=sys.stderr)
            exit()

        (Rx, Ry, s) = sign(converted_message, int(private_key))
        print(base64.b64encode(bytes(f'{str(Rx)} {str(Ry)} {str(s)}', 'utf-8')).decode('utf-8'))

    elif args.mode == 'verify':
        data = args.message.encode()
        hash = hashlib.sha256(data).hexdigest()
        converted_message = int(binascii.hexlify(hash.encode()), 16)

        try:    
            with open(args.signature, 'r') as file:
                    sig = file.read()
        except:
            sig = args.signature
        signature_str = base64.b64decode(sig).decode('utf-8')
        signature_components = signature_str.split(' ')

        public_key = None
        with open('store.txt', 'r') as identity_store:
            while True:
                line = identity_store.readline()
                if not line: break

                tokens = line.split(' ')
                if len(tokens) != 3: continue
                identity = tokens[0]

                if identity == args.identity:
                    public_key = tokens[2]
                    break
        
        if public_key == None:
            print(f'No keys found for identity {args.identity}', file=sys.stderr)
            exit()

        key_str = base64.b64decode(public_key).decode('utf-8')
        key_components = key_str.split(' ')
        try:
            R = Point(int(signature_components[0]), int(signature_components[1]), curve)
            A = Point(int(key_components[0]), int(key_components[1]), curve)
        except:
            print('Signature is NOT valid')
            exit()
        s = int(signature_components[2])
        verify(converted_message, (R, s), A)
    
    elif args.mode == 'register':
        with open('store.txt', 'r') as identity_store:
            while True:
                line = identity_store.readline()
                if not line: break

                tokens = line.split(' ')
                if len(tokens) != 3: continue
                identity = tokens[0]

                if identity == args.identity:
                    print(f'Identity {identity} is already registered', file=sys.stderr)
                    exit()

            keysize = args.keysize
            key = number.getPrime(keysize, randfunc=get_random_bytes)
            A = curve.mul_point(key, G)
            A_base64 = base64.b64encode(bytes(f'{str(A.x)} {str(A.y)}', 'utf-8')).decode('utf-8')

            with open('store.txt', 'a') as identity_store:
                identity_store.write(f'{args.identity} {key} {A_base64}\n')


if __name__ == '__main__':
    main()
