import argparse
import binascii
import base64
import sys
from ecpy.curves import Curve, Point
from random import randint


# argument parsing
parser = argparse.ArgumentParser(prog="ElGamal Signature with EC",
                                description="This is a basic implementation of the El Gamal signature scheme using elliptic curves")
parser.add_argument('--mode')
parser.add_argument('--key')
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


if args.mode == 'sign':
    converted_message = int(binascii.hexlify(args.message.encode()), 16)
    try:
        key = int(args.key)
    except:
        with open(args.key, 'r') as file:
            key = int(file.read())
    (Rx, Ry, s) = sign(converted_message, key)
    print(base64.b64encode(bytes(f'{str(Rx)} {str(Ry)} {str(s)}', 'utf-8')).decode('utf-8'))

elif args.mode == 'verify':
    converted_message = int(binascii.hexlify(args.message.encode()), 16)
    try:    
        with open(args.signature, 'r') as file:
                sig = file.read()
    except:
        sig = args.signature
    signature_str = base64.b64decode(sig).decode('utf-8')
    signature_components = signature_str.split(' ')
    try:
        with open(args.key, 'r') as file:
            key = file.read()
    except:
        key = args.key
    key_str = base64.b64decode(key).decode('utf-8')
    key_components = key_str.split(' ')
    try:
        R = Point(int(signature_components[0]), int(signature_components[1]), curve)
        A = Point(int(key_components[0]), int(key_components[1]), curve)
    except:
        print('Failed to generate points for given coordinates; cannot establish signature validity', file=sys.stderr)
        exit()
    s = int(signature_components[2])
    verify(converted_message, (R, s), A)

elif args.mode == 'generate':
    try:
        key = int(args.key)
    except:
        with open(args.key, 'r') as file:
            key = int(file.read())
    A = curve.mul_point(key, G)
    print(base64.b64encode(bytes(f'{str(A.x)} {str(A.y)}', 'utf-8')).decode('utf-8'))
