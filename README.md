# ElGamal digital signature scheme implementation using ECC

This repository represents a demonstration of how the ElGamal digital signature scheme can be implemented using Elliptic Curve Cryptography (ECC). The language used for the
implementation is Python3 and the main external dependencies are modules [ecpy](https://pypi.org/project/ECPy/) and [Crypto](https://pypi.org/project/pycrypto/).
The mathematics used here are based on the 2005 article "Elliptic Curve ElGamal Encryption and Signature Schemes" by Kefa Rabah. For comparison purposes, 
this repository provides two scripts: one that uses the elliptic curves-based algorithm outlined in the paper above (elgamal_ecc.py) 
and one that relies on the classic version of the scheme (elgamal_classic.py).

## Usage
### !!! before running the script, you must create an empty store.txt file in your working directory !!!

The elliptic curves implementation works in three modes: register, sign, and verify. 

The register mode allows users to provide a name (and optionally the curve they wish to use for key generation)
and then generates a pair of private/public keys associated with the given name and stored in the store.txt file. The other 2 modes use the name provided here to determine which pair
of keys should be used for signing/verification.

The sign mode takes the name associated with the pair of keys that will be used for the operation and a message. The output is the base64 encoded signature of the message.

The verify mode takes a message, signature, and the name associated with the pair of keys which will be used for signature verification. It will output a message that specifies whether
the signature is valid for the given message and key pair.

This is example of how to use the three modes:
```
>> python3 elgamal_ecc.py --mode register --identity test1 --keysize 128
>> python3 elgamal_ecc.py --mode sign --identity test1 --message 'some secret message' > signature
>> python3 elgamal_ecc.py --mode verify --identity test1 --message 'some secret message' --signature ./signature
Signature is valid
>> python3 elgamal_ecc.py --mode verify --identity test1 --message 'some secret messages' --signature ./signature
Signature is NOT valid
```

