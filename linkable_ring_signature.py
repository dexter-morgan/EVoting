#! /usr/bin/env python
#
# Provide an implementation of Linkable Spontaneus Anonymous Group Signature
# over elliptic curve cryptography.
#
# Implementation of cryptographic scheme from: https://eprint.iacr.org/2004/027.pdf
#
#
# Written in 2017 by Fernanddo Lobato Meeser and placed in the public domain.

import os
import hashlib
import functools
import ecdsa
import sys

from ecdsa.util import randrange
from ecdsa.ecdsa import curve_secp256k1
from ecdsa.curves import SECP256k1
from ecdsa import numbertheory
from eth_abi.packed import encode_single_packed, encode_abi_packed


def ring_signature(siging_key, key_idx, M, y, G=SECP256k1.generator, hash_func=hashlib.sha256):
    """
        Generates a ring signature for a message given a specific set of
        public keys and a signing key belonging to one of the public keys
        in the set.

        PARAMS
        ------

            signing_key: (int) The with which the message is to be anonymously signed.

            key_idx: (int) The index of the public key corresponding to the signature
                private key over the list of public keys that compromise the signature.

            M: (str) Message to be signed.

            y: (list) The list of public keys which over which the anonymous signature
                will be compose.

            G: (ecdsa.ellipticcurve.Point) Base point for the elliptic curve.

            hash_func: (function) Cryptographic hash function that recieves an input
                and outputs a digest.

        RETURNS
        -------

            Signature (c_0, s, Y) :
                c_0: Initial value to reconstruct signature.
                s = vector of randomly generated values with encrypted secret to
                    reconstruct signature.
                Y = Link for current signer.

    """
    n = len(y)
    c = [0] * n
    s = [0] * n

    # STEP 1
    H = H2(y, hash_func=hash_func)
    Y =  H * siging_key

    # STEP 2
    u = randrange(SECP256k1.order)

    c[(key_idx + 1) % n] = H1([y, Y, M, G * u, H * u], hash_func=hash_func)

    # STEP 3
    for i in [ i for i in range(key_idx + 1, n) ] + [i for i in range(key_idx)]:

        s[i] = randrange(SECP256k1.order)

        z_1 = (G * s[i]) + (y[i] * c[i])
        z_2 = (H * s[i]) + (Y * c[i])

        c[(i + 1) % n] = H1([y, Y, M, z_1, z_2], hash_func=hash_func)

    # STEP 4
    s[key_idx] = (u - siging_key * c[key_idx]) % SECP256k1.order
    return (c[0], s, Y)


def verify_ring_signature(message, y, c_0, s, Y, G=SECP256k1.generator, hash_func=hashlib.sha256):
    """
        Verifies if a valid signature was made by a key inside a set of keys.


        PARAMS
        ------
            message: (str) message whos' signature is being verified.

            y: (list) set of public keys with which the message was signed.

            Signature:
                c_0: (int) initial value to reconstruct the ring.

                s: (list) vector of secrets used to create ring.

                Y = (int) Link of unique signer.

            G: (ecdsa.ellipticcurve.Point) Base point for the elliptic curve.

            hash_func: (function) Cryptographic hash function that recieves an input
                and outputs a digest.

        RETURNS
        -------
            Boolean value indicating if signature is valid.

    """
    n = len(y)
    c = [c_0] + [0] * (n - 1)

    H = H2(y, hash_func=hash_func)
    # print ("H=",H)

    for i in range(n):
        z_1 = (G * s[i]) + (y[i] * c[i])
        z_2 = (H * s[i]) + (Y * c[i])

        # print ("z_1=",z_1)
        # print ("z_2=",z_2)

        if i < n - 1:
            c[i + 1] = H1([y, Y, message, z_1, z_2], hash_func=hash_func)
            # print ("c=",c[i+1])
        else:
            return c_0 == H1([y, Y, message, z_1, z_2], hash_func=hash_func)

    return False


def map_to_curve(x, P=curve_secp256k1.p()):
    """
        Maps an integer to an elliptic curve.

        Using the try and increment algorithm, not quite
        as efficient as I would like, but c'est la vie.

        PARAMS
        ------
            x: (int) number to be mapped into E.

            P: (ecdsa.curves.curve_secp256k1.p) Modulo for elliptic curve.

        RETURNS
        -------
            (ecdsa.ellipticcurve.Point) Point in Curve
    """
    x -= 1
    y = 0
    found = False

    while not found:
        x += 1
        f_x = (x * x * x + 7) % P

        try:
            y = numbertheory.square_root_mod_prime(f_x, P)
            found = True
        except Exception as e:
            pass

    return ecdsa.ellipticcurve.Point(curve_secp256k1, x, y)


def H1(msg, hash_func=hashlib.sha256):
    """
        Return an integer representation of the hash of a message. The
        message can be a list of messages that are concatenated with the
        concat() function.

        PARAMS
        ------
            msg: (str or list) message(s) to be hashed.

            hash_func: (function) a hash function which can recieve an input
                string and return a hexadecimal digest.

        RETURNS
        -------
            Integer representation of hexadecimal digest from hash function.
    """

    # print ("H1=",int('0x'+ hash_func(concat(msg)).hexdigest(), 16))
    return int('0x'+ hash_func(concat(msg)).hexdigest(), 16)


def H2(msg, hash_func=hashlib.sha256):
    """
        Hashes a message into an elliptic curve point.

        PARAMS
        ------
            msg: (str or list) message(s) to be hashed.

            hash_func: (function) Cryptographic hash function that recieves an input
                and outputs a digest.
        RETURNS
        -------
            ecdsa.ellipticcurve.Point to curve.
    """
    return map_to_curve(H1(msg, hash_func=hash_func))

def H1_improv(y, Y, message, z_1, z_2, hash_func=hashlib.sha3_256):

    return int('0x'+ hash_func(concat2(y, Y, message, z_1, z_2)).hexdigest(), 16)

def concat2(y, Y, message, z_1, z_2):

    return encode_abi_packed(['int256[2][]', 'uint256[2]', 'bytes32', 'uint256[2]', 'uint256[2]'], (y, Y, message, z_1, z_2))
    

def concat(params):
    """
        Concatenates a list of parameters into a bytes. If one
        of the parameters is a list, calls itself recursively.

        PARAMS
        ------
            params: (list) list of elements, must be of type:
                - int
                - list
                - str
                - ecdsa.ellipticcurve.Point

        RETURNS
        -------
            concatenated bytes of all values.
    """
    n = len(params)
    bytes_value = [0] * n

    for i in range(n):

        if type(params[i]) is int:
            bytes_value[i] = params[i].to_bytes(32, 'big')
            # print (bytes_value[i])
        if type(params[i]) is list:
            bytes_value[i] = concat(params[i])
            # print (bytes_value[i])
        if type(params[i]) is ecdsa.ellipticcurve.Point:
            bytes_value[i] = params[i].x().to_bytes(32, 'big') + params[i].y().to_bytes(32, 'big')
        if type(params[i]) is str:
            bytes_value[i] = params[i].encode()
            # print (bytes_value[i])
        if bytes_value[i] == 0:
            bytes_value[i] = params[i].x().to_bytes(32, 'big') + params[i].y().to_bytes(32, 'big')

    # print (bytes_value)
    return functools.reduce(lambda x, y: x + y, bytes_value)


def stringify_point(p):
    """
        Represents an elliptic curve point as a string coordinate.

        PARAMS
        ------
            p: ecdsa.ellipticcurve.Point - Point to represent as string.

        RETURNS
        -------
            (str) Representation of a point (x, y)
    """
    return '{},{}'.format(p.x(), p.y())


def stringify_point_js(p):
    """
        Represents an elliptic curve point as a string coordinate, the
        string format is javascript so other javascript scripts can
        consume this.

        PARAMS
        ------
            p: ecdsa.ellipticcurve.Point - Point to represent as string.

        RETURNS
        -------
            (str) Javascript string representation of a point (x, y)
    """
    return 'new BigNumber("{}"), new BigNumber("{}")'.format(p.x(), p.y())


def export_signature(y, message, signature, foler_name='./data', file_name='signature.txt'):
    """ Exports a signature to a specific folder and filename provided.

        The file contains the signature, the ring used to generate signature
        and the message being signed.
    """
    if not os.path.exists(foler_name):
        os.makedirs(foler_name)

    for k in range(0,len(signature[1])):
        signature[1][k] = hex(int(signature[1][k]))

    keyimage = [0, 0]
    keyimage[0] = hex(signature[2].x())
    keyimage[1] = hex(signature[2].y())

    arch = open(os.path.join(foler_name, file_name), 'w')
    S = ''.join(map(lambda x: str(x) + ',', signature[1]))[:-1]
    # Y = stringify_point(signature[2])
    Y = keyimage

    dump = '{}\n'.format("Here is your signature:")
    dump += '{}'.format("c0 = ")
    dump += '{}\n'.format(hex(signature[0]))
    dump += '{}'.format("S array = ")
    dump += '{}\n'.format(S)
    dump += '{}'.format("KeyImage = ")
    dump += '{}\n'.format(Y)

    arch.write(dump)

    data = '\n'
    data += "You will be voting for proposal {}\n".format(message)
    data += '\n'
    pub_keys = ''.join(map(lambda yi: stringify_point(yi) + ';', y))[:-1]
    # data = '{}\n'.format(''.join([ '{},'.format(m) for m in str(message)])[:-1])
    data += '{}'.format("Public Keys given = ")
    data += '{}\n,'.format(pub_keys)[:-1]

    arch.write(data)
    arch.close()


def export_private_keys(s_keys, foler_name='./data', file_name='secrets.txt'):
    """ Exports a set  of private keys to a file.

        Each line in the file is one key.
    """
    if not os.path.exists(foler_name):
        os.makedirs(foler_name)

    arch = open(os.path.join(foler_name, file_name), 'w')

    for key in s_keys:
        arch.write('{}\n'.format(key))

    arch.close()


def export_signature_javascript(y, message, signature, foler_name='./data', file_name='signature.js'):
    """ Exports a signatrue in javascript format to a file and folder.
    """
    if not os.path.exists(foler_name):
        os.makedirs(foler_name)

    arch = open(os.path.join(foler_name, file_name), 'w')

    S = ''.join(map(lambda x: 'new BigNumber("' + str(x) + '"),', signature[1]))[:-1]
    Y = stringify_point_js(signature[2])

    dump = 'var c_0 = new BigNumber("{}");\n'.format(signature[0])
    dump += 'var s = [{}];\n'.format(S)
    dump += 'var Y = [{}];\n'.format(Y)

    arch.write(dump)

    pub_keys = ''.join(map(lambda yi: stringify_point_js(yi) + ',', y))[:-1]

    data = 'var message = [{}];\n'.format(''.join([ 'new BigNumber("{}"),'.format(m) for m in message])[:-1])
    data += 'var pub_keys = [{}];'.format(pub_keys)

    arch.write(data + '\n')
    arch.close()


def main():
    number_participants = 5

    x = [56121026420206427922036047295033295468704194889942276402384109623365910341114,97148831986497178251981347099741561152929354799719003736306468101246934956731,73582564991556101489090114036789577051420144847960038776033502314051350434733,58959788109781048630827926226104720045842317320518204126269224311951440226761,41745480486210574223547556272772914684478811935146531809992005566760468807878]
    # x = [ randrange(SECP256k1.order) for i in range(number_participants)]
    y = list(map(lambda xi: SECP256k1.generator * xi, x))

    private_key = input("Please enter your private key : ")
    private_key = int(private_key)
    
    i = 0
    j = 0
    for k in range(0,number_participants):
        if private_key == x[k]:
            i = k   
            break
        j += 1

    if j == number_participants:
        print ("Sorry, wrong private key. Try again")
        return 0

    message = input("Whom do you want to cast your vote among the 3 proposals? ")
    message = int(message)

    if message >= 3:
        print ("Sorry, the proposal doesn't exist")
        return 0

    signature = ring_signature(x[i], i, message, y)
    
    assert(verify_ring_signature(message, y, *signature))
    export_signature(y, message, signature, './data', 'signature.txt')
    print ("Signature created! Please check data/signature.txt")

if __name__ == '__main__':
    main()