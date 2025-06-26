#!/usr/bin/env python

# script to convert key dumps to OpenSSH private ED25519 key format
# I read about the file format in a blog article from Peter Lyons here:
#   https://peterlyons.com/problog/2017/12/openssh-ed25519-private-key-file-format/

import sys
import base64
import json

def convertED25519(b64data, comment):
    d = base64.b64decode(b64data)
    l = getInt(d[0:4])
    ktype = try_ascii(d[4 : 4 + l])
    if ktype is None:
        print("failed to get key type")
        return
    print("key type: {}".format(ktype))
    if ktype != "ssh-ed25519":
        return
    o = 4 + l

    l = getInt(d[o : o + 4])
    if l != 0x20:
        print("unexpected key length {}".format(l))
        return
    pub = d[o + 4 : o + 4 + l]
    o += 4 + l

    l = getInt(d[o : o + 4])
    if l != 0x40:
        print("unexpected key length {}".format(l))
        return
    pri = d[o + 4 : o + 4 + l]
    o += 4 + l

    if pub != pri[0x20:0x40]:
        print("pub key doesn't match")
        return

    if o != len(d):
        print("unexpected len: {} != {}", o, len(d))
        return

    # reconstruct the key
    key = b"openssh-key-v1\0"
    key += b"\0\0\0\x04" + b"none"
    key += b"\0\0\0\x04" + b"none"
    key += b"\0\0\0\0"
    key += b"\0\0\0\x01"

    key += b"\0\0\0\x33"
    key += b"\0\0\0\x0b"
    key += b"ssh-ed25519"
    # len, pubkey
    key += b"\0\0\0\x20"
    key += pub

    # length of the rest, padded to 8 bytes
    b_cmt = comment.encode("ascii")
    unpadded_len = 8 + 4 + 11 + 4 + 32 + 4 + 64 + 4 + len(b_cmt)
    padded_len = (unpadded_len + 7) & ~7
    key += padded_len.to_bytes(4, byteorder="big")

    # random? checksum? anyway, zero works
    key += b"\0\0\0\0\0\0\0\0"

    key += b"\0\0\0\x0b"
    key += b"ssh-ed25519"
    # len, pubkey again
    key += b"\0\0\0\x20"
    key += pub

    # len, pri+pubkey
    key += b"\0\0\0\x40"
    key += pri

    # comment
    key += len(b_cmt).to_bytes(4, byteorder="big")
    key += b_cmt

    # padding
    key += b"\x01\x02\x03\x04\x05\x06\x07"[0 : padded_len - unpadded_len]

    b64key = try_ascii(base64.b64encode(key))

    print("-----BEGIN OPENSSH PRIVATE KEY-----")
    for i in range(0, len(b64key), 70):
        print(b64key[i : i + 70])
    print("-----END OPENSSH PRIVATE KEY-----")
    return


def try_ascii(data):
    try:
        return data.decode("ascii")
    except:
        return


def getInt(buf):
    return int.from_bytes(buf, byteorder="big")


def run(filename):
    with open(filename, "r") as fp:
        keysdata = json.loads(fp.read())

    for jkey in keysdata:
        for keycomment, data in jkey.items():
            print("[+] Key Comment: {}".format(keycomment))
            convertED25519(data, keycomment)


if __name__ == "__main__":
    if len(sys.argv) == 2:
        filename = sys.argv[1]
        run(filename)
    else:
        print("Usage: {} extracted_keyblobs.json".format(sys.argv[0]))
