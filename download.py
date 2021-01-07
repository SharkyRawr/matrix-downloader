import argparse
from base64 import urlsafe_b64decode

import requests
from Crypto.Cipher import AES

MEDIA_API = '/_matrix/media/r0/download/'

args = argparse.ArgumentParser("matrix-download-and-decrypt")
args.add_argument('-m', '--mxc', nargs=1, required=True, help='mxc:// URL')
args.add_argument('-k', '--key', nargs=1, required=True, help="k value")
args.add_argument('-i', '--iv', nargs=1, required=True, help='iv value')
args.add_argument('-s', '--homeserver', nargs=1, required=False, default=["https://matrix-client.matrix.org"],
                  help='Matrix homeserver to contact')
args.add_argument('-o', '--output', nargs=1, required=True, help='output file')


def b64decode(s: str) -> bytes:
    s_bin = s.encode('ascii')
    s_bin += b'=' * (4 - len(s_bin) % 4)
    return urlsafe_b64decode(s_bin)

def download_mxc(mxcurl: str, homeserver: str) -> bytes:
    if 'mxc://' in mxcurl:
        mxcurl = mxcurl[mxcurl.index('mxc://')+6:]

    r = requests.get(
        homeserver + MEDIA_API + f"{mxcurl}"
    )
    r.raise_for_status()
    return r.content

def decrypt_data(data: bytes, key: str, iv: str) -> bytes:
    decoded_key = b64decode(key)
    decoded_iv = b64decode(iv)
    c = AES.new(decoded_key, AES.MODE_CTR, nonce=decoded_iv[:8], initial_value=decoded_iv[8:])
    decrypted = c.decrypt(data)
    return decrypted

if __name__ == '__main__':
    argv = args.parse_args()
    data = download_mxc(argv.mxc[0], argv.homeserver[0])
    decrypted_data = decrypt_data(data, argv.key[0], argv.iv[0])
    with open(argv.output[0], 'wb') as f:
        f.write(decrypted_data)

