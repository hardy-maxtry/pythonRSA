import base64
from Crypto.Hash import MD5
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.PublicKey import RSA


def get_encrypt_data(params, public_key):
    """分段加密"""
    # params = json.dumps(params)
    params = params.encode("utf-8")
    length = len(params)
    default_length = 117
    if length < default_length:
        return encrypt_data(params, public_key)
    offset = 0
    params_lst = []
    while length - offset > 0:
        if length - offset > default_length:
            params_lst.append(encrypt_data(params[offset:offset+default_length], public_key))                               
        else:           
            params_lst.append(encrypt_data(params[offset:], public_key))
        offset += default_length
    res = b"".join(params_lst)
    return res

def encrypt_data(params, public_key):
    """使用公钥对数据加密"""
    key = public_key
    rsakey = RSA.importKey(base64.b64decode(key))
    cipher = Cipher_pkcs1_v1_5.new(rsakey)
    text = cipher.encrypt(params)
    return text

def get_decrypt_data(params, private_key):
    """分段解密"""
    # params = json.dumps(params)
    params = base64.b64decode(params.encode("utf-8"))
    length = len(params)
    default_length = 128
    if length < default_length:
        return decrypt_data(params, private_key)
    offset = 0
    params_lst = []
    while length - offset > 0:
        if length - offset > default_length:
            params_lst.append(decrypt_data(params[offset:offset+default_length], private_key))                               
        else:           
            params_lst.append(decrypt_data(params[offset:], private_key))
        offset += default_length
    res = b"".join(params_lst)
    return res

def decrypt_data(params, private_key):
    """使用私钥对数据解密"""
    key = private_key
    rsakey = RSA.importKey(base64.b64decode(key))
    cipher = Cipher_pkcs1_v1_5.new(rsakey)
    text = cipher.decrypt(params,b'error')
    return text

if __name__ == '__main__':
    pkcs8_private_key = '''
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBANalW5ASwRyC6Fxe
r9pRJDUYsxjEmRi+zqDnEL6NQOtRaicpz7zpHNfTv3eUCVlVpeWs+WtOFbKMy83P
WcouMmxvLujBrTyA8T1djGnLZVSuSWR+0786UkV1c03MazqqeOxJnaNiaGwJ/QtD
y/IMaT+1q7v2LwI7UJA0JWecVYOFAgMBAAECgYB+HUYBDqPcBqZTr2aPVWF6uPpx
sQFq4qExNNJHw2LDYGCIhi6ChkzmGonCzn33uTTyD4G0pHpnIAaW9B+DhUUmEWrL
nnUqyTvsaRaLty1T0C0xVOIKl1MFtN3kRBq5BmzjiTh9Mhz/7aPvVIXqmpHBIz8T
N3uNMkNfXlROhvffuQJBAO0iZJ5FYRsbZtz6Y/agWWM4eecwNFYoyLvk3pcfmjxx
NpkryqJQlBOWVcbM8pFRjqBTmqKWTn3SEN/JMDqt97MCQQDnuPQIzqUeSAuFv+5C
D5Gx16NEyq2StaB3hyq7Br4dEUiW9HTqTwLTmtascYcTnaTYBM94AscxxPVrO4pz
SHvnAkEA2a6l0Qh9YMXhwl70XtTJ2aRhe1Gr6Z/czWcG0pHHI08GQMuLYz82/1gU
+77tuWq11AWLQU9bVHL+3H+yj1tdswJAMqDfeNkljIMzOUrhFL/wFkpGGu6pk+dp
IxR+SpTDjvhKwuiwbs1Kkc8/3jeDys5jyOrsJY191irxcDd3HY8VuwJAEl2DuCuv
ETIPT72yjx6OwSxafLK5OyzRjOodQF4u6nRpaG6nZbe0xJXhBXA768KE9tUN6XGq
05tjvo08Cbk/qg==
'''


    pkcs8_public_key = '''MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDWpVuQEsEcguhcXq/aUSQ1GLMY
xJkYvs6g5xC+jUDrUWonKc+86RzX0793lAlZVaXlrPlrThWyjMvNz1nKLjJsby7o
wa08gPE9XYxpy2VUrklkftO/OlJFdXNNzGs6qnjsSZ2jYmhsCf0LQ8vyDGk/tau7
9i8CO1CQNCVnnFWDhQIDAQAB'''

    # len = 120 > 117
    message = "111111111122222222221111111111222222222211111111112222222222111111111122222222221111111111222222222211111111112222222222"

    print('using Crypto')
    result2_1 = get_encrypt_data(message,pkcs8_public_key)
    print(result2_1)
    result2_2 = base64.b64encode(result2_1).decode('utf-8')
    print(result2_2)
    result3 = get_decrypt_data(result2_2, pkcs8_private_key)
    print(result3)