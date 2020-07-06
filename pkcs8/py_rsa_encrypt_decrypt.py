import base64
from Crypto.Hash import MD5
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.PublicKey import RSA

MAX_ENCRYPT_BLOCK_1024 = 117
MAX_DECRYPT_BLOCK_1024 = 128

MAX_ENCRYPT_BLOCK_2048 = 245
MAX_DECRYPT_BLOCK_2048 = 256

def get_encrypt_data(params, public_key, max_encrypt_block):
    """分段加密"""
    # params = json.dumps(params)
    params = params.encode("utf-8")
    length = len(params)
    default_length = max_encrypt_block
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

def get_decrypt_data(params, private_key, max_decrypt_block):
    """分段解密"""
    # params = json.dumps(params)
    params = base64.b64decode(params.encode("utf-8"))
    length = len(params)
    default_length = max_decrypt_block
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

    private_key_2048 = '''MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDYSFY87wbOH5Fk
bXETVw2FWCpvZTFGtbvTGh8MGPLg3ecH58WrehapoxvRqY5RN4lt53EeWuQWMYCz
9DAKQP2AAQpeROAzykPH9GVg8IEiU5YZ+Xm3qmmVW1Tvr0k5lcCXifbpccAiVjlQ
z/Ta+mjfEstWeR5DacKWYF7b+0sgcAGtAn+AQBXCmnqASrImPL8CLS6k+S/JuOAQ
4iqg57UwyjiCLmq+26KnI/7YBKrd4MmNkYvocECZUubBe8tc65aJQloUFHS2vLbM
BsLoUXOMIrAP3t669QpHzhy8xqNNHCnrMTaPOVoUa4zvWXR7Mgu7hPdtZH3WGJkQ
d2X+c5JFAgMBAAECggEBAIovLWohDagEY1BW3DgPFoRroDEr5h/XXPmzZsLD7end
3Q4f9xtoFbKsk8mRG2yonxWpGYzbZX8IgcJ38XmbrFtsTsOMHfL49/V5IIyfHOJh
pTVTP4EpT+wtPkclJxOzqikn7KmaE7fcfyIyu65s7zQXPfMxzzQjDkAlsnW6SHWf
7PU1TOcpiEkW1MlVV+MStu5lReV7qPBlbill2ovrjSocZtqGdMllUFdbSCZtW5Jd
k6wkKgiAayNNTGPr99iwhndN6tsjOV7PionJHpm8R3ZRipQ1KcNqpbd+OvE1S9g0
1fhtzHc95MaaksJgAohetSs6gki6o+5Fsxk6iHl6dgECgYEA/TN7THSnC9N9Ye/o
skyIkxw2UcEgeOmPOvYy2ubKJL3tssxSslU3Z6akMyh+7HuVH7xcW5hNAjBYY+zL
xpmLA7JdMU5MVj7MaKgd0JQuiyEDKBrBgeWPtkAi1FGOVJqAXyZIt8dnxbjU6DaR
DdMtH/zhDR43J2iCbnMxE5q4AmkCgYEA2qxhuH79BCWCD6lD9es/No3Zln2D6ZJO
b08wzbX4PRHchDNhWW2wM/qoGe7HkMz2noIepuTDWyWgIB77K/YYe+a3K3TMARwH
h5pAizT2ZD7BOaovRsVsgt+iwerHPkdkPYfxK+UBDCmB8h4cAj1iv0XVCX6juPpk
K8t2DGwgnX0CgYEAh9EfqElCeZN+RBR+S3XGJLMTaBMiKfmOfOAnM0hs0fyXDjuP
eF1BlPXMSizEuHEp8pYFLJSraisonqEcRXGDIf6BAruvMuwIlXLoW0PBG5wfp1mC
xvyuc+I/TIhawoMFrQRKKVprDaIxgkYS1MmcAPaSeYjlqNvkav6bKprpbVECgYEA
kGjm4AB89xAOJGmUCAOja1OiLlAVnVqRkdCqWi+iEDKLfoKv928Ivkr6WKXoBShW
dbdYpr7MhJUEejH7jbynzqs+q+QmFVV9Y3/qwAPp86m90WcicYpPbt5hjc6OZgKf
oEL2chZ56p4+wrY/qPsBC3ACkJKhbLdvD7z96JY/s8ECgYAhWKxBkRu/oMQN239w
LW3K4yCLM3FtBt0gx7377dWmt9icW5JPSbUN5qpDQoa5rQgS8YJVu95nR3tQGulB
6y0bddoYrqxKrr6aHhfYuR/biG0MGb2r8fzkVF6Mve9ZQpgS+ziRpLliYFMwYKG9
ajgbI8eGPUyJFIzuRhcIMFX/yA=='''

    public_key_2048 = '''MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2EhWPO8Gzh+RZG1xE1cN
hVgqb2UxRrW70xofDBjy4N3nB+fFq3oWqaMb0amOUTeJbedxHlrkFjGAs/QwCkD9
gAEKXkTgM8pDx/RlYPCBIlOWGfl5t6pplVtU769JOZXAl4n26XHAIlY5UM/02vpo
3xLLVnkeQ2nClmBe2/tLIHABrQJ/gEAVwpp6gEqyJjy/Ai0upPkvybjgEOIqoOe1
MMo4gi5qvtuipyP+2ASq3eDJjZGL6HBAmVLmwXvLXOuWiUJaFBR0try2zAbC6FFz
jCKwD97euvUKR84cvMajTRwp6zE2jzlaFGuM71l0ezILu4T3bWR91hiZEHdl/nOS
RQIDAQAB'''

    # len = 120 > 117
    message = "111111111122222222221111111111222222222211111111112222222222111111111122222222221111111111222222222211111111112222222222"

    print('using Crypto 1024')
    result2_1 = get_encrypt_data(message,pkcs8_public_key, MAX_ENCRYPT_BLOCK_1024)
    print(result2_1)
    result2_2 = base64.b64encode(result2_1).decode('utf-8')
    print(result2_2)
    result3 = get_decrypt_data(result2_2, pkcs8_private_key, MAX_DECRYPT_BLOCK_1024)
    print(result3)

    print('using Crypto 2048')
    result2_1 = get_encrypt_data(message,public_key_2048, MAX_ENCRYPT_BLOCK_2048)
    print(result2_1)
    result2_2 = base64.b64encode(result2_1).decode('utf-8')
    print(result2_2)
    result3 = get_decrypt_data(result2_2, private_key_2048, MAX_DECRYPT_BLOCK_2048)
    print(result3)
