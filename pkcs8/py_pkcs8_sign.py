from Crypto.IO import PKCS8
import base64
import rsa as rsa1

def RSA_sign_with_pkcs8(message, pkcs8_private_key):
    # pkcs8的私钥 转为  pkcs1的私钥
    private_keyBytes = base64.b64decode(pkcs8_private_key)
    pkcs8_unwraped = PKCS8.unwrap(private_keyBytes)
    # pkcs8_unwraped是个tuple  [0]是oid  [1]是der编码bytes秘钥
    pkkkk = rsa1.PrivateKey._load_pkcs1_der(pkcs8_unwraped[1])

    signature = rsa1.sign(message.encode('utf-8'), pkkkk, 'SHA-1')
    sign = base64.b64encode(signature).decode('utf-8')
    return sign

if __name__ == '__main__':
    pkcs8_private_key = '''
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALkFbpP0ZVpob96k
YOM+ljfA3QOsG342iO/GQSClR04DGAB6mp4ZtKq1cB34w44FsfEg4TCsUL2y2TKl
CDGsHj21cMj7gmPwy4ojXkcSYjyTv61EM6UnlMVIvYn0oDca5BvJUCGWnGX5idXv
KPE/2XV2RsCmDWLFJ3ko49tpDTRZAgMBAAECgYBiKrOk5MLx2P+iDW0qpQZmxnl9
fU+JA75cGcBsZcUTayjM+EAZKmJlQKcf/+Eh9XuYCG3yuTqNq9r5t/5E/KF+DTNb
uhfLSmbwPChbv7R87NDiwRh6irNr9WuRjBHkHEFr4rJPUcKLi5eiDIOVBPWnRlPS
JqpkF9MCl3JWSZxAQQJBAOF8+X4guXRuHQfw5GgyabEBkyfb3f517jjU6UCMvcKw
XjKFRR1q8BhYzREBXkwm0pRNHhmlFeQH+mqSDJPGmv0CQQDSDqlBGlwbG6Wvbvnx
mU4t0vwHWfW5ut7jrggpDTM18REqFH+PtTwsYX7eaFm6hIR2SXAsInxky8iGRXS/
wmONAkEA22pc7JqzW9R6c2u5FptXtWIu665LSn0/HhYwExvg2z37q3V7V7DjiQ2A
HngSZk+wwZZ5H8NAlfAdgO41RucPkQJADtIZ/w3tEbyRpB8gY3t9mJ4aSip+u+wD
be0Jhlv4EQZBP8bSeUFATaFTYj3alt5iujXUREjqnfIC4/ZilmUQwQJAY3OGqyFh
8OJbBThDdplaRGu/vi4heTUdCgUfUG2HNAlNvMof8sSpk3xZVq7dt/jXIDHZiho6
wgkm05RNhx+HXg==
'''
    message = "abcde12345"
    result = RSA_sign_with_pkcs8(message,pkcs8_private_key)
    print(result)