import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import org.apache.commons.codec.binary.Base64;


public class Main {


    public static final String SIGNATURE_ALGORITHM = "SHA1withRSA";

    public static final String KEY_ALGORITHM = "RSA";

    public static String sign(String text, String privateKey, String charset) throws SignatureException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, UnsupportedEncodingException {
        byte[] result = {};
        byte[] keyBytes = Base64.decodeBase64(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory;
        // should handle exception following code
        keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PrivateKey privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateK);

        byte[] bytes = text.getBytes(charset);

        signature.update( bytes);
        result = signature.sign();

        return Base64.encodeBase64String(result);

    }

    public static void main(String[] args) throws NoSuchAlgorithmException, SignatureException, InvalidKeySpecException, InvalidKeyException, UnsupportedEncodingException {
        // a test key , pkcs8
        String privateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALkFbpP0ZVpob96k\n" +
                "YOM+ljfA3QOsG342iO/GQSClR04DGAB6mp4ZtKq1cB34w44FsfEg4TCsUL2y2TKl\n" +
                "CDGsHj21cMj7gmPwy4ojXkcSYjyTv61EM6UnlMVIvYn0oDca5BvJUCGWnGX5idXv\n" +
                "KPE/2XV2RsCmDWLFJ3ko49tpDTRZAgMBAAECgYBiKrOk5MLx2P+iDW0qpQZmxnl9\n" +
                "fU+JA75cGcBsZcUTayjM+EAZKmJlQKcf/+Eh9XuYCG3yuTqNq9r5t/5E/KF+DTNb\n" +
                "uhfLSmbwPChbv7R87NDiwRh6irNr9WuRjBHkHEFr4rJPUcKLi5eiDIOVBPWnRlPS\n" +
                "JqpkF9MCl3JWSZxAQQJBAOF8+X4guXRuHQfw5GgyabEBkyfb3f517jjU6UCMvcKw\n" +
                "XjKFRR1q8BhYzREBXkwm0pRNHhmlFeQH+mqSDJPGmv0CQQDSDqlBGlwbG6Wvbvnx\n" +
                "mU4t0vwHWfW5ut7jrggpDTM18REqFH+PtTwsYX7eaFm6hIR2SXAsInxky8iGRXS/\n" +
                "wmONAkEA22pc7JqzW9R6c2u5FptXtWIu665LSn0/HhYwExvg2z37q3V7V7DjiQ2A\n" +
                "HngSZk+wwZZ5H8NAlfAdgO41RucPkQJADtIZ/w3tEbyRpB8gY3t9mJ4aSip+u+wD\n" +
                "be0Jhlv4EQZBP8bSeUFATaFTYj3alt5iujXUREjqnfIC4/ZilmUQwQJAY3OGqyFh\n" +
                "8OJbBThDdplaRGu/vi4heTUdCgUfUG2HNAlNvMof8sSpk3xZVq7dt/jXIDHZiho6\n" +
                "wgkm05RNhx+HXg==";
        String message = "abcde12345";
        String result = sign(message, privateKey, "UTF-8");
        System.out.println(result);

    }
}
