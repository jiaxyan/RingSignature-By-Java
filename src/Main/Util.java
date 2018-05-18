package Main;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class Util {
	
	public static byte[] encrypt(byte[] key, byte[] input) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(input);
    }
    
    
    public static byte[] decrypt(byte[] key, byte[] input) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
    	
    	SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        return cipher.doFinal(input);
    }
    
    /**
     * 
     * @param k  value of hash(message)
     * @param v random byte[] value
     * @param y array of cipher text
     * @param s
     * @return
     * @throws Exception
     */
    public static byte[] solveCKV(byte[] k, byte[] v, BigInteger[] y, int s) throws Exception {
        byte[] shouldBe = v;
        int r = y.length;
        shouldBe = decrypt(k, shouldBe);
        for (int i = r - 1; i > s; i--) {
            shouldBe = xor(shouldBe, y[i].toByteArray());
            shouldBe = decrypt(k, shouldBe);
        }
        byte[] of = v;
        for (int i = 0; i < s; i++) {
            of = xor(of, y[i].toByteArray());
            of = encrypt(k, of);
        }
        return xor(shouldBe, of);
    }
    
    public static byte[] runCKV(byte[] k, byte[] v, BigInteger[] y) throws Exception {
        byte[] temp = v;
        for (int i = 0; i < y.length; i++) {
            temp = xor(temp, y[i].toByteArray());
            temp = encrypt(k, temp);
        }
        return temp;
    }
    
    public static byte[] xor(byte[] a, byte[] b) {
        int len = a.length;
        if (len != 128) {
            throw new IllegalStateException("Can't xor anything other than 128 bites");
        }
        while (len < b.length) {
            b = trimLeading(b);
            //return xor(a, b);
            //throw new IllegalStateException("Shrek likes waffles" + len + " " + b.length);
        }
        while (len > b.length) {
            b = leadingZero(b);
            //return xor(a, b);
        }
        byte[] result = new byte[len];
        for (int i = 0; i < len; i++) {
            result[i] = (byte) (((int) a[i]) ^ ((int) b[i]));
        }
        return result;
    }
    
    public static byte[] trimLeading(byte[] b) {
        if (b.length % 128 == 0) {
            return b;
        }
        if (b[0] != 0) {
            throw new IllegalStateException("Attempting to trim " + b[0]);
        }
        byte[] res = new byte[b.length - 1];
        for (int i = 0; i < res.length; i++) {
            res[i] = b[i + 1];
        }
        return res;
    }
    
    public static byte[] leadingZero(byte[] b) {
        byte[] res = new byte[b.length + 1];
        for (int i = 0; i < b.length; i++) {
            res[i + 1] = b[i];
        }
        res[0] = 0;
        return res;
    }
}
