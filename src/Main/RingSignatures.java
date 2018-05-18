package Main;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Random;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author leijurv
 */
public class RingSignatures {
    
    
    public static byte[] hash(byte[] message, int size) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(message);
        byte[] d = digest.digest();
        byte[] res = new byte[size / 8];//Extend this hash out to however long it needs to be
        int dlen = d.length;
        for (int i = 0; i < res.length / dlen; i++) {
            System.arraycopy(d, 0, res, i * dlen, dlen);
        }
        return res;
    }
    
    public static boolean verify(byte[][] sig, RSAKeyPair[] keys, byte[] message, int bitlength) throws Exception {
        byte[] k = hash(message, 256);
        byte[] v = sig[sig.length - 1];
        BigInteger[] x = new BigInteger[sig.length - 1];
        BigInteger[] y = new BigInteger[x.length];
        for (int i = 0; i < x.length; i++) {
            x[i] = new BigInteger(Util.leadingZero(sig[i]));
            y[i] = keys[i].encode(x[i], bitlength);
        }
        byte[] res = Util.runCKV(k, v, y);
        return new BigInteger(res).equals(new BigInteger(v));
    }
    
    
    /**
     * 
     * @param keys 群内所有人的公私玥（包括一个私钥和剩余的公钥）
     * @param message 消息本身
     * @param b 
     * @param r
     * @return
     * @throws Exception
     */
    public static byte[][] genRing(RSAKeyPair[] keys, byte[] message, int b, Random r) throws Exception {
        byte[] k = hash(message, 256);
        int s = -1;
        for (int i = 0; i < keys.length; i++) {
        	//找到群里唯一一个有私钥的
        	//Find the one that we have the private key to
            if (keys[i].hasPrivate()) {
                if (s != -1) {
                    throw new IllegalStateException("Too many private keyssss");
                }
                s = i;
            }
        }
        
        if (s == -1) {
            throw new IllegalStateException("Need at least 1 private key to create a ring signature");
        }
        
        byte[] v = new byte[b / 8];//Number of bytes = number of bits / 8
        r.nextBytes(v);//Maybe this should be more random?
        BigInteger[] x = new BigInteger[keys.length];
        BigInteger[] y = new BigInteger[keys.length];
        
        for (int i = 0; i < keys.length; i++) {
            if (i != s) {//Do this for everyone but me, mine is generated later
                x[i] = new BigInteger(b, r);//b为新生成大数的最大bit数
                y[i] = keys[i].encode(x[i], b);
            }
        }
        
        //k是message的哈希值
        byte[] CKV = Util.solveCKV(k, v, y, s);
        //System.out.println(CKV.length);
//System.out.println("--------------------------"+CKV[0]);
        y[s] = new BigInteger(Util.leadingZero(CKV));
        x[s] = keys[s].decode(y[s], b);
        //System.out.println("YS: " + y[s]);
        byte[] check = Util.runCKV(k, v, y);
        int d = new BigInteger(check).compareTo(new BigInteger(v));
        if (d != 0) {
            throw new IllegalStateException("Shrek");
        }
        byte[][] result = new byte[keys.length + 1][];
        for (int i = 0; i < keys.length; i++) {
            byte[] X = x[i].toByteArray();
            if (X.length == 129) {
                X = Util.trimLeading(X);
            }
            result[i] = X;
        }
        result[keys.length] = v;
        return result;
    }
    

    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws Exception {
        /*
         System.out.println(System.getProperty("java.home"));
         RSAKeyPair dank = RSAKeyPair.generate(new BigInteger("61"), new BigInteger("53"), new BigInteger("17"));
         System.out.println(dank.encode(new BigInteger("65000000"), 100));
         System.out.println(dank.decode(new BigInteger("65001491"), 100));
         byte[] key = new BigInteger("5021").toByteArray(); // TODO
         byte[] input = new BigInteger("5021").toByteArray(); // TODO
         byte[] output = encrypt(hash(key), input);
         System.out.println(new BigInteger(decrypt(hash(key), encrypt(hash(key), input))));*/
        int bitlength = 1024;
        Random rondom = new Random(1224);//new Random(5021);
        while (true) {
            int numKeys = rondom.nextInt(10) + 1;//群内成员个数
            System.out.println("---------Group num will be:"+numKeys);
            RSAKeyPair[] keys = new RSAKeyPair[numKeys];
            int s = rondom.nextInt(numKeys);
            byte[] message = new byte[8];//一个8字节的随机数组
            rondom.nextBytes(message);
            
            for (int i = 0; i < keys.length; i++) {//给每个群内成员都生成公私玥
                keys[i] = RSAKeyPair.generate(new BigInteger(bitlength / 2 - 4, 8, rondom), new BigInteger(bitlength / 2, 8, rondom));
                if (i != s) {
                	//只需要一个私钥   别的keys存公钥就行
                    keys[i] = keys[i].withoutPriv();//We only need one of the private keys
                }
                System.out.println("keypair_"+i+"__"+keys[i].toString()+"\n");
            }
            
            System.out.println("---------Creating and verifying");
            long time = System.currentTimeMillis();
            byte[][] sig = genRing(keys, message, bitlength, rondom);
            boolean b = verify(sig, keys, message, bitlength);
            System.out.println(b + " numKeys:" + numKeys + " No." + s + " time:" + (System.currentTimeMillis() - time));
//            if (!b) {
//                return;
//            }
            System.out.println("result: "+b);
            return;
        }
    }//main ends
}