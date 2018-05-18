package Main;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Test {

	public static void main(String[] args) throws NoSuchAlgorithmException {
		// TODO Auto-generated method stub
		byte[] b = "dcd".getBytes();
		
		byte[] hashvalue = hash(b,256);
		
		System.out.println(new String(b));
	}
	
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
}
