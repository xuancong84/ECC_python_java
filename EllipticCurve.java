import java.io.*;
import java.util.*;

import javax.crypto.*;
import javax.crypto.spec.*;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 * This class represents Elliptic Curve in Galois Field G(p). The equation will
 * be in form y^2 = x^3 + ax + b (mod p), for which a and b satisfy 4a^3 + 27b^2
 * != 0 (mod p).
 * 
 * A point in the elliptic curve will be represented as a pair of BigInteger,
 * which is represented as ECPoint class.
 * 
 * This class implements some very basic operations of Points in the elliptic
 * curve, which are addition, multiplication (scalar), and subtraction.
 * 
 * @author Wang Xuancong, Ahmad Zaky
 */
public class EllipticCurve {

	public static void main(String[] args) throws Exception {
		// Java encode Java decode
		byte [] msg = "Text to be encrypted by ECC public key and decrypted by its corresponding ECC private key1234567".getBytes();
		System.out.println("original msg: " + (new String(msg, "UTF-8")));
		BigInteger privKey = randbelow(curve.n);
		ECPoint pubKey = curve.multiply(curve.g, privKey);
		System.out.println("Private key: " + privKey);
		System.out.println("Public key: " + pubKey);
		Object [] encryptedObj = encrypt_ECC(msg, pubKey);
		System.out.printf("encrypted msg:{\n ciphertext: %s,\n IV: %s,\n EncryptedAESKey: %s}\n",
				ByteArrayToHexString((byte[])encryptedObj[0]), ByteArrayToHexString((byte[])encryptedObj[1]), encryptedObj[2]);
		byte [] decryptedMsg = decrypt_ECC(encryptedObj, privKey);
		System.out.println("decrypted msg: " + new String (decryptedMsg, "UTF-8"));

		// Python encode Java decode
		byte [] decryptedMsg2 = decrypt_ECC(new Object [] {
				hexStringToByteArray("683e9cea584a9408821735c958a8a95e94f37c0fe3373e165a414f5cece7fb593ccd9ad18c0b90622f5001b636ee287aed2fc7e127906afcbb7df68f054e4daf6a773aeafb6471a92ee2ef4bb01148ed06b8c7a8cf48972bfe0247c6852efc8f2b0dbf62c978961372873574232b00b2"),
				hexStringToByteArray("7de7c7a397e3ac1266f02baa9b3d4cbe"),
				new ECPoint(new BigInteger("106504475433703131298556354423268993749403842826244952418115160744777692256733"),
						new BigInteger("112353531522751447419464862576385479114567958719827052736911763021690231831294"))
			},
			new BigInteger("75186921650391519650532175449590053817943957292013655745118533638504557674992")
		);
		System.out.println("Python-encrypted decrypted msg: " + new String (decryptedMsg2, "UTF-8"));
	}
	
	public static byte [] decrypt_ECC(Object [] encryptedObj, BigInteger privKey) throws Exception {
	    byte [] ciphertext = (byte[])encryptedObj[0];
	    byte [] iv = (byte[])encryptedObj[1];
	    ECPoint EncryptedAESKey = (ECPoint)encryptedObj[2];
	    ECPoint AESPoint = curve.multiply(EncryptedAESKey, privKey);
	    byte [] AESKey = ecc_point_to_256_bit_key(AESPoint);
	    byte [] ret = decrypt_AES_CBC(ciphertext, AESKey, iv);
	    return ret;
	}
	
	public static byte [] decrypt_AES_CBC(byte [] ciphertext, byte [] AESKey, byte [] iv) throws Exception {
		Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		aesCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(AESKey, "AES"), new IvParameterSpec(iv));
		byte[] ret = aesCipher.doFinal(ciphertext);
	    return ret;
	}
	
	public static Object [] encrypt_AES_CBC(byte [] msg, byte [] AESKey) throws Exception {
		Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		aesCipher.init( Cipher.ENCRYPT_MODE, new SecretKeySpec(AESKey, "AES"));
		byte [] ciphertext = aesCipher.doFinal(msg);
		byte [] iv = aesCipher.getIV();
		return new Object[] {ciphertext, iv};
	}
	
	public static Object [] encrypt_AES_CBC_stream(byte [] msg, byte [] AESKey) throws Exception {
		ByteArrayOutputStream byteOutputStream = new ByteArrayOutputStream();
		Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		aesCipher.init( Cipher.ENCRYPT_MODE, new SecretKeySpec(AESKey, "AES"));
		byte [] iv = aesCipher.getIV();
		CipherOutputStream cipherOutputStream = new CipherOutputStream(byteOutputStream, aesCipher);
		cipherOutputStream.write(msg);
		cipherOutputStream.close();
		byte [] ciphertext = byteOutputStream.toByteArray();
		return new Object[] {ciphertext, iv};
	}
	
	public static Object [] encrypt_ECC(byte [] msg, ECPoint pubKey) throws Exception {
		BigInteger ciphertextPrivKey = randbelow(curve.n);
		ECPoint AESPoint = curve.multiply(pubKey, ciphertextPrivKey);
		byte [] AESKey = ecc_point_to_256_bit_key(AESPoint);
		
		Object [] cipher_iv = true?encrypt_AES_CBC_stream(msg, AESKey):encrypt_AES_CBC(msg, AESKey);
		byte [] ciphertext = (byte [])cipher_iv[0];
		byte [] iv = (byte [])cipher_iv[1];
		
		ECPoint EncryptedAESKey = curve.multiply(curve.g, ciphertextPrivKey);
		return new Object [] {ciphertext, iv, EncryptedAESKey};
	}
	
	public static String ByteArrayToHexString(byte[] ba)
	{
	  StringBuilder hex = new StringBuilder(ba.length * 2);
	  for(byte b : ba)
	    hex.append(String.format("%02x", b));
	  return hex.toString();
	}
	
	public static byte[] hexStringToByteArray(String s) {
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                             + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	}
	
	public static BigInteger randbelow(BigInteger upperLimit) {
		BigInteger randomNumber;
		do {
		    randomNumber = new BigInteger(upperLimit.bitLength(), new SecureRandom());
		} while (randomNumber.compareTo(upperLimit) >= 0);
		return randomNumber;
	}
	
	public static byte [] bigInteger2byteArray(BigInteger i, int length) {
		byte [] ret = new byte [length];
		byte [] I = i.toByteArray();
		// delete leading null bytes (for sign)
		while(I[0]==0 && I.length>0) I = Arrays.copyOfRange(I, 1, I.length);
		System.arraycopy(I, 0, ret, length-I.length, I.length);
		return ret;
	}
	
	public static byte [] ecc_point_to_256_bit_key(ECPoint p) throws Exception {
		MessageDigest sha = MessageDigest.getInstance("SHA-256");
		sha.update(bigInteger2byteArray(p.x, 32));
		return sha.digest(bigInteger2byteArray(p.y, 32));
	}

	// The three parameters of the elliptic curve equation.
	private BigInteger a;
	private BigInteger b;
	private BigInteger p;
	public BigInteger n;

	// Optional attribute, the base point g.
	private ECPoint g = null;

	// some BigInteger constants that might help us in some calculations
	private static BigInteger THREE = new BigInteger("3");

	public EllipticCurve(BigInteger a, BigInteger b, BigInteger p, BigInteger n, ECPoint g) {
		this.a = a;
		this.b = b;
		this.p = p;
		this.g = g;
		this.n = n;
	}

	// We provide some standard curves
	// Source: http://csrc.nist.gov/groups/ST/toolkit/documents/dss/NISTReCur.pdf

	public static final EllipticCurve NIST_P_192 = new EllipticCurve(new BigInteger("-3"), 
			new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16), 
			new BigInteger("6277101735386680763835789423207666416083908700390324961279"),
			new BigInteger("6277101735386680763835789423176059013767194773182842284081"),
			new ECPoint(new BigInteger("188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012", 16), 
					new BigInteger("07192b95ffc8da78631011ed6b24cdd573f977a11e794811", 16)));

	public static final EllipticCurve NIST_P_224 = new EllipticCurve(new BigInteger("-3"),
			new BigInteger("b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4", 16),
			new BigInteger("26959946667150639794667015087019630673557916260026308143510066298881"),
			new BigInteger("26959946667150639794667015087019625940457807714424391721682722368061"),
			new ECPoint(new BigInteger("b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21", 16), 
					new BigInteger("bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34", 16)));

	public static final EllipticCurve NIST_P_256 = new EllipticCurve(new BigInteger("-3"), 
			new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16),
			new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853951"),
			new BigInteger("115792089210356248762697446949407573529996955224135760342422259061068512044369"),
			new ECPoint(new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16), 
					new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16)));

	public static final EllipticCurve NIST_P_384 = new EllipticCurve(new BigInteger("-3"), 
			new BigInteger("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", 16),
			new BigInteger("39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319"),
			new BigInteger("39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643"),
			new ECPoint(new BigInteger("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", 16),
					new BigInteger("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", 16)));

	public static final EllipticCurve NIST_P_521 = new EllipticCurve(new BigInteger("-3"), 
			new BigInteger("051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00", 16),
			new BigInteger("6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151"),
			new BigInteger("6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449"),
			new ECPoint(new BigInteger("c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66", 16),
					new BigInteger("11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650", 16)));

	public static EllipticCurve curve = NIST_P_256;	// currently selected curve
	
	/**
	 * This method will check whether a point belong to this curve or not.
	 */
	public boolean isPointInsideCurve(ECPoint point) {
		if (point.isPointOfInfinity())
			return true;

		return point.x.multiply(point.x).mod(p).add(a).multiply(point.x).add(b).mod(p).subtract(point.y.multiply(point.y)).mod(p).compareTo(BigInteger.ZERO) == 0;
	}

	/**
	 * Add two points. The result of this addition is the reflection of the
	 * intersection of the line formed by the two points to the same curve with
	 * respect to the x-axis. The line is the tangent when the two points equal.
	 * 
	 * The result will be point of infinity when the line is parallel to the y-axis.
	 * 
	 * If one of them is point of infinity, then the other will be returned.
	 * 
	 * @param p1
	 * @param p2
	 * @return
	 */
	public ECPoint add(ECPoint p1, ECPoint p2) {
		if (p1 == null || p2 == null)
			return null;

		if (p1.isPointOfInfinity()) {
			return new ECPoint(p2);
		} else if (p2.isPointOfInfinity()) {
			return new ECPoint(p1);
		}

		// The lambda (the slope of the line formed by the two points) are
		// different when the two points are the same.
		BigInteger lambda;
		if (p1.x.subtract(p2.x).mod(p).compareTo(BigInteger.ZERO) == 0) {
			if (p1.y.subtract(p2.y).mod(p).compareTo(BigInteger.ZERO) == 0) {
				// lambda = (3x1^2 + a) / (2y1)
				BigInteger nom = p1.x.multiply(p1.x).multiply(THREE).add(a);
				BigInteger den = p1.y.add(p1.y);
				lambda = nom.multiply(den.modInverse(p));
			} else {
				// lambda = infinity
				return ECPoint.INFINTIY;
			}
		} else {
			// lambda = (y2 - y1) / (x2 - x1)
			BigInteger nom = p2.y.subtract(p1.y);
			BigInteger den = p2.x.subtract(p1.x);
			lambda = nom.multiply(den.modInverse(p));
		}

		// Now the easy part:
		// The result is (lambda^2 - x1 - y1, lambda(x2 - xr) - yp)
		BigInteger xr = lambda.multiply(lambda).subtract(p1.x).subtract(p2.x).mod(p);
		BigInteger yr = lambda.multiply(p1.x.subtract(xr)).subtract(p1.y).mod(p);
		return new ECPoint(xr, yr);
	}

	/**
	 * Subtract two points, according to this equation: p1 - p2 = p1 + (-p2), where
	 * -p2 is the reflection of p2 with respect to the x-axis.
	 * 
	 * @param p1
	 * @param p2
	 * @return
	 */
	public ECPoint subtract(ECPoint p1, ECPoint p2) {
		if (p1 == null || p2 == null)
			return null;

		return add(p1, p2.negate());
	}

	/**
	 * Multiply p1 to a scalar n. That is, perform addition n times. The following
	 * method implements divide and conquer approach.
	 * 
	 * @param p1
	 * @param n
	 * @return
	 */
	public ECPoint multiply(ECPoint p1, BigInteger n) {
		if (p1.isPointOfInfinity()) {
			return ECPoint.INFINTIY;
		}

		ECPoint result = ECPoint.INFINTIY;
		int bitLength = n.bitLength();
		for (int i = bitLength - 1; i >= 0; --i) {
			result = add(result, result);
			if (n.testBit(i)) {
				result = add(result, p1);
			}
		}

		return result;
	}

	public ECPoint multiply(ECPoint p1, long n) {
		return multiply(p1, BigInteger.valueOf(n));
	}

	/**
	 * Calculate the right hand side of the equation.
	 * 
	 * @param x
	 * @return
	 */
	public BigInteger calculateRhs(BigInteger x) {
		return x.multiply(x).mod(p).add(a).multiply(x).add(b).mod(p);
	}
}

class ECPoint {
	public BigInteger x;
	public BigInteger y;
	private boolean pointOfInfinity;

	public ECPoint() {
		this.x = this.y = BigInteger.ZERO;
		this.pointOfInfinity = false;
	}

	public ECPoint(BigInteger x, BigInteger y) {
		this.x = x;
		this.y = y;
		this.pointOfInfinity = false;
	}

	public ECPoint(long x, long y) {
		this.x = BigInteger.valueOf(x);
		this.y = BigInteger.valueOf(y);
		this.pointOfInfinity = false;
	}

	public ECPoint(ECPoint p) {
		this.x = p.x;
		this.y = p.y;
		this.pointOfInfinity = p.pointOfInfinity;
	}

	public boolean equals(ECPoint point) {
		if (point == null)
			return false;

		if (this.pointOfInfinity == point.pointOfInfinity)
			return true;

		return (this.x.compareTo(point.x) | this.y.compareTo(point.y)) == 0;
	}

	public boolean isPointOfInfinity() {
		return pointOfInfinity;
	}

	public ECPoint negate() {
		if (isPointOfInfinity()) {
			return INFINTIY;
		} else {
			return new ECPoint(x, y.negate());
		}
	}

	private static ECPoint infinity() {
		ECPoint point = new ECPoint();
		point.pointOfInfinity = true;
		return point;
	}

	public static final ECPoint INFINTIY = infinity();

	@Override
	public String toString() {
		if (isPointOfInfinity()) {
			return "INFINITY";
		} else {
			return "(" + x.toString() + ", " + y.toString() + ")";
		}
	}

	public String toString(int radix) {
		if (isPointOfInfinity()) {
			return "INFINITY";
		} else {
			return "(" + x.toString(radix) + ", " + y.toString(radix) + ")";
		}
	}
}
