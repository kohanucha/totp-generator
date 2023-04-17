package com.kohanucha.totpgenerator;

import org.apache.commons.codec.binary.Base32;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class TotpGeneratorApplication {

	private static int OTP_TIME_SECOND = 30;
	private static int OTP_DIGITS = 6;

	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException {
		System.out.println("TOTP : " + getTOTP("NBSWY3DPMFXGI53FNRRW63LF"));
	}

	private static String getTOTP(String base32Key) throws NoSuchAlgorithmException, InvalidKeyException {
		long counter = getCounter();

		// Step 1: Generate an HMAC-SHA-1 value
		byte[] hmacSha1 = hmacSha1(base32Key, counter);

		// Step 2: Generate a 4-byte string (Dynamic Truncation) and Convert String to a number
		int number = get4BytesStringAndConvertToNumber(hmacSha1);

		// Step 3: Compute an OTP value
		return formatOptNumber(number);
	}

	private static long getCounter() {
		return System.currentTimeMillis() / 1000 / OTP_TIME_SECOND;
	}

	private static byte[] hmacSha1(String base32Key, long counter) throws NoSuchAlgorithmException, InvalidKeyException {
		String algorithm = "HmacSHA1";
		byte[] base32DecodedKey = new Base32().decode(base32Key);
		SecretKeySpec secretKeySpec = new SecretKeySpec(base32DecodedKey, algorithm);
		Mac mac = Mac.getInstance(algorithm);
		mac.init(secretKeySpec);
		return mac.doFinal(convertLongTo8BigEndianOrderedBytes(counter));
	}

	private static byte[] convertLongTo8BigEndianOrderedBytes(long value) {
		byte[] data = new byte[8];

		for (int i = 8; i-- > 0; value >>>= 8) {
			data[i] = (byte) value;
		}

		return data;
	}

	private static int get4BytesStringAndConvertToNumber(byte[] hmacSha1) {
		int offset = hmacSha1[19] & 0xf;
		return ((hmacSha1[offset] & 0x7f) << 24
				| (hmacSha1[offset + 1] & 0xff) << 16
				| (hmacSha1[offset + 2] & 0xff) << 8
				| (hmacSha1[offset + 3] & 0xff))
				& 0x7FFFFFFF;
	}

	private static String formatOptNumber(int number) {
		return String.format("%0" + OTP_DIGITS + "d", number % ((int) Math.pow(10, OTP_DIGITS)));
	}

}
