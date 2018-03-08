package Lab01;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class CCMP {
	// RandomNumGenerator
	static Random random = new Random();

	// CryptoParameters
	static GCMParameterSpec parameterSpec;
	static SecretKey key;
	static Cipher MICAES;
	static Cipher encrypt;
	static Cipher decrypt;
	static SecretKeySpec secretKeySpec;

	static class ClearTextFrame {
		private byte[] frameHeader;
		private byte[] data;
		private byte[] PN;

		public ClearTextFrame() {
			this.frameHeader = new byte[64];
			random.nextBytes(this.frameHeader);
			this.data = new byte[128];
			random.nextBytes(this.data);
			this.PN = new byte[16];
			random.nextBytes(this.PN);
		}

		public ClearTextFrame(byte[] frameHeader, byte[] data, byte[] pN) {
			this.frameHeader = frameHeader;
			this.data = data;
			PN = pN;
		}

		public String toString() {
			StringBuffer sb = new StringBuffer("");
			sb.append("----------------------------------\n");
			sb.append("FRAME HEADER  :  " + new String(this.frameHeader) + "\n");
			sb.append("DATA  :  " + new String(this.data) + "\n");
			sb.append("PN  :  " + new String(this.PN) + "\n");
			sb.append("----------------------------------\n");
			return sb.toString();
		}

		public byte[] getFrameHeader() {
			return frameHeader;
		}

		public byte[] getData() {
			return data;
		}

		public byte[] getPN() {
			return PN;
		}

		public byte[] getBytesForMIC() throws IOException {
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

			outputStream.write(this.frameHeader);
			outputStream.write(this.data);

			return outputStream.toByteArray();
		}

		public byte[] getBytesForEncryption() throws IOException {
			return this.data;
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + Arrays.hashCode(PN);
			result = prime * result + Arrays.hashCode(data);
			result = prime * result + Arrays.hashCode(frameHeader);
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (getClass() != obj.getClass())
				return false;
			ClearTextFrame other = (ClearTextFrame) obj;
			if (!Arrays.equals(PN, other.PN))
				return false;
			if (!Arrays.equals(data, other.data))
				return false;
			if (!Arrays.equals(frameHeader, other.frameHeader))
				return false;
			return true;
		}

	}

	static class EncryptedFrame {
		private byte[] frameHeader;
		private byte[] data;
		private byte[] PN;
		private byte[] MIC;

		public EncryptedFrame(byte[] frameHeader, byte[] data, byte[] PN, byte[] MIC) {
			this.frameHeader = frameHeader;
			this.data = data;
			this.PN = PN;
			this.MIC = MIC;
		}

		public String toString() {
			StringBuffer sb = new StringBuffer("");
			sb.append("----------------------------------\n");
			sb.append("FRAME HEADER  :  " + new String(this.frameHeader) + "\n");
			sb.append("DATA  :  " + new String(this.data) + "\n");
			sb.append("PN  :  " + new String(this.PN) + "\n");
			sb.append("MIC  :  " + new String(this.MIC) + "\n");
			sb.append("----------------------------------\n");
			return sb.toString();
		}

		public byte[] getFrameHeader() {
			return frameHeader;
		}

		public byte[] getData() {
			return data;
		}

		public byte[] getPN() {
			return PN;
		}

		public byte[] getMIC() {
			return MIC;
		}

	}

	public static void initializeCryptoParameters() throws NoSuchAlgorithmException, NoSuchProviderException,
			NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {

		// set provider
		Security.addProvider(new BouncyCastleProvider());

		// set encryption/decryption type
		MICAES = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
		encrypt = Cipher.getInstance("AES/CCM/NoPadding", "BC");
		decrypt = Cipher.getInstance("AES/CCM/NoPadding", "BC");

		// set 128bit secret key
		KeyGenerator keygen = KeyGenerator.getInstance("AES");
		key = keygen.generateKey();
	}

	// function for generating MIC
	public static byte[] generateMIC(ClearTextFrame frame) throws InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {

		// set cipher mode
		MICAES.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(frame.getPN()));

		// encrypt frame
		byte[] encrypted = MICAES.doFinal(frame.getBytesForMIC());

		byte[] res = new byte[8];

		// get bytes for MIC
		System.arraycopy(encrypted, encrypted.length - 1 - 16, res, 0, 8);

		return res;
	}

	// ecnryption function
	public static EncryptedFrame encryptFrame(ClearTextFrame frame) throws InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {

		// set IV
		byte[] IV = new byte[13];
		System.arraycopy(frame.getPN(), 0, IV, 0, 13);

		// set encryption params
		encrypt.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV));

		// generate MIC
		byte[] MIC = generateMIC(frame);

		// get data from frame
		byte[] data = frame.getBytesForEncryption();

		// concatenate data and MIC for encryption
		ArrayList<byte[]> arr = new ArrayList<byte[]>();
		arr.add(data);
		arr.add(MIC);
		byte[] readyForEncryption = concatByteArrays(arr);

		// encrypt
		byte[] encrypted = encrypt.doFinal(readyForEncryption);

		// extract data from cipher
		byte[] encryptedData = new byte[128];
		System.arraycopy(encrypted, 0, encryptedData, 0, 128);

		// extract MIC from cipher
		byte[] encryptedMIC = new byte[8];
		System.arraycopy(encrypted, 128, encryptedMIC, 0, 8);

		// generate the final encrypted frame
		EncryptedFrame encryptedFrame = new EncryptedFrame(frame.frameHeader, encryptedData, frame.PN, encryptedMIC);

		return encryptedFrame;
	}

	// decryption function
	public static ClearTextFrame decryptFrame(EncryptedFrame frame) throws InvalidKeyException,
			InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException {

		// set IV
		byte[] IV = new byte[13];
		System.arraycopy(frame.getPN(), 0, IV, 0, 13);

		// set encryption params
		decrypt.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV));

		// get MIC
		byte[] MIC = frame.getMIC();

		// get data from frame
		byte[] data = frame.getData();

		// concatenate data and MIC for decryption
		ArrayList<byte[]> arr = new ArrayList<byte[]>();
		arr.add(data);
		arr.add(MIC);
		byte[] readyForDecryption = concatByteArrays(arr);

		// decrypt
		byte[] decrypted = encrypt.doFinal(readyForDecryption);

		// extract data from decrypted array
		byte[] decryptedData = new byte[128];
		System.arraycopy(decrypted, 0, decryptedData, 0, 128);

		// extract MIC from decrypted array
		byte[] decryptedMIC = new byte[8];
		System.arraycopy(decrypted, 128, decryptedMIC, 0, 8);

		// generate the final decrypted frame
		ClearTextFrame decryptedFrame = new ClearTextFrame(frame.getFrameHeader(), decryptedData, frame.getPN());

		System.out.println("RECIEVED MIC  :  " + Arrays.toString(decryptedMIC));
		System.out.println("ORIGINAL MIC  :  " + Arrays.toString(generateMIC(decryptedFrame)));

		return decryptedFrame;
	}

	static byte[] concatByteArrays(ArrayList<byte[]> arr) throws IOException {
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

		for (byte[] tmp : arr)
			outputStream.write(tmp);

		return outputStream.toByteArray();
	}

	static ArrayList<ClearTextFrame> generateFrames(int count) {
		ArrayList<ClearTextFrame> frames = new ArrayList<ClearTextFrame>();

		for (int i = 0; i < count; ++i)
			frames.add(new ClearTextFrame());

		return frames;
	}

	public static void main(String[] args) throws Exception {

		// function call to initialize crypto parameters
		initializeCryptoParameters();

		ArrayList<ClearTextFrame> frames = generateFrames(4);

		System.out.println("ORIGINAL FRAME");
		System.out.println(frames.get(0));
		System.out.println();

		System.out.println("ENCRYPTED FRAME");
		EncryptedFrame enc = encryptFrame(frames.get(0));
		System.out.println(enc);
		System.out.println();

		System.out.println("DECRYPTED FRAME");
		ClearTextFrame decryptedFrame = decryptFrame(enc);
		System.out.println(decryptedFrame);
		System.out.println();

		System.out.println("CHECK FRAME EQUALITY  :  " + frames.get(0).equals(decryptedFrame));
	}
}
