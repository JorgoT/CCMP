package Lab01;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
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

	static class FrameHeader {
		byte[] PN;
		byte[] SourceMAC;
		byte[] QoS;

		public FrameHeader() {
			this.PN = new byte[6];
			random.nextBytes(this.PN);

			this.SourceMAC = new byte[6];
			random.nextBytes(this.SourceMAC);

			this.QoS = new byte[2];
			random.nextBytes(this.QoS);
		}

		public FrameHeader(byte[] PN, byte[] SourceMAC, byte[] QoS) {
			this.PN = Arrays.copyOf(PN, PN.length);
			this.SourceMAC = Arrays.copyOf(SourceMAC, SourceMAC.length);
			this.QoS = Arrays.copyOf(QoS, QoS.length);
		}

		@Override
		public String toString() {
			StringBuilder sb = new StringBuilder();

			sb.append("FRAME HEADER : \n");
			sb.append("    PN : " + new String(this.PN) + "\n");
			sb.append("    SourceMAC : " + new String(this.SourceMAC) + "\n");
			sb.append("    QoS : " + new String(this.QoS) + "\n");

			return sb.toString();
		}

		public byte[] getBytesForCBC_IV() throws IOException, NoSuchAlgorithmException, NoSuchProviderException {
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

			outputStream.write(this.PN);
			outputStream.write(this.SourceMAC);
			outputStream.write(this.QoS);

			MessageDigest sha1 = MessageDigest.getInstance("SHA-1", "BC");

			byte[] hash = new byte[sha1.getDigestLength()];

			sha1.update(outputStream.toByteArray());
			hash = sha1.digest();

			return Arrays.copyOf(hash, 16);
		}

		public byte[] getBytesForCCM_IV() throws IOException {
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

			outputStream.write(this.PN);
			outputStream.write(this.SourceMAC);
			outputStream.write(this.QoS);

			return Arrays.copyOf(outputStream.toByteArray(), 13);
		}

		public byte[] getBytes() throws IOException {
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

			outputStream.write(this.PN);
			outputStream.write(this.SourceMAC);
			outputStream.write(this.QoS);

			return outputStream.toByteArray();
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + Arrays.hashCode(PN);
			result = prime * result + Arrays.hashCode(QoS);
			result = prime * result + Arrays.hashCode(SourceMAC);
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
			FrameHeader other = (FrameHeader) obj;
			if (!Arrays.equals(PN, other.PN))
				return false;
			if (!Arrays.equals(QoS, other.QoS))
				return false;
			if (!Arrays.equals(SourceMAC, other.SourceMAC))
				return false;
			return true;
		}

	}

	static class ClearTextFrame {
		private FrameHeader frameHeader;
		private byte[] data;

		public ClearTextFrame() {
			this.frameHeader = new FrameHeader();

			this.data = new byte[128];
			random.nextBytes(this.data);
		}

		public ClearTextFrame(FrameHeader frameHeader, byte[] data) {
			this.frameHeader = new FrameHeader(frameHeader.PN, frameHeader.SourceMAC, frameHeader.QoS);
			this.data = Arrays.copyOf(data, data.length);
		}

		public String toString() {
			StringBuffer sb = new StringBuffer("");
			sb.append("----------------------------------\n");
			sb.append(this.frameHeader.toString());
			sb.append("DATA  :  " + new String(this.data) + "\n");
			sb.append("----------------------------------\n");
			return sb.toString();
		}

		public FrameHeader getFrameHeader() {
			return frameHeader;
		}

		public byte[] getData() {
			return data;
		}

		public byte[] getBytesForMIC() throws IOException {
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

			outputStream.write(this.frameHeader.getBytes());
			outputStream.write(this.data);

			return outputStream.toByteArray();
		}

		public byte[] getBytesForCCM_IV() throws IOException {
			return frameHeader.getBytesForCCM_IV();
		}

		public byte[] getBytesForCBC_IV() throws IOException, NoSuchAlgorithmException, NoSuchProviderException {
			return frameHeader.getBytesForCBC_IV();
		}

		public byte[] getBytesForEncryption() throws IOException {
			return this.data;
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + Arrays.hashCode(data);
			result = prime * result + ((frameHeader == null) ? 0 : frameHeader.hashCode());
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
			if (!Arrays.equals(data, other.data))
				return false;
			if (frameHeader == null) {
				if (other.frameHeader != null)
					return false;
			} else if (!frameHeader.equals(other.frameHeader))
				return false;
			return true;
		}

	}

	static class EncryptedFrame {
		private FrameHeader frameHeader;
		private byte[] data;
		private byte[] MIC;

		public EncryptedFrame(FrameHeader frameHeader, byte[] data, byte[] MIC) {
			this.frameHeader = new FrameHeader(frameHeader.PN, frameHeader.SourceMAC, frameHeader.QoS);
			this.data = data;
			this.MIC = MIC;
		}

		public String toString() {
			StringBuffer sb = new StringBuffer("");
			sb.append("----------------------------------\n");
			sb.append(this.frameHeader.toString());
			sb.append("DATA  :  " + new String(this.data) + "\n");
			sb.append("MIC  :  " + new String(this.MIC) + "\n");
			sb.append("----------------------------------\n");
			return sb.toString();
		}

		public FrameHeader getFrameHeader() {
			return frameHeader;
		}

		public byte[] getData() {
			return data;
		}

		public byte[] getMIC() {
			return MIC;
		}

		public byte[] getBytesForCCM_IV() throws IOException {
			return frameHeader.getBytesForCCM_IV();
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
	public static byte[] generateMIC(ClearTextFrame frame)
			throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException, IOException, NoSuchAlgorithmException, NoSuchProviderException {

		// set cipher mode
		MICAES.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(frame.getBytesForCBC_IV()));

		// encrypt frame
		byte[] encrypted = MICAES.doFinal(frame.getBytesForMIC());

		byte[] res = new byte[8];

		// get bytes for MIC
		System.arraycopy(encrypted, encrypted.length - 1 - 16, res, 0, 8);

		return res;
	}

	// ecnryption function
	public static EncryptedFrame encryptFrame(ClearTextFrame frame)
			throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException, IOException, NoSuchAlgorithmException, NoSuchProviderException {

		// set IV
		byte[] IV = frame.getBytesForCCM_IV();

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
		EncryptedFrame encryptedFrame = new EncryptedFrame(frame.frameHeader, encryptedData, encryptedMIC);

		return encryptedFrame;
	}

	// decryption function
	public static ClearTextFrame decryptFrame(EncryptedFrame frame)
			throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException,
			BadPaddingException, NoSuchAlgorithmException, NoSuchProviderException {

		// set IV
		byte[] IV = frame.getBytesForCCM_IV();

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
		ClearTextFrame decryptedFrame = new ClearTextFrame(frame.getFrameHeader(), decryptedData);

		System.out.println("RECIEVED MIC  :  " + Arrays.toString(decryptedMIC));
		System.out.println("CALCULATED MIC  :  " + Arrays.toString(generateMIC(decryptedFrame)));

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
