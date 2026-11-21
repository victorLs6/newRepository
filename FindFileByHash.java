package ro.ism.sap.java;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class FindFileByHash {

	// computes the SHA-256 of one file, reading it in chunks
	public static byte[] getFileHash(String filePath) 
			throws IOException, NoSuchAlgorithmException {
		File file = new File(filePath);
		if(!file.exists()) {
			System.out.println("********************** Where is the file ?");
			return null;
		}
		
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		
		FileInputStream fis = new FileInputStream(file);
		byte[] buffer = new byte[1024]; //it could be any size from 1byte to ......
		int noOfBytesWeGot = 0;
		while((noOfBytesWeGot = fis.read(buffer)) != -1) {
			md.update(buffer, 0, noOfBytesWeGot);
		}
		fis.close();
		
		return md.digest();
	}
	
	// looks in a directory for the file whose SHA-256 matches expectedHash
	// returns the name of the file or null if nothing matches
	public static String findFileByHash(String directoryPath, String expectedHash) 
			throws IOException, NoSuchAlgorithmException {
		File directory = new File(directoryPath);
		if(!directory.exists() || !directory.isDirectory()) {
			System.out.println("********************** Where is the directory ?");
			return null;
		}
		
		File[] content = directory.listFiles();
		for(File entry : content) {
			//we only hash files, not sub-folders
			if(entry.isFile()) {
				byte[] hash = getFileHash(entry.getAbsolutePath());
				String hexHash = Utility.getHexString(hash);
				System.out.println(entry.getName() + " -> " + hexHash);
				
				if(hexHash.equalsIgnoreCase(expectedHash.trim())) {
					System.out.println("FOUND: " + entry.getName());
					return entry.getName();
				}
			}
		}
		System.out.println("No file matches the given hash");
		return null;
	}
	
	// STEP 2: computes HMAC-SHA256 of a file using a shared secret key
	public static byte[] getFileHmac(String filePath, String secretKey) 
			throws IOException, NoSuchAlgorithmException, InvalidKeyException {
		File file = new File(filePath);
		if(!file.exists()) {
			System.out.println("********************** Where is the file ?");
			return null;
		}
		
		Mac mac = Mac.getInstance("HmacSHA256");
		SecretKeySpec keySpec = 
				new SecretKeySpec(secretKey.getBytes(), "HmacSHA256");
		mac.init(keySpec);
		
		FileInputStream fis = new FileInputStream(file);
		byte[] buffer = new byte[1024];
		int noOfBytesWeGot = 0;
		while((noOfBytesWeGot = fis.read(buffer)) != -1) {
			mac.update(buffer, 0, noOfBytesWeGot);
		}
		fis.close();
		
		return mac.doFinal();
	}
	
	// saves a text (here the HMAC as hex string) into a file
	public static void saveText(String filePath, String text) throws IOException {
		FileWriter fileWriter = new FileWriter(filePath);
		fileWriter.write(text);
		fileWriter.close();
	}
	
	// STEP 3: generates a random salt of the given size (in bytes)
	public static byte[] generateSalt(int size) {
		byte[] salt = new byte[size];
		SecureRandom random = new SecureRandom();
		random.nextBytes(salt);
		return salt;
	}
	
	// derives a key from a password using PBKDF2
	// keySizeInBytes can be anything we need: 16 or 32 for AES, 24 for 3DES
	public static byte[] getPBKDF2Key(String password, byte[] salt, 
			int iterations, int keySizeInBytes) 
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		// PBEKeySpec wants the key length in BITS
		PBEKeySpec spec = new PBEKeySpec(
				password.toCharArray(), salt, iterations, keySizeInBytes * 8);
		SecretKeyFactory factory = 
				SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		return factory.generateSecret(spec).getEncoded();
	}
	
	// STEP 4: generates a random IV (AES block size = 16 bytes)
	public static byte[] generateIV(int size) {
		byte[] iv = new byte[size];
		SecureRandom random = new SecureRandom();
		random.nextBytes(iv);
		return iv;
	}
	
	// AES in CBC mode with PKCS5 padding
	public static byte[] encryptAesCbc(byte[] plainData, byte[] key, byte[] iv) 
			throws Exception {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
		IvParameterSpec ivSpec = new IvParameterSpec(iv);
		cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
		return cipher.doFinal(plainData);
	}
	
	// reverse operation, used here only to test that we can decrypt
	public static byte[] decryptAesCbc(byte[] encryptedData, byte[] key, byte[] iv) 
			throws Exception {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
		IvParameterSpec ivSpec = new IvParameterSpec(iv);
		cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
		return cipher.doFinal(encryptedData);
	}
	
	// STEP 5: file encryption in ECB mode, read and written block by block
	// algorithm = "DESede" for 3DES (key must be 24 bytes)
	public static void encryptECB(
			byte[] key,
			String algorithm,
			String inputFile,
			String outputFile
			) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, 
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		
		File input = new File(inputFile);
		if(!input.exists()) {
			System.out.println("********* NO File");
			throw new FileNotFoundException();
		}
		FileInputStream fis = new FileInputStream(input);
		
		File output = new File(outputFile);
		if(!output.exists()) {
			output.createNewFile();
		}
		FileOutputStream fos = new FileOutputStream(output);
		
		//create Cipher object
		Cipher cipher = Cipher.getInstance(algorithm + "/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, algorithm));
		
		byte[] block = new byte[cipher.getBlockSize()];
		int noBytesWeGot = 0;
		while((noBytesWeGot = fis.read(block)) > 0) {
			//encrypt current block
			byte[] cipherBlock = cipher.update(block, 0, noBytesWeGot);
			if(cipherBlock != null) {   //update can return null
				fos.write(cipherBlock);
			}
		}
		//don't forget the last one (it adds the padding)
		fos.write(cipher.doFinal());
		
		fis.close();
		fos.close();
	}
	
	public static void decryptECB(
			byte[] key,
			String algorithm,
			String inputFile,
			String outputFile
			) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, 
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		
		File input = new File(inputFile);
		if(!input.exists()) {
			throw new FileNotFoundException("NO Input file");
		}
		File output = new File(outputFile);
		if(!output.exists()) {
			output.createNewFile();
		}
		
		FileInputStream fis = new FileInputStream(input);
		FileOutputStream fos = new FileOutputStream(output);
		
		Cipher cipher = Cipher.getInstance(algorithm + "/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, algorithm));
		
		byte[] block = new byte[cipher.getBlockSize()];
		int noBytes = 0;
		while((noBytes = fis.read(block)) > 0) {
			byte[] plaintext = cipher.update(block, 0, noBytes);
			if(plaintext != null) {
				fos.write(plaintext);
			}
		}
		fos.write(cipher.doFinal());   //removes the padding
		
		fis.close();
		fos.close();
	}
	
	// saves raw bytes (needed here because the obfuscated data is no longer text)
	public static void saveBytes(String filePath, byte[] data) throws IOException {
		FileOutputStream fos = new FileOutputStream(filePath);
		fos.write(data);
		fos.close();
	}
	
	// STEP 6: cyclic (circular) left shift by 2 bits on every byte
	public static byte[] rotateLeft2(byte[] data) {
		byte[] result = new byte[data.length];
		for(int i = 0; i < data.length; i++) {
			int value = data[i] & 0xFF;   //unsigned value 0..255
			//the 2 leftmost bits move to the right side
			result[i] = (byte) (((value << 2) | (value >>> 6)) & 0xFF);
		}
		return result;
	}
	
	// reverse: cyclic right shift by 2 bits on every byte
	public static byte[] rotateRight2(byte[] data) {
		byte[] result = new byte[data.length];
		for(int i = 0; i < data.length; i++) {
			int value = data[i] & 0xFF;
			//the 2 rightmost bits move to the left side
			result[i] = (byte) (((value >>> 2) | (value << 6)) & 0xFF);
		}
		return result;
	}
	
	public static void main(String[] args) 
			throws Exception {
		String directory = "safecorp_random_messages";
		String expectedHash = "PUT_THE_EXPECTED_SHA256_HERE";
		String secretKey = "PUT_THE_SHARED_SECRET_KEY_HERE";
		String password = "PUT_THE_MASTER_PASSWORD_HERE";
		int iterations = 10000; //from the Excel file
		
		// STEP 1
		String fileName = findFileByHash(directory, expectedHash);
		if(fileName == null) {
			System.out.println("Cannot continue without the assigned file");
			return;
		}
		System.out.println("Assigned file: " + fileName);
		
		// STEP 2
		String messagePath = directory + File.separator + fileName;
		byte[] hmac = getFileHmac(messagePath, secretKey);
		String hmacHex = Utility.getHexString(hmac);
		System.out.println("HMAC-SHA256: " + hmacHex);
		saveText("hmac.txt", hmacHex);
		
		// STEP 3
		byte[] salt = generateSalt(16);
		saveText("salt.txt", Utility.getHexString(salt));
		byte[] derivedKey = getPBKDF2Key(password, salt, iterations, 32);
		System.out.println("Salt: " + Utility.getHexString(salt));
		System.out.println("Derived key: " + Utility.getHexString(derivedKey));
		
		// STEP 4
		byte[] messageBytes = Files.readAllBytes(new File(messagePath).toPath());
		byte[] iv = generateIV(16);
		byte[] encrypted = encryptAesCbc(messageBytes, derivedKey, iv);
		
		String encryptedBase64 = Base64.getEncoder().encodeToString(encrypted);
		String ivBase64 = Base64.getEncoder().encodeToString(iv);
		saveText("encrypted.txt", encryptedBase64);
		saveText("iv.txt", ivBase64);
		System.out.println("IV (Base64): " + ivBase64);
		
		// test: decode from Base64, decrypt and compare with the original
		byte[] decrypted = decryptAesCbc(
				Base64.getDecoder().decode(encryptedBase64), 
				derivedKey, 
				Base64.getDecoder().decode(ivBase64));
		System.out.println("Decryption works: " + 
				Arrays.equals(messageBytes, decrypted));
		
		// STEP 5
		byte[] desKey = getPBKDF2Key(password, salt, iterations, 24);
		encryptECB(desKey, "DESede", messagePath, "archived.sec");
		
		// test: decrypt the binary file and compare with the original
		decryptECB(desKey, "DESede", "archived.sec", "archived_decrypted.txt");
		byte[] check = Files.readAllBytes(new File("archived_decrypted.txt").toPath());
		System.out.println("3DES decryption works: " + 
				Arrays.equals(messageBytes, check));
		
		// STEP 6
		byte[] encryptedFile = Files.readAllBytes(new File("encrypted.txt").toPath());
		byte[] obfuscated = rotateLeft2(encryptedFile);
		saveBytes("obfuscated.txt", obfuscated);
		
		// test: reverse the rotation and compare with encrypted.txt
		byte[] obfuscatedFile = Files.readAllBytes(new File("obfuscated.txt").toPath());
		byte[] restored = rotateRight2(obfuscatedFile);
		System.out.println("Obfuscation is reversible: " + 
				Arrays.equals(encryptedFile, restored));
		
		// test: the whole receiving side (undo step 6, Base64 decode, AES decrypt)
		byte[] fromBase64 = Base64.getDecoder().decode(new String(restored));
		byte[] finalPlain = decryptAesCbc(fromBase64, derivedKey, iv);
		System.out.println("Full chain works: " + 
				Arrays.equals(messageBytes, finalPlain));
	}
}
