package encryptionalgorithms;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.Cipher;

import gui.*;

public class RSAAlgorihtm {

	KeyPairGenerator keyPairGenerator;
	KeyPair keyPair;
	PublicKey publicKey;
	PrivateKey privateKey;
	Cipher cipher;
	String data;
	byte[] encryptedData;
	String text;
	DisplayTextPanel display;
	int key;

	public RSAAlgorihtm(DisplayTextPanel display) {
		this.display = display;
	}

	public void setKey(int key){
		this.key = key;
	}
	
	public void generateKey() {
		try {

			display.addText("GENRATING PUBLIC and PRIVATE KEY..........");
			keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(key);
			keyPair = keyPairGenerator.generateKeyPair();
			publicKey = keyPair.getPublic();
			privateKey = keyPair.getPrivate();
			display.addText("\nPublic Key - " + publicKey);
			display.addText("\nPrivate Key - " + privateKey);

			display.addText("\nEXTRACTING PARAMETERS WHICH MAKES KEYPAIR..........\n");
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			RSAPublicKeySpec rsaPubKeySpec = keyFactory.getKeySpec(publicKey,
					RSAPublicKeySpec.class);
			RSAPrivateKeySpec rsaPrivKeySpec = keyFactory.getKeySpec(
					privateKey, RSAPrivateKeySpec.class);
			display.addText("\nPubKey Modulus : " + rsaPubKeySpec.getModulus());
			display.addText("\nPubKey Exponent : "
					+ rsaPubKeySpec.getPublicExponent());
			display.addText("\nPrivKey Modulus : " + rsaPrivKeySpec.getModulus());
			display.addText("\nPrivKey Exponent : "
					+ rsaPrivKeySpec.getPrivateExponent());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
	}

	private byte[] encryptData(String data) {

		display.addText("\n\nENCRYPTION STARTED..........");
		display.addText("Data Before Encryption :" + data);
		byte[] dataToEncrypt = data.getBytes();
		byte[] encryptedData = null;
		try {
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			encryptedData = cipher.doFinal(dataToEncrypt);
			display.addText("Encryted Data: " + encryptedData);
		} catch (Exception e) {
			e.printStackTrace();
		}

		display.addText("ENCRYPTION COMPLETED..........");
		return encryptedData;
	}

	private void decryptData(byte[] data) {
		display.addText("\n\nDECRYPTION STARTED..........");
		byte[] decryptedData = null;

		try {
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			decryptedData = cipher.doFinal(data);
			display.addText("Decrypted Data: " + new String(decryptedData));
		} catch (Exception e) {
			e.printStackTrace();
		}

		display.addText("DECRYPTION COMPLETED..........");
	}

	public void process(String input) {
		this.data = input;
		long startTime = System.currentTimeMillis();
		if (key == 0)
			display.addText("Please  select a key size in the File menu.....");
		else{
			generateKey();
			long keyGenTime = System.currentTimeMillis();
			display.addText("\nTime to generate keys: "+(keyGenTime-startTime)+ " Milli Seconds");
			encryptedData = encryptData(this.data);
			long encryptionEndTime = System.currentTimeMillis();
			display.addText("\nTime to encrypt: " + (encryptionEndTime - keyGenTime) + " Milli Seconds");
			decryptData(encryptedData);
			long endTime = System.currentTimeMillis();
			display.addText("\nTime to decrypt: " + (endTime - encryptionEndTime) + " Milli Seconds");
			display.addText("\nTotal time for the process: "+(endTime - startTime) + " Milli Seconds");
		}
		
	}
}
