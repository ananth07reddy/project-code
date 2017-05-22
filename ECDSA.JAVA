package encryptionalgorithms;

import gui.DisplayTextPanel;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;

import javax.security.auth.kerberos.KeyTab;

public class ECDSA {

	DisplayTextPanel display;
	String data;
	String ecCurve;

	public ECDSA(DisplayTextPanel display) {
		this.display = display;
	}

	public void setEcCurve(String ecCurve) {
		this.ecCurve = ecCurve;
	}

	public void sign(String data) {
		this.data = data;
		if (ecCurve == null)
			display.addText("Please  select a key size in the File menu.....");
		else {
			try {
				long startTime = System.currentTimeMillis();
				KeyPairGenerator kpg;
				kpg = KeyPairGenerator.getInstance("EC", "SunEC");

				display.addText("ECDSA Sign and Verification.....\n");
				ECGenParameterSpec ecsp;
				ecsp = new ECGenParameterSpec(ecCurve);
				kpg.initialize(ecsp);

				KeyPair kp = kpg.genKeyPair();
				PrivateKey privKey = kp.getPrivate();

				PublicKey pubKey = kp.getPublic();
				display.addText(privKey.toString());
				display.addText(pubKey.toString() + "\n");
				long keyTime = System.currentTimeMillis();
				display.addText("Time to generate keys: "
						+ (keyTime - startTime) + " Milli Seconds\n");

				Signature ecdsa;
				ecdsa = Signature.getInstance("SHA1withECDSA", "SunEC");
				ecdsa.initSign(privKey);

				display.addText("Text: " + data + "\n");
				byte[] baText = data.getBytes("UTF-8");

				ecdsa.update(baText);
				byte[] baSignature = ecdsa.sign();
				display.addText("Signature: 0x"
						+ (new BigInteger(1, baSignature).toString(16))
								.toUpperCase() + "\n");
				long signTime = System.currentTimeMillis();
				display.addText("Time to sign the information: "
						+ (signTime - keyTime) + " Milli Seconds\n");
				Signature signature;
				signature = Signature.getInstance("SHA1withECDSA", "SunEC");
				signature.initVerify(pubKey);
				signature.update(baText);
				boolean result = signature.verify(baSignature);
				long verifyTime = System.currentTimeMillis();
				display.addText("Valid: " + result);
				display.addText("Time to generate keys: "
						+ (verifyTime - signTime) + " Milli Seconds\n");
				display.addText("\nTotal time for the process: "
						+ (verifyTime - startTime) + " Milli Seconds");
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}
}
