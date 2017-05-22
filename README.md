# project-code
# Elliptic curve time codeexecution
package encryptionalgorithms;

import gui.DisplayTextPanel;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;

import javax.crypto.KeyAgreement;

public class ECDH {
	KeyPairGenerator keyPairGenerator;
	DisplayTextPanel display;
	String ecCurve;

	public ECDH(DisplayTextPanel display) {
		this.display = display;
	}

	public void setEcCurve(String ecCurve) {
		this.ecCurve = ecCurve;
	}

	public void generateKeys() {

		long startTime = System.currentTimeMillis();
		if (ecCurve == null)
			display.addText("Please  select a key size in the File menu.....");
		else {
			try {
				keyPairGenerator = KeyPairGenerator.getInstance("EC", "SunEC");
				ECGenParameterSpec ecsp;
				display.addText("ECDH Key Exchange scheme.....\n");
				ecsp = new ECGenParameterSpec(ecCurve);
				keyPairGenerator.initialize(ecsp);

				KeyPair keyPairAlice = keyPairGenerator.genKeyPair();
				PrivateKey privKeyAlice = keyPairAlice.getPrivate();
				PublicKey pubKeyAlice = keyPairAlice.getPublic();
				display.addText("Alice: " + privKeyAlice.toString());
				display.addText("Alice: " + pubKeyAlice.toString());

				KeyPair keyPairBob = keyPairGenerator.genKeyPair();
				PrivateKey privKeyBob = keyPairBob.getPrivate();
				PublicKey pubKeyBob = keyPairBob.getPublic();
				display.addText("\nBob: " + privKeyBob.toString());
				display.addText("Bob: " + pubKeyBob.toString());

				KeyAgreement ecdhAlice = KeyAgreement.getInstance("ECDH");
				ecdhAlice.init(privKeyAlice);
				ecdhAlice.doPhase(pubKeyBob, true);

				KeyAgreement ecdhBob = KeyAgreement.getInstance("ECDH");
				ecdhBob.init(privKeyBob);
				ecdhBob.doPhase(pubKeyAlice, true);

				display.addText("\nSecret computed by Alice: 0x"
						+ (new BigInteger(1, ecdhAlice.generateSecret())
								.toString(16)).toUpperCase());
				display.addText("\nSecret computed by Bob: 0x"
						+ (new BigInteger(1, ecdhBob.generateSecret())
								.toString(16)).toUpperCase());
				long endTime = System.currentTimeMillis();
				display.addText("\n Time to generate keys:"
						+ (endTime - startTime) + " Milli Seconds\n");
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

	}
}
