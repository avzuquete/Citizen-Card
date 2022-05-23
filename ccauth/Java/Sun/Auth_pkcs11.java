import java.io.*;
import java.util.*;
import java.security.*;
import java.security.cert.*;

import sun.security.x509.*;
import sun.security.pkcs11.SunPKCS11;

/*
 * @author André Zúquete
 */
public class Auth_pkcs11 {
    private static KeyStore getToken () throws KeyStoreException
    {
        String conf, prefix = "", postfix = "";
	KeyStore ks;
	boolean switchSeparator = false;
	
	if (System.getProperty ( "os.name" ).contains ( "Windows" )) {
	     postfix = ".dll";
	     switchSeparator = true;
	}
	else if (System.getProperty ( "os.name" ).contains ( "Linux" )) {
	     prefix = "lib";
	     postfix = ".so";
	}
	
	String path = System.getProperty("user.dir") +
			System.getProperty("file.separator") +
			prefix + "pteidpkcs11" + postfix;

	if (switchSeparator) {
	    path = path.replace ( "\\", "/" );
	}

	conf = "name = PortugueseEId\nlibrary = \"" + path + "\"\n";
	System.out.print ( conf );

        // Pre-Java 9 version
        // SunPKCS11 provider = new SunPKCS11 ( new ByteArrayInputStream ( conf.getBytes () ) );

        // Java 9 version
        Provider providerProtype = Security.getProvider( "SunPKCS11" );
        Provider provider = providerProtype.configure( "--" + conf );

	ks = KeyStore.getInstance ( "PKCS11", provider );

	try {

	// Initialize the PKCS#11 token
	ks.load ( null, null );

	} catch (Exception e) {
            System.out.println ( "Exception while initializing PKCS#11 token:" + e );
	}

	// Just for debug, list the aliases (names of objects) known by the token
	System.out.println ( "PKCS#11 token contains the following aliases:" );
	for (Enumeration e = ks.aliases (); e.hasMoreElements () ;) {
            System.out.println ( "\t" + e.nextElement () );
	}
	
	return ks;
    }

    private static java.security.cert.Certificate getCertificate ( KeyStore token, String label ) throws KeyStoreException
    {
	java.security.cert.Certificate cert = token.getCertificate ( label );
        // System.out.println( cert );

        return cert;
    }
    
    private static PrivateKey getPrivateKey ( KeyStore token, String label, String PIN ) throws KeyStoreException
    {
        PrivateKey key = null;
	
	try {

	key = (PrivateKey) token.getKey ( label, PIN == null ? null : PIN.toCharArray () );
	if (key == null) {
            System.out.println ( "Could not get private key with label " + label );
	}

	} catch (UnrecoverableKeyException e) {
            System.out.println ( "UnrecoverableKeyException for key " + label + ":" + e );
	} catch (NoSuchAlgorithmException e) {
            System.out.println ( "NoSuchAlgorithmException for key " + label + ":" + e );
	}

	return key;
    }
    
    private static boolean validateResponse ( KeyStore token, byte [] challenge, byte [] response, String label, String method ) throws KeyStoreException
    {
        java.security.cert.Certificate cert; // public key certificate
        Signature signature; // signature validator
        
        try {
        
        // Get public key certificate for authentication (that will be used for validation the signature)
        cert = getCertificate ( token, label );
        
        // Create a signature object for verifying the signature
        signature = Signature.getInstance ( method );
        
        // Setup the verification element (the certificate of the signer)
        signature.initVerify ( cert.getPublicKey() );
   
        // Provide the data that was signed
        signature.update ( challenge );
   
        // Verify the signature
        return signature.verify ( response );
        
        } catch (SignatureException e) {
            System.out.println ( "SignatureException error while validating signature:" + e );
        } catch (InvalidKeyException e) {
            System.out.println ( "InvalidKeyException error while validating signature:" + e );
	} catch (NoSuchAlgorithmException e) {
            System.out.println ( "NoSuchAlgorithmException (" + method + ") for token:" + e );
        }
        
        return false;
    }
    
    private static byte [] computeResponse ( KeyStore token, byte [] challenge, String keyLabel, String PIN, String method ) throws KeyStoreException
    {
	Signature signature; // the object to compute the signature
        byte [] response = null; // response byte array
        PrivateKey key; // key to sign with
        
        // Login with PIN for private authentication key (bound to CKU_USER)
        // Change the comment to use PIN instead of a pop-up window
        key = getPrivateKey ( token, keyLabel, null/*PIN*/ );

        // Compute signature of data

	try {

        signature = Signature.getInstance ( method, token.getProvider () );
	signature.initSign ( key );
        signature.update ( challenge );
        response = signature.sign ();

	} catch (NoSuchAlgorithmException e) {
            System.out.println ( "NoSuchAlgorithmException (" + method + ") for token:" + e );
	} catch (InvalidKeyException e) {
            System.out.println ( "InvalidKeyException while computing signature:" + e );
	} catch (SignatureException e) {
            System.out.println ( "SignatureException while computing signature:" + e );
	} catch (Exception e) {
            System.out.println ( "Exception while computing signature:" + e );
	}
        
        return response;
    }
    
    private static void testChallengeResponse ( KeyStore token, String method ) throws KeyStoreException
    {
        byte [] challenge = "1234567890ABCDEF".getBytes();
        byte [] response;
        
	// The last parameter is the test CC authentication PIN
	// It's a bit odd, but with the Sun PKCS#11 provider the CC's
	// authentication private key has a label where CERTIFICATE is used
	// instead of KEY ...
        response = computeResponse ( token, challenge, "CITIZEN SIGNATURE CERTIFICATE", "", method );
        if (response != null && validateResponse ( token, challenge, response, "CITIZEN SIGNATURE CERTIFICATE", method )) {
            System.out.println ( method + ": YES!" );
        }
        else {
            System.out.println ( method + ": No ..." );
        }
    }

    /*
     * @param args the command line arguments
     */
    public static void main(String[] args)
    {
	try {

        // Select the correct PKCS#11 module for dealing with Citizen Card tokens
        KeyStore token = getToken ();
      
	// Do a challeng-response calculation with the token's AUTHENTICATION private key and public key certificate
	// testChallengeResponse ( token, "MD5withRSA" );
	// testChallengeResponse ( token, "SHA1withRSA" );
	testChallengeResponse ( token, "SHA224withRSA" );
	// testChallengeResponse ( token, "SHA256withRSA" );
	testChallengeResponse ( token, "SHA384withRSA" );
	testChallengeResponse ( token, "SHA512withRSA" );

	// testChallengeResponse ( token, "SHA1withRSA/PSS" );
	// testChallengeResponse ( token, "SHA256withRSA/PSS" );
	// testChallengeResponse ( token, "SHA512withRSA/PSS" );
     
        } catch (KeyStoreException e) {
            System.out.println ( "KeyStore error: " + e );
	}
    }
}
