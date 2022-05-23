/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

import static java.lang.System.err;
import static java.lang.System.out;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPrivateKey;

import iaik.pkcs.pkcs11.objects.*;
import jdk.nashorn.internal.parser.Token;
import sun.security.pkcs11.wrapper.PKCS11Constants;

/**
 *
 * @author André Zúquete
 */
public class Auth_pkcs11_objects {
    static final String ccAuthKeyLabel = "CITIZEN AUTHENTICATION KEY";
    static final String ccAuthCertLabel = "CITIZEN AUTHENTICATION CERTIFICATE";
    static final char [] PIN = "1111".toCharArray(); // Test cards PIN

    static iaik.pkcs.pkcs11.Module module; // PKCS#11 module, suitable to access particular types of smartcards
    static Token token; // token (present in slot and suitable for module)

    private static iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate getCertificate ( Session session, String label )
            throws TokenException
    {
        iaik.pkcs.pkcs11.objects.Object [] certificates;
        GenericTemplate attrs = new GenericTemplate ();
        Attribute attr;
        X509PublicKeyCertificate certificate;
        
        attr = new CharArrayAttribute ( PKCS11Constants.CKA_LABEL );
        ((CharArrayAttribute) attr).setCharArrayValue ( label.toCharArray() );
        attrs.addAttribute ( attr );
        
        // Find objects with those attributes (should be only 1, in our case)
        session.findObjectsInit ( attrs );
        certificates = session.findObjects ( 1 );
        session.findObjectsFinal ();
        
        // out.println ( "Found " + certificates.length + " certificate objects with label \"" + label + "\"" );

        certificate = new X509PublicKeyCertificate ();
        certificate.setObjectHandle ( certificates[0].getObjectHandle() );
        
        return certificate;
    }
    
    private static iaik.pkcs.pkcs11.objects.RSAPrivateKey getPrivateKey ( Session session, String label )
               throws TokenException
    {
        iaik.pkcs.pkcs11.objects.Object [] keys;
        GenericTemplate attrs = new GenericTemplate ();
        Attribute attr;
        RSAPrivateKey privKey;
        
        attr = new CharArrayAttribute ( PKCS11Constants.CKA_LABEL );
        ((CharArrayAttribute) attr).setCharArrayValue ( label.toCharArray() );
        attrs.addAttribute ( attr );
        
        // Find objects with those attributes (should be only 1, in our case)
        session.findObjectsInit ( attrs );
        keys = session.findObjects ( 1 );
        session.findObjectsFinal ();
        
        // out.println ( "Found " + keys.length + " private key objects with label \"" + label + "\"" );
        
        privKey = new RSAPrivateKey ();
        privKey.setObjectHandle ( keys[0].getObjectHandle() );
        
        return privKey;
    }
    
    private static String getHexString ( byte[] b ) throws Exception
    {
        String result = "";
        for (int i=0; i < b.length; i++) {
            result += Integer.toString( ( b[i] & 0xff ) + 0x100, 16).substring( 1 );
        }
        return result;
    }
    
    private static boolean validateResponse ( byte [] challenge, byte [] response, String digFunc, String label )
    {
        Session session; // session object
        iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate iaikCert; // IAIK certificate object
        java.security.cert.Certificate certificate; // certificate object
        Signature signature; // signature validator
        
        try {
        
        // Open serial, read-only PKCS#11 session to manipulate token objects
        session = token.openSession ( true, false, null, null );

        // Get public key certificate for authentication (that will be used for validation the signature)
        iaikCert = getCertificate ( session, label );
        
        // Get the contents (value) of the certificate (DER encoded byte array)
        // Create a X.509 certificate from the DER encoded byte array
        iaikCert.readAttributes ( session );        
        certificate = CertificateFactory.getInstance( "X.509" ).
                        generateCertificate( new ByteArrayInputStream( iaikCert.getValue().getByteArrayValue() ));
           
        // Close the session, no more needed
        session.closeSession();
        
        // Create a signature object for verifying the signature
        signature = Signature.getInstance ( digFunc + "withRSA" );
        
        // Setup the verification element (the certificate of the signer)
        signature.initVerify ( certificate.getPublicKey() );
  
	// Provide the data that was signed
	signature.update ( challenge );
   
	// Verify the signature
	return signature.verify ( response );
        
        } catch (TokenException e) {
            err.println ( "Token error: " + e );
        } catch (CertificateException e) {
            err.println ( "Cannot create certificate from PKCS#11 object: " + e );
        } catch (NoSuchAlgorithmException e) {
            err.println ( "Algorithm " + digFunc + "withRSA not available: " + e );
        } catch (InvalidKeyException e) {
            err.println ( "Cannot use certificate for validating signature: " + e );
        } catch (SignatureException e) {
            err.println ( "Error while validating signature:" + e );
            System.out.println ( "Error while validating signature:" + e );
        }
        
        return false;
    }
    
    private static byte [] signature ( byte [] data, String digFunc, String keyLabel )
    {
        Session session; // PKCS#11 session
        iaik.pkcs.pkcs11.objects.RSAPrivateKey key; // key to sign with
        byte [] response; // response byte array
        iaik.pkcs.pkcs11.Mechanism mechanism;
        
        try {

        switch (digFunc) {
        case "SHA1": 
            mechanism = iaik.pkcs.pkcs11.Mechanism.get(PKCS11Constants.CKM_SHA1_RSA_PKCS);
            break;
        case "SHA256": 
            mechanism = iaik.pkcs.pkcs11.Mechanism.get(PKCS11Constants.CKM_SHA256_RSA_PKCS);
            break;
        default:
            err.println( "Digest function \"" + digFunc + "\" not implemented" );
            return null;
        }


        // Open serial, read-only PKCS#11 session to manipulate token objects
        session = token.openSession ( true, false, null, null );
        
        // Get handle to private authentication key (that will be used for signing)
        key = getPrivateKey ( session, keyLabel );

        // Login with PIN for private authentication key (bound to CKU_USER)
        session.login ( Session.UserType.USER, PIN );
                
        // Choose signature method
        session.signInit ( mechanism, key );

        response = session.sign ( data );

        // Logout, PIN must be entered again for signing with the same key
        session.logout();
        
        // Close PKCS#11 session
        session.closeSession();
        
        return response;
        
        } catch (TokenException e) {
            err.println ( "Token error: " + e );
            return null;
        }
    }
    private static void testChallengeResponse ( String digFunc, String keyLabel, String certLabel )
    {
        byte [] challenge = "1234567890ABCDEF".getBytes();
        byte [] response;
        
	// The last parameter is the test CC authentication PIN
        response = signature ( challenge, digFunc, keyLabel );
        if (response != null && validateResponse ( challenge, response, digFunc, certLabel )) {
            out.println ( "YES!" );
        }
        else {
            out.println ( "No ..." );
        }
    }
  
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args)
    {
        Slot [] slots; // smartcard slot
        
        try {
            
        // Find all Citizen Card tokens
        module = iaik.pkcs.pkcs11.Module.getInstance( "pteidpkcs11" );
        module.initialize( null );
        slots = module.getSlotList( true );
        
        if (slots.length == 0) {
            err.println ( "No card inserted" );
            return;
        }
        
        // Perform a challenge-response operation using the authentication key pair
        for (int i = 0; i < slots.length; i++) {
            token = slots[i].getToken();
            out.println ( "Token label = \"" + token.getTokenInfo().getLabel() + "\"" );
            if (token.getTokenInfo().getLabel() == "CARTAO DE CIDADAO") {
                out.println ( "Found CC, model " + token.getTokenInfo().getModel() );
            }
            
            out.println( "Challenge-response with AUTH key, SHA-1 hashing" );
            testChallengeResponse ( "SHA1", ccAuthKeyLabel, ccAuthCertLabel );

            out.println( "Challenge-response with AUTH key, SHA-256 hashing" );
            testChallengeResponse ( "SHA256", ccAuthKeyLabel, ccAuthCertLabel );
        }
 
        module.finalize( null );

        } catch (IOException e) {
            err.println ( "I/O error: " + e );
        }
        catch (TokenException e) {
            err.println ( "Token error: " + e );
        }
    }
}
