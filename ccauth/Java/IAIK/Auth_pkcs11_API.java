/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

import static java.lang.System.*;

import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.security.*;
import java.security.cert.*;

import java.io.*;
import java.security.*;
import java.security.cert.*;

import iaik.pkcs.pkcs11.wrapper.*;

/**
 *
 * @author André Zúquete
 */
public class Auth_pkcs11_API {

    static final String ccAuthKeyLabel = "CITIZEN AUTHENTICATION KEY";
    static final String ccAuthCertLabel = "CITIZEN AUTHENTICATION CERTIFICATE";
    static char [] PIN;

    static long tokenHandle;
    static PKCS11 module; // PKCS#11 module, suitable to access particular types of smartcards

    private static long getCertificate ( final PKCS11 module, final long sessHandle, final String label)
            throws PKCS11Exception {
        long[] certificates;
        final CK_ATTRIBUTE[] attrs = new CK_ATTRIBUTE[1];

        // Prepare only 1 search attributes: LABEL (the last function argument)
        attrs[0] = new CK_ATTRIBUTE();
        attrs[0].type = PKCS11Constants.CKA_LABEL;
        attrs[0].pValue = label.toCharArray();

        // Find objects with those attributes (should be only 1, in our case)
        module.C_FindObjectsInit(sessHandle, attrs);
        certificates = module.C_FindObjects(sessHandle, 1);
        module.C_FindObjectsFinal(sessHandle);

        // out.println ( "Found " + certificates.length + " certificate objects with
        // label \"" + label + "\"" );
        return certificates[0];
    }

    private static long getPrivateKey(final PKCS11 module, final long sessHandle, final String label)
            throws PKCS11Exception {
        long[] keys;
        final CK_ATTRIBUTE[] attrs = new CK_ATTRIBUTE[1];

        // Prepare only 1 search attributes: LABEL (the last function argument)
        attrs[0] = new CK_ATTRIBUTE();
        attrs[0].type = PKCS11Constants.CKA_LABEL;
        attrs[0].pValue = label.toCharArray();

        // Find objects with those attributes (should be only 1, in our case)
        module.C_FindObjectsInit(sessHandle, attrs);
        keys = module.C_FindObjects(sessHandle, 1);
        module.C_FindObjectsFinal(sessHandle);

        // out.println ( "Found " + keys.length + " private key objects with label \"" +
        // label + "\"" );
        return keys[0];
    }

    private static boolean validate(final byte[] challenge, final byte[] response, final String label,
            final String digFunc) {
        long sessHandle; // session handle
        long certHandle; // certificate handle
        final CK_ATTRIBUTE[] attrs = new CK_ATTRIBUTE[1];
        java.security.cert.Certificate certificate; // certificate object
        Signature signature; // signature validator

        out.print("validate signature, ");
        try {

            // Open serial, read-only PKCS#11 session to manipulate token objects
            sessHandle = module.C_OpenSession(tokenHandle, PKCS11Constants.CKF_SERIAL_SESSION, null, null);

            // Get handle to public key certificate for authentication (that will be used
            // for validation the signature)
            certHandle = getCertificate(module, sessHandle, label);

            // Get the contents (value) of the certificate (DER encoded byte array)
            attrs[0] = new CK_ATTRIBUTE();
            attrs[0].type = PKCS11Constants.CKA_VALUE;
            module.C_GetAttributeValue(sessHandle, certHandle, attrs);

            // Close the session, no more needed
            module.C_CloseSession(sessHandle);

            // Create a X.509 certificate from the DER encoded byte array
            certificate = CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream((byte[]) attrs[0].pValue));

            // Create a signature object for verifying the signature
            signature = Signature.getInstance(digFunc.replaceAll("-", "") + "withRSA");

            // Setup the verification element (the ceetificate of the signer)
            signature.initVerify(certificate.getPublicKey());

            // Provide the data that was signed
            signature.update(challenge);

            // Verify the signature
            return signature.verify(response);

        } catch (final PKCS11Exception e) {
            out.println("PKCS#11 error: " + e);
        } catch (final CertificateException e) {
            out.println("Cannot create certificate from PKCS#11 object: " + e);
        } catch (final NoSuchAlgorithmException e) {
            out.println("Algorithm " + digFunc + "withRSA not available: " + e);
        } catch (final InvalidKeyException e) {
            out.println("Cannot use certificate for validating signature: " + e);
        } catch (final SignatureException e) {
            out.println("Error while validating signature:" + e);
        }

        return false;
    }

    private static byte[] signature(final byte[] data, final CK_MECHANISM mechanism, final String keyLabel) {
        long sessHandle; // session handle
        byte[] response; // response byte array
        long key; // key to sign with
        String op = "";

        try {

            // Open serial, read-only PKCS#11 session to manipulate token objects
            op = "OpenSession";
            sessHandle = module.C_OpenSession(tokenHandle, PKCS11Constants.CKF_SERIAL_SESSION, null, null);

            // Login with PIN for private authentication key (bound to CKU_USER)
            op = "Login";
            module.C_Login(sessHandle, PKCS11Constants.CKU_USER, PIN);

            // Get handle to private authentication key (that will be used for signing)
            key = getPrivateKey(module, sessHandle, keyLabel);

            // Compute signature of data (using two alternative methods)

            // Method 1
            op = "SignInit";
            module.C_SignInit(sessHandle, mechanism, key);

            // We should be able to do simply this ...
            op = "Sign";
            response = module.C_Sign(sessHandle, data);
            // but, for some reason, we get a CKR_ARGUMENTS_BAD error ...

            // Logout, PIN must be entered again for signing with the same key
            op = "Logout";
            module.C_Logout ( sessHandle );

            // Close PKCS#11 session
            op = "CloseSession";
            module.C_CloseSession(sessHandle);

            out.print("signature done, ");

            return response;

        } catch (final PKCS11Exception e) {
            out.println("PKCS#11 error (" + op + "): " + e);
            // Exit upon PIN error to avoid blocking the card
            if (e.getErrorCode() == PKCS11Constants.CKR_PIN_INCORRECT) {
                System.exit( 2 );
            }
            return null;
        }
    }

    private static byte[] getResponse(final byte[] challenge, final String keyLabel, final String digFunc) {
        final CK_MECHANISM mechanism = new CK_MECHANISM(); // signature mechanism

        // Choose signature method
        switch (digFunc) {
        case "SHA-1":
            mechanism.mechanism = PKCS11Constants.CKM_SHA1_RSA_PKCS;
            break;
        case "RIPEMD128":
            mechanism.mechanism = PKCS11Constants.CKM_RIPEMD128_RSA_PKCS;
            break;
        case "RIPEMD160":
            mechanism.mechanism = PKCS11Constants.CKM_RIPEMD160_RSA_PKCS;
            break;
        case "SHA-256":
            mechanism.mechanism = PKCS11Constants.CKM_SHA256_RSA_PKCS;
            break;
        case "SHA-384":
            mechanism.mechanism = PKCS11Constants.CKM_SHA384_RSA_PKCS;
            break;
        case "SHA-512":
            mechanism.mechanism = PKCS11Constants.CKM_SHA512_RSA_PKCS;
            break;
        default:
            err.println("Digest function \"" + digFunc + "\" not yet handled");
            return null;
        }
        mechanism.pParameter = null;

        return signature(challenge, mechanism, keyLabel);
    }

    private static byte[] getResponseDigest(final byte[] digest, final String keyLabel, final String digFunc) {
        final CK_MECHANISM mechanism = new CK_MECHANISM(); // signature mechanism

        mechanism.mechanism = PKCS11Constants.CKM_RSA_PKCS;
        mechanism.pParameter = null;

        return signature(digest, mechanism, keyLabel);
    }

    private static byte[] getResponseASN1(final byte[] challenge, final String keyLabel, final String digFunc) {
        final CK_MECHANISM mechanism = new CK_MECHANISM(); // signature mechanism
        byte[] asn1Hash;
        byte[] digest;
        int prefixLen;

        try {

            digest = MessageDigest.getInstance(digFunc).digest(challenge);

        } catch (final NoSuchAlgorithmException e) {
            System.out.println("Digest error, no \"" + digFunc + "\" function");
            return null;
        }

        switch (digFunc) {
        case "SHA-1":
            final byte[] sha1Prefix = { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00,
                    0x04, 0x14 };
            prefixLen = sha1Prefix.length;
            asn1Hash = new byte[prefixLen + digest.length];
            System.arraycopy(sha1Prefix, 0, asn1Hash, 0, prefixLen);
            System.arraycopy(digest, 0, asn1Hash, prefixLen, digest.length);
            break;
        case "SHA-256":
            final byte[] sha256Prefix = { 0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03,
                    0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };
            prefixLen = sha256Prefix.length;
            asn1Hash = new byte[prefixLen + digest.length];
            System.arraycopy(sha256Prefix, 0, asn1Hash, 0, prefixLen);
            System.arraycopy(digest, 0, asn1Hash, prefixLen, digest.length);
            break;
        case "SHA-512":
            final byte[] sha512Prefix = { 0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03,
                    0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 };
            prefixLen = sha512Prefix.length;
            asn1Hash = new byte[prefixLen + digest.length];
            System.arraycopy(sha512Prefix, 0, asn1Hash, 0, prefixLen);
            System.arraycopy(digest, 0, asn1Hash, prefixLen, digest.length);
            break;
        default:
            err.println("Digest function \"" + digFunc + "\" not yet handled");
            return null;
        }

        mechanism.mechanism = PKCS11Constants.CKM_RSA_PKCS;
        mechanism.pParameter = null;

        return signature(asn1Hash, mechanism, keyLabel);
    }

    private static void testChallengeResponse(final String operation, String digFunc) {
        byte[] challenge = "1234567890ABCDEF".getBytes();
        byte[] response;
        boolean success = false;

        switch (operation) {
        case "API": // High level approach
            response = getResponse(challenge, ccAuthKeyLabel, digFunc);
            break;
        case "API + digest":
            try {

                challenge = MessageDigest.getInstance(digFunc).digest(challenge);
                response = getResponseDigest(challenge, ccAuthKeyLabel, digFunc);
                digFunc = "NONE";

            } catch (final NoSuchAlgorithmException e) {
                response = null;
            }

            break;
        case "API + ASN.1 wrapping":
            response = getResponseASN1(challenge, ccAuthKeyLabel, digFunc);
            break;
        default:
            out.println("Operation \"" + operation + "\" not yet implemented");
            return;
        }

        if (response != null) {
            success = validate(challenge, response, ccAuthCertLabel, digFunc);
        }

        out.print(operation + " + " + digFunc + ": ");

        if (success) {
            out.println("YES!");
        } else {
            out.println("No ...");
        }
    }

    /**
     * @param args the command line arguments
     */
    public static void main(final String[] args) {
        long[] tokens;

        if (args.length < 2) {
            err.println("usage: java Auth_pkcs11_API PTEID_PKCS11_lib_path PIN");
            System.exit(1);
        }

        PIN = args[1].toCharArray();

        try {

            // Select the correct PKCS#11 module for dealing with Citizen Card tokens
            module = PKCS11Connector.connectToPKCS11Module(
                    System.getProperty("os.name").contains("Windows") ? "pteidpkcs11" : "libpteidpkcs11.so");

            // Initialize module
            module.C_Initialize(null);

            // Find all Citizen Card tokens
            tokens = module.C_GetSlotList(true);

            if (tokens.length == 0) {
                out.println("No card inserted");
                return;
            }

            // Perform a challenge-response operation using the authentication key pair
            for (int i = 0; i < tokens.length; i++) {
                final CK_TOKEN_INFO tokenInfo = module.C_GetTokenInfo(tokens[i]);
                out.println("Token label = \"" + new String(tokenInfo.label) + "\"");
                tokenHandle = tokens[i];

                if (String.valueOf(tokenInfo.label).startsWith("CARTAO DE CIDADAO")) {
                    out.println("Found CC, model " + new String(tokenInfo.model));

                    out.println("Challenge-response with AUTH key, middleware hashing");
                    // testChallengeResponse("API", "SHA-1");
                    // testChallengeResponse ( "API", "RIPEMD160" );
                    // testChallengeResponse("API", "SHA-256");
                    // testChallengeResponse("API", "SHA-512");

                    out.println("Challenge-response with AUTH key, client hashing");
                    // testChallengeResponse("API + digest", "SHA-1");
                    // testChallengeResponse ( "API + digest", "RIPEMD160" );
                    // testChallengeResponse("API + digest", "SHA-256");
                    // testChallengeResponse("API + digest", "SHA-512");

                    out.println("Challenge-response with AUTH key, ASN.1 wrapped client hashing");
                    // testChallengeResponse("API + ASN.1 wrapping", "SHA-1");
                    // testChallengeResponse ( module, tokens[i], "API + ASN.1 wrapping", "RIPEMD160" );
                    // testChallengeResponse("API + ASN.1 wrapping", "SHA-256");
                    testChallengeResponse("API + ASN.1 wrapping", "SHA-512");
                }
            }
            module.C_Finalize(null);

        } catch (final IOException e) {
            out.println("I/O error: " + e);
        } catch (final PKCS11Exception e) {
            out.println ( "PKCS#11 error: " + e );
        }
    }
}
