/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

import java.util.*;
import java.io.*;
import java.nio.*;
import java.nio.charset.*;
import java.nio.file.*;
import java.net.*;
import java.security.*;
import java.security.cert.*;
import javax.security.auth.x500.*;

import iaik.pkcs.pkcs11.wrapper.*;

/**
 *
 * @author André Zúquete
 */
public class ccCertValidate {

    // static String altCertPath = null;	// Alternative path to load certificates
    private static String keyStorePath = "CC_KS";	// Default name, may be superseeded by command args
    private static char[] keyStorePwd = "password".toCharArray();	// Default password, may be superseeded by command args

    private static long getTokenCertificate ( PKCS11 module, long sessHandle, String label )
            throws PKCS11Exception
    {
        long [] certificates;
        CK_ATTRIBUTE [] attrs = new CK_ATTRIBUTE[1];
        
        // Prepare only 1 search attributes: LABEL (the last function argument)
        attrs[0] = new CK_ATTRIBUTE();
        attrs[0].type = PKCS11Constants.CKA_LABEL;
        attrs[0].pValue = label.toCharArray();
        
        // Find objects with those attributes (should be only 1, in our case)
        module.C_FindObjectsInit( sessHandle, attrs );
        certificates = module.C_FindObjects( sessHandle,  1 );
        module.C_FindObjectsFinal( sessHandle );
        
        System.out.println( "======================\nFound " + certificates.length + " certificate objects with label \"" + label + "\"" );
        return certificates[0];
    }

    private static X509Certificate getCertificate ( PKCS11 module, long token, String certLabel )
    {
        long sessHandle; // session handle
        long certHandle; // certificate handle
        CK_ATTRIBUTE [] attrs = new CK_ATTRIBUTE[1];
	CertificateFactory cf;
	X509Certificate cert;
	String isoName;

	try {

        // Open serial, read-only PKCS#11 session to manipulate token objects
        sessHandle = module.C_OpenSession( token, PKCS11Constants.CKF_SERIAL_SESSION, null, null );
	
        // Get handle to public key certificate for with a label equal to certLabel
        certHandle = getTokenCertificate ( module, sessHandle, certLabel );

        // Get the contents (value) of the certificate (DER encoded byte array)
        attrs[0] = new CK_ATTRIBUTE();
        attrs[0].type = PKCS11Constants.CKA_VALUE;
        module.C_GetAttributeValue( sessHandle , certHandle, attrs );
        
        // Close the session, no more needed
        module.C_CloseSession( sessHandle );

        } catch (PKCS11Exception e) {
            System.out.println( "PKCS#11 error: " + e );
	}

	try {

	cf = CertificateFactory.getInstance( "X.509" );
	cert = (X509Certificate) cf.generateCertificate( new ByteArrayInputStream ( (byte []) attrs[0].pValue ) );
	//isoName = ((X500Principal) cert.getSubjectX500Principal()).getNam ( javax.security.auth.x500.X500Principal.RFC2253 );
	//System.out.println( "Certificate of \"" + isoName + "\"" );

	} catch (CertificateException e) {
	    return null;
	}

        return cert;
    }

    private static X509Certificate loadCertFromFile ( String fileName )
    {
        FileInputStream fis;
	CertificateFactory cf;
	X509Certificate cert;

	try {

	fis = new FileInputStream( fileName );
	cf = CertificateFactory.getInstance( "X.509" );
	cert = (X509Certificate) cf.generateCertificate( fis );

	} catch (Exception e) {
	    return null;
	}

	return cert;
    }

    private static ArrayList<X509Certificate> loadCertsAtPath ( String certsPath, boolean root )
    {
	X509Certificate cert;
	DirectoryStream<Path> dirStream;
        ArrayList<X509Certificate> result = new ArrayList<X509Certificate> ();

	try{

	dirStream = Files.newDirectoryStream( FileSystems.getDefault().getPath( certsPath ), "*.{ber,cer,der,crt,pem}" );

	} catch (Exception e) {
	    System.err.println( "Error when looking for certificate files in directory \"" + certsPath + "\": " + e );
	    return null;
	}
	
	for (Path path: dirStream) {
	    cert = loadCertFromFile ( path.toString() );
	    if (cert == null) continue;

	    if (cert.getSubjectDN().equals( cert.getIssuerDN() )) {
		if (root == true) {
		    result.add( cert );
		}
	    }
	    else {
		if (root == false) {
		    result.add( cert );
		}
	    }
	}

	return result;
    }

    private static ArrayList<X509Certificate> loadCertsAtKeystore ( String ksPath, char[] pwd, boolean root )
    {
	X509Certificate cert;
	FileInputStream f;
	KeyStore ks;
        ArrayList<X509Certificate> result = new ArrayList<X509Certificate> ();

	try {

	f = new FileInputStream( ksPath );
	ks = KeyStore.getInstance( KeyStore.getDefaultType() );
	ks.load( f, pwd );

	for (Enumeration<String> aliases = ks.aliases(); aliases.hasMoreElements();) {
	    cert = (X509Certificate) ks.getCertificate( aliases.nextElement() );

	    if (cert == null) continue;

	    if (cert.getSubjectDN().equals( cert.getIssuerDN() )) {
		if (root == true) {
		    result.add( cert );
		}
	    }
	    else {
		if (root == false) {
		    result.add( cert );
		}
	    }
	}

	} catch (Exception e) {
	    System.err.println( "Error when loading certificate from keystore \"" + ksPath + "\": " + e );
	    return null;
	}

	return result;
    }

    private static X509CRL getCRL ( String crlUrl, X509Certificate issuer )
    {
	X509CRL crl = null;
	CertificateFactory cf;
    	URL url;

	try {

    	url = new URL( crlUrl );
	InputStream crlStream = url.openStream ();
	cf = CertificateFactory.getInstance ( "X.509" );
	crl = (X509CRL) cf.generateCRL( crlStream );
	crlStream.close ();

	System.out.println( "Check CRL validity using the certificate of \n\t" + issuer.getSubjectDN() );
	crl.verify ( issuer.getPublicKey () );

	} catch (MalformedURLException e) {
	    System.out.println( "Invalid URL for getting a CRL:" + e );
	} catch (IOException e) {
	    System.out.println( "Cannot access URL for getting a CRL:" + e );
	} catch (CertificateException e) {
	    System.out.println( "Cannot create a certificate factory:" + e );
	} catch (CRLException e) {
	    System.out.println( "Cannot build a local CRL:" + e );
	} catch (NoSuchAlgorithmException e) {
	    System.out.println( "Invalid algorithm for validating the CRL:" + e );
	} catch (InvalidKeyException e) {
	    System.out.println( "Invalid key for validating the CRL:" + e );
	} catch (NoSuchProviderException e) {
	    System.out.println( "Invalid provider for validating the CRL:" + e );
	} catch (SignatureException e) {
	    System.out.println( "Invalid signature in CRL:" + e );
	}

        return crl;
    }

    private static boolean validateCRL ( List<? extends java.security.cert.Certificate> certs )
    {
	X509Certificate cert, issuer;
    	Set<String> extensions;
	byte [] extension;
	String crlUrl = null, deltaUrl = null;
	X509CRL crl;
	X509CRLEntry entry;

	// Recursively go until the last pair of the list

	if (certs.size () > 2) {
	    List<? extends java.security.cert.Certificate> reduced = certs.subList ( 1, certs.size () );
	    validateCRL( reduced );
	}

	cert = (X509Certificate) certs.get ( 0 );
	issuer = (X509Certificate) certs.get ( 1 );

	System.out.println( "-----------------------------------------------\nValidate certificate owned by \n\t" +
				cert.getSubjectDN() +
				"\nusing CRL issued by issued by \n\t" +
				issuer.getSubjectDN() );

    	// Get non-critical extensions

	extensions = cert.getNonCriticalExtensionOIDs ();
	for (String oid : extensions) {
	     if (oid.equals ( "2.5.29.31" )) {
	         System.out.println( "CRL Distribution Points:" );
		 extension = cert.getExtensionValue ( oid );
		 crlUrl = (new String ( extension )).substring ( 12 );
	         System.out.println( "\t" + crlUrl );
	     }
	     else if (oid.equals ( "2.5.29.46" )) {
	         System.out.println( "FreshestCRL:" );
		 extension = cert.getExtensionValue ( oid );
		 deltaUrl = (new String ( extension )).substring ( 12 );
	         System.out.println( "\t" + deltaUrl );
	     }
	}

	// Check CRL and Delta CRL

	if (crlUrl != null) {
	    crl = getCRL( crlUrl, issuer );
	    if (crl == null)
		return false;

	    entry = crl.getRevokedCertificate ( cert );
	    if (entry != null) {
		CRLReason reason = entry.getRevocationReason ();
		String reasonMsg = (reason == null) ? "no reason specified" : reason.toString();

		System.out.println( "**********" );
		System.out.println( "CERTIFICATE REVOKED: " + reasonMsg + "\n" + cert.getSubjectX500Principal() ); 
		System.out.println( "**********" );
	    }


	    if (deltaUrl != null) {
		crl = getCRL( deltaUrl, issuer );
		if (crl == null)
		    return false;

		entry = crl.getRevokedCertificate ( cert );
		if (entry != null) {
		    System.out.println( "Certificate " + cert.getSubjectX500Principal () +
					" revoked: " + entry.getRevocationReason () );
	    	}
	    }
	}

        return true;
    }

    private static void validateCertificate ( PKCS11 module, long token, String certLabel, String issuerLabel )
    {
	Set<String> extensions;
	byte [] extension;
	X509Certificate cert, issuer;
	CertificateFactory cf = null;
	ArrayList<X509Certificate> rootCerts;
	ArrayList<X509Certificate> otherCerts;
	ArrayList<X509Certificate> targetCerts;
	CertPath cp = null;
	CertPathValidator cpv = null;

        cert = getCertificate ( module, token, certLabel );
	issuer = getCertificate ( module, token, issuerLabel );
	
	// Check validity

	try {
	    cert.checkValidity ();
	} catch (CertificateExpiredException e) {
	    System.out.println( "Certificate has already expired (at " + cert.getNotAfter () + ")" );
	} catch (CertificateNotYetValidException e) {
	    System.out.println( "Certificate has not yet started (only at " + cert.getNotBefore () + ")" );
	}

	// Load certificates for building cetification chains

	// rootCerts = loadCertsAtPath ( "eidstore/certs", true );
	// otherCerts = loadCertsAtPath ( "eidstore/certs", false );

	rootCerts = loadCertsAtKeystore( keyStorePath, keyStorePwd, true );
	otherCerts = loadCertsAtKeystore( keyStorePath, keyStorePwd, false );

	/*
	if (altCertPath != null) {
	     rootCerts.addAll ( loadCertsAtPath ( altCertPath, true ) );
	     otherCerts.addAll ( loadCertsAtPath ( altCertPath, false ) );
	}
	*/

	if (issuer.getSubjectDN().equals ( issuer.getIssuerDN() )) {
	    rootCerts.add ( 0, issuer );
	}
	else {
	    otherCerts.add ( 0, issuer );
	}

	System.out.println( "Loaded " + rootCerts.size() +
				" root certificates and " +
				otherCerts.size() +
				" intermediate certificates" );

	// Select the relevant certificates

	targetCerts = new ArrayList<X509Certificate> ();
	targetCerts.add ( 0, cert );

	boolean match = true;
	int index = 0;

        while (match == true) {
	    match = false;
	    for (X509Certificate c: otherCerts) {
	        if (targetCerts.get ( index ).getIssuerDN().equals ( c.getSubjectDN() )) {
		    System.out.println( c.getSubjectDN() );
		    System.out.println( "\t" + c.getIssuerDN() );
		    targetCerts.add ( index + 1, c );
		    index++;
		    match = true;
		    break;
		}
	    }
	}

	// Build the certification chain for the target certificate (cert)

	try {

	cp = CertificateFactory.getInstance ( "X.509" ).generateCertPath ( targetCerts );
	
	// System.out.println( "Certificate validation path:" + cp );

	} catch (CertificateException e) {
	    System.out.println( "Problem while building certificate path:" + e );
	}

	System.out.println( "Check this chain of certificates" );
	for (java.security.cert.Certificate x: cp.getCertificates ()) {
	    System.out.println( "\tCertificate of \"" + ((X509Certificate) x).getSubjectDN() + "\"" );
	    System.out.println( "\t\tissued by \"" + ((X509Certificate) x).getIssuerDN() + "\"" );
	}

	// Validate the certification chain (i.e. its signatures) obtained against a set of roots

	try {

	cpv = CertPathValidator.getInstance ( "PKIX" );
	HashSet<TrustAnchor> trustAnchors = new HashSet<TrustAnchor> ();
	for (X509Certificate c: rootCerts) {
	    trustAnchors.add ( new TrustAnchor ( c , null ) ); 
	}
	PKIXParameters params = new PKIXParameters ( trustAnchors );
	params.setRevocationEnabled ( false );

	cpv.validate ( cp, params );

	} catch (Exception e) {
	    try {

	    cert.checkValidity();
	    System.out.println( "Certificate path validation error:" + e );
		
            } catch (CertificateExpiredException e1) {
		Calendar date = GregorianCalendar.getInstance();
		date.setTime( cert.getNotAfter() );
		System.out.println( "Certificate is not valid anymore (expired at " +
					date.get(Calendar.DAY_OF_MONTH) + "/" +
					(date.get(Calendar.MONTH) + 1) + "/" +
					date.get(Calendar.YEAR) + ")" );
            } catch (CertificateNotYetValidException e2) {
		Calendar date = GregorianCalendar.getInstance();
		date.setTime( cert.getNotBefore() );
		System.out.println( "Certificate was not yet (!) issued (issued at " +
					date.get(Calendar.DAY_OF_MONTH) + "/" +
					(date.get(Calendar.MONTH) + 1) + "/" +
					date.get(Calendar.YEAR) + ") or the local date is wrong" );
	    }

	    return;
	}

	// Validate each certificate of the certification chain against the CRL of its issuer

        validateCRL( cp.getCertificates () );
	
	// TODO: validate last certificate against trusted root
    }
    
    /**
     * @param args the command line arguments
     */

    public static void main(String[] args)
    {
        long [] tokens;

        if (args.length >= 1) {
	    // altCertPath = args[0];
	    keyStorePath = args[0];
	}
        if (args.length >= 2) {
	    keyStorePwd = args[1].toCharArray();
	}
        
        try {
        
        // Select the correct PKCS#11 module for dealing with Citizen Card tokens
        PKCS11 module = PKCS11Connector.connectToPKCS11Module( System.getProperty( "os.name" ).contains( "Windows" ) ?
								"pteidpkcs11" : "libpteidpkcs11.so" );
      
        // Initialize module
        module.C_Initialize(null);
        
        // Find all Citizen Card tokens
        tokens = module.C_GetSlotList(true);
        
        if (tokens.length == 0) {
            System.out.println( "No card inserted" );
            return;
        }
        
        // Perform a challenge-response operation using the authentication key pair
        for (int i = 0; i < tokens.length; i++) {
            CK_TOKEN_INFO tokenInfo = module.C_GetTokenInfo( tokens[i] );
            System.out.println( "Token label = \"" + new String ( tokenInfo.label ) + "\"" );
            if (String.valueOf( tokenInfo.label ).startsWith( "CARTAO DE CIDADAO" )) {
                System.out.println( "Found CC, model " + new String ( tokenInfo.model ) );
                
                validateCertificate ( module, tokens[i], "CITIZEN AUTHENTICATION CERTIFICATE", "AUTHENTICATION SUB CA" );
                validateCertificate ( module, tokens[i], "CITIZEN SIGNATURE CERTIFICATE", "SIGNATURE SUB CA" );
            }
        
        }
        module.C_Finalize( null );
        
        } catch (IOException e) {
            System.out.println( "I/O error: " + e );
        }
        catch (PKCS11Exception e) {
            System.out.println( "PKCS#11 error: " + e );
        }
    }
}
