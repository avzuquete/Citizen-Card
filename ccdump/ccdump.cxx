/*
* This program dumps most of the contents from a Citizen Card to the stdout
*
* It also creates a file pic.jp2 with the JPEG 2000 contents of the owner
* picture and a pic.cbeff file with the picture's CBEFF buffer.
*/

#include <stdio.h>
#include <wchar.h>	// wide chars (unicode and other)
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <signal.h>

#include "eidlib.h"	// CC PTEID includes
#include "eidlibException.h"	// CC PTEID exceptions
#include "pkcs11.h"	// Cryptoki includes
#include "x509.h"	// Openssl includes

#include "ccerrors.h"

using namespace eIDMW;

#ifndef PTEID_EXIT_LEAVE_CARD
#define PTEID_EXIT_LEAVE_CARD 0
#endif

#ifndef PTEID_EXIT_UNPOWER
#define PTEID_EXIT_UNPOWER 2
#endif

#define USAGE_STR "[-vs]\n\t-v: verbose\n\t-s: perform SOD checking"
#define VERBOSE(msg) if (verbose) { printf ( "%s\n", msg );} else {}
#define VERBOSE2(msg1,msg2) if (verbose) { printf ( "%s %s\n", msg1, msg2 );} else {}

static int verbose = 0;
static int SODchecking = 0;

void
PTEID_error ( const char * msg, long code )
{
    fprintf ( stderr, "Error code in \"%s\": %s\n", msg,
		PTEID_errorString ( code ) );
    exit ( 1 );
}

void
PKCS11_error ( const char * msg, long code )
{
    fprintf ( stderr, "Error code in \"%s\": %ld (%lxH)\n", msg, code, code );
    // exit ( 1 );
}

/*
 * Dump PTEID identity information
 */

void
dumpId ( PTEID_EId & eid )
{
    printf ( "Version: %s\n", eid.getDocumentVersion () );
    printf ( "Document type: %s\n", eid.getDocumentType () );
    printf ( "Country: %s\n", eid.getCountry () );
    printf ( "Given name: %s\n", eid.getGivenName () );
    printf ( "Surname: %s\n", eid.getSurname () );
    printf ( "Gender: %s\n", eid.getGender () );
    printf ( "Birth date: %s\n", eid.getDateOfBirth () );
    printf ( "Nationality: %s\n", eid.getNationality () );
    printf ( "Document PAN: %s\n", eid.getDocumentPAN() );
    printf ( "Initial validity date: %s\n", eid.getValidityBeginDate () );
    printf ( "Final validity date: %s\n", eid.getValidityEndDate () );
    printf ( "Height: %s\n", eid.getHeight () );
    printf ( "Card number: %s\n", eid.getDocumentNumber () );
    printf ( "BI (civilian number): %s\n", eid.getCivilianIdNumber () );
    printf ( "NIF (tax number): %s\n", eid.getTaxNo () );
    printf ( "SS (social security number): %s\n", eid.getSocialSecurityNumber () );
    printf ( "SNS (health system number): %s\n", eid.getHealthNumber () );
    printf ( "Issuing Entity: %s\n", eid.getIssuingEntity () );
    printf ( "Local of request: %s\n", eid.getLocalofRequest () );
    printf ( "Father given name: %s\n", eid.getGivenNameFather () );
    printf ( "Father surname: %s\n", eid.getSurnameFather () );
    printf ( "Mother given name: %s\n", eid.getGivenNameMother () );
    printf ( "Mother surname: %s\n", eid.getSurnameMother () );
    printf ( "Card validation: %s\n", eid.getValidation () );
    printf ( "Accidental indications: %s\n", eid.getAccidentalIndications () );
    printf ( "MRZ1: %s\n", eid.getMRZ1() );
    printf ( "MRZ2: %s\n", eid.getMRZ2() );
    printf ( "MRZ3: %s\n", eid.getMRZ3() );
}

/*
* Dump the photo stored in the card
*/

void
dumpPhoto ( PTEID_EId & eid )
{
    PTEID_Photo& photoObj = eid.getPhotoObj();
    PTEID_ByteArray& praw = photoObj.getphotoRAW();     // JPEG2000
    PTEID_ByteArray& ppng = photoObj.getphoto();        // PNG

    praw.writeToFile( "photo.jp2" );
    ppng.writeToFile( "photo.png" );
    printf ( "Photo stored in photo.jp2 & photo.png\n" );
}

/*
* Dump certificate information
*/

void
dumpCertificate ( PTEID_Certificate & cert )
{
    printf ( "--------------- Label = %s -------------------\n", cert.getLabel () );
    printf ( "Root? %s\n", cert.isRoot () ? "yes" : "no" );
    printf ( "In Card? %s\n", cert.isFromCard () ? "yes" : "no" );
    printf ( "Test? %s\n", cert.isTest () ? "yes" : "no" );
    printf ( "X.509 fields:\n" );
    // printf ( "\t\tVersion: %ld\n", ASN1_INTEGER_get ( cert->cert_info->version ) );
    printf ( "\tSerial number: %s\n", cert.getSerialNumber () );
    printf ( "\tSubject: %s\n", cert.getOwnerName () );
    printf ( "\tIssuer: %s\n", cert.getIssuerName () );
    printf ( "\tValid from %s to %s\n", cert.getValidityBegin (), cert.getValidityEnd () );
}

/*
 * Dump information about all certificates found in the CC using the PTEID library
 */

unsigned char byteFromPattern ( char * p, size_t * offset )
{
    unsigned int val;

    *offset += 3;
    sscanf ( p + 2, "%x", &val );
    return (unsigned char) val;
}

char * toAscii ( char * from )
{
    static unsigned char * to = 0;
    size_t i, j;
    size_t len = strlen ( from );

    if (to != 0) {
        free ( to );
    }
    to = (unsigned char *) malloc ( 2 * len * sizeof(char) + 1 );

    for (i = 0, j = 0; i < len; i++, j++) {
        if (from[i] == '\\') {
	    to[j] = byteFromPattern ( from + i, &i );
	}
	else {
	    to[j] = (unsigned char) from[i];
	}
    }

    to[j] = 0;

    return (char *) to;
}

/*
 * Dump information about the PTEID PKCS #11 library
 */

void
dumpPKCS11Info ( CK_INFO * info )
{
    char txt[33] = {0};

    printf ( "\nPKCS #11:\n" );
    printf ( "\tVersion: %u.%u\n", info->cryptokiVersion.major,
				    info->cryptokiVersion.minor );
    memcpy ( txt, info->manufacturerID, 32 );
    printf ( "\tManufacturer ID: %s\n", txt );
    printf ( "\tFlags: %lx\n", info->flags );
    memcpy ( txt, info->libraryDescription, 32 );
    printf ( "\tLibrary description: %s\n", txt );
    printf ( "\tLibrary version: %u.%u\n", info->libraryVersion.major,
				    info->libraryVersion.minor );
}

/*
 * Dump information about a PKCS#11 slot
 */

void
dumpSlotInfo ( int index, CK_SLOT_INFO * info )
{
    char txt[65] = {0};

    printf ( "\nSlot index %d:\n", index );
    memcpy ( txt, info->slotDescription, 64 );
    printf ( "\tDescription: %s\n", txt );
    memcpy ( txt, info->manufacturerID, 64 );
    printf ( "\tManufacturer ID: %s\n", txt );
    printf ( "\tFlags: %lx\n", info->flags );
}

/*
 * Dump information about a PKCS#11 token
 */

void
dumpTokenInfo ( CK_TOKEN_INFO * info )
{
    char txt[33] = {0};

    printf ( "\nToken:\n" );
    memcpy ( txt, info->label, 32 );
    printf ( "\tLabel: %s\n", txt );
    memcpy ( txt, info->manufacturerID, 32 );
    printf ( "\tManufacturer ID: %s\n", txt );
    txt[16] = 0;
    memcpy ( txt, info->model, 16 );
    printf ( "\tModel: %s\n", txt );
    memcpy ( txt, info->serialNumber, 16 );
    printf ( "\tSerial number: %s\n", txt );
    printf ( "\tFlags: %lx\n", info->flags );
    if (info->flags & CKF_RNG)
	printf ( "\t\tHas random generator (*)\n" );
    else 
	printf ( "\t\tHas not random generator\n" );
    if (info->flags & CKF_WRITE_PROTECTED)
	printf ( "\t\tIs write protected (*)\n" );
    else 
	printf ( "\t\tIs not write protected\n" );
    if (info->flags & CKF_LOGIN_REQUIRED)
	printf ( "\t\tUser must login (*)\n" );
    else 
	printf ( "\t\tUser must not login\n" );
    if (info->flags & CKF_USER_PIN_INITIALIZED)
	printf ( "\t\tNormal user's PIN is set (*)\n" );
    else 
	printf ( "\t\tNormal user's PIN is not set\n" );
    if (info->flags & CKF_RESTORE_KEY_NOT_NEEDED)
	printf ( "\t\tRestore key not needed (*)\n" );
    else 
	printf ( "\t\tRestore key needed\n" );
    if (info->flags & CKF_CLOCK_ON_TOKEN)
	printf ( "\t\tClock on token (*)\n" );
    else 
	printf ( "\t\tNo clock on token\n" );
    if (info->flags & CKF_PROTECTED_AUTHENTICATION_PATH)
	printf ( "\t\tProtected authentication path (*)\n" );
    else 
	printf ( "\t\tNo protected authentication path\n" );
    if (info->flags & CKF_DUAL_CRYPTO_OPERATIONS)
	printf ( "\t\tDual crypto operations (*)\n" );
    else 
	printf ( "\t\tNo dual crypto operations\n" );
    if (info->flags & CKF_TOKEN_INITIALIZED)
	printf ( "\t\tToken initialized (*)\n" );
    else 
	printf ( "\t\tToken not initialized\n" );
    if (info->flags & CKF_SECONDARY_AUTHENTICATION)
	printf ( "\t\tSecondary authentication (*)\n" );
    else 
	printf ( "\t\tNo secondary authentication\n" );
    if (info->flags & CKF_USER_PIN_COUNT_LOW)
	printf ( "\t\tUser pin count low (*)\n" );
    else 
	printf ( "\t\tUser pin count not low\n" );
    if (info->flags & CKF_USER_PIN_FINAL_TRY)
	printf ( "\t\tUser pin final try (*)\n" );
    else 
	printf ( "\t\tUser pin not yet in final try\n" );
    if (info->flags & CKF_USER_PIN_LOCKED)
	printf ( "\t\tUser pin locked (*)\n" );
    else 
	printf ( "\t\tUser pin unlocked\n" );
    printf ( "\tMax session count: %lu\n", info->ulMaxSessionCount );
    printf ( "\tSession count: %lu\n", info->ulSessionCount );
    printf ( "\tMax RW session count: %lu\n", info->ulMaxRwSessionCount );
    printf ( "\tRW session count: %lu\n", info->ulRwSessionCount );
    printf ( "\tMax PIN len: %lu\n", info->ulMaxPinLen );
    printf ( "\tMin PIN len: %lu\n", info->ulMinPinLen );
    printf ( "\tTotal public memory: %lu\n", info->ulTotalPublicMemory );
    printf ( "\tFree public memory: %lu\n", info->ulFreePublicMemory );
    printf ( "\tTotal private memory: %lu\n", info->ulTotalPrivateMemory );
    printf ( "\tFree private memory: %lu\n", info->ulFreePrivateMemory );
    printf ( "\tHardware version: %u.%u\n", info->hardwareVersion.major,
				    info->hardwareVersion.minor );
    printf ( "\tFirmware version: %u.%u\n", info->firmwareVersion.major,
				    info->firmwareVersion.minor );
    memcpy ( txt, info->utcTime, 16 );
    printf ( "\tUTC time: %s\n", txt );
}

/*
 * List PKCS#11 objects of a given class (e.g. CKO_PUBLIC_KEY, CKO_CERTIFICATE, etc.)
 * inside a token at a given slot
 *
 * name is used just for printing information
 */

static void
getAttribute( CK_SESSION_HANDLE sessH, CK_OBJECT_HANDLE objH, CK_ATTRIBUTE * attrs )
{
    CK_ULONG ret;

    attrs->pValue = 0;
    attrs->ulValueLen = 0;
    VERBOSE("C_GetAttributeValue (get size)");
    ret = C_GetAttributeValue ( sessH, objH, attrs, 1 );
    if (ret != CKR_OK) {
        PKCS11_error ( "C_GetAttributeValue (get size)", (long) ret );
        return;
    }
    attrs->pValue = malloc( attrs->ulValueLen );
        
    VERBOSE("C_GetAttributeValue");
    ret = C_GetAttributeValue ( sessH, objH, attrs, 1 );
    if (ret != CKR_OK) {
        PKCS11_error ( "C_GetAttributeValue", (long) ret );
        return;
    }
}

void
listObjects ( CK_SLOT_ID slot, const char * name, CK_ULONG objClass )
{
    CK_ULONG ret;
    CK_SESSION_HANDLE sessH; 
    CK_ATTRIBUTE attrs;
    CK_ULONG objCount;
    CK_OBJECT_HANDLE objH;
    CK_ULONG objValue;

    printf ( "List %s objects of token at slot %lu\n", name, slot );

    VERBOSE("C_OpenSession");
    ret = C_OpenSession ( slot, CKF_SERIAL_SESSION, 0, 0, &sessH );
    if (ret != CKR_OK) {
	PKCS11_error ( "C_OpenSession", (long) ret );
        return;
    }

    objValue = objClass;
    attrs.type = CKA_CLASS;
    attrs.pValue = &objValue;
    attrs.ulValueLen = (CK_ULONG) sizeof(objValue);

    VERBOSE("C_FindObjectsInit");
    ret = C_FindObjectsInit ( sessH, &attrs, 1 );
    if (ret != CKR_OK) {
        if (ret != CKR_ATTRIBUTE_VALUE_INVALID) {
            PKCS11_error ( "C_FindObjectsInit", (long) ret );
        }
        goto session_end;
    }

    for (;;) {
	VERBOSE("C_FindObjects");
	ret = C_FindObjects ( sessH, &objH, 1, &objCount );
	if (ret != CKR_OK) {
	    PKCS11_error ( "C_FindObjects", (long) ret );
            goto session_end;
	}
	if (objCount == 0) break;

	printf ( "\tFound %s key:\n", name );

        /* Read ID */

	attrs.type = CKA_ID;
        getAttribute( sessH, objH, &attrs );
	printf ( "\t\tObject ID: " ); 
        for (int i = (int) attrs.ulValueLen - 1; i >= 0; i--) {
            printf( "%2.2x ", ((unsigned char*)attrs.pValue)[i]);
        }
        free( attrs.pValue );
        printf( "\n" );

        /* Read LABEL */

	attrs.type = CKA_LABEL;
        getAttribute( sessH, objH, &attrs );
	printf ( "\t\tObject label: " );
        for (int i = 0; i < (int) attrs.ulValueLen; i++) {
            printf( "%c", ((char*)attrs.pValue)[i]);
        }
        free( attrs.pValue );
        printf( "\n" );
    }

    VERBOSE("C_FindObjectsFinal");
    C_FindObjectsFinal ( sessH );

session_end:

    ret = C_CloseSession ( sessH );
    if (ret != CKR_OK) {
	PKCS11_error ( "C_CloseSession", (long) ret );
        return;
    }
}

#define CODE_NAME(code) { code, #code }

static struct {
    CK_MECHANISM_TYPE code;
    const char * name ;
} mechanismList [] = {
    CODE_NAME(CKM_RSA_PKCS_KEY_PAIR_GEN),
    CODE_NAME(CKM_RSA_PKCS),
    CODE_NAME(CKM_RSA_9796),
    CODE_NAME(CKM_RSA_X_509),
    CODE_NAME(CKM_MD2_RSA_PKCS),
    CODE_NAME(CKM_MD2_RSA_PKCS),
    CODE_NAME(CKM_MD5_RSA_PKCS),
    CODE_NAME(CKM_SHA1_RSA_PKCS),
    CODE_NAME(CKM_RIPEMD128_RSA_PKCS),
    CODE_NAME(CKM_RIPEMD160_RSA_PKCS),
    CODE_NAME(CKM_RSA_PKCS_OAEP),
    CODE_NAME(CKM_RSA_X9_31_KEY_PAIR_GEN),
    CODE_NAME(CKM_RSA_X9_31),
    CODE_NAME(CKM_SHA1_RSA_X9_31),
    CODE_NAME(CKM_RSA_PKCS_PSS),
    CODE_NAME(CKM_SHA1_RSA_PKCS_PSS),
    CODE_NAME(CKM_DSA_KEY_PAIR_GEN),
    CODE_NAME(CKM_DSA),
    CODE_NAME(CKM_DSA_SHA1),
    CODE_NAME(CKM_DH_PKCS_KEY_PAIR_GEN),
    CODE_NAME(CKM_DH_PKCS_DERIVE),
    CODE_NAME(CKM_X9_42_DH_KEY_PAIR_GEN),
    CODE_NAME(CKM_X9_42_DH_DERIVE),
    CODE_NAME(CKM_X9_42_DH_HYBRID_DERIVE),
    CODE_NAME(CKM_X9_42_MQV_DERIVE),
    CODE_NAME(CKM_SHA224_RSA_PKCS),
    CODE_NAME(CKM_SHA256_RSA_PKCS),
    CODE_NAME(CKM_SHA384_RSA_PKCS),
    CODE_NAME(CKM_SHA512_RSA_PKCS),
    CODE_NAME(CKM_SHA224_RSA_PKCS_PSS),
    CODE_NAME(CKM_SHA256_RSA_PKCS_PSS),
    CODE_NAME(CKM_SHA384_RSA_PKCS_PSS),
    CODE_NAME(CKM_SHA512_RSA_PKCS_PSS),
    CODE_NAME(CKM_RC2_KEY_GEN),
    CODE_NAME(CKM_RC2_ECB),
    CODE_NAME(CKM_RC2_CBC),
    CODE_NAME(CKM_RC2_MAC),
    CODE_NAME(CKM_RC2_MAC_GENERAL),
    CODE_NAME(CKM_RC2_MAC_GENERAL),
    CODE_NAME(CKM_RC2_CBC_PAD),
    CODE_NAME(CKM_RC4_KEY_GEN),
    CODE_NAME(CKM_RC4),
    CODE_NAME(CKM_DES_KEY_GEN),
    CODE_NAME(CKM_DES_ECB),
    CODE_NAME(CKM_DES_CBC),
    CODE_NAME(CKM_DES_MAC),
    CODE_NAME(CKM_DES_MAC_GENERAL),
    CODE_NAME(CKM_DES_MAC_GENERAL),
    CODE_NAME(CKM_DES_CBC_PAD),
    CODE_NAME(CKM_DES2_KEY_GEN),
    CODE_NAME(CKM_DES3_KEY_GEN),
    CODE_NAME(CKM_DES3_ECB),
    CODE_NAME(CKM_DES3_CBC),
    CODE_NAME(CKM_DES3_MAC),
    CODE_NAME(CKM_DES3_MAC_GENERAL),
    CODE_NAME(CKM_DES3_MAC_GENERAL),
    CODE_NAME(CKM_DES3_CBC_PAD),
    CODE_NAME(CKM_CDMF_KEY_GEN),
    CODE_NAME(CKM_CDMF_ECB),
    CODE_NAME(CKM_CDMF_CBC),
    CODE_NAME(CKM_CDMF_MAC),
    CODE_NAME(CKM_CDMF_MAC_GENERAL),
    CODE_NAME(CKM_CDMF_CBC_PAD),
    CODE_NAME(CKM_DES_OFB64),
    CODE_NAME(CKM_DES_CFB64),
    CODE_NAME(CKM_DES_CFB8),
    CODE_NAME(CKM_MD2),
    CODE_NAME(CKM_MD2_HMAC),
    CODE_NAME(CKM_MD2_HMAC),
    CODE_NAME(CKM_MD2_HMAC_GENERAL),
    CODE_NAME(CKM_MD5),
    CODE_NAME(CKM_MD5_HMAC),
    CODE_NAME(CKM_MD5_HMAC),
    CODE_NAME(CKM_MD5_HMAC_GENERAL),
    CODE_NAME(CKM_SHA_1),
    CODE_NAME(CKM_SHA_1_HMAC),
    CODE_NAME(CKM_SHA_1_HMAC),
    CODE_NAME(CKM_SHA_1_HMAC_GENERAL),
    CODE_NAME(CKM_RIPEMD128),
    CODE_NAME(CKM_RIPEMD128_HMAC),
    CODE_NAME(CKM_RIPEMD128_HMAC_GENERAL),
    CODE_NAME(CKM_RIPEMD160),
    CODE_NAME(CKM_RIPEMD160_HMAC),
    CODE_NAME(CKM_RIPEMD160_HMAC_GENERAL),
    CODE_NAME(CKM_SHA256),
    CODE_NAME(CKM_SHA256_HMAC),
    CODE_NAME(CKM_SHA256_HMAC_GENERAL),
    CODE_NAME(CKM_SHA224),
    CODE_NAME(CKM_SHA224_HMAC),
    CODE_NAME(CKM_SHA224_HMAC_GENERAL),
    CODE_NAME(CKM_SHA384),
    CODE_NAME(CKM_SHA384_HMAC),
    CODE_NAME(CKM_SHA384_HMAC_GENERAL),
    CODE_NAME(CKM_SHA512),
    CODE_NAME(CKM_SHA512_HMAC),
    CODE_NAME(CKM_SHA512_HMAC_GENERAL),
    CODE_NAME(CKM_SHA512_224),
    CODE_NAME(CKM_SHA512_224_HMAC),
    CODE_NAME(CKM_SHA512_224_HMAC_GENERAL),
    CODE_NAME(CKM_SHA512_256),
    CODE_NAME(CKM_SHA512_256_HMAC),
    CODE_NAME(CKM_SHA512_256_HMAC_GENERAL),
    CODE_NAME(CKM_CAST_KEY_GEN),
    CODE_NAME(CKM_CAST_ECB),
    CODE_NAME(CKM_CAST_CBC),
    CODE_NAME(CKM_CAST_MAC),
    CODE_NAME(CKM_CAST_MAC_GENERAL),
    CODE_NAME(CKM_CAST_CBC_PAD),
    CODE_NAME(CKM_CAST3_KEY_GEN),
    CODE_NAME(CKM_CAST3_ECB),
    CODE_NAME(CKM_CAST3_CBC),
    CODE_NAME(CKM_CAST3_MAC),
    CODE_NAME(CKM_CAST3_MAC_GENERAL),
    CODE_NAME(CKM_CAST3_CBC_PAD),
    CODE_NAME(CKM_CAST5_KEY_GEN),
    CODE_NAME(CKM_CAST128_KEY_GEN),
    CODE_NAME(CKM_CAST5_ECB),
    CODE_NAME(CKM_CAST128_ECB),
    CODE_NAME(CKM_CAST5_CBC),
    CODE_NAME(CKM_CAST128_CBC),
    CODE_NAME(CKM_CAST5_MAC),
    CODE_NAME(CKM_CAST128_MAC),
    CODE_NAME(CKM_CAST5_MAC_GENERAL),
    CODE_NAME(CKM_CAST128_MAC_GENERAL),
    CODE_NAME(CKM_CAST5_CBC_PAD),
    CODE_NAME(CKM_CAST128_CBC_PAD),
    CODE_NAME(CKM_RC5_KEY_GEN),
    CODE_NAME(CKM_RC5_ECB),
    CODE_NAME(CKM_RC5_CBC),
    CODE_NAME(CKM_RC5_MAC),
    CODE_NAME(CKM_RC5_MAC_GENERAL),
    CODE_NAME(CKM_RC5_CBC_PAD),
    CODE_NAME(CKM_IDEA_KEY_GEN),
    CODE_NAME(CKM_IDEA_ECB),
    CODE_NAME(CKM_IDEA_CBC),
    CODE_NAME(CKM_IDEA_MAC),
    CODE_NAME(CKM_IDEA_MAC_GENERAL),
    CODE_NAME(CKM_IDEA_CBC_PAD),
    CODE_NAME(CKM_GENERIC_SECRET_KEY_GEN),
    CODE_NAME(CKM_CONCATENATE_BASE_AND_KEY),
    CODE_NAME(CKM_CONCATENATE_BASE_AND_DATA),
    CODE_NAME(CKM_CONCATENATE_DATA_AND_BASE),
    CODE_NAME(CKM_XOR_BASE_AND_DATA),
    CODE_NAME(CKM_EXTRACT_KEY_FROM_KEY),
    CODE_NAME(CKM_SSL3_PRE_MASTER_KEY_GEN),
    CODE_NAME(CKM_SSL3_MASTER_KEY_DERIVE),
    CODE_NAME(CKM_SSL3_KEY_AND_MAC_DERIVE),
    CODE_NAME(CKM_SSL3_MASTER_KEY_DERIVE_DH),
    CODE_NAME(CKM_TLS_PRE_MASTER_KEY_GEN),
    CODE_NAME(CKM_TLS_MASTER_KEY_DERIVE),
    CODE_NAME(CKM_TLS_KEY_AND_MAC_DERIVE),
    CODE_NAME(CKM_TLS_MASTER_KEY_DERIVE_DH),
    CODE_NAME(CKM_SSL3_MD5_MAC),
    CODE_NAME(CKM_SSL3_SHA1_MAC),
    CODE_NAME(CKM_MD5_KEY_DERIVATION),
    CODE_NAME(CKM_MD2_KEY_DERIVATION),
    CODE_NAME(CKM_SHA1_KEY_DERIVATION),
    CODE_NAME(CKM_SHA224_KEY_DERIVATION),
    CODE_NAME(CKM_SHA256_KEY_DERIVATION),
    CODE_NAME(CKM_SHA384_KEY_DERIVATION),
    CODE_NAME(CKM_SHA512_KEY_DERIVATION),
    CODE_NAME(CKM_PBE_MD2_DES_CBC),
    CODE_NAME(CKM_PBE_MD5_DES_CBC),
    CODE_NAME(CKM_PBE_MD5_CAST_CBC),
    CODE_NAME(CKM_PBE_MD5_CAST3_CBC),
    CODE_NAME(CKM_PBE_MD5_CAST5_CBC),
    CODE_NAME(CKM_PBE_MD5_CAST128_CBC),
    CODE_NAME(CKM_PBE_SHA1_CAST5_CBC),
    CODE_NAME(CKM_PBE_SHA1_CAST128_CBC),
    CODE_NAME(CKM_PBE_SHA1_RC4_128),
    CODE_NAME(CKM_PBE_SHA1_RC4_40),
    CODE_NAME(CKM_PBE_SHA1_DES3_EDE_CBC),
    CODE_NAME(CKM_PBE_SHA1_DES2_EDE_CBC),
    CODE_NAME(CKM_PBE_SHA1_RC2_128_CBC),
    CODE_NAME(CKM_PBE_SHA1_RC2_40_CBC),
    CODE_NAME(CKM_PKCS5_PBKD2),
    CODE_NAME(CKM_PKCS5_PBKD2),
    CODE_NAME(CKM_PBA_SHA1_WITH_SHA1_HMAC),
    CODE_NAME(CKM_KEY_WRAP_LYNKS),
    CODE_NAME(CKM_KEY_WRAP_SET_OAEP),
    CODE_NAME(CKM_SKIPJACK_KEY_GEN),
    CODE_NAME(CKM_SKIPJACK_ECB64),
    CODE_NAME(CKM_SKIPJACK_CBC64),
    CODE_NAME(CKM_SKIPJACK_OFB64),
    CODE_NAME(CKM_SKIPJACK_CFB64),
    CODE_NAME(CKM_SKIPJACK_CFB32),
    CODE_NAME(CKM_SKIPJACK_CFB16),
    CODE_NAME(CKM_SKIPJACK_CFB8),
    CODE_NAME(CKM_SKIPJACK_WRAP),
    CODE_NAME(CKM_SKIPJACK_PRIVATE_WRAP),
    CODE_NAME(CKM_SKIPJACK_RELAYX),
    CODE_NAME(CKM_KEA_KEY_PAIR_GEN),
    CODE_NAME(CKM_KEA_KEY_DERIVE),
    CODE_NAME(CKM_FORTEZZA_TIMESTAMP),
    CODE_NAME(CKM_BATON_KEY_GEN),
    CODE_NAME(CKM_BATON_ECB128),
    CODE_NAME(CKM_BATON_ECB96),
    CODE_NAME(CKM_BATON_CBC128),
    CODE_NAME(CKM_BATON_COUNTER),
    CODE_NAME(CKM_BATON_SHUFFLE),
    CODE_NAME(CKM_BATON_WRAP),
    CODE_NAME(CKM_ECDSA_KEY_PAIR_GEN),
    CODE_NAME(CKM_ECDSA_KEY_PAIR_GEN),
    CODE_NAME(CKM_EC_KEY_PAIR_GEN),
    CODE_NAME(CKM_ECDSA),
    CODE_NAME(CKM_ECDSA_SHA1),
    CODE_NAME(CKM_ECDSA_SHA224),
    CODE_NAME(CKM_ECDSA_SHA256),
    CODE_NAME(CKM_ECDSA_SHA384),
    CODE_NAME(CKM_ECDSA_SHA512),
    CODE_NAME(CKM_ECDH1_DERIVE),
    CODE_NAME(CKM_ECDH1_COFACTOR_DERIVE),
    CODE_NAME(CKM_ECMQV_DERIVE),
    CODE_NAME(CKM_JUNIPER_KEY_GEN),
    CODE_NAME(CKM_JUNIPER_ECB128),
    CODE_NAME(CKM_JUNIPER_CBC128),
    CODE_NAME(CKM_JUNIPER_COUNTER),
    CODE_NAME(CKM_JUNIPER_SHUFFLE),
    CODE_NAME(CKM_JUNIPER_WRAP),
    CODE_NAME(CKM_FASTHASH),
    CODE_NAME(CKM_AES_KEY_GEN),
    CODE_NAME(CKM_AES_ECB),
    CODE_NAME(CKM_AES_CBC),
    CODE_NAME(CKM_AES_MAC),
    CODE_NAME(CKM_AES_MAC_GENERAL),
    CODE_NAME(CKM_AES_CBC_PAD),
    CODE_NAME(CKM_AES_CTR),
    CODE_NAME(CKM_AES_GCM),
    CODE_NAME(CKM_DSA_PARAMETER_GEN),
    CODE_NAME(CKM_DH_PKCS_PARAMETER_GEN),
    CODE_NAME(CKM_X9_42_DH_PARAMETER_GEN),
    CODE_NAME(CKM_AES_OFB),
    CODE_NAME(CKM_AES_CFB64),
    CODE_NAME(CKM_AES_CFB8),
    CODE_NAME(CKM_AES_CFB128),
    CODE_NAME(CKM_VENDOR_DEFINED),
    { (unsigned long) 0, 0 }
};

static const char *
mechanismName( CK_MECHANISM_TYPE mechanism )
{
    for (int i = 0; mechanismList[i].name; i++) {
        if (mechanismList[i].code == mechanism) {
            return mechanismList[i].name ;
        }
    }

    return "???";
}

void
listMechanisms( CK_SLOT_ID slot )
{
    CK_ULONG ret;
    CK_MECHANISM_TYPE * list = 0; 
    CK_ULONG count;

    printf ( "List mechanisms of token at slot %lu, ", slot );

    VERBOSE("C_GetMechanismList (get size)");
    ret = C_GetMechanismList( slot, list, &count );
    if (ret != CKR_OK) {
	PKCS11_error ( "C_GetMechanismList (get size)", (long) ret );
    }

    printf ( "found %lu mechanisms:\n", count );
    list = (CK_MECHANISM_TYPE *) malloc( count * sizeof(CK_MECHANISM_TYPE) );

    VERBOSE("C_GetMechanismList");
    C_GetMechanismList( slot, list, &count );
    if (ret != CKR_OK) {
	PKCS11_error ( "C_GetMechanismList", (long) ret );
    }

    for (int i = 0; i < (int) count; i++) {
        printf ( "\t%s\n", mechanismName( list[i]) );
    }
}

/*
 * Dump information about PKCS#11 slots and tokens found
 */

void
dumpPKCS11SlotsTokens ()
{
    CK_RV ret;
    CK_ULONG i;
    CK_ULONG slots;
    CK_SLOT_ID * slotIds;
    CK_SLOT_INFO slotInfo;
    CK_TOKEN_INFO tokenInfo;

    slots = 0;
    VERBOSE("C_GetSlotList");
    ret = C_GetSlotList ( FALSE, 0, &slots );
    if (ret != CKR_OK) {
        PKCS11_error ( "C_GetSlotList", (long) ret );
        return;
    }

    printf ( "%ld slots found\n", slots );

    slotIds = (CK_SLOT_ID*) alloca ( slots * sizeof(CK_SLOT_ID) );
    VERBOSE("C_GetSlotList");
    ret = C_GetSlotList ( FALSE, slotIds, &slots );
    if (ret != CKR_OK) {
        PKCS11_error ( "C_GetSlotList", (long) ret );
        return;
    }

    for (i = 0; i < slots; i++) {
	VERBOSE("C_GetSlotInfo");
	ret = C_GetSlotInfo ( slotIds[i], &slotInfo );
	if (ret != CKR_OK) {
	    PKCS11_error ( "C_GetSlotInfo", (long) ret );
            return;
	}
	// dumpSlotInfo ( slotIds[i], &slotInfo );
	
	if (slotInfo.flags & CKF_TOKEN_PRESENT) {
	    VERBOSE("C_GetTokenInfo");
	    ret = C_GetTokenInfo ( slotIds[i], &tokenInfo );
	    if (ret != CKR_OK) {
		PKCS11_error ( "C_GetTokenInfo", (long) ret );
	    }
	    dumpTokenInfo ( &tokenInfo );

	    listObjects ( slotIds[i], "private key", CKO_PRIVATE_KEY );
	    listObjects ( slotIds[i], "public key", CKO_PUBLIC_KEY );
	    listObjects ( slotIds[i], "certificate", CKO_CERTIFICATE );
	    listObjects ( slotIds[i], "data", CKO_DATA );
	    listObjects ( slotIds[i], "secret key", CKO_SECRET_KEY );
	    listObjects ( slotIds[i], "hardware feature", CKO_HW_FEATURE );
	    listObjects ( slotIds[i], "domain features", CKO_DOMAIN_PARAMETERS );
	    listObjects ( slotIds[i], "vendor defined", CKO_VENDOR_DEFINED );

            listMechanisms( slotIds[i] );
	}
    }
}

/*
 * Test the PTEID PKCS#11 interface
 */


void
dumpPKCS11 ()
{
    CK_ULONG ret;
    CK_INFO info;
    
    VERBOSE("C_Initialize");
    ret = C_Initialize ( 0 );
    if (ret != CKR_OK) {
        PKCS11_error ( "C_Initialize", (long) ret );
    }

    VERBOSE("C_GetInfo");
    ret = C_GetInfo ( &info );
    if (ret != CKR_OK) {
        PKCS11_error ( "C_GetInfo", (long) ret );
    }
    dumpPKCS11Info ( &info );
    dumpPKCS11SlotsTokens ();

    VERBOSE("C_Finalize");
    ret = C_Finalize ( 0 );
}

void terminate ( int sig )
{
    static int called = 0;

    if (called == 1) {
	exit ( 2 );
    }

    called = 1;

    fprintf ( stderr, "Caught signal %d, exiting ...\n", sig );

    PTEID_Exit ( PTEID_EXIT_UNPOWER );

    exit ( 2 );
}

void
dumpCardType ( PTEID_ReaderContext & rc )
{
    PTEID_CardType ct = rc.getCardType ();

    if (ct == PTEID_CARDTYPE_UNKNOWN) {
	fprintf ( stdout, "Unknown card type\n" );
    } else if (ct == PTEID_CARDTYPE_IAS07) {
	fprintf ( stdout, "IAS 0.7 card\n" );
    }
    else if (ct == PTEID_CARDTYPE_IAS101) {
	fprintf ( stdout, "IAS 1.0.1 card\n" );
    }
    else {
	fprintf ( stdout, "Unknown answer to card type\n" );
    }
}

int
main ( int argc, char ** argv )
{
    int opt;

    while ((opt = getopt ( argc, argv, "vs" )) != -1) {
        switch (opt) {
	case 'v':
	    verbose = 1;
	    break;
	case 's':
	    SODchecking = 1;
	    break;
	default:
	    fprintf ( stderr, "Usage: %s %s\n", argv[0], USAGE_STR );
	    return 1;
	}
    }

    signal ( SIGINT, terminate );
    signal ( SIGTERM, terminate );
    signal ( SIGQUIT, terminate );
    signal ( SIGHUP, terminate );

    PTEID_ReaderSet::initSDK ( true );

    const char * const * rList = ReaderSet.readerList ( true );
    for (const char * const * rName = rList; *rName != NULL; rName++) {
        fprintf ( stdout, "Using reader %s --------------\n", *rName );

        PTEID_ReaderContext & rc = ReaderSet.getReaderByName ( *rName );
	if (rc.isCardPresent () == true) {
	    dumpCardType ( rc );
	    PTEID_EIDCard & idCard = rc.getEIDCard ();

            try {
                if (idCard.isActive ()) {
                    fprintf ( stdout, "Card is active\n" );
                    dumpId ( idCard.getID () );
                }
            } catch (PTEID_ExSOD&){
                fprintf ( stdout, "Card not active\n" );
            }

            if (SODchecking == 1) {
                try {
                    idCard.doSODCheck ( true );
                    dumpPhoto ( idCard.getID () );
                } catch (PTEID_ExSOD&){
                    fprintf ( stdout, "SOD checking failed, probably a test card\n" );
                }
            }

            PTEID_Certificates & certs = idCard.getCertificates ();
            fprintf ( stdout, "\n%lu certificates, %lu of them on card\n",

            certs.countAll (), certs.countFromCard () );

            for (unsigned int i = 0; i < certs.countAll (); i++) {
                dumpCertificate ( certs.getCert ( i ) );
            }
 
            dumpPKCS11 ();
	}
	else {
	    fprintf ( stdout, "Card not present\n" );
	}
    }

    PTEID_ReaderSet::releaseSDK ();

    return 0;
}
