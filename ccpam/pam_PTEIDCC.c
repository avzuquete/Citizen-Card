/*
* PAM_PTEIDCC.c
*
* Description: This dinamic library uses the Portuguese Citizen
*              Card to authenticate a user already registered
* Usage: auth sufficient pam_PTEIDCC.so [public key file]
* Author: André Zúquete (http://wiki.ieeta.pt/wiki/index.php/Andr%C3%A9_Z%C3%BAquete)
* Creation date: May 2009
* Last update: May 2018
* PTEID middleware version: 3.0.15
*/

// #define PAM_DEBUG

#include <sys/param.h>

#include <errno.h>
#include <fcntl.h>
#include <malloc.h>
#include <memory.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <unistd.h>

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define	PAM_SM_PASSWORD

#include <security/pam_modules.h>
#include <security/pam_client.h>
#include <security/_pam_macros.h>
#include <security/pam_ext.h>

#include <opencryptoki/apiclient.h>
#include <openssl/x509.h>
#include "eidlib.h"

#include "CCkpubFile.h"

static char * command;

/*
* Generic function that finds a PKCS#11 object, given its class and
* label, in a crypto token
*/

static int 
CC_findObject ( CK_SESSION_HANDLE sessH, CK_ULONG objClass, const char * label,
		CK_OBJECT_HANDLE * objH )
{
    long ret;
    CK_ATTRIBUTE attrs;
    CK_ULONG objCount;
    unsigned int objValue;
    unsigned char objId;

    objValue = objClass;
    attrs.type = CKA_CLASS;
    attrs.pValue = &objValue;
    attrs.ulValueLen = sizeof(objValue);
    ret = C_FindObjectsInit ( sessH, &attrs, 1 );
    if (ret != CKR_OK) {
	D(("Error in PTEID PKCS #11 C_FindObjectsInit: %ld", ret));
	return ret;
    }

    for (;;) {
	ret = C_FindObjects ( sessH, objH, 1, &objCount );
	if (ret != CKR_OK) {
	    D(("Error in PTEID PKCS #11 C_FindObjects: %ld", ret));
	    return ret;
	}
	if (objCount == 0) return -1;

	attrs.type = CKA_LABEL;
	attrs.pValue = 0;
	attrs.ulValueLen = 1;
	ret = C_GetAttributeValue ( sessH, *objH, &attrs, 1 );
	if (ret != CKR_OK) {
	    D(("Error in PTEID PKCS #11 C_GetAttributeValue: %ld", ret));
	    return ret;
	}
	attrs.pValue = alloca ( attrs.ulValueLen + 1 );
	((char*)attrs.pValue)[attrs.ulValueLen] = 0;
	ret = C_GetAttributeValue ( sessH, *objH, &attrs, 1 );
	if (ret != CKR_OK) {
	    D(("Error in PTEID PKCS #11 C_GetAttributeValue: %ld", ret));
	    return ret;
	}

	if (strcmp ( (const char *) attrs.pValue, label ) == 0) {
	    C_FindObjectsFinal ( sessH );

	    return CKR_OK;
	}
    }

    C_FindObjectsFinal ( sessH );

    return CKR_TOKEN_NOT_RECOGNIZED;
}

/*
* Check if a given public key exists in a certificate inside the
* crypto token
* If present, use the corresponding private key to encrypt a
* challenge and decrypt the result with the public key
*/

static int
CC_checkCard ( pam_handle_t * pamh, RSA * pubKey )
{
    int fd;
    int i;
    CK_RV ret;
    CK_ULONG slots;
    CK_SLOT_ID * slotIds, slot;
    CK_SLOT_INFO slotInfo;
    CK_TOKEN_INFO tokenInfo;
    CK_SESSION_HANDLE sessH;
    CK_OBJECT_HANDLE objH;
    CK_MECHANISM mechanism;
    CK_ULONG signatureLen;
    CK_BYTE * signature;
    SHA_CTX ctx;
    unsigned char challenge[64];
    unsigned char digest[20];
    char * PIN;

    ret = C_Initialize ( 0 );
    if (ret != CKR_OK) {
	D(("Error in PTEID PKCS #11 C_Initialize: %ld", ret));
	C_Finalize ( 0 );
	return ret;
    }

    slots = 0;
    ret = C_GetSlotList ( FALSE, 0, &slots );
    if (ret != CKR_OK) {
        D(("Error in PTEID PKCS #11 C_GetSlotList: %ld", ret));
	C_Finalize ( 0 );
	return ret;
    }

    slotIds = (CK_SLOT_ID *) alloca ( slots * sizeof(CK_SLOT_ID) );
    ret = C_GetSlotList ( FALSE, slotIds, &slots );
    if (ret != CKR_OK) {
        D(("Error in PTEID PKCS #11 C_GetSlotList: %ld", ret));
	C_Finalize ( 0 );
	return ret;
    }

    for (i = 0; i < slots; i++) {
	ret = C_GetSlotInfo ( slotIds[i], &slotInfo );
	if (ret != CKR_OK) {
	    D(("Error in PTEID PKCS #11 C_GetSlotInfo: %ld", ret));
	    C_Finalize ( 0 );
	    return ret;
	}
	if (slotInfo.flags & CKF_TOKEN_PRESENT) {
	    ret = C_GetTokenInfo ( slotIds[i], &tokenInfo );
	    if (ret != CKR_OK) {
		D(("Error in PTEID PKCS #11 C_GetTokenInfo: %ld", ret));
		C_Finalize ( 0 );
		return ret;
	    }
	    if (strncmp ( (const char *) tokenInfo.label, "CARTAO DE CIDADAO", 17 ) == 0) {
		D(("Found PTEID CC"));
	        slot = slotIds[i];
		goto sign;
	    }
	}
    }

    return CKR_TOKEN_NOT_PRESENT;

sign:
    pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &PIN,
		"Enter PTEID CC Authentication PIN (or return for aborting): ");
    if (strlen ( PIN ) == 0)
	return PAM_AUTH_ERR;
    if (strlen ( PIN ) != 4) {
        goto sign;
    }

    /*
    * Generate random challenge
    */

    fd = open ( "/dev/urandom", O_RDONLY );
    read ( fd, challenge, sizeof(challenge) );
    close ( fd );

    /*
    * Encrypt challenge with CC private key
    */

    ret = C_OpenSession ( 0, CKF_SERIAL_SESSION, 0, 0, &sessH );
    if (ret != CKR_OK) {
	D(("Error in PTEID PKCS #11 C_OpenSession: %ld", ret));
	C_Finalize ( 0 );
	return ret;
    }

    ret = C_Login ( sessH, CKU_USER, (unsigned char *) PIN, strlen(PIN) );
    if (ret != CKR_OK) {
	D(("Error in PTEID PKCS #11 C_Login: %ld", ret));
	C_Finalize ( 0 );
	return ret;
    }

    if (CC_findObject ( sessH, CKO_PRIVATE_KEY, "CITIZEN AUTHENTICATION KEY", &objH ) != CKR_OK) {
	C_Finalize ( 0 );
	return ret;
    }

    D(("Found CITIZEN AUTHENTICATION KEY"));

    mechanism.mechanism = CKM_SHA1_RSA_PKCS;
    ret = C_SignInit ( sessH, &mechanism, objH );
    if (ret != CKR_OK) {
	D(("Error in PTEID PKCS #11 C_SignInit: %ld", ret));
	C_Finalize ( 0 );
	return ret;
    }

    signatureLen = 0;
    ret = C_Sign ( sessH, challenge, sizeof(challenge), 0, &signatureLen );
    signature = (CK_BYTE *) alloca ( signatureLen );
    ret = C_Sign ( sessH, challenge, sizeof(challenge), signature, &signatureLen );
    if (ret != CKR_OK) {
	D(("Error in PTEID PKCS #11 C_Sign: %ld", ret));
	C_Finalize ( 0 );
	return ret;
    }

    ret = C_Logout ( sessH );
    if (ret != CKR_OK) {
	D(("Error in PTEID PKCS #11 C_Logout: %ld", ret));
	C_Finalize ( 0 );
	return ret;
    }

    ret = C_CloseSession ( sessH );
    if (ret != CKR_OK) {
	D(("Error in PTEID PKCS #11 C_CloseSession", ret));
	C_Finalize ( 0 );
	return ret;
    }

    C_Finalize ( 0 );

    /*
    * Decrypt result with public key
    */

    SHA1_Init ( &ctx );
    SHA1_Update ( &ctx, challenge, sizeof(challenge) );
    SHA1_Final ( digest, &ctx );

    if (RSA_verify ( NID_sha1, digest, sizeof(digest), signature, signatureLen, pubKey ) == 1) {
	D(("PTEID CC authentication: success!"));
	return CKR_OK;
    }

    D(("PTEID CC authentication: failure (signature not validated!"));

    return PAM_AUTHTOK_ERR;
}

static int
CC_login ( pam_handle_t * pamh, struct passwd * pwd,
	    const char * kpubfile )
{
    struct pubkey_t * pubKeys;
    long ret;
    int i;

    pubKeys = CC_loadKeys ( (char *) kpubfile );

    for (i = 0; pubKeys[i].username != 0; i++) {
        if (strcmp ( pubKeys[i].username, pwd->pw_name ) == 0) {
	    BIGNUM * n = 0;
	    BIGNUM * e = 0;
	    RSA * key = RSA_new ();

	    BN_hex2bn ( &e, pubKeys[i].e );
	    BN_hex2bn ( &n, pubKeys[i].n );

	    RSA_set0_key ( key, n, e, 0 );

	    D(("Found public key for user %s", pwd->pw_name));

	    ret = CC_checkCard ( pamh, key );
	    if (ret == CKR_OK)
	    	return PAM_SUCCESS;
	    else if (ret < 0) {
	        printf ( "PTEID CC error" );
	    }

	    return PAM_AUTH_ERR;
	}
    }

    return PAM_AUTHINFO_UNAVAIL;
}

/*
* Authentication management
*/

PAM_EXTERN int
pam_sm_authenticate ( pam_handle_t *pamh, int flags, int argc,
			const char *argv[] )
{
	struct passwd *pwd;
	int retval;
	const char *user, *realpw, *prompt;

	retval = pam_get_user ( pamh, &user, NULL );
	if (retval != PAM_SUCCESS)
		return retval;
	pwd = getpwnam ( user );

	D(("Got user: %s", user));

	if (pwd == NULL) {
	    return PAM_AUTH_ERR;
	}

	return CC_login ( pamh, pwd, (argc >= 1) ? argv[0] : CC_KPUB_FILE );
}

/*
* Credentials management
*/

PAM_EXTERN int
pam_sm_setcred ( pam_handle_t *pamh, int flags, int argc,
			const char *argv[] )
{
    return PAM_SUCCESS;
}

/*
* Account management
*/

PAM_EXTERN int
pam_sm_acct_mgmt ( pam_handle_t *pamh, int flags, int argc,
			const char *argv[] )
{
    return PAM_SUCCESS;
}

/*
* Password management
*/

PAM_EXTERN int
pam_sm_chauthtok ( pam_handle_t *pamh, int flags, int argc,
			const char *argv[] )
{
    return PAM_SERVICE_ERR;
}

PAM_EXTERN int
pam_sm_open_session ( pam_handle_t *pamh, int flags, int argc,
			const char **argv)
{
    return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_close_session ( pam_handle_t *pamh, int flags, int argc,
			const char **argv)
{
    return PAM_SUCCESS;
}
#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("pam_PTEIDCC");
#endif
