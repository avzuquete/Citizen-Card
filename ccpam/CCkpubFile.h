#ifndef _PTEID_CC_KPUB_FILE_H_
#define _PTEID_CC_KPUB_FILE_H_

#define CC_KPUB_FILE	"/etc/CC/keys"

struct pubkey_t {
    char * username;
    char * e;
    char * n;
};

struct pubkey_t * CC_loadKeys ( const char * file );
int CC_storeKeys ( const char * file, struct pubkey_t * keys );

#endif /* _PTEID_CC_KPUB_FILE_H_ */
