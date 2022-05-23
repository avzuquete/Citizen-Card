#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

// Definitions that should be provided by clients, as defined in V3.0

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

// Definitions that add to be provided to compiler

#define CK_BYTE CK_BOOL
#define CK_HANDLE CK_BYTE_PTR

#include "pkcs11.h"

#define ENV_LIB_PATH "PTEIDPKCS11_WRAPPER"
#define DEFAULT_LIB_PATH "/usr/local/lib/libpteidpkcs11.so"

#define LOG(name) printf("%s\n",#name);
#define DEBUG(fmt,name) printf(fmt,name);

static CK_FUNCTION_LIST_PTR funcs = 0;
static CK_FUNCTION_LIST _funcs;

void resolve();

CK_RV
_C_GetFunctionList ( CK_FUNCTION_LIST_PTR_PTR list_ptr )
{
    *list_ptr = &_funcs;
    return CKR_OK;
}

static void 
bootstrap()
{
    void * handle;
    char * libname;

    CK_RV (*gfl) ( CK_FUNCTION_LIST_PTR_PTR );

    if (funcs) return;

    libname = getenv( ENV_LIB_PATH );
    if (libname == 0) {
        libname = DEFAULT_LIB_PATH;
    }
    
    handle = dlopen( libname, RTLD_NOW );
    gfl = dlsym( handle, "C_GetFunctionList" );
    gfl( &funcs );

    resolve();
    funcs->C_GetFunctionList = _C_GetFunctionList;

    printf( "Bootstrap done!\n" );
}
