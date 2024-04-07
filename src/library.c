/**
 * Copyright Jerily LTD. All Rights Reserved.
 * SPDX-FileCopyrightText: 2023 Neofytos Dimitriou (neo@jerily.cy)
 * SPDX-License-Identifier: MIT.
 */
#include "library.h"
#include <stdio.h>
#include <string.h>
#include "crypt/bcrypt.h"

#ifndef TCL_SIZE_MAX
typedef int Tcl_Size;
# define Tcl_GetSizeIntFromObj Tcl_GetIntFromObj
# define Tcl_NewSizeIntObj Tcl_NewIntObj
# define TCL_SIZE_MAX      INT_MAX
# define TCL_SIZE_MODIFIER ""
#endif

#define XSTR(s) STR(s)
#define STR(s) #s

#ifdef DEBUG
# define DBG(x) x
#else
# define DBG(x)
#endif

#define CheckArgs(min,max,n,msg) \
                 if ((objc < min) || (objc >max)) { \
                     Tcl_WrongNumArgs(interp, n, objv, msg); \
                     return TCL_ERROR; \
                 }

#define BCRYPT_HASHSIZE BCRYPT_HASHSPACE

static int bcrypt_ModuleInitialized;

/*
 * This function expects a work factor between 4 and 31 and a char array to
 * store the resulting generated salt. The char array should typically have
 * BCRYPT_HASHSIZE bytes at least. If the provided work factor is not in the
 * previous range, it will default to 12.
 *
 * The return value is zero if the salt could be correctly generated and
 * nonzero otherwise.
 *
 */
int bcrypt_gensalt(int workfactor, unsigned char salt[BCRYPT_HASHSIZE]) {
    return bcrypt_initsalt(workfactor, salt, BCRYPT_HASHSIZE);
}

/*
 * This function expects a password to be hashed, a salt to hash the password
 * with and a char array to leave the result. Both the salt and the hash
 * parameters should have room for BCRYPT_HASHSIZE characters at least.
 *
 * It can also be used to verify a hashed password. In that case, provide the
 * expected hash in the salt parameter and verify the output hash is the same
 * as the input hash. However, to avoid timing attacks, it's better to use
 * bcrypt_checkpw when verifying a password.
 *
 * The return value is zero if the password could be hashed and nonzero
 * otherwise.
 */
int bcrypt_hashpw(const char *passwd, const char salt[BCRYPT_HASHSIZE],
                  char hash[BCRYPT_HASHSIZE]) {
    return bcrypt_hashpass(passwd, salt, hash, BCRYPT_HASHSIZE);
}

/*
 * This function expects a password and a hash to verify the password against.
 * The internal implementation is tuned to avoid timing attacks.
 *
 * The return value will be -1 in case of errors, zero if the provided password
 * matches the given hash and greater than zero if no errors are found and the
 * passwords don't match.
 *
 */

int timingsafe_bcmp(const void *s1, const void *s2, size_t n) {
    const unsigned char *us1 = (const unsigned char *)s1;
    const unsigned char *us2 = (const unsigned char *)s2;
    int result = 0;

    for (size_t i = 0; i < n; i++) {
        result |= us1[i] ^ us2[i];
    }

    return result != 0;
}

int bcrypt_checkpw(const char *pass, const char goodhash[BCRYPT_HASHSIZE]) {
    char hash[BCRYPT_HASHSPACE];

    if (bcrypt_hashpass(pass, goodhash, hash, sizeof(hash)) != 0)
        return -1;
    if (strlen(hash) != strlen(goodhash) ||
        timingsafe_bcmp(hash, goodhash, strlen(goodhash)) != 0) {
//        errno = EACCES;
        return 1;
    }

    explicit_bzero(hash, sizeof(hash));
    return 0;

}

/*
 * Brief Example
 * -------------
 *
 * Hashing a password:
 *
 *	char salt[BCRYPT_HASHSIZE];
 *	char hash[BCRYPT_HASHSIZE];
 *	int ret;
 *
 *	ret = bcrypt_gensalt(12, salt);
 *	assert(ret == 0);
 *	ret = bcrypt_hashpw("thepassword", salt, hash);
 *	assert(ret == 0);
 *
 *
 * Verifying a password:
 *
 *	int ret;
 *
 *      ret = bcrypt_checkpw("thepassword", "expectedhash");
 *      assert(ret != -1);
 *
 *	if (ret == 0) {
 *		printf("The password matches\n");
 *	} else {
 *		printf("The password does NOT match\n");
 *	}
 *
 */



static int bcrypt_GenSaltCmd(ClientData  clientData, Tcl_Interp *interp, int objc, Tcl_Obj * const objv[] ) {
    DBG(fprintf(stderr, "GenSaltCmd\n"));
    CheckArgs(1, 2, 1, "?workfactor?");

    int workfactor = 12;
    if (objc == 2) {
        if (TCL_OK != Tcl_GetIntFromObj(interp, objv[1], &workfactor) || workfactor < 4 || workfactor > 31) {
            Tcl_SetObjResult(interp, Tcl_NewStringObj("workfactor must be between 4 and 31", -1));
            return TCL_ERROR;
        }
    }

    unsigned char salt[BCRYPT_HASHSIZE];
    if (bcrypt_gensalt(workfactor, salt)) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("bcrypt_gensalt failed", -1));
        return TCL_ERROR;
    }
    Tcl_SetObjResult(interp, Tcl_NewStringObj(salt, -1));
    return TCL_OK;
}

static int bcrypt_HashPasswordCmd(ClientData  clientData, Tcl_Interp *interp, int objc, Tcl_Obj * const objv[] ) {
    DBG(fprintf(stderr, "HashPasswordCmd\n"));
    CheckArgs(3, 3, 1, "passwd salt");

    Tcl_Size passwd_len;
    const char *passwd = Tcl_GetStringFromObj(objv[1], &passwd_len);
    if (passwd_len < 1) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("passwd must be at least 1 char", -1));
        return TCL_ERROR;
    }

    Tcl_Size salt_len;
    const char *salt = Tcl_GetStringFromObj(objv[2], &salt_len);

    char hash[BCRYPT_HASHSIZE];
    if (bcrypt_hashpw(passwd, salt, hash)) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("bcrypt_hashpw failed", -1));
        return TCL_ERROR;
    }
    Tcl_SetObjResult(interp, Tcl_NewStringObj(hash, -1));
    return TCL_OK;
}

static int bcrypt_CheckPasswordCmd(ClientData  clientData, Tcl_Interp *interp, int objc, Tcl_Obj * const objv[] ) {
    DBG(fprintf(stderr, "CheckPasswordCmd\n"));
    CheckArgs(3, 3, 1, "passwd hash");

    Tcl_Size passwd_len;
    const char *passwd = Tcl_GetStringFromObj(objv[1], &passwd_len);
    if (passwd_len < 1) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("passwd must be at least 1 char", -1));
        return TCL_ERROR;
    }

    Tcl_Size hash_len;
    const char *hash = Tcl_GetStringFromObj(objv[2], &hash_len);

    int ret = bcrypt_checkpw(passwd, hash);
    if (-1 == ret) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("bcrypt_checkpw failed", -1));
        return TCL_ERROR;
    }
    // true if passwords match, otherwise false
    Tcl_SetObjResult(interp, Tcl_NewBooleanObj(ret == 0));
    return TCL_OK;
}

static void bcrypt_ExitHandler(ClientData unused) {
}


void bcrypt_InitModule() {
    if (!bcrypt_ModuleInitialized) {
        bcrypt_ModuleInitialized = 1;
        DBG(fprintf(stderr, "bcrypt-tcl module initialized\n"));
    }
}

int Bcrypt_Init(Tcl_Interp *interp) {
    if (Tcl_InitStubs(interp, "8.6", 0) == NULL) {
        return TCL_ERROR;
    }

    bcrypt_InitModule();

    Tcl_CreateNamespace(interp, "::bcrypt", NULL, NULL);
    Tcl_CreateObjCommand(interp, "::bcrypt::gensalt", bcrypt_GenSaltCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::bcrypt::hashpw", bcrypt_HashPasswordCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::bcrypt::checkpw", bcrypt_CheckPasswordCmd, NULL, NULL);

    return Tcl_PkgProvide(interp, "bcrypt", XSTR(VERSION));
}

#ifdef USE_NAVISERVER
int Ns_ModuleInit(const char *server, const char *module) {
    Ns_TclRegisterTrace(server, (Ns_TclTraceProc *) Bcrypt_Init, server, NS_TCL_TRACE_CREATE);
    return NS_OK;
}
#endif
