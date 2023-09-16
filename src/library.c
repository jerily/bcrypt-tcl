/**
 * Copyright Jerily LTD. All Rights Reserved.
 * SPDX-FileCopyrightText: 2023 Neofytos Dimitriou (neo@jerily.cy)
 * SPDX-License-Identifier: MIT.
 */
#include "library.h"
#include <stdio.h>
#include <string.h>
#include "bcrypt/bcrypt.h"

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

static int bcrypt_ModuleInitialized;

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

    char salt[BCRYPT_HASHSIZE];
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

    int passwd_len;
    const char *passwd = Tcl_GetStringFromObj(objv[1], &passwd_len);
    if (passwd_len < 1) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("passwd must be at least 1 char", -1));
        return TCL_ERROR;
    }

    int salt_len;
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

    int passwd_len;
    const char *passwd = Tcl_GetStringFromObj(objv[1], &passwd_len);
    if (passwd_len < 1) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("passwd must be at least 1 char", -1));
        return TCL_ERROR;
    }

    int hash_len;
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
