/* Copyright Jerily LTD. SPDX-License-Identifier: MIT */
#include "library.h"
#include "crypt/bcrypt.h"
#include <openssl/crypto.h>
#include <string.h>

#ifndef TCL_SIZE_MAX
typedef int Tcl_Size;
#endif

static int Fail(Tcl_Interp *interp, const char *message) {
    Tcl_SetObjResult(interp, Tcl_NewStringObj(message, -1));
    Tcl_SetErrorCode(interp, "BCRYPT", "INVALID", NULL);
    return TCL_ERROR;
}

/* Validate before the bundled C implementation reads any fixed-position bytes. */
static int ValidRecord(const char *s, Tcl_Size length, int hashOnly) {
    static const char alphabet[] = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    if (length != 60 && (hashOnly || length != 29)) return 0;
    if (s[0] != '$' || s[1] != '2' || (s[2] != 'a' && s[2] != 'b' && s[2] != 'y') ||
        s[3] != '$' || s[4] < '0' || s[4] > '3' || s[5] < '0' || s[5] > '9' || s[6] != '$') return 0;
    int cost = (s[4] - '0') * 10 + s[5] - '0';
    if (cost < 4 || cost > 31) return 0;
    for (Tcl_Size j = 7; j < length; ++j) {
        if (s[j] == '\0' || strchr(alphabet, s[j]) == NULL) return 0;
    }
    /* Unused base64 bits must be zero in a canonical salt/hash. */
    if (((strchr(alphabet, s[28]) - alphabet) & 15) != 0) return 0;
    if (length == 60 && ((strchr(alphabet, s[59]) - alphabet) & 3) != 0) return 0;
    return 1;
}

/* Text input has the same standard UTF-8 representation on Tcl 8.6 and Tcl 9. */
static int PasswordBytes(Tcl_Interp *interp, Tcl_Obj *obj, Tcl_DString *bytes) {
    Tcl_Size length;
    const char *text = Tcl_GetStringFromObj(obj, &length);
    Tcl_Encoding utf8 = Tcl_GetEncoding(interp, "utf-8");
    if (utf8 == NULL) return TCL_ERROR;
    Tcl_UtfToExternalDString(utf8, text, length, bytes);
    Tcl_FreeEncoding(utf8);
    Tcl_Size n = Tcl_DStringLength(bytes);
    if (n < 1 || n > 72 || memchr(Tcl_DStringValue(bytes), 0, n) != NULL) {
        OPENSSL_cleanse(Tcl_DStringValue(bytes), n);
        Tcl_DStringFree(bytes);
        return Fail(interp, "password must contain 1..72 UTF-8 bytes and no NUL characters");
    }
    return TCL_OK;
}

static int GenSalt(ClientData unused, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)unused;
    if (objc != 1 && objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "?workfactor?"); return TCL_ERROR;
    }
    int cost = 12;
    if (objc == 2 && Tcl_GetIntFromObj(interp, objv[1], &cost) != TCL_OK) return TCL_ERROR;
    if (cost < 4 || cost > 31) return Fail(interp, "workfactor must be between 4 and 31");
    char salt[BCRYPT_HASHSPACE];
    if (bcrypt_initsalt(cost, salt, sizeof(salt)) != 0) return Fail(interp, "secure salt generation failed");
    Tcl_SetObjResult(interp, Tcl_NewStringObj(salt, -1));
    return TCL_OK;
}

static int Password(ClientData verify, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, verify ? "password hash" : "password salt");
        return TCL_ERROR;
    }
    Tcl_Size length;
    const char *record = Tcl_GetStringFromObj(objv[2], &length);
    if (!ValidRecord(record, length, verify != NULL)) {
        if (!verify) return Fail(interp, "invalid bcrypt salt or hash");
        Tcl_SetObjResult(interp, Tcl_NewBooleanObj(0)); return TCL_OK;
    }
    Tcl_DString bytes;
    if (PasswordBytes(interp, objv[1], &bytes) != TCL_OK) return TCL_ERROR;
    char hash[BCRYPT_HASHSPACE];
    int status = bcrypt_hashpass(Tcl_DStringValue(&bytes), record, hash, sizeof(hash));
    OPENSSL_cleanse(Tcl_DStringValue(&bytes), Tcl_DStringLength(&bytes));
    Tcl_DStringFree(&bytes);
    if (status != 0) {
        OPENSSL_cleanse(hash, sizeof(hash));
        return Fail(interp, "bcrypt hashing failed");
    }
    if (verify) Tcl_SetObjResult(interp, Tcl_NewBooleanObj(CRYPTO_memcmp(record, hash, 60) == 0));
    else Tcl_SetObjResult(interp, Tcl_NewStringObj(hash, 60));
    OPENSSL_cleanse(hash, sizeof(hash));
    return TCL_OK;
}

int Bcrypt_Init(Tcl_Interp *interp) {
#if TCL_MAJOR_VERSION >= 9
    const char *minimum = "9.0";
#else
    const char *minimum = "8.6";
#endif
    if (Tcl_InitStubs(interp, minimum, 0) == NULL) return TCL_ERROR;
    if (Tcl_CreateNamespace(interp, "::bcrypt", NULL, NULL) == NULL) return TCL_ERROR;
    Tcl_CreateObjCommand(interp, "::bcrypt::gensalt", GenSalt, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::bcrypt::hashpw", Password, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::bcrypt::checkpw", Password, (ClientData)1, NULL);
    return Tcl_PkgProvide(interp, "bcrypt", PROJECT_VERSION);
}
#ifdef USE_NAVISERVER
NS_EXPORT int Ns_ModuleVersion = 1;
int Ns_ModuleInit(const char *server, const char *module) {
    (void)module;
    Ns_TclRegisterTrace(server, (Ns_TclTraceProc *)Bcrypt_Init, server, NS_TCL_TRACE_CREATE);
    return NS_OK;
}
#endif
