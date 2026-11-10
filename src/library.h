/* Copyright Jerily LTD. SPDX-License-Identifier: MIT */
#ifndef BCRYPT_TCL_LIBRARY_H
#define BCRYPT_TCL_LIBRARY_H
#ifdef USE_NAVISERVER
#include <ns.h>
#else
#include <tcl.h>
#endif
#ifdef __cplusplus
extern "C" {
#endif
#ifdef BUILD_bcrypt
#undef TCL_STORAGE_CLASS
#define TCL_STORAGE_CLASS DLLEXPORT
#endif
EXTERN int Bcrypt_Init(Tcl_Interp *interp);
#ifdef USE_NAVISERVER
NS_EXTERN int Ns_ModuleInit(const char *server, const char *module);
#endif
#ifdef __cplusplus
}
#endif
#endif
