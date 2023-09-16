/**
 * Copyright Jerily LTD. All Rights Reserved.
 * SPDX-FileCopyrightText: 2023 Neofytos Dimitriou (neo@jerily.cy)
 * SPDX-License-Identifier: MIT.
 */
#ifndef BCRYPT_TCL_LIBRARY_H
#define BCRYPT_TCL_LIBRARY_H

#ifdef USE_NAVISERVER
#include "ns.h"
#include <stdint.h>
#else
#include <tcl.h>
#endif


#ifdef __cplusplus
extern "C" {
#endif

extern int Bcrypt_Init(Tcl_Interp *interp);
#ifdef USE_NAVISERVER
NS_EXTERN int Ns_ModuleVersion = 1;
NS_EXTERN int Ns_ModuleInit(const char *server, const char *module);
#endif

#ifdef __cplusplus
}
#endif

#endif //BCRYPT_TCL_LIBRARY_H
