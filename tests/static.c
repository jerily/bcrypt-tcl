#include "library.h"
#include <stdio.h>
int main(int argc, char **argv) {
    (void)argc;
    Tcl_FindExecutable(argv[0]);
    Tcl_Interp *interp = Tcl_CreateInterp();
    if (Tcl_Init(interp) != TCL_OK) return 1;
#if TCL_MAJOR_VERSION >= 9
    Tcl_StaticLibrary(NULL, "Bcrypt", Bcrypt_Init, NULL);
#else
    Tcl_StaticPackage(NULL, "Bcrypt", Bcrypt_Init, NULL);
#endif
    int code = Tcl_Eval(interp, "load {} Bcrypt; set hash [bcrypt::hashpw example [bcrypt::gensalt 4]];"
        "if {![bcrypt::checkpw example $hash] || [bcrypt::checkpw wrong $hash]} {error {static bcrypt failed}}");
    if (code != TCL_OK) fprintf(stderr, "%s\n", Tcl_GetStringResult(interp));
    Tcl_DeleteInterp(interp);
    Tcl_Finalize();
    return code != TCL_OK;
}
