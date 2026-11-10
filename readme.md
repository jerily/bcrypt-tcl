# bcrypt-tcl

Bcrypt password hashing for Tcl 8.6 and 9.x, using the bundled OpenBSD bcrypt
implementation and OpenSSL 3 for salt entropy and constant-time comparison.

```tcl
package require bcrypt 2.0.1
set salt [bcrypt::gensalt] ;# cost 12, fresh random salt
set hash [bcrypt::hashpw {a long example passphrase} $salt]
bcrypt::checkpw {a long example passphrase} $hash ;# 1
bcrypt::checkpw wrong $hash ;# 0
```

- `bcrypt::gensalt ?workfactor?` generates a `$2b$` salt. Cost defaults to 12;
  the supported range is 4–31. Each increment doubles the work. Select the cost
  in trusted application configuration, not from a request.
- `bcrypt::hashpw password salt` accepts a 29-character salt or a 60-character
  existing hash and returns a 60-character hash. `$2a$`, `$2b$`, and `$2y$` are
  supported. Invalid or noncanonical records raise an error.
- `bcrypt::checkpw password hash` returns a boolean, using constant-time comparison.
  Malformed hashes return false. Valid stored costs are honored; applications
  should restrict costs when accepting hashes from untrusted sources.

Passwords are Tcl **text**, encoded internally to standard UTF-8 consistently on
Tcl 8.6 and Tcl 9. Do not pass an already-encoded byte array. Leading/trailing
spaces are preserved. Empty passwords, embedded NULs and passwords exceeding
72 UTF-8 bytes raise an error; they are never silently truncated. Applications
set their own minimum password length. The 72-byte bound follows
[the bcrypt password limit](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#input-limits-of-bcrypt).

Version 2.0.1 tightens input validation and corrects Unicode handling. Old Tcl
8.6 hashes made from supplementary Unicode characters may have used Tcl's modified
UTF-8 representation; those passwords need resetting if they no longer verify.
ASCII and ordinary BMP Unicode hashes retain compatibility. The obsolete bundled
arc4random port has been removed; salt generation uses OpenSSL's cryptographic RNG.

## Build and test

Requirements: C11 compiler, CMake 3.22+, matching Tcl headers/stub library and
OpenSSL 3 Crypto.

```sh
cmake -S . -B build -DCMAKE_INSTALL_PREFIX="$PWD/install"
cmake --build build --parallel
ctest --test-dir build --output-on-failure
cmake --install build
```

Shared builds define `USE_TCL_STUBS` and link only Tcl's stub archive, following
the same approach as tjson. They do not link `libtcl`. Select an installation with
`TCL_INCLUDE_DIR` and `TCL_LIBRARY_DIR`, or set `TCL_INCLUDE_PATH`,
`TCL_STUB_LIBRARY`, and `TCL_TCLSH` explicitly. `OPENSSL_ROOT_DIR` selects OpenSSL.
Build separately against Tcl 8.6 and Tcl 9 headers/stubs for the intended runtime.
The package index loads the shared library; tests load the exact library built.

Use `-DBUILD_SHARED_LIBS=OFF` for embedding. The archive's consumer links Tcl and
OpenSSL Crypto and registers `Bcrypt_Init` using `Tcl_StaticLibrary(NULL, ...)`
(Tcl 9) or `Tcl_StaticPackage(NULL, ...)` (Tcl 8.6), then `load {} Bcrypt`.
The static build includes a small embedding test and installs no loadable index.
Set `BUILD_TESTING=OFF` for cross-compilation without the target Tcl runtime.

For NaviServer, `make NAVISERVER=/path/to/ns` builds the module with OpenSSL's
`libcrypto.pc` on `PKG_CONFIG_PATH`. Shared/static Tcl builds and their runtime
checks are the primary supported build paths.
