# bcrypt-tcl

TCL module for bcrypt, a password-hashing function.

## What is bcrypt?

bcrypt is a password-hashing function designed by Niels Provos
and David Mazières, based on the Blowfish cipher, and presented
at USENIX in 1999. Besides incorporating a salt to protect against
rainbow table attacks, bcrypt is an adaptive function: over time,
the iteration count can be increased to make it slower,
so it remains resistant to brute-force search attacks even with
increasing computation power.

## Examples

```tcl
package require bcrypt

set salt [::bcrypt::gensalt 15]
# $2a$15$2rmMs5kDAKqq2q1XJQtEre

set hash [::bcrypt::hashpw "password" $salt]
# $2a$15$2rmMs5kDAKqq2q1XJQtEre5qG.qJpLJlNrk5Zb3Mv7cgn0JBK4xR2

set match_correct_pw [::bcrypt::checkpw "password" $hash]
puts match_correct_pw=$match_correct_pw
# match_correct_pw=1

set match_incorrect_pw [::bcrypt::checkpw "hello world" $hash]
puts match_incorrect_pw=$match_incorrect_pw
# match_incorrect_pw=0

```

## Build for TCL
    
```bash
wget https://github.com/jerily/bcrypt-tcl/archive/refs/tags/v1.0.2.tar.gz
tar -xzf v1.0.2.tar.gz
cd bcrypt-tcl-1.0.2
export BCRYPT_TCL_DIR=`pwd`
mkdir build
cd build
cmake .. \
  -DTCL_LIBRARY_DIR=/usr/local/lib \
  -DTCL_INCLUDE_DIR=/usr/local/include
make
# IMPORTANT: run the tests to make sure
# everything is working fine on your system
make test
make install
```

## Build for NaviServer

```bash
cd ${BCRYPT_TCL_DIR}
make
make install
```


## TCL Commands

* **::bcrypt::gensalt** *?work_factor?*
  - returns a salt
* **::bcrypt::hashpw** *password salt*
  - returns a hash
* **::bcrypt::checkpw** *password hash*
  - returns 1 if the password matches the hash, 0 otherwise
