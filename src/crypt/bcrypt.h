#ifndef BCRYPT_H
#define	BCRYPT_H

#include <sys/types.h>
#include <stdint.h>

#define	BCRYPT_HASHSPACE	61

int bcrypt_initsalt(int log_rounds, uint8_t *salt, size_t saltbuflen);
int bcrypt_hashpass(const char *key, const char *salt, char *encrypted, size_t encryptedlen);
int	bcrypt_newhash(const char *, int, char *, size_t);

#endif /* BCRYPT_H */
