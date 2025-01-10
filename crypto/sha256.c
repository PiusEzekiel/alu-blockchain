#include <openssl/sha.h>
#include <stddef.h>
#include <stdint.h>

/**
 * sha256 - computes the hash of a sequence of bytes
 * @s: the sequence of bytes to be hashed
 * @len: the number of bytes to hash in s
 * @digest: the resulting hash
 * Return: a pointer to digest
 */

uint8_t *sha256(int8_t const *s, size_t len,
		uint8_t digest[SHA256_DIGEST_LENGTH])
{
	if (!s || !digest)
		return (NULL);
	return (SHA256((uint8_t const *)s, len, digest));
}
