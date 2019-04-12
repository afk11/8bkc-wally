#include <stdint.h>

#define BIP32_MAX_DERIVATIONS 255

// Takes path and it's length, and attempts
// to extract the bip32 derivation indices
// into `derivs`, the number of derivations
// to `num_derivs`, and whether the path was
// for a public or private derivation.
int bip32_parse_absolute_path(const char* path, size_t path_len, uint32_t derivs[], size_t* num_derivs, int* public);
