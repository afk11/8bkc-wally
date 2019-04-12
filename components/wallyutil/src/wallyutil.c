#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_script.h>
#include <wally_bip39.h>
#include <wally_bip32.h>
#include <secp256k1.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "wallyutil_bip32.h"

// https://github.com/trezor/trezor-mcu/blob/fa3481e37d528794adb3b234855c23300782ad92/firmware/storage.h#L62
#define MNEMONIC_MAX_SIZE 241
#define BIP32_MAX_LEVELS 255

int exit_error(char *msg)
{
    printf("ERR: %s\n", msg);
    return 1;
}

int mygetline(FILE* input, char line[], int maxline)
{
    int c, i;
    for (i = 0; i < maxline-1 && (c = fgetc(input)) != EOF && c != '\n'; ++i) {
        line[i] = c;
    }
    line[i] = '\0';
    return i;
}

void print_hex(FILE* output, unsigned char* data, int len) 
{
    for (int i = 0; i < len; i++) {
	fprintf(output, "%02x", data[i]);
    }
}

int cmd_create_mnemonic(const unsigned char* entropy, size_t entlen, FILE* output) {
    char* mnemonic;
   if (WALLY_OK != bip39_mnemonic_from_bytes(NULL, entropy, entlen, &mnemonic)) {
	return exit_error("failed to produce mnemonic");
    }
    if (WALLY_OK != bip39_mnemonic_validate(NULL, mnemonic)) {
	return exit_error("failed to validate own mnemonic");
    }
    fprintf(output, "%s", mnemonic);
    return 0;
}

int cmd_validate_mnemonic(char* mnemonic)
{
    if (WALLY_OK != bip39_mnemonic_validate(NULL, mnemonic)) {
        return exit_error("invalid mnemonic");
    }
    return 0;
}

int cmd_multisig(struct ext_key key[],  char* path_str, size_t path_str_len, int m, int n, int sort, FILE* output)
{
    int i, j;
    //struct ext_key key[n];
    struct ext_key script_keys[n];

    uint32_t child_path[BIP32_MAX_LEVELS];
    size_t num_derivs;
    int request_public;
    if (!bip32_parse_absolute_path(path_str, path_str_len, child_path, &num_derivs, &request_public)) {
        return exit_error("failed to parse path");
    }

    for (i = 0; i < n; ++i) {
        if (num_derivs == 0) {
            script_keys[i] = key[i];
	} else if (WALLY_OK != bip32_key_from_parent_path(&key[i], child_path,
                        num_derivs, BIP32_FLAG_KEY_PRIVATE, &script_keys[i])) {
            return exit_error("failed to derive child key");
        }
    }

    if (sort) {
	for (i = 0; i < n; i++) {
	    for (j = 0; j < n; j++) {
	       if (strcmp(script_keys[i].pub_key, script_keys[j].pub_key) < 0) {
	           struct ext_key tmp = script_keys[i];
	           script_keys[i] = script_keys[j];
	           script_keys[j] = tmp;
	       }
	    }
        }
    }

    unsigned char* pubkey_bytes = malloc(n*EC_PUBLIC_KEY_LEN);
    for (i = 0; i < n; i++) {
        memcpy(pubkey_bytes+(i*EC_PUBLIC_KEY_LEN), script_keys[i].pub_key, EC_PUBLIC_KEY_LEN);
    }
    size_t script_len = 1 + n*(1 + EC_PUBLIC_KEY_LEN) + 2;
    size_t written;
    unsigned char script[script_len];
    unsigned char script_p2sh[WALLY_SCRIPTPUBKEY_P2SH_LEN];
    unsigned char script_p2wsh[WALLY_SCRIPTPUBKEY_P2WSH_LEN];	
    unsigned char script_p2wsh_p2sh[WALLY_SCRIPTPUBKEY_P2SH_LEN];

    if (WALLY_OK != wally_scriptpubkey_multisig_from_bytes(pubkey_bytes, n*EC_PUBLIC_KEY_LEN,
            m, 0, script, script_len, &script_len)) {
        return exit_error("failed to create multisig script");
    }
    free(pubkey_bytes);
    if (WALLY_OK != wally_scriptpubkey_p2sh_from_bytes(script, script_len,
   	    WALLY_SCRIPT_HASH160, script_p2sh, WALLY_SCRIPTPUBKEY_P2SH_LEN, &written)) {
        return exit_error("failed to create multisig-p2sh script");
    }
	
    if (WALLY_OK != wally_witness_program_from_bytes(script, script_len,
	    WALLY_SCRIPT_SHA256, script_p2wsh, WALLY_SCRIPTPUBKEY_P2WSH_LEN, &written)) {
        return exit_error("failed to create multisig-p2wsh script");
    }

    if (WALLY_OK != wally_scriptpubkey_p2sh_from_bytes(script_p2wsh, WALLY_SCRIPTPUBKEY_P2WSH_LEN,
	    WALLY_SCRIPT_HASH160, script_p2wsh_p2sh, WALLY_SCRIPTPUBKEY_P2SH_LEN, &written)) {
        return exit_error("failed to create multisig-p2wsh-p2sh script");
    }

    fprintf(output, "## multisig\n");
    print_hex(output, script, script_len);
    fprintf(output, "\n");

    fprintf(output, "## p2sh(multisig)\n");
    print_hex(output, script_p2sh, WALLY_SCRIPTPUBKEY_P2SH_LEN);
    fprintf(output, "\n");
    print_hex(output, script, script_len);
    fprintf(output, "\n");

    fprintf(output, "## p2wsh(multisig)\n");
    print_hex(output, script_p2wsh, WALLY_SCRIPTPUBKEY_P2WSH_LEN);
    fprintf(output, "\n");
    print_hex(output, script, script_len);
    fprintf(output, "\n");

    fprintf(output, "## p2sh(p2wsh(multisig))\n");
    print_hex(output, script_p2wsh_p2sh, WALLY_SCRIPTPUBKEY_P2SH_LEN);
    fprintf(output, "\n");
    print_hex(output, script_p2wsh, WALLY_SCRIPTPUBKEY_P2WSH_LEN);
    fprintf(output, "\n");
    print_hex(output, script, script_len);
    fprintf(output, "\n");
    return 0;
}

int cmd_usage(int argc, char** argv)
{
    printf("---- walletutil ----\n");
    printf("commands: \n");
    printf(" - validate-mnemonic:\n");
    printf("   accepts a bip39 mnemonic via STDIN and\n");
    printf("   returns the 0 exit code if it is valid\n");
    printf(" - multisig <m> <n> [-s|--sort]:\n");
    printf("   accepts a series of bip32 keys via STDIN\n");
    printf("   and computes various script and address\n");
    printf("   formats\n");
    printf(" - ecmult <--outfile=/path/to/file> [-u|--uncompressed]:\n");
    printf("   accepts a 32-byte private key as input and\n");
    printf("   writes the public key to a file\n");
    return 0;
}

int cmd_validate_privkey(unsigned char* priv, size_t priv_len, FILE* out)
{
    int result = wally_ec_private_key_verify(priv, priv_len);
    if (result) {
	fprintf(out, "valid");
    } else {
	fprintf(out, "invalid");
    }
    return 0;
}

int cmd_ecmult(unsigned char* priv, int compressed, FILE* out)
{
    size_t addr_pubkey_len;
    unsigned char pubkey[EC_PUBLIC_KEY_LEN];
    unsigned char* addr_pubkey;

    if (compressed) {
	addr_pubkey_len = EC_PUBLIC_KEY_LEN;
    } else {
	addr_pubkey_len = EC_PUBLIC_KEY_UNCOMPRESSED_LEN;
    }

    if (WALLY_OK != wally_ec_public_key_from_private_key(priv, EC_PRIVATE_KEY_LEN,
	    pubkey, EC_PUBLIC_KEY_LEN)) {
	return exit_error("failed to compute public key");
    }

    addr_pubkey = malloc(addr_pubkey_len);
    if (addr_pubkey_len == EC_PUBLIC_KEY_LEN) {
	memcpy(addr_pubkey, pubkey, EC_PUBLIC_KEY_LEN);
    } else {
	if (WALLY_OK != wally_ec_public_key_decompress(pubkey, EC_PUBLIC_KEY_LEN,
		addr_pubkey, EC_PUBLIC_KEY_UNCOMPRESSED_LEN)) {
            return exit_error("unable to compress public key");
	}
    }

    for (int i = 0; i < addr_pubkey_len; i++) {
	fprintf(out, "%c", addr_pubkey[i]);
    }

    free(addr_pubkey);
    
    return 0;
}

int main(int argc, char** argv)
{
    if (argc == 1) {
        return cmd_usage(argc, argv);
    }

    int result;
    if (0 == strcmp(argv[1], "validate-mnemonic")) {
	if (WALLY_OK != wally_init(0)) {
            return exit_error("couldn't init libwally");
	}
        
        char mnemonic[MNEMONIC_MAX_SIZE]; 
        int c, i;
        for (i = 0; i < MNEMONIC_MAX_SIZE && (c = getchar()) != EOF; ++i) {
            mnemonic[i] = c;
        }
        mnemonic[i] = '\0';
	result = cmd_validate_mnemonic(mnemonic);
	wally_cleanup(0);
    } else if (0 == strcmp(argv[1], "create-mnemonic")) {
	int c, arglen;
	size_t entlen;
	unsigned char entropy[BIP39_ENTROPY_LEN_320];
	FILE* entfile = NULL;
	FILE* outfile = NULL;
	FILE* output = stdout;
	for (int i = 2; i < argc; i++) {
            arglen = strlen(argv[i]);
	    if (arglen > 9 && 0 == strncmp("--entfile=", argv[i], 10)) {
                if (entfile) {
	            return exit_error("duplicate entfile");
		} else if (NULL == (entfile = fopen(argv[i]+10, "r"))) {
	            return exit_error("unable to open privfile for reading");
		}
	    } else if (arglen > 9 && 0 == strncmp("--outfile=", argv[i], 10)) {
		if (outfile) {
		    return exit_error("duplicate outfile");
		} else if (outfile = fopen(argv[i]+10, "w")) {
	            output = outfile;
		} else {
                    return exit_error("failed to open outfile for writing");
                }
	    } else {
		return exit_error("unknown flag");
	    }
	}

        for (entlen = 0; entlen <= BIP39_ENTROPY_LEN_320 && (c = fgetc(entfile)) != EOF; ++entlen) {
	    entropy[entlen] = c;
	}
	// both these must be met to have read the key correctly
	if (!(entlen == BIP39_ENTROPY_LEN_128 || entlen == BIP39_ENTROPY_LEN_160 ||
	      entlen == BIP39_ENTROPY_LEN_192 || entlen == BIP39_ENTROPY_LEN_224 ||
	      entlen == BIP39_ENTROPY_LEN_256 || entlen == BIP39_ENTROPY_LEN_288 ||
	      entlen == BIP39_ENTROPY_LEN_320) && c == EOF) {
	    return exit_error("failed to read private key file");
	}
	if (WALLY_OK != wally_init(0)) {
	    return exit_error("failed to init libwally");
	}
	result = cmd_create_mnemonic(entropy, entlen, output);
	wally_cleanup(0);
	if (outfile) {
	    fclose(outfile);
        }
    } else if (0 == strcmp(argv[1], "multisig")) {	
        if (argc < 5) {
            return exit_error("m, n, and path required as arguments\n");
        }
        int m, n, sort = 0;
	char *path, *end;
	FILE* input = stdin;
        FILE* output = stdout;
	FILE* xpubfile = NULL;
	FILE* outfile = NULL;
	m = strtol(argv[2], &end, 10);
        if (m == 0 || m > 16) {
            return exit_error("invalid value for num sigs");
        }
        n = strtol(argv[3], &end, 10);
        if (n == 0 || n > 16) {
            return exit_error("invalid value for num keys");
        }
	if (m > n) {
	    return exit_error("num signers cannot be greater than num keys");
	}
        path = argv[4];
        for (int i = 5; i < argc; i++) {
            int arglen = strlen(argv[i]);
	    if (arglen > 10 && 0 == strncmp("--xpubfile=", argv[i], 11)) {
                if (xpubfile) {
	            return exit_error("duplicate xpubfile");
		} else if (xpubfile = fopen(argv[i]+11, "r")) {
                    input = xpubfile;
		} else {	
	            return exit_error("unable to open xpubfile for reading");
		}
            } else if (strcmp(argv[i], "--sort") == 0 || strcmp(argv[i], "-s")) {
    	        sort = 1;
            } else {
   	        return exit_error("unknown flag");
            }
        }
	
	size_t path_str_len = strlen(path);
	if (WALLY_OK != wally_init(0)) {
	    return exit_error("couldn't init libwally");
	}

        char xpub[113];
	struct ext_key keys[n];
        for (int i = 0; i < n; i++) {
	    if (xpubfile == NULL) {    
                printf("please enter xpub %d\n", i);
	    }
	    mygetline(input, xpub, 113);
	    if (WALLY_OK != bip32_key_from_base58(xpub, &keys[i])) {
  	        return exit_error("invalid xpub");
	    }
	    memset(xpub, 0, 113);
        }
	result = cmd_multisig(keys, path, path_str_len, m, n, sort, output);
	wally_cleanup(0);
	if (outfile) {
	    fclose(outfile);
	}
	if (xpubfile) {
	    fclose(outfile);
	}
    } else if (0 == strcmp(argv[1], "ecmult")) {
	FILE* input = stdin;
	FILE* output = stdout;
	FILE* outfile = NULL;
	FILE* privfile = NULL;
	int compressed = 1;
	int arglen, i, c;
	for (i = 2; i < argc; i++) {
            arglen = strlen(argv[i]);
	    if (arglen > 10 && 0 == strncmp("--privfile=", argv[i], 11)) {
                if (privfile) {
	            return exit_error("duplicate privfile");
		} else if (privfile = fopen(argv[i]+11, "r")) {
		    input = privfile;
		} else {
	            return exit_error("unable to open privfile for reading");
		}
	    } else if (arglen > 9 && 0 == strncmp("--outfile=", argv[i], 10)) {
		if (outfile) {
		    return exit_error("duplicate outfile");
		} else if (outfile = fopen(argv[i]+10, "w")) {
	            output = outfile;
		} else {
                    return exit_error("failed to open outfile for writing");
                }
	    } else if (0 == strcmp("-u", argv[i]) || 0 == strcmp("--uncompressed", argv[i])) {
		compressed = 0;
	    } else {
		return exit_error("unknown flag");
	    }
	}

	unsigned char priv[EC_PRIVATE_KEY_LEN];
        for (i = 0; i <= EC_PRIVATE_KEY_LEN && (c = fgetc(privfile)) != EOF; ++i) {
	    priv[i] = c;
	}
	// both these must be met to have read the key correctly
	if (!(i == EC_PRIVATE_KEY_LEN && c == EOF)) {
	    return exit_error("failed to read private key file");
	}        
	if (WALLY_OK != wally_init(0)) {
	    return exit_error("failed to init libwally");
	}
	result = cmd_ecmult(priv, compressed, output);
	wally_cleanup(0);
	if (outfile) {
	    fclose(outfile);
        }
	if (privfile) {
	    fclose(privfile);
	}
    } else if (0 == strcmp(argv[1], "-h") || 0 == strcmp(argv[1], "help")) {
	result = cmd_usage(argc, argv);
    } else {
	result = exit_error("unknown command, try help (-h) for usage");
    }

    wally_cleanup(0);
    return result;
}
