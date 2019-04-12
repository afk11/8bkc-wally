#include <stdio.h>
#include <string.h>
#include "wallyutil_bip32.h"
#include "wallyutil_bip39.h"

int assert_bip32_path_attrs(char *test, char* path, int pathLen,
        uint32_t* expected_derivs, int expect_num_derivs, int expect_public) {
    uint32_t derivs[BIP32_MAX_DERIVATIONS];
    size_t num_derivs;
    int public;

    if (!bip32_parse_absolute_path(path, pathLen,
        derivs, &num_derivs, &public)) {
        printf("parsing path in test %s\n", test);
        return 0;
    }
    if (public != expect_public) {
        printf("parsing public flag in test %s", test);
        return 0;
    }
    if (num_derivs != expect_num_derivs) {
        printf("test %s: num_derivs (%ld) didn't match expected (%d)", test, num_derivs, expect_num_derivs);
        return 0;
    }
    for (size_t i = 0; i < expect_num_derivs; i++) {
        if (derivs[i] != expected_derivs[i]) {
            printf("test %s: path index %zu (%d) != expected (%d)",
                test, i, derivs[i], expected_derivs[i]);
            return 0;
        }
    }
    return 1;
}

int test_bip32() {
    uint32_t derivs[BIP32_MAX_DERIVATIONS];
    size_t num_derivs;
    int public, ret;
    uint32_t noderivs[0];

    // check *public
    char* rootPriv = "m";
    if (!assert_bip32_path_attrs("rootPriv",
        rootPriv, strlen(rootPriv), noderivs, 0, 0)) {
        return 0;
    }
    char* rootPub = "M";
    if (!assert_bip32_path_attrs("rootPub",
        rootPub, strlen(rootPub), noderivs, 0, 1)) {
        return 0;
    }

    // check 1 level paths - private, hardened with h
    char *privDerivH = "m/0h";
    uint32_t privDerivDerivs[1] = {0 | 1 << 31};
    if (!assert_bip32_path_attrs("privDerivH",
        privDerivH, strlen(privDerivH), privDerivDerivs,
        1, 0)) {
        return 0;
    }
    // check 1 level paths - private, hardened with '
    char *privDerivDash = "m/0'";
    if (!assert_bip32_path_attrs("privDerivDash",
        privDerivDash, strlen(privDerivDash), privDerivDerivs,
        1, 0)) {
        return 0;
    }
    // check 1 level paths - public
    char* pubDeriv = "M/0";
    uint32_t pubDerivDerivs[1] = {0};
    if (!assert_bip32_path_attrs("pubDeriv",
        pubDeriv, strlen(pubDeriv), pubDerivDerivs, 1, 1)) {
        return 0;
    }
    // check 1 level paths - public, hardened
    char* pubHardenedDeriv = "M/0'";
    uint32_t pubHardenedDerivDerivs[1] = {0|(1<<31)};
    if (!assert_bip32_path_attrs("pubHardenedDeriv",
        pubHardenedDeriv, strlen(pubHardenedDeriv), pubHardenedDerivDerivs, 1, 1)) {
        return 0;
    }
    char* bip44PubAccount = "M/44'/0'/0'";
    uint32_t bip44PubDerivs[] = {44 | (1 << 31), 0 | (1 << 31), 0 | (1 << 31)};
    if (!assert_bip32_path_attrs("bip44PubAccount", bip44PubAccount, strlen(bip44PubAccount), bip44PubDerivs, 3, 1)) {
        return 0;
    }

    char* bip44Address = "M/44'/0'/0'/2/292";
    uint32_t bip44AddressDerivs[] = {44|1<<31, 0|(1<<31), 0|(1<<31), 2, 292};
    if (!assert_bip32_path_attrs("bip44Address", bip44Address, strlen(bip44Address), bip44AddressDerivs, 5, 1)) {
        return 0;
    }

    size_t n_invalid = 2;
    char* invalid[] = {
        "",
        "z",
        "M[",
        "M//",
        "M/1/",
        "M/1//",
        "Mh",
        "M'",
        "mh",
        "m'",
        "m/-1",
        "m/9''",
        "m/9hh",
        "m/9h'",
    };

    for (size_t i = 0; i < n_invalid; i++) {
        if (bip32_parse_absolute_path(invalid[i], strlen(invalid[i]), derivs, &num_derivs, &public)) {
            printf("accepted invalid path: `%s`\n", invalid[i]);
            return 0;
        }
    }

    return 1;
}

int test_bip39(void) {
    if (BIP39_MNEMONIC_SIZE_128 != bip39_word_count_from_entropy_size(128)) {
        printf("wordcount from entropy_size: 128 != 12\n");
        return 0;
    }
    if (128 != bip39_entropy_size_from_word_count(BIP39_MNEMONIC_SIZE_128)) {
        printf("bip_entropy_size_from_word_count: expected 128\n");
        return 0;
    }
    if (BIP39_MNEMONIC_SIZE_160 != bip39_word_count_from_entropy_size(160)) {
        printf("wordcount from entropy_size: 160 != 15\n");
        return 0;
    }
    if (160 != bip39_entropy_size_from_word_count(BIP39_MNEMONIC_SIZE_160)) {
        printf("bip_entropy_size_from_word_count: expected 160\n");
        return 0;
    }
    if (BIP39_MNEMONIC_SIZE_192 != bip39_word_count_from_entropy_size(192)) {
        printf("wordcount from entropy_size: 192 != 18\n");
        return 0;
    }
    if (192 != bip39_entropy_size_from_word_count(BIP39_MNEMONIC_SIZE_192)) {
        printf("bip_entropy_size_from_word_count: expected 192\n");
        return 0;
    }
    if (BIP39_MNEMONIC_SIZE_224 != bip39_word_count_from_entropy_size(224)) {
        printf("wordcount from entropy_size: 224 != 21\n");
        return 0;
    }
    if (224 != bip39_entropy_size_from_word_count(BIP39_MNEMONIC_SIZE_224)) {
        printf("bip_entropy_size_from_word_count: expected 224\n");
        return 0;
    }
    if (BIP39_MNEMONIC_SIZE_256 != bip39_word_count_from_entropy_size(256)) {
        printf("wordcount from entropy_size: 256 != 24\n");
        return 0;
    }
    if (256 != bip39_entropy_size_from_word_count(BIP39_MNEMONIC_SIZE_256)) {
        printf("bip_entropy_size_from_word_count: expected 256\n");
        return 1;
    }
    if (0 != bip39_entropy_size_from_word_count(11)) {
        printf("bip39_entropy_size_from_word_count: accepted invalid word count 11");
        return 0;
    }
    if (0 != bip39_word_count_from_entropy_size(1024)) {
        printf("bip39_word_count_from_entropy_size: accepted invalid length: 1024\n");
        return 0;
    }
    return 1;
}

int main(void) {
    if (!test_bip32()) {
        printf("bip32 test");
        return 1;
    }
    if (!test_bip39()) {
        printf("bip39 test");
        return 1;
    }
    return 0;
}
