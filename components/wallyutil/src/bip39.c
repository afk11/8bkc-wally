#include <wallyutil_bip39.h>

int bip39_word_count_from_entropy_size(int ent) {
    if (ent == 128 || ent == 160 || ent == 192 ||
        ent == 224 || ent == 256) {
        return (ent+ent/32)/11;
    }
    return 0;
}

int bip39_entropy_size_from_word_count(int wc) {
    if (wc == 12 || wc == 15 || wc == 18 ||
        wc == 21 || wc == 24) {
        return (32*(wc*11))/33;
    }
    return 0;
}

