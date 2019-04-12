#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <wallyutil_bip32.h>

int bip32_parse_absolute_path(const char* path, size_t path_len, uint32_t derivs[], size_t* num_derivs, int* public) {
    size_t start = 1;
    if (path_len < 1) {
	return 0;
    }

    // create a copy, as strtok_r modifies input
    // to preserve it's position

    // process prefix before looping through derivations
    if ('M' == path[0]) {
        if (NULL != public) {
	    *public = 1;
        }
    } else if ('m' == path[0]) {
        if (NULL != public) {
	    *public = 0;
        }
    } else {
	return 0;
    }

    if (path_len > 1) {
        if (path[1] != '/') {
            return 0;
        }
        start++;
    }

    int j = 0;
    uint32_t tmp = 0;
    size_t i;
    *num_derivs = 0;
    for (i = start; i < path_len; i++) {
        if (path[i] >= '0' && path[i] <= '9') {
	    tmp = 10 * tmp + (path[i] - '0');
	    j++; 
        } else if (path[i] == 'h' || path[i] == '\'') {
            // passed h or ' twice
            if (((tmp >> 31) & 1) != 0) {
                return 0;
            }
            tmp |= (1 << 31);
        } else if (path[i] != '/') {
            return 0;
        }

        if (path[i] == '/' || i == path_len - 1) {
            // sequential /'s are not allowed
            if (j == 0) {
                return 0;
            }
            // can't derive more than 255 levels
	    if (*num_derivs > BIP32_MAX_DERIVATIONS) {
                return 0;
	    }
            derivs[*num_derivs] = tmp;
            *num_derivs = *num_derivs + 1;
            tmp = 0;
            j = 0;
        }
    }

    if (i != path_len) {
        return 0;
    }
    return 1;
}
