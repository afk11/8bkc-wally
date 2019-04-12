#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "8bkc-hal.h"
#include "8bkc-ugui.h"
#include "appfs.h"
#include "powerbtn_menu.h"
#include "ugui.h"

#include "esp_system.h"

#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_bip39.h>
#include <wallyutil_bip32.h>
#include <wallyutil_bip39.h>

#define TITLE "Wally"
#define BIP39_NUM_MNEMONIC_SIZES 5

// fill `len` elements in entropy with a random uint32_t
static void reset_entropy(uint32_t* entropy, size_t len)
{
    for(int i = 0; i < len; ++i) {
        entropy[i] = esp_random();
    }
}
// takes input and separator, and loops until n'th word is found.
// if found, creates a copy and writes pointer to dest, returning 0.
// resulting pointer should be free'd by the caller.
// if we run out of words, 1 will be returned.
int strnword(char *input, char* separator, int n, char** dest) {
    char* copy;
    char* original;
    char* wordcopy;
    if (NULL == (copy = malloc(strlen(input)+1))) {
	// trouble on the high seas
        return 0;
    }
    strcpy(copy, input);
    original = copy;    
    int word_n = 0;
    char* word;
    while ((word = strsep(&copy, separator))) {
        if (word_n == n) {
            break;
        }
        ++word_n;
    }

    if (word_n != n) {
	//memset(copy, 0, strlen(input));
        free(copy);
        return 0;
    }

    wordcopy = malloc(strlen(word)+1);
    strcpy(wordcopy, word);
    //memset(copy, 0, strlen(input));
    free(original);
    *dest = wordcopy;
    return 1;
}

int get_keydown() {
    static int old_buttons = 0xffff;
    int new_buttons = kchal_get_keys();
    int ret = (old_buttons ^ new_buttons) & new_buttons;
    old_buttons = new_buttons;
    return ret;
}

uint16_t centered_text_offset(char *text, uint8_t font_width) {
    size_t text_length = strlen(text) + 1;
    return (KC_SCREEN_W / 2) - ((text_length / 2) * font_width);
}

int do_confirm_screen() {
    while (1) {
        int btn = get_keydown();
        if (btn & KC_BTN_POWER) {
            kchal_exit_to_chooser();
        }

        if (btn & KC_BTN_A) {
            return 1;
        } else if (btn & KC_BTN_B) {
            return 0;
        }
    }
}

int print_and_confirm(char *msg) {
    kcugui_cls();
    UG_PutString(0, 0, msg);
    kcugui_flush();
    return do_confirm_screen();
}

void do_close_screen() {
    uint8_t font_width = 6;
    uint8_t font_height = 8;

    kcugui_cls();
    UG_PutString(0, 0, "Closing");
    kcugui_flush();

    while (1) {
        int btn = get_keydown();
        if (btn) {
            kchal_exit_to_chooser();
        }
    }
}

void draw_show_int_screen(int i) {
    uint8_t font_width = 6;
    uint8_t font_height = 8;

    kcugui_cls();
    UG_SetForecolor(C_LAWN_GREEN);
    UG_PutString(centered_text_offset(TITLE, font_width), 0, TITLE);

    char str[8];
    sprintf(str, "%d", i);
    UG_FontSetHSpace(0);
    UG_SetForecolor(C_TOMATO);
    UG_PutString(centered_text_offset(str, font_width), 3 * font_height + 6, str);
    kcugui_flush();
}

int draw_show_mnemonic_word_screen(char* mnemonic, int current_word) {
    uint8_t font_width = 6;
    uint8_t font_height = 8;

    char* word;
    if (1 != strnword(mnemonic, " ", current_word, &word)) {
        return 0;
    }

    kcugui_cls();
    UG_SetForecolor(C_LAWN_GREEN);
    UG_PutString(centered_text_offset(TITLE, font_width), 0, TITLE);
    UG_FontSetHSpace(0);

    char num[2];
    sprintf(num, "%d", current_word + 1);
    UG_SetForecolor(C_ANTIQUE_WHITE);
    UG_PutString(centered_text_offset(num, font_width), 2 * font_height + 3, num);
    UG_FontSetHSpace(0);
    UG_SetForecolor(C_TOMATO);
    UG_PutString(centered_text_offset(word, font_width), 3 * font_height + 6, word);
    kcugui_flush();
    wally_free_string(word);

    return 1;
}

int do_generate_mnemonic(int wordcount, char **mnemonic) {
    uint8_t font_width = 6;
    uint8_t font_height = 8;

    int current_word = 0;
    int max_word = 0;

    int entropy_bits = bip39_entropy_size_from_word_count(wordcount);
    if (-1 == entropy_bits) {
	print_and_confirm("ERR:ent_from_word_count error");
	return 0;
        // problem captain!
    } 

    size_t entlen = entropy_bits/32;
    uint32_t entropy[entlen];
    reset_entropy(entropy, entlen);

    if (WALLY_OK != bip39_mnemonic_from_bytes(NULL, 
            (unsigned char *)entropy, entropy_bits/8, mnemonic)) {
        print_and_confirm("ERR:mnemonic_from_bytes");
        return 0;
    }

    while (1) {
        if (!draw_show_mnemonic_word_screen(*mnemonic, current_word)) {
            return 0;
        }

        int btn = get_keydown();
        if (btn & KC_BTN_POWER) {
            kchal_exit_to_chooser();
        }
        if (btn & KC_BTN_LEFT) {
            if (current_word > 0) {
                --current_word;
            }
        } else if (btn & KC_BTN_RIGHT) {
            if (current_word < wordcount-1) {
                ++current_word;
                if (current_word > max_word) {
			++max_word;
		}
            }
        } else if (btn & KC_BTN_A) {
            // If user has finished recording the seed save
            // our state. Otherwise resume display of the seed.
	    if (max_word < wordcount-1) {
            	kcugui_cls();
                UG_PutString(0, 0, "Please read your entire seed");
		kcugui_flush();
		do_confirm_screen();
	    } else {
                kcugui_cls();
                UG_PutString(0, 0, "Have you saved your seed?");
                kcugui_flush();
                if (do_confirm_screen()) {
                    return 1;
                }
	    }
        }
    }
    return 1;
}

// returns whatever mnemonic size the user chooses
int do_select_mnemonic_word_count() {
    uint8_t font_width = 6;
    uint8_t font_height = 8;
    int current_size = 0;
    // can't assign arrays this way with a 'dynamic' size
    int sizes[BIP39_NUM_MNEMONIC_SIZES] = {
        BIP39_MNEMONIC_SIZE_128, BIP39_MNEMONIC_SIZE_160, 
        BIP39_MNEMONIC_SIZE_192, BIP39_MNEMONIC_SIZE_224,
        BIP39_MNEMONIC_SIZE_256,
    };

    while (1) {
        draw_show_int_screen(sizes[current_size]);
        int btn = get_keydown();
        if (btn & KC_BTN_POWER) {
            kchal_exit_to_chooser();
        }
        if (btn & KC_BTN_LEFT) {
            if (current_size > 0) {
                --current_size;
            }
        } else if (btn & KC_BTN_RIGHT) {
            if (current_size < BIP39_NUM_MNEMONIC_SIZES-1) {
                ++current_size;
            }
        } else if (btn & KC_BTN_A) {
	    return sizes[current_size];
        }
    }
}

void do_list_files_screen() {
    print_and_confirm("list files");

    if (ESP_OK != appfsInit(APPFS_PART_TYPE, APPFS_PART_SUBTYPE)) {
        print_and_confirm("failed to init appfs");
        wally_cleanup(0);
        do_close_screen();
    }

    appfs_handle_t fh = APPFS_INVALID_FD;
    char *filename;
    int filesize;
	while (APPFS_INVALID_FD != (fh = appfsNextEntry(fh))) {
        appfsEntryInfo(fh, &filename, &filesize);
        print_and_confirm(filename);
    }
    print_and_confirm("done listing files");
}

void app_main() {
    kchal_init();
    kcugui_init();
    UG_FontSelect(&FONT_6X8);
    if (WALLY_OK != wally_init(0)) {
        print_and_confirm("failed to init wally");
        do_close_screen();
    }

    const unsigned char seed[EC_PRIVATE_KEY_LEN] = {
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
            0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
            0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
            0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };

    unsigned char pubKey[EC_PUBLIC_KEY_LEN];

    if (WALLY_OK != wally_ec_public_key_from_private_key(seed, EC_PRIVATE_KEY_LEN, pubKey, EC_PUBLIC_KEY_LEN)) {
        print_and_confirm("failed to create pubkey");
        wally_cleanup(0);
        do_close_screen();
    }

    print_and_confirm("select mnemonic size");
    // wallet type (pub|priv?)
    // if priv, 
    //   word count?
    //   mnemonic?
    //   save mnemonic
    // have public data:
    //   xpub, and wallet type
    int wordcount = do_select_mnemonic_word_count();

    char* mnemonic;
    if (!do_generate_mnemonic(wordcount, &mnemonic)) {
        wally_cleanup(0);
	do_close_screen();
    }

    wally_cleanup(0);
    do_close_screen();
}
