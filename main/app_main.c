#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "8bkc-hal.h"
#include "8bkc-ugui.h"

#include "powerbtn_menu.h"
#include "ugui.h"
#include "esp_system.h"

#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_bip39.h>

#define TITLE "Wally"

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

static void reset_entropy(uint32_t* entropy, size_t len)
{
    for(int i = 0; i < 10; ++i) {
        entropy[i] = esp_random();
    }
}

void draw_title_screen(uint32_t* entropy, int current_word) {
    uint8_t font_width = 6;
    uint8_t font_height = 8;

    kcugui_cls();
    UG_SetForecolor(C_LAWN_GREEN);
    UG_PutString(centered_text_offset(TITLE, font_width), 0, TITLE);
    UG_FontSetHSpace(0);
    char *word;
    int word_n = 0;
    char *mnemonic, *original;
    int res;
    res = bip39_mnemonic_from_bytes(NULL, (unsigned char *)entropy, BIP39_ENTROPY_LEN_320, &mnemonic);
    if (res != WALLY_OK) {
        UG_PutString(centered_text_offset("Error", font_width), KC_SCREEN_H / 2, "Error");
        kcugui_flush();
        return;
    }
    original = mnemonic;
    while ((word = strsep(&mnemonic, " "))) {
        if (word_n == current_word) {
            break;
        }
        ++word_n;
    }
    char num[2];
    sprintf(num, "%d", current_word + 1);
    UG_SetForecolor(C_ANTIQUE_WHITE);
    UG_PutString(centered_text_offset(num, font_width), 2 * font_height + 3, num);
    UG_FontSetHSpace(0);
    UG_SetForecolor(C_TOMATO);
    UG_PutString(centered_text_offset(word, font_width), 3 * font_height + 6, word);
    kcugui_flush();
    wally_free_string(original);
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
void do_title_screen() {
    size_t entlen = 10;
    uint32_t entropy[entlen];
    reset_entropy(entropy, entlen);

    int current_word = 0;
    draw_title_screen(entropy, current_word);
    while (1) {
        int btn = get_keydown();
        if (btn & KC_BTN_POWER) {
            kchal_exit_to_chooser();
        }
        if(btn & KC_BTN_LEFT) {
            if (current_word > 0) {
                --current_word;
                draw_title_screen(entropy, current_word);
            }
        }
        else if(btn & KC_BTN_RIGHT) {
            if (current_word < 23) {
                ++current_word;
                draw_title_screen(entropy, current_word);
            }
        } else if(btn & KC_BTN_A) {
            // If user has finished recording the seed save
            // our state. Otherwise resume display of the seed.
            kcugui_cls();
            UG_PutString(0, 0, "Have you saved your seed?");
            kcugui_flush();
            if (do_confirm_screen()) {
                return;
            }
            draw_title_screen(entropy, current_word);
        }
    }
}
void print_and_confirm(char *msg) {
    kcugui_cls();
    UG_PutString(0, 0, msg);
    kcugui_flush();
    do_confirm_screen();
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

    unsigned char* pubKey = NULL;
    pubKey = malloc(EC_PUBLIC_KEY_LEN);
    if (!pubKey) {
        print_and_confirm("failed to alloc for pub key");
        wally_cleanup(0);
        do_close_screen();
    }
    print_and_confirm("gen ctx");
    if (WALLY_OK != wally_ec_public_key_from_private_key(seed, EC_PRIVATE_KEY_LEN, pubKey, EC_PUBLIC_KEY_LEN)) {
        print_and_confirm("failed to create pubkey");
        wally_cleanup(0);
        do_close_screen();
    }

    do_title_screen();
    wally_cleanup(0);
    do_close_screen();
}
