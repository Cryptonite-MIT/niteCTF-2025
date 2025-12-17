#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

const uint16_t K1 = 13337;      // 0x3419
const uint16_t K2 = 17771;      // 0x456b
const uint16_t IV1 = 21881;     // 0x5579
const uint16_t IV2 = 28883;     // 0x70d3

uint16_t rol(uint16_t value, int shift) {
    return (value << shift) | (value >> (16 - shift));
}

uint16_t ror(uint16_t value, int shift) {
    return (value >> shift) | (value << (16 - shift));
}

uint16_t F1(uint16_t value, uint16_t key) {
    uint16_t term1 = rol(value, 5) + key;
    //printf("F1: rotate left = %x\n", term1 - key);
    uint16_t term2 = (value >> 3) * key;
    return term1 ^ term2;
}

uint16_t F2(uint16_t value, uint16_t key) {
    uint16_t term1 = ror(value, 7) - key;
    uint16_t divisor = key | 1; 
    uint16_t term2 = value / divisor;

    return term1 ^ term2;
}

void encrypt_flag(uint16_t* flag_words) {
    uint16_t feedback1 = IV1;
    for (int i = 0; i < 12; i++) {
        uint16_t keystream = F1(feedback1, K1);
        uint16_t plaintext = flag_words[i];
        uint16_t ciphertext = plaintext ^ keystream;
        flag_words[i] = ciphertext;
        feedback1 = ciphertext;
    }

    uint16_t feedback2 = IV2;
    for (int i = 0; i < 12; i++) {
        uint16_t keystream = F2(feedback2, K2);
        feedback2 = keystream;
        uint16_t plaintext = flag_words[12 + i];
        flag_words[12 + i] = plaintext ^ keystream;
    }

    for (int i = 0; i < 12; i++) {
        uint16_t temp = flag_words[i];
        flag_words[i] = flag_words[12 + i];
        flag_words[12 + i] = temp;
    }
}

void decrypt_flag(uint16_t* flag_words) {
    for (int i = 0; i < 12; i++) {
        uint16_t temp = flag_words[i];
        flag_words[i] = flag_words[12 + i];
        flag_words[12 + i] = temp;
    }

    uint16_t feedback1 = IV1;
    for (int i = 0; i < 12; i++) {
        uint16_t keystream = F1(feedback1, K1);
        uint16_t ciphertext = flag_words[i];
        uint16_t plaintext = ciphertext ^ keystream;
        flag_words[i] = plaintext;
        feedback1 = ciphertext;
    }

    uint16_t feedback2 = IV2;
    for (int i = 0; i < 12; i++) {
        uint16_t keystream = F2(feedback2, K2);
        feedback2 = keystream;
        uint16_t ciphertext = flag_words[12 + i];
        flag_words[12 + i] = ciphertext ^ keystream;
    }
}


int main() {
    char flag[48] = "nite{cr4ck_7h3_5h311_4nd_9h057_70_g3t_7h3_7ru7h}";

    uint16_t flag_data[24];

    for(int i=0; i<24; ++i) {
        flag_data[i] = (uint16_t)flag[i*2] | ((uint16_t)flag[i*2+1] << 8);
    }

    printf("Original flag:\n");
    for (int i = 0; i < 24; i++) {
        printf("%c%c", flag_data[i]&0xFF, (flag_data[i]&0xFF00) >> 8);
    }
    printf("\n\n");

    encrypt_flag(flag_data);

    printf("\nEncrypted flag:\n");
    for (int i = 0; i < 24; i++) {
        printf("%x%x", flag_data[i]&0xFF, (flag_data[i]&0xFF00) >> 8);
        //printf("%x", flag_data[i]);
    }
    printf("\n\n");

    decrypt_flag(flag_data);

    printf("Decrypted flag:\n");
    for (int i = 0; i < 24; i++) {
        printf("%c%c", flag_data[i]&0xFF, (flag_data[i]&0xFF00) >> 8);
    }
    printf("\n");

    return 0;
}
