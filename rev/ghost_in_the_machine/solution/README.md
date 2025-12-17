# ghost_in_the_machine Solution

```c
uint16_t rol(uint16_t value, int shift) {
    return (value << shift) | (value >> (16 - shift));
}

uint16_t ror(uint16_t value, int shift) {
    return (value >> shift) | (value << (16 - shift));
}

uint16_t F1(uint16_t value, uint16_t key) {
    uint16_t term1 = rol(value, 5) + key;
    uint16_t term2 = (value >> 3) * key;
    return term1 ^ term2;
}

uint16_t F2(uint16_t value, uint16_t key) {
    uint16_t term1 = ror(value, 7) - key;
    uint16_t divisor = key | 1; 
    uint16_t term2 = value / divisor;

    return term1 ^ term2;
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
```

### nite{cr4ck_7h3_5h311_4nd_9h057_70_g3t_7h3_7ru7h}

[Solve script](solve.py)
