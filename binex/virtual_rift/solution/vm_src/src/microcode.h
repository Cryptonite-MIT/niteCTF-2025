#include <stdint.h>


typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint16_t opcode_id;
    uint16_t code_length;
    uint32_t checksum;
} MicrocodeHeader;
