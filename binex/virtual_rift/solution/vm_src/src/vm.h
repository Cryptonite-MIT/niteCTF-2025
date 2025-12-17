#ifndef VM_H
#define VM_H

#include <stdint.h>
#include "cpu.h"

#define RAM_SIZE 0xFFFF // 65535 bytes, 32767 words
#define ROM_SIZE 0xFFFF  // 65535 bytes, 32767 words

#define BASE 0x2000
#define DATA_SEGMENT 0x1000
#define STACK 256
#define MESSAGE_BOX_BASE_1 32
#define MESSAGE_BOX_BASE_2 34

typedef enum {
    c,
    xb,
    xw,
    ib,
    iw
} FORMAT_SPECIFIER;

typedef struct {
    CPU_State cpu_state;
    uint8_t* ram_memory;
    uint8_t* handlers;
    uint16_t microcode_jump_table[100];
} VM;

VM* create_vm();
void destroy_vm(VM* vm);
void run_vm(VM* vm);
uint8_t read_ram_byte(VM* vm, uint16_t address);
uint16_t read_ram_word(VM* vm, uint16_t address);
void write_ram_word(VM* vm, uint16_t address, uint16_t value);
uint32_t read_rom_dword(VM* vm, uint16_t address);

#endif
