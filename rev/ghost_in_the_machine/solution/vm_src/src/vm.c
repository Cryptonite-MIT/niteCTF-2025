#include "vm.h"
#include "cpu.h"
#include "opcode.h"
#include "microcode.h"
#include <fcntl.h>
#include <stdlib.h>
#include <ncurses.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

uint8_t read_ram_byte(VM* vm, uint16_t address);
uint16_t read_ram_word(VM* vm, uint16_t address);
uint32_t read_ram_dword(VM* vm, uint16_t address);
void write_ram_word(VM* vm, uint16_t address, uint16_t value);
void write_ram_byte(VM* vm, uint16_t address, uint8_t value);
uint32_t read_rom_dword(VM* vm, uint16_t address);

extern uint8_t handlers_bin[];
extern int handlers_bin_len;

void load_memory(VM* vm) {
    vm->ram_memory = (uint8_t*)malloc(RAM_SIZE);
    memset(vm->ram_memory, 0, RAM_SIZE);
}


int probe_and_build_jump_table(VM* vm) {
    memset(&vm->microcode_jump_table, -1, sizeof(vm->microcode_jump_table));    

    vm->handlers = handlers_bin;
    uint8_t *rom_base = (uint8_t *)vm->handlers;
    uint8_t *scanner = rom_base;
    uint8_t * rom_end = rom_base + handlers_bin_len;

    const uint8_t magic_bytes[] = {0x32, 0x43, 0x87, 0xAF};

    while(scanner < rom_end) {
        if(memcmp(scanner, magic_bytes, sizeof(magic_bytes)) == 0) {
            MicrocodeHeader header;

            memcpy(&header, scanner, sizeof(MicrocodeHeader));

            if(scanner + sizeof(MicrocodeHeader) + header.code_length > rom_end) {
                fprintf(stderr, "Error: Found corrupted header at offset %ld.\n", scanner - rom_base);
                scanner++;
                continue;
            }

            vm->microcode_jump_table[header.opcode_id] = ((scanner - rom_base) + sizeof(MicrocodeHeader));

            scanner += sizeof(MicrocodeHeader) + header.code_length;
        } else {
            scanner += sizeof(MicrocodeHeader);
        }
    }
    return 0;
}

VM* create_vm() {
    VM* vm = (VM*)malloc(sizeof(VM));
    memset(&vm->cpu_state, 0, sizeof(CPU_State)) ;

    load_memory(vm);
    probe_and_build_jump_table(vm);
    // Initialize virtual registers (SP, LCL, ARG)
    write_ram_word(vm, 22, 256); // SP starts at 256
    //write_ram_word(vm, 24, 400); // LCL base
    //write_ram_word(vm, 26, 500); // ARG base
    //write_ram_word(vm, 28, 600); // that pointer
    write_ram_word(vm, 30, DATA_SEGMENT); // data segment start
    return vm;
}

void destroy_vm(VM* vm) {
    if (vm) {
        free(vm);
    }
}

void execute_micro_program(VM* vm, uint16_t base_address) {
    CPU_State* state = &vm->cpu_state;
    
    state->registers.pc.out = 0;

    while (1) {
        state->cpu_in.instruction = read_rom_dword(vm, base_address + state->registers.pc.out);

        CPU(state, &state->cpu_in);

        if (state->cpu_out.load) {
            if(state->cpu_out.size == 1)
                write_ram_byte(vm, state->cpu_out.addressM, state->cpu_out.out);
            else
                write_ram_word(vm, state->cpu_out.addressM, state->cpu_out.out);

        }
        
        if((INS(state->cpu_in.instruction)) == 2) {
            if(state->cpu_out.size == 1)
                state->cpu_in.inM = read_ram_byte(vm, state->cpu_out.addressM);
            else
                state->cpu_in.inM = read_ram_word(vm, state->cpu_out.addressM);
        }

        if (state->cpu_out.pc == 0xFFFF) {
            break;
        }
    }
}

void run_vm(VM* vm) {
    uint16_t main_pc = 0; 
    while(1) {
        Opcode opcode = (Opcode)read_ram_byte(vm, BASE + main_pc);
        main_pc += 1;
        uint16_t micro_program_addr = vm->microcode_jump_table[opcode];


        switch (opcode) {
            case OP_EXIT: {
                exit(0);
            }
            case OP_PUSH_CONSTANT: {
                uint16_t operand = read_ram_word(vm, BASE + main_pc);
                main_pc += 2;
                write_ram_word(vm, MESSAGE_BOX_BASE_1, operand);
                break;
            }
            case OP_PEEK:
            case OP_POKE:
            case OP_PUSH_ARGUMENT:
            case OP_PUSH_LOCAL:
            case OP_POP_ARGUMENT:
            case OP_POP_LOCAL: {
                uint8_t operand = read_ram_byte(vm, BASE + main_pc);
                main_pc += 1;
                write_ram_word(vm, MESSAGE_BOX_BASE_1, operand);
                break;
            }
            case OP_FUNCTION: {
                uint8_t n_locals = read_ram_byte(vm, BASE + main_pc);
                main_pc += 1;
                write_ram_word(vm, MESSAGE_BOX_BASE_1, n_locals);
                break;
            }
            case OP_CALL: {
                uint16_t jump_address = read_ram_word(vm, BASE + main_pc);
                main_pc += 2;
                uint8_t n_args = read_ram_byte(vm, BASE + main_pc);
                main_pc += 1;
                uint16_t return_address = main_pc;
                write_ram_word(vm, MESSAGE_BOX_BASE_1, return_address);
                write_ram_word(vm, MESSAGE_BOX_BASE_2, n_args);

                if(micro_program_addr != 0) {
                    execute_micro_program(vm, micro_program_addr);
                }

                main_pc = jump_address;
                continue;
            }
            case OP_RETURN: {
                if (micro_program_addr != 0) {
                    execute_micro_program(vm, micro_program_addr);
                }
                main_pc = read_ram_word(vm, MESSAGE_BOX_BASE_1);
                continue;
            }
            case OP_IFGOTO: {
                uint16_t jump_address = read_ram_word(vm, BASE + main_pc);
                main_pc += 2;
                if (micro_program_addr != 0) {
                    execute_micro_program(vm, micro_program_addr);
                }

                uint16_t condition = read_ram_word(vm, MESSAGE_BOX_BASE_1);
                if (condition != 0) {
                    main_pc = jump_address;
                }
                continue;
            }
            case OP_GOTO: {
                uint16_t jump_address = read_ram_word(vm, BASE + main_pc);
                main_pc = jump_address;
                continue;
            }
            case OP_PRINT: {
                uint8_t format_specifier = read_ram_byte(vm, BASE + main_pc);
                main_pc += 1;
                if (micro_program_addr != 0) {
                    execute_micro_program(vm, micro_program_addr);
                }
                uint16_t offset = read_ram_word(vm, MESSAGE_BOX_BASE_1);
                uint16_t length = read_ram_word(vm, MESSAGE_BOX_BASE_2);
                uint16_t number_written = 0;


                if(length > 0 && offset + length < RAM_SIZE) {
                    switch(format_specifier) {
                        case c: {
                            number_written = write(STDOUT_FILENO, vm->ram_memory + DATA_SEGMENT + offset, length);
                            break;
                        }
                        case xb: {
                            for(int i=0; i<length; i++) {
                                printf("%x", *(uint8_t*)(vm->ram_memory + DATA_SEGMENT + offset + i));
                            }
                            break;
                        }
                        case xw: {
                            for(int i=0; i<length; i++) {
                                printf("%x", *(uint16_t*)(vm->ram_memory + DATA_SEGMENT + offset + i));
                            }
                            break;
                        }
                        case ib: {
                            for(int i=0; i<length; i++) {
                                printf("%d", *(uint8_t*)(vm->ram_memory + DATA_SEGMENT + offset + i));
                            }
                            break;
                        }
                        case iw: {
                            for(int i=0; i<length; i++) {
                                printf("%d", *(uint16_t*)(vm->ram_memory + DATA_SEGMENT + offset + i));
                            }
                            break;
                        }
                    }
                    //uint8_t *output = NULL;
                    //memcpy(output, vm->ram_memory + DATA_SEGMENT + offset, length);
                }
                write_ram_word(vm, MESSAGE_BOX_BASE_1, number_written);
                continue;
            }
            case OP_READ: {
                if (micro_program_addr != 0) {
                    execute_micro_program(vm, micro_program_addr);
                }
                uint16_t offset = read_ram_word(vm, MESSAGE_BOX_BASE_1);
                uint16_t length = read_ram_word(vm, MESSAGE_BOX_BASE_2);
                uint16_t char_read = 0;
                if(length > 0 && offset + length < RAM_SIZE) {
                    char_read = read(STDIN_FILENO, vm->ram_memory + DATA_SEGMENT + offset, length);
                }

                write_ram_word(vm, MESSAGE_BOX_BASE_1, char_read);
                continue;

            }
            default:
                break;
        }
            
        if (micro_program_addr != -1 && opcode != OP_CALL && opcode != OP_RETURN && opcode != OP_IFGOTO) {
            execute_micro_program(vm, micro_program_addr);
        }
        //usleep(16000);
    }
}

uint8_t read_ram_byte(VM* vm, uint16_t address) {
    return vm->ram_memory[address];
}

uint16_t read_ram_word(VM* vm, uint16_t address) {
    uint16_t value = vm->ram_memory[address];
    value |= vm->ram_memory[address + 1] << 8;
    return value;
}

uint32_t read_ram_dword(VM* vm, uint16_t address) {
    if (address < ROM_SIZE - 3) {
        uint32_t value = vm->ram_memory[address];
        value |= vm->ram_memory[address + 1] << 8;
        value |= vm->ram_memory[address + 2] << 16;
        value |= vm->ram_memory[address + 3] << 24;
        return value;
    }
    return 0;
}

void write_ram_word(VM* vm, uint16_t address, uint16_t value) {
    *(uint16_t*)(&vm->ram_memory[address]) = value;
}

void write_ram_byte(VM* vm, uint16_t address, uint8_t value) {
    vm->ram_memory[address] = value;
    //vm->ram_memory[address + 1] = (value >> 8) & 0xFF;
}

uint32_t read_rom_dword(VM* vm, uint16_t address) {
    if (address < ROM_SIZE - 3) {
        uint32_t value = vm->handlers[address];
        value |= vm->handlers[address + 1] << 8;
        value |= vm->handlers[address + 2] << 16;
        value |= vm->handlers[address + 3] << 24;
        return value;
    }
    return 0;
}
