#ifndef CPU_H
#define CPU_H

#include <stdint.h>
#include "registers.h"

#define INS_LEN 20

typedef enum {
    ADDR_MODE_DIRECT = 0,
    ADDR_MODE_POST_INC = 1,
    ADDR_MODE_PRE_OFFSET = 2,
    ADDR_MODE_PRE_INC = 3
} AddrMode;

typedef enum {
    J_NULL = 0,
    JGT,
    JEQ,
    JGE,
    JLT,
    JNE,
    JLE,
    JMP
} JumpCondition;

typedef struct {
    uint16_t inM; 
    uint32_t instruction;
    uint8_t reset;
} CPU_IN;

typedef struct {
    uint16_t out;
    uint8_t fetch;
    uint8_t load;
    uint16_t addressM;
    uint16_t pc;
    uint8_t size;
} CPU_OUT;


typedef struct {
    Register a_reg;
    Register d_reg;
    Register ptr_reg;
    Register off_reg;
    PC pc;
} Registers;

// 0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 16 17 18 19
// x  x  x  d  d  d  d  c  c  c  c  c  c  c  r  r  r  r  i  i
// 19 18 17 16 15 14 13 12 11 10 9  8  7  6  5  4  3  2  1  0
#define INS(instruction) (instruction) & 0x3
#define IMM(instruction) (instruction >> 4) & 0xFFFF
#define REG1(instruction) (instruction >> 2) & 0x3
#define REG2(instruction) (instruction >> 4) & 0x3
#define COMPUTE(instruction) (instruction >> 6) & 0x7F
#define SIZE(instruction) (instruction >> 6) & 0x01
#define DEST(instruction) (instruction >> 13) & 0x0F
#define JUMP(instruction) (instruction >> 17) & 0x07

#define DEST_A(d) (d & 0x1)

#define DEST_D(d) (d >> 1) & 0x1

#define DEST_OFF(d) (d >> 2) & 0x1

#define DEST_PTR(d) (d >> 3) & 0x1

#include "alu.h"

typedef struct {
    CPU_IN cpu_in;
    Registers registers;
    ALU_IN alu_in;
    ALU_OUT alu_out;
    CPU_OUT cpu_out;
} CPU_State;

CPU_OUT* CPU(CPU_State *state, CPU_IN* IN);

#endif
