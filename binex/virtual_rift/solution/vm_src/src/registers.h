#include <stdint.h>

#ifndef REGISTERS_H
#define REGISTERS_H

typedef struct {
    uint8_t load;
    uint16_t val;
} Register;

typedef struct {
    uint16_t out;
    uint8_t inc;
    uint8_t reset;
    uint8_t load;
} PC;

void reg_set_load(Register *reg, uint8_t load);
void reg_set_val(Register *reg, uint16_t val);
uint16_t reg_read_val(Register *reg);
void evaluate_pc(PC* pc, uint16_t in);

#endif
