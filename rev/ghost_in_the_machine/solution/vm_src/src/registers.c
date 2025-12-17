#include "registers.h"
#include <stdint.h>

void reg_set_load(Register *reg, uint8_t load) {
    reg->load = load;
}

void reg_set_val(Register *reg, uint16_t val) {
    if(reg->load) reg->val = val;
}

uint16_t reg_read_val(Register *reg) {
    return reg->val;
}

void evaluate_pc(PC *pc, uint16_t in) {
    if(pc->reset) {
        pc->out = 0;
    } else if (pc->load) {
        pc->out = in;
    } else if (pc->inc) {
        pc->out += 4;
    }
}
