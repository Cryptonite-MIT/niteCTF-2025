#include <stdint.h> 
#include "cpu.h"
#include "alu.h"
#include "registers.h"


Register* get_reg(CPU_State *state, uint8_t reg) {
    switch (reg) {
        case 0: return &state->registers.a_reg;
        case 1: return &state->registers.d_reg;
        case 2: return &state->registers.ptr_reg;
        default: return &state->registers.off_reg;
    }
}

void set_register_value(Register *reg, uint16_t value) {
    reg_set_load(reg, 1);
    reg_set_val(reg, value);
    reg_set_load(reg, 0);
}

void handle_dest_register(CPU_State *state, uint8_t dest, uint16_t value) {
    if(DEST_A(dest)) {
        set_register_value(&state->registers.a_reg, value);
    }
    if(DEST_D(dest)) {
        set_register_value(&state->registers.d_reg, value);
    }
    if(DEST_OFF(dest)) {
        set_register_value(&state->registers.off_reg, value);
    }
    if(DEST_PTR(dest)) {
        set_register_value(&state->registers.ptr_reg, value);
    }
}

void handle_dest_register_compute(CPU_State *state, uint8_t dest, uint16_t value) {
    if(DEST_A(dest)) {
        state->registers.a_reg.val = value;
    }
    if(DEST_D(dest)) {
        state->registers.d_reg.val = value;
    }
    if(DEST_OFF(dest)) {
        state->registers.off_reg.val = value;
    }
    if(DEST_PTR(dest)) {
        state->registers.ptr_reg.val = value;
    }
}

void compute_addr_mode(CPU_State *state, CPU_IN *in) {
    uint8_t addr_mode = REG2(in->instruction);

    if(addr_mode == ADDR_MODE_DIRECT) {
        state->cpu_out.addressM = state->registers.ptr_reg.val;
    } else {
        state->alu_in.flag = ALU_OP_ADD_XY;
        state->alu_in.x = state->registers.ptr_reg.val;
        state->alu_in.y = state->registers.off_reg.val;
        ALU(&state->alu_in, &state->alu_out);
        
        if(addr_mode == ADDR_MODE_PRE_OFFSET || addr_mode == ADDR_MODE_PRE_INC) {
            state->cpu_out.addressM = state->alu_out.out;
        } else {
            state->cpu_out.addressM = state->registers.ptr_reg.val;
        }

        if(addr_mode == ADDR_MODE_POST_INC || addr_mode == ADDR_MODE_PRE_INC) {
            reg_set_load(&state->registers.ptr_reg, 1);
            reg_set_val(&state->registers.ptr_reg, state->alu_out.out);
            reg_set_load(&state->registers.ptr_reg, 0);
        }
    } 
}

void instruction_a(CPU_State *state, CPU_IN *in) {
    uint8_t reg1 = REG1(in->instruction);
    Register *reg = get_reg(state, reg1);
    set_register_value(reg, IMM(in->instruction));
}

void instruction_str(CPU_State *state, CPU_IN *in) {
    uint8_t reg1 = REG1(in->instruction); 
    uint8_t size = SIZE(in->instruction);
    state->cpu_out.out = get_reg(state, reg1)->val;
    
    state->cpu_out.load = 1;
    state->cpu_out.size = size;

    compute_addr_mode(state, in);

    uint8_t dest = DEST(in->instruction);

    if(dest) {
        handle_dest_register(state, dest, state->alu_out.out);
    }
}

void instruction_ld(CPU_State *state, CPU_IN *in) {
    uint8_t reg1 = REG1(in->instruction);
    uint8_t size = SIZE(in->instruction);

    reg_set_load(get_reg(state, reg1), 1);

    state->cpu_out.size = size;

    compute_addr_mode(state, in);

    uint8_t dest = DEST(in->instruction);
    if(dest) {
        handle_dest_register(state, dest, state->alu_out.out);
    }
}

void instruction_compute(CPU_State *state, CPU_IN *in) {
    uint8_t dest = DEST(in->instruction);
    uint8_t comp = COMPUTE(in->instruction);
    uint8_t jump = JUMP(in->instruction);

    uint8_t reg1 = REG1(in->instruction);
    uint8_t reg2 = REG2(in->instruction);

    state->alu_in.x = get_reg(state, reg1)->val;
    state->alu_in.y = get_reg(state, reg2)->val;
    state->alu_in.flag = comp;

    ALU(&state->alu_in, &state->alu_out);

    if (dest) {
        handle_dest_register_compute(state, dest, state->alu_out.out);
    }
    if (jump) {
        uint8_t zr_flag = zr(state->alu_out.out_flag);
        uint8_t ng_flag = ng(state->alu_out.out_flag);
        uint8_t should_jump = 0;

        switch (jump) {
            case JGT:
                if (!ng_flag && !zr_flag) should_jump = 1;
                break;
            case JEQ:
                if (zr_flag) should_jump = 1;
                break;
            case JGE:
                if (!ng_flag) should_jump = 1;
                break;
            case JLT:
                if (ng_flag) should_jump = 1;
                break;
            case JNE:
                if (!zr_flag) should_jump = 1;
                break;
            case JLE:
                if (ng_flag || zr_flag) should_jump = 1;
                break;
            case JMP:
                should_jump = 1;
                break;
        }

        if (should_jump) {
            state->registers.pc.load = 1;
            state->registers.pc.inc = 0;
        }
    }
}

CPU_OUT* CPU(CPU_State *state, CPU_IN *in) {
    reg_set_val(&state->registers.a_reg, in->inM);
    reg_set_val(&state->registers.d_reg, in->inM);
    reg_set_val(&state->registers.off_reg, in->inM);
    reg_set_val(&state->registers.ptr_reg, in->inM);

    state->registers.a_reg.load = 0;
    state->registers.d_reg.load = 0;
    state->registers.off_reg.load = 0;
    state->registers.ptr_reg.load = 0;

    state->registers.pc.inc = 1;
    state->registers.pc.load = 0;
    state->registers.pc.reset = in->reset;

    state->cpu_out.load = 0;

    uint8_t instr = INS(in->instruction);
    if(instr == 0) {
        instruction_a(state, in);
    } else if(instr == 1) {
        instruction_str(state, in);
    } else if(instr == 2) {
        instruction_ld(state, in);
    } else {
        instruction_compute(state, in);
    }
    
    evaluate_pc(&state->registers.pc, state->registers.ptr_reg.val);

    state->cpu_out.pc = state->registers.pc.out;

    return &state->cpu_out;
}
