#ifndef OPCODE_H
#define OPCODE_H

typedef enum {
    OP_PUSH_CONSTANT,
    OP_PUSH_ARGUMENT,
    OP_PUSH_LOCAL,
    OP_POP_ARGUMENT,
    OP_POP_LOCAL,
    OP_ADD,
    OP_SUB,
    OP_MUL,
    OP_DIV,
    OP_XOR,
    OP_CALL,
    OP_RETURN,
    OP_FUNCTION,
    OP_LABEL,
    OP_GOTO,
    OP_IFGOTO,
    OP_NEG,
    OP_AND,
    OP_OR,         
    OP_NOT,
    OP_GT,
    OP_LT,
    OP_EQ,
    OP_PEEK,
    OP_POKE,
    OP_PRINT,
    OP_READ,
    OP_DROP,
    OP_EXIT,
    OP_GETMESSAGE

} Opcode;

#endif // OPCODE_H
