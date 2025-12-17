#include "vm.h"
#include "microcode.h"
#include <syscall.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

void load_program(VM* vm, const char* filename) {
    FILE* file = fopen(filename, "rb");
    if (file == NULL) {
        perror("Error opening program file");
        exit(EXIT_FAILURE);
    }

    fseek(file, 0, SEEK_END);
    long program_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if(program_size > (RAM_SIZE - BASE)) {
        fprintf(stderr, "ERROR: program file too large\n");
        fclose(file);
        exit(EXIT_FAILURE);
    }

    uint8_t* ram_program_start = (uint8_t*)vm->ram_memory + BASE;

    size_t bytes_read = fread(ram_program_start, 1, program_size, file);

    if(bytes_read != program_size) {
        if (ferror(file)) {
            perror("Error reading program file");
        }
        fclose(file);
        exit(EXIT_FAILURE);
    }
    printf("Loaded %zu instructions from %s.\n", bytes_read, filename);

    fclose(file);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <program.bin>\n", argv[0]);
        return EXIT_FAILURE;
    }

    VM* vm = create_vm();

    load_program(vm, argv[1]);

    run_vm(vm);

    destroy_vm(vm);

    return 0;
}
