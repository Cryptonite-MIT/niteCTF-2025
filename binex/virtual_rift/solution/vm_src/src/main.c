#include "vm.h"
#include "microcode.h"
#include <syscall.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>

VM* g_vm = NULL;

typedef struct Bytecode {
    uint8_t* bc;
    int bc_len;
} Bytecode;
typedef struct User {
    Bytecode* bcs[10];
    int total_programs;
    char name[20];
} User;

typedef struct Admin {
    int number_of_users;
    int active_user_idx;
    User *users[16];
} Admin;

void load_program(VM* vm, Bytecode* bc) {
    if (!vm || !bc || !bc->bc) {
        puts("Invalid VM or bytecode");
        return;
    }
    if (bc->bc_len < 0 || bc->bc_len > RAM_SIZE) {
        puts("Program too large for VM");
        return;
    }
    uint8_t* ram_program_start = (uint8_t*)vm->ram_memory + BASE; memcpy(ram_program_start, bc->bc, (size_t)bc->bc_len);
    printf("Loaded %d bytes\n", bc->bc_len);
}

void execute_program(Bytecode* bc) {
    if (!bc) return;
    if (!g_vm) { puts("Global VM not initialized"); return;
    }
    load_program(g_vm, bc);
    run_vm(g_vm);
}

void handle_active_user(Admin *admin) {
    if (!admin) return;
    int n = admin->active_user_idx;
    if (n < 0 || n >= 16) {
        puts("Invalid active user index\n");
        return;
    }
    User *user = admin->users[n];
    if (!user) {
        puts("No such user\n");
        return;
    }

    while (1) {
        puts("\n--------------------");
        printf("username: %s\n", user->name);
        printf("total programs: %d\n", user->total_programs);
        puts("User choice");
        puts("1. Create program");
        puts("2. Execute program");
        puts("3. Delete program");
        puts("4. Back to main menu");
        printf("Enter choice: ");
        fflush(stdout);

        int user_choice = 0;
        if (scanf("%d", &user_choice) != 1) {
            int c; while ((c = getchar()) != '\n' && c != EOF) {}
            puts("Invalid input");
            continue;
        }
        getchar();

        if (user_choice == 1) {
            if (user->total_programs >= 10) {
                puts("User has maximum number of programs\n");
                continue;
            }

            printf("Enter program size (bytes): ");
            fflush(stdout);
            int p_size = 0;
            if (scanf("%d", &p_size) != 1) {
                int c; while ((c = getchar()) != '\n' && c != EOF) {}
                puts("Invalid size");
                continue;
            }
            getchar();
            if (p_size <= 0 || p_size > 0x1000) {
                printf("Size must be between 1 and %d\n", 0x1000);
                continue;
            }

            uint8_t* program = (uint8_t*)malloc((size_t)p_size);
            if (!program) {
                puts("Memory allocation failed for program\n");
                continue;
            }

            printf("Send %d bytes over stdin\n", p_size);
            fflush(stdout);
            ssize_t s = read(STDIN_FILENO, program, (size_t)p_size);

            Bytecode *bc = malloc(sizeof(Bytecode));
            if (!bc) {
                free(program);
                puts("Failed to allocate Bytecode struct\n");
                continue;
            }
            bc->bc = program;
            bc->bc_len = s;

            printf("Enter program index (0..9): ");
            fflush(stdout);
            int idx = -1;
            if (scanf("%d", &idx) != 1) {
                int c; while ((c = getchar()) != '\n' && c != EOF) {}
                free(bc->bc);
                free(bc);
                puts("Invalid index");
                continue;
            }
            getchar();

            if (idx < 0 || idx >= 10) {
                printf("Index out of range 0..9\n");
                free(bc->bc);
                free(bc);
                continue;
            }

            if (user->bcs[idx]) {
                free(user->bcs[idx]->bc);
                free(user->bcs[idx]);
                user->bcs[idx] = NULL;
                if (user->total_programs > 0) user->total_programs -= 1;
            }

            user->bcs[idx] = bc;
            user->total_programs += 1;

            puts("Program created\n");
        } else if (user_choice == 2) {
            printf("Enter program number: ");
            fflush(stdout);
            int num = -1;
            if (scanf("%d", &num) != 1) {
                int c; while ((c = getchar()) != '\n' && c != EOF) {}
                puts("Invalid input");
                continue;
            }
            getchar();
            if (num >= 0 && num < 10 && user->bcs[num]) {
                execute_program(user->bcs[num]);
            } else {
                puts("Program does not exist\n");
            }
        } else if (user_choice == 3) {
            printf("Enter program number to delete: ");
            fflush(stdout);
            int num = -1;
            if (scanf("%d", &num) != 1) {
                int c; while ((c = getchar()) != '\n' && c != EOF) {}
                puts("Invalid input");
                continue;
            }
            getchar();
            if (num >= 0 && num < 10 && user->bcs[num]) {
                free(user->bcs[num]->bc);
                free(user->bcs[num]);
                if (user->total_programs > 0) user->total_programs -= 1;
                puts("Program deleted\n");
            } else {
                puts("Program does not exist\n");
            }
        } else if (user_choice == 4) {
            puts("Returning to main menu\n");
            break;
        } else {
            puts("Invalid choice\n");
        }
    }
}

int main(int argc, char** argv) {

    setbuf(stdout,NULL);
    setbuf(stdin,NULL);
    setbuf(stderr,NULL);
    g_vm = create_vm();
    if(!g_vm) {
        puts("Failed to create VM");
        return 1;
    }
    int choice = 0;
    Admin *admin = calloc(1, sizeof(Admin));
    if (!admin) {
        perror("calloc admin");
        return 1;
    }

    while(1) {
        puts("\n=== Main Menu ===");
        puts("1. Create user");
        puts("2. Select user");
        puts("3. Delete user");
        puts("4. Exit");
        printf("Enter choice: ");
        fflush(stdout);

        if (scanf("%d", &choice) != 1) {
            int c; while ((c = getchar()) != '\n' && c != EOF) {}
            puts("Invalid input");
            choice = 0; // Reset choice
            continue;
        }
        getchar();

        if(choice == 1) {
            if(admin->number_of_users < 16) {
                printf("Enter user index (0..15): ");
                fflush(stdout);
                int idx = -1;
                if (scanf("%d", &idx) != 1) {
                    int c; while ((c = getchar()) != '\n' && c != EOF) {}
                    puts("Invalid input");
                    continue;
                }
                getchar();

                if(idx < 0 || idx > 15) {
                    puts("Index out of range\n");
                    continue;
                }

                if (admin->users[idx]) {
                    puts("User slot already used\n");
                    continue;
                }

                User *u = malloc(sizeof(User));
                if (!u) {
                    puts("Could not create user\n");
                    continue;
                }
                printf("Enter user name (max 20 chars): ");
                fflush(stdout);
                char tmp[20];
                ssize_t z = read(STDIN_FILENO, tmp, sizeof(tmp));
                if (z <= 0) {
                    puts("\nFailed to read name\n");
                    free(u);
                    continue;
                }

                strncpy(u->name, tmp, 20);
                u->total_programs = 0;
                for (int i = 0; i < 10; ++i) u->bcs[i] = NULL;

                admin->users[idx] = u;
                admin->number_of_users += 1;
                printf("\nUser %s created\n", admin->users[idx]->name);
            } else {
                puts("Maximum users reached\n");
            }
        } else if(choice == 2) {
            printf("Enter user index: ");
            fflush(stdout);
            int idx = -1;
            if (scanf("%d", &idx) != 1) {
                int c; while ((c = getchar()) != '\n' && c != EOF) {}
                puts("Invalid input");
                continue;
            }
            getchar();

            if(idx < 0 || idx > 15) {
                puts("Index out of range\n");
                continue;
            }

            if(admin->users[idx]) {
                admin->active_user_idx = idx;
                puts("User selected\n");
                handle_active_user(admin);
            } else {
                puts("User does not exist\n");
            }
        } else if(choice == 3) {
            printf("Enter user index to delete: ");
            fflush(stdout);
            int idx = -1;
            if (scanf("%d", &idx) != 1) {
                int c; while ((c = getchar()) != '\n' && c != EOF) {}
                puts("Invalid input");
                continue;
            }
            getchar();

            if(idx < 0 || idx > 15) {
                puts("Index out of range\n");
                continue;
            }

            if(admin->users[idx]) {
                User *usr = admin->users[idx];
                for(int i = 0; i < 10; i++) {
                    if(usr->bcs[i]) {
                        if(usr->bcs[i]->bc) {
                            free(usr->bcs[i]->bc);
                        }
                        free(usr->bcs[i]);
                        usr->bcs[i] = NULL;
                    }
                }
                free(usr);
                admin->users[idx] = NULL;
                admin->number_of_users -= 1;
                puts("User deleted\n");
            } else {
                puts("User does not exist\n");
            }

        } else if (choice == 4) {
            for (int i = 0; i < 16; ++i) {
                if (admin->users[i]) {
                    User *usr = admin->users[i];
                    for (int j = 0; j < 10; ++j) {
                        if (usr->bcs[j]) {
                            free(usr->bcs[j]->bc);
                            free(usr->bcs[j]);
                        }
                    }
                    free(usr);
                    admin->users[i] = NULL;
                }
            }
            free(admin);
            destroy_vm(g_vm);
            puts("Exiting");
            break;
        } else {
            puts("Invalid option\n");
        }
    }

    return 0;
}
