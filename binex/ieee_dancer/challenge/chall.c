#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <seccomp.h>

void enable_seccomp() {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    if (!ctx) {
        perror("seccomp_init");
        exit(1);
    }

    seccomp_arch_remove(ctx, SCMP_ARCH_X32);

    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

    if (seccomp_load(ctx) < 0) {
        perror("seccomp_load");
        exit(1);
    }

    seccomp_release(ctx);
}

int main() {
    setbuf(stdout,NULL);
    setbuf(stdin,NULL);
    setbuf(stderr,NULL);
    int n;
    puts("enter the number of floats you want to enter!");
    scanf("%d", &n);

    if (n > 100) {
        puts("too much");
        exit(0);
    }

    double *buf = calloc(n, sizeof(double));
    if (!buf) {
        perror("calloc");
        return 1;
    }

    for (int i = 0; i < n; i++) {
        scanf("%lf", &buf[i]);
    }

    size_t pagesize = sysconf(_SC_PAGESIZE);
    void *aligned = (void *) ((uintptr_t)buf & ~(pagesize - 1));

    if (mprotect(aligned, pagesize, PROT_READ | PROT_WRITE | PROT_EXEC) < 0) {
        perror("mprotect");
        return 1;
    }

    enable_seccomp();

    puts("draining in progress...");
    void (*func)() = (void *) buf;
    func();

    return 0;
}

