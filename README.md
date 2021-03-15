# linux-process-injection

## About
There are two ways to start debugging a process:

1. The first and more immediate one, is to make our debugger start the process: `fork` and `exec`. This is what happens when you pass a program name as a parameter to `gdb` or `strace`.
2. The other option we have is to dynamically attach our debugger to a running process. _This enables process injection._

## Project organization

```
.
├── inject.c
├── README.md
└── samples     # sample applications to inject into
```

## Run

```
# compile shellcode
nasm -f elf64 -o shellcode.o shellcode.asm

# convert shellcode to C string
./bin2sc.py shellcode.o

# run hello
./hello

# inject shellcode into hello's process
./inject <pid of hello>
```

## References
- [Linux: Infecting running processes](https://0x00sec.org/t/linux-infecting-running-processes/1097)

## To read
- [Linux process injection into sshd for fun](https://blog.xpnsec.com/linux-process-injection-aka-injecting-into-sshd-for-fun/)
  - [`xpn/ssh-inject` source code](https://github.com/xpn/ssh-inject)
