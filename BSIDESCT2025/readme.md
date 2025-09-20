# BSides Connecticut 2025 Capture The Flag Competition

"Put on the sunglasses. See the flags hidden in plain sight."

<img width="1062" height="391" alt="image" src="https://github.com/user-attachments/assets/e3a7eb4f-d4a5-4ed9-9a11-17c536ed3bb2" />

---

<img width="752" height="208" alt="image" src="https://github.com/user-attachments/assets/c605cdb6-3331-4e36-b309-28af70aee081" />


This was a great team building experience with my coworkers and new friends; tackling some diverse CTF challenges. Below are some of the challenges we were able to solve.

# Table of Contents

- [Cryptography](#cryptography)
- [Steganography](#steganography)
- [Web Applications](#web-application-challenges)
- [Reverse Engineering](reverse-engineering)
- [Misc Challenges](#misc-challenges)

---



# Cryptography


<img width="751" height="391" alt="image" src="https://github.com/user-attachments/assets/b86b1da5-56d6-422b-ba29-fa5cb8194e05" />

----

We are running a decryption process using the KEY for a XOR encoded flag.

The following is the output:
```bash
BSIDESCT{XOR_FUN_1}
```

<img width="752" height="302" alt="image" src="https://github.com/user-attachments/assets/4dfd5eec-6348-498e-9e31-332a60091b71" />

---
# Steganography

<img width="772" height="378" alt="image" src="https://github.com/user-attachments/assets/c1e2f3f7-ceb5-4cd5-9bba-66d43f8b3e6e" />

---

Download and open the `challenge.wav` file in Audacity.

The flag is obtained by switching to spectrogram view on the track:
<img width="754" height="214" alt="image" src="https://github.com/user-attachments/assets/0607d5e0-9209-4c28-ae6d-fab50daaec20" />


---
# Web Application Challenges


<img width="757" height="310" alt="image" src="https://github.com/user-attachments/assets/fa3d2e95-252d-4610-9e20-068786582b36" />


---

The source code tracks the amount of clicks; 0 -> 5.

This will open an opportunity to click a bar between 49 - 51% of the way where you can then open a window here with the flag:
<img width="584" height="428" alt="image" src="https://github.com/user-attachments/assets/879dc6ab-5b0c-48d6-92f1-2f91343118d4" />

----

# Reverse Engineering


<img width="746" height="397" alt="image" src="https://github.com/user-attachments/assets/751269eb-d697-46c4-ac73-9ea30e0fea31" />


---

ELF Binary identified:
```
┌──(root㉿kali)-[/home/kali/Downloads]
└─# file challenge
challenge: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=8e79b0672d82d33f4bb76d70883b674b57618885, for GNU/Linux 3.2.0, with debug_info, not stripped
```

Running Strings against the binary to find a potential vector:
```bash
┌──(root㉿kali)-[/home/kali/Downloads]
└─# strings challenge 
;gKWa
/lib64/ld-linux-x86-64.so.2
setvbuf
puts
stdout
__libc_start_main
libc.so.6
GLIBC_2.2.5
GLIBC_2.34
__gmon_start__
PTE1
H= @@
QlNJREVTQ1R7U1RSSU5HU19GVU59
Welcome to the strings challenge!
If you
re clever, you might find something hidden
;*3$"
GCC: (Debian 14.3.0-5) 14.3.0
_IO_buf_end
_old_offset
ENC_FLAG
_IO_save_end
short int
size_t
_IO_lock_t
_IO_write_ptr
_flags
_IO_buf_base
_markers
_IO_read_end
_freeres_buf
setvbuf
_lock
long int
_cur_column
_IO_FILE
unsigned char
GNU C17 14.3.0 -mtune=generic -march=x86-64 -g -O0 -fno-stack-protector -fasynchronous-unwind-tables
_prevchain
_IO_marker
_shortbuf
puts
_IO_write_base
_unused2
_IO_read_ptr
short unsigned int
main
_freeres_list
_IO_codecvt
long unsigned int
_IO_write_end
__off64_t
__off_t
_chain
_IO_wide_data
_IO_backup_base
_flags2
_mode
_IO_read_base
_vtable_offset
_IO_save_base
_fileno
stdout
_short_backupbuf
Chal_5.c
/home/kali/Desktop
/usr/lib/gcc/x86_64-linux-gnu/14/include
/usr/include/x86_64-linux-gnu/bits
/usr/include/x86_64-linux-gnu/bits/types
/usr/include
stddef.h
types.h
struct_FILE.h
stdio.h
crt1.o
__abi_tag
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.0
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
Chal_5.c
ENC_FLAG
__FRAME_END__
_DYNAMIC
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_start_main@GLIBC_2.34
stdout@GLIBC_2.2.5
puts@GLIBC_2.2.5
_edata
_fini
__data_start
__gmon_start__
__dso_handle
_IO_stdin_used
_end
_dl_relocate_static_pie
__bss_start
main
setvbuf@GLIBC_2.2.5
__TMC_END__
_init
.symtab
.strtab
.shstrtab
.note.gnu.property
.note.gnu.build-id
.interp
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.note.ABI-tag
.init_array
.fini_array
.dynamic
.got
.got.plt
.data
.bss
.comment
.debug_aranges
.debug_info
.debug_abbrev
.debug_line
.debug_str
.debug_line_str
```

Decoded the Base64 text:
```bash
┌──(root㉿kali)-[/home/kali/Downloads]
└─# echo "QlNJREVTQ1R7U1RSSU5HU19GVU59" | base64 -d
BSIDESCT{STRINGS_FUN}   
```

<img width="750" height="386" alt="image" src="https://github.com/user-attachments/assets/67ddebbe-f33c-4e64-aac4-084c5fad4b1d" />

---

ELF Binary identified:
```bash
┌──(root㉿kali)-[/home/kali/Downloads]
└─# file challenge
challenge: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=b7943f2108aea5edd7589c6df2cd5f0deb136428, for GNU/Linux 3.2.0, with debug_info, not stripped
```

The Strings utility finds a separated flag:
```bash
┌──(root㉿kali)-[/home/…/Downloads/BSIDESCT_2025/REVERSE/Two]
└─# strings challenge| head -n 15
d(/lib64/ld-linux-x86-64.so.2
puts
__libc_start_main
libc.so.6
GLIBC_2.2.5
GLIBC_2.34
__gmon_start__
PTE1
AASFHGFAHSAFDKGAKSHFGKH*(DSGHG==
QlNJREVTQ1R7QkFTRTY0
meowmeowmeowmeowmeow
X0ZVTjN9
RAWRARAWRARAWRARARAWRAWRARAW
parts of the flag are separated...
;*3$"

```


Reconstructing the flag:
```
echo "AASFHGFAHSAFDKGAKSHFGKH*(DSGHG==" | base64 -d
echo "QlNJREVTQ1R7QkFTRTY0" | base64 -d
echo "X0ZVTjN9" | base64 -d
```

The reconstructed flag:
```bash
┌──(root㉿kali)-[/home/…/Downloads/BSIDESCT_2025/REVERSE/Two]
└─# echo "AASFHGFAHSAFDKGAKSHFGKH*(DSGHG==" | base64 -d
echo "QlNJREVTQ1R7QkFTRTY0" | base64 -d
echo "X0ZVTjN9" | base64 -d
�a@ 
    ��)!�▒�base64: invalid input
BSIDESCT{BASE64_FUN3}       
```

---
# MISC Challenges

<img width="742" height="346" alt="image" src="https://github.com/user-attachments/assets/c319df2b-7bad-4f02-aec0-0b90bb984e09" />

---

```bash
┌──(root㉿kali)-[/home/kali/Downloads]
└─# mkdir /mnt/bsides
                                                                                                                                     
┌──(root㉿kali)-[/home/kali/Downloads]
└─# sudo mount -o loop bsidesOS.iso /mnt/bsides
mount: /mnt/bsides: WARNING: source write-protected, mounted read-only.
                                                                                                                                     
┌──(root㉿kali)-[/home/kali/Downloads]
└─# ls -la /mnt/bsides
total 7
dr-xr-xr-x 1 root root 2048 Sep 19 23:52 .
drwxr-xr-x 3 root root 4096 Sep 20 13:54 ..
-r-xr-xr-x 1 root root  600 Sep 19 23:51 flag.txt
```

Able to read the flag in ASCII art:
```bash
┌──(root㉿kali)-[/home/kali/Downloads]
└─# cat /mnt/bsides/flag.txt
 ____  ___  ____  ____  ____  ___   ___  ____  ,- __  __  ___  __  __  _  _  ____      ___  ____       ____  __  __  ____  _  _       __  __  ___ -. 
(  _ \/ __)(_  _)(  _ \( ___)/ __) / __)(_  _)_| (  \/  )/ _ \(  )(  )( \( )(_  _)    / _ \(  _ \     (  _ \(  )(  )(  _ \( \( )     (  \/  )(__ ) |_
 ) _ <\__ \ _)(_  )(_) ))__) \__ \( (__   )(   |  )    (( (_) ))(__)(  )  (   )(  ___( (_) ))   / ___  ) _ < )(__)(  )   / )  (  ___  )    (  (_ \ | 
(____/(___/(____)(____/(____)(___/ \___) (__)  `-(_/\/\_)\___/(______)(_)\_) (__)(___)\___/(_)\_)(___)(____/(______)(_)\_)(_)\_)(___)(_/\/\_)(___/-' 
```

Opening this up in Gedit will make the image clearer:
<img width="753" height="104" alt="image" src="https://github.com/user-attachments/assets/34a53958-91ae-4501-b858-4658174eed24" />

The flag is:
```bash
bsidesct{mount_or_burn_m3}
```


<img width="744" height="246" alt="image" src="https://github.com/user-attachments/assets/004dd418-3b4b-4ccd-94d5-c66508c796e6" />

---

Going to robots.txt returns a flag:
<img width="756" height="281" alt="image" src="https://github.com/user-attachments/assets/3f4444b1-5b12-4b8e-a2cb-b2dbca6b6942" />


Running `fcrackzip` to acquire a password to access the zip:
```bash
┌──(root㉿kali)-[/home/kali/Downloads]
└─# fcrackzip -v -u -D -p /usr/share/wordlists/rockyou.txt flag.zip

found file 'rock.png', (size cp/uc   4776/  5711, flags 9, chk 04b6)
checking pw udei9Qui                                

PASSWORD FOUND!!!!: pw == smilebig!
```

Unzipping:
```bash
┌──(root㉿kali)-[/home/kali/Downloads]
└─# unzip flag.zip 
Archive:  flag.zip
[flag.zip] rock.png password: 
  inflating: rock.png       
```

Open the image:
```bash
┌──(root㉿kali)-[/home/kali/Downloads]
└─# open rock.png     
```

When you open the image you get:
<img width="502" height="186" alt="image" src="https://github.com/user-attachments/assets/694b45c8-cd11-4034-86d9-3ba088633a4c" />
