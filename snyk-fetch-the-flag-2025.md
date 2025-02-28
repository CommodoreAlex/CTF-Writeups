# Snyk Fetch The Flag 2025 CTF Writeup

Welcome to my **CTF Writeup** for the **Snyk Fetch The Flag 2025 CTF** competition. In this file, I’ll walk through the challenges I solved during the event, providing insights into the tools, techniques, and vulnerabilities I encountered and how I approached solving each problem.

---

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
![image](https://github.com/user-attachments/assets/7e107d38-12ca-4046-9011-dbb17d1c9b15)

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

## Conclusion

In this CTF event, I had the opportunity to apply various cybersecurity techniques and tools. Each challenge provided unique problems, ranging from cryptography to web exploitation and reverse engineering.

Unfortunately that is as far as I was able to get with the time constraints I had, and limitations of skills at the given time for tackling the other reverse engineering problems.

Since I have the files locally I will be experimenting with them and attempting to add more of the solutions to this repository over time. 

I hope this writeup helps others who are interested in solving similar challenges and learning more about cybersecurity. If you have any questions or want to discuss any of the techniques used, feel free to reach out!

---
