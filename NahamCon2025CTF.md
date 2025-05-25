# NahamCon 2025 CTF Writeup

Welcome to my CTF Writeup for challenges my team and I solved for the CTF competition.

In this file, I’ll walk through the challenges I solved during the event, providing insights into the tools, techniques, and vulnerabilities I encountered and how I approached solving each problem.

---

![NahamCert](https://github.com/user-attachments/assets/cfcdd41c-1f19-41de-bcf1-fab300f0d20a)

# Table of Contents
---

## Table of Contents
- [Challenge 1: Screenshot](#Challenge-1:-Screenshot)
- [Challenge 2: Free Flags](#Challenge-2:-Free-Flags)
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

![[Pasted image 20250523155213.png]]

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
![[Pasted image 20250523153742.png]]

When we view the page source we can see a JavaScript source that has interesting text:
![[Pasted image 20250523154720.png]]

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
![[Pasted image 20250523154821.png]]

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

![[Pasted image 20250523162506.png]]

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
![[Pasted image 20250523174805.png]]

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
![[Pasted image 20250523185216.png]]

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

![[Pasted image 20250523200617.png]]


Our team member Bryan Bidleman was able to copy and paste this into chatGPT, the HTML source, in order to create a solution with chat GPT for attacking this endpoint:
![[Pasted image 20250523200745.png]]

The payload:
```javascript
(function forceSettleAllGrains() { const targets = [ { x: 367, y: 238, colorHue: 0 }, { x: 412, y: 293, colorHue: 40 }, { x: 291, y: 314, colorHue: 60 }, { x: 392, y: 362, colorHue: 120 }, { x: 454, y: 319, colorHue: 240 }, { x: 349, y: 252, colorHue: 280 }, { x: 433, y: 301, colorHue: 320 } ]; // Clear existing particles and grid particles.length = 0; resetGrid(); // Inject perfectly positioned and settled particles targets.forEach(({ x, y, colorHue }) => { injectSand(x, y, colorHue); }); console.log("✅ Settled grains injected at all target positions."); setTimeout(() => { checkFlag(); }, 200); })();
```


![[Pasted image 20250523200935.png]]
![[Pasted image 20250523200946.png]]

# Challenge 8: The Best Butler

Author: @Kkevsterrr  
  
Truly, he's the best butler - he might even be able to serve up a `/flag.txt`!  
  
**NOTE, this challenge might take a bit more time to start. The flag is located at the root of the filesystem (`/flag.txt`)**  
  
**Press the `Start` button on the top-right to begin this challenge.**



---


This challenge has you enter a Jenkins environment:
![[Pasted image 20250523222651.png]]

There is a build setup already:
![[Pasted image 20250523222719.png]]

Click on configure:
![[Pasted image 20250523222752.png]]

The previous builds show that we're running as the user 'SYSTEM' when we build.

This means we likely have permissions to view `/flag.txt`:
```groovy
println new File("/flag.txt").text
```

Use this command in the script console.

We are able to retrieve the flag after running the command in the script console:
![[Pasted image 20250523222455.png]]

Flag:
```bash
flag{ab63a76362c3972ac83d5cb8830fdb51}
```
