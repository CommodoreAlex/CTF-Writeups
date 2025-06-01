![image](https://github.com/user-attachments/assets/5a197ed4-0976-4700-8eda-dc5cd77a5aac)![image](https://github.com/user-attachments/assets/31f07c07-0bce-47bb-a82d-7fa5c67fdfd4)![image](https://github.com/user-attachments/assets/227cda75-6635-4488-af2f-20634d5d1fc9)

---

# Challenge 1 - Rules

We obtain the first flag as a result of viewing the pinned messages in Discord

![image](https://github.com/user-attachments/assets/b15e2f90-bb43-4267-9f3d-2d43250119ce)

# Challenge 2 - The Emperor

![image](https://github.com/user-attachments/assets/ec65ff7f-bdf7-4b8e-aa12-5493a1223447)

We receive a `challenge.txt` file that contains the following ASCII text:
```bash
┌──(root㉿kali)-[/home/kali/NOPS]
└─# file challenge.txt 
challenge.txt: ASCII text
```

Checking the contents reveals a question, a label, and cipher text:
```bash
┌──(root㉿kali)-[/home/kali/NOPS]
└─# cat challenge.txt 
Ea, kag pqoapqp uf tgt?
Ftqz, tqdq ue ftq rxms:
UVGEFPQOAPQPMOMQEMDOUBTQDITUOTYMWQEYQMBDARQEEUAZMXODKBFATQDA   
```

I ran this through [dcode](https://www.dcode.fr/cipher-identifier) and got the following results:

![image](https://github.com/user-attachments/assets/64294996-9f21-449c-bbed-d0463a5e0cb1)

This is probably one of the top two given its a 'basic' challenge, and these ciphers are great beginner ones especially with AI tools.

The Python script we will create to decode against a Caesar Cipher, removing the distracting text above what appears to be the actual cipher text:
```python
#!/usr/bin/env python3

ciphertext = "UVGEFPQOAPQPMOMQEMDOUBTQDITUOTYMWQEYQMBDARQEEUAZMXODKBFATQDA"

def decrypt_caesar(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base - shift) % 26 + base)
        else:
            result += char
    return result

for shift in range(1, 26):
    print(f"[Shift {shift}] {decrypt_caesar(ciphertext, shift)}")
```

Running our script to review the outputs reveals line 12 for the answer:
```bash
┌──(root㉿kali)-[/home/kali/NOPS]
└─# python3 reverse.py 
[Shift 1] TUFDEOPNZOPOLNLPDLCNTASPCHSTNSXLVPDXPLACZQPDDTZYLWNCJAEZSPCZ
[Shift 2] STECDNOMYNONKMKOCKBMSZROBGRSMRWKUOCWOKZBYPOCCSYXKVMBIZDYROBY
[Shift 3] RSDBCMNLXMNMJLJNBJALRYQNAFQRLQVJTNBVNJYAXONBBRXWJULAHYCXQNAX
[Shift 4] QRCABLMKWLMLIKIMAIZKQXPMZEPQKPUISMAUMIXZWNMAAQWVITKZGXBWPMZW
[Shift 5] PQBZAKLJVKLKHJHLZHYJPWOLYDOPJOTHRLZTLHWYVMLZZPVUHSJYFWAVOLYV
[Shift 6] OPAYZJKIUJKJGIGKYGXIOVNKXCNOINSGQKYSKGVXULKYYOUTGRIXEVZUNKXU
[Shift 7] NOZXYIJHTIJIFHFJXFWHNUMJWBMNHMRFPJXRJFUWTKJXXNTSFQHWDUYTMJWT
[Shift 8] MNYWXHIGSHIHEGEIWEVGMTLIVALMGLQEOIWQIETVSJIWWMSREPGVCTXSLIVS
[Shift 9] LMXVWGHFRGHGDFDHVDUFLSKHUZKLFKPDNHVPHDSURIHVVLRQDOFUBSWRKHUR
[Shift 10] KLWUVFGEQFGFCECGUCTEKRJGTYJKEJOCMGUOGCRTQHGUUKQPCNETARVQJGTQ
[Shift 11] JKVTUEFDPEFEBDBFTBSDJQIFSXIJDINBLFTNFBQSPGFTTJPOBMDSZQUPIFSP
[Shift 12] IJUSTDECODEDACAESARCIPHERWHICHMAKESMEAPROFESSIONALCRYPTOHERO
[Shift 13] HITRSCDBNCDCZBZDRZQBHOGDQVGHBGLZJDRLDZOQNEDRRHNMZKBQXOSNGDQN
[Shift 14] GHSQRBCAMBCBYAYCQYPAGNFCPUFGAFKYICQKCYNPMDCQQGMLYJAPWNRMFCPM
[Shift 15] FGRPQABZLABAXZXBPXOZFMEBOTEFZEJXHBPJBXMOLCBPPFLKXIZOVMQLEBOL
[Shift 16] EFQOPZAYKZAZWYWAOWNYELDANSDEYDIWGAOIAWLNKBAOOEKJWHYNULPKDANK
[Shift 17] DEPNOYZXJYZYVXVZNVMXDKCZMRCDXCHVFZNHZVKMJAZNNDJIVGXMTKOJCZMJ
[Shift 18] CDOMNXYWIXYXUWUYMULWCJBYLQBCWBGUEYMGYUJLIZYMMCIHUFWLSJNIBYLI
[Shift 19] BCNLMWXVHWXWTVTXLTKVBIAXKPABVAFTDXLFXTIKHYXLLBHGTEVKRIMHAXKH
[Shift 20] ABMKLVWUGVWVSUSWKSJUAHZWJOZAUZESCWKEWSHJGXWKKAGFSDUJQHLGZWJG
[Shift 21] ZALJKUVTFUVURTRVJRITZGYVINYZTYDRBVJDVRGIFWVJJZFERCTIPGKFYVIF
[Shift 22] YZKIJTUSETUTQSQUIQHSYFXUHMXYSXCQAUICUQFHEVUIIYEDQBSHOFJEXUHE
[Shift 23] XYJHISTRDSTSPRPTHPGRXEWTGLWXRWBPZTHBTPEGDUTHHXDCPARGNEIDWTGD
[Shift 24] WXIGHRSQCRSROQOSGOFQWDVSFKVWQVAOYSGASODFCTSGGWCBOZQFMDHCVSFC
[Shift 25] VWHFGQRPBQRQNPNRFNEPVCUREJUVPUZNXRFZRNCEBSRFFVBANYPELCGBUREB
```

The flag:
```bash
B4BY{IJUSTDECODEDACAESARCIPHERWHICHMAKESMEAPROFESSIONALCRYPTOHERO}
```

# Challegne 3 - Unknown File

![image](https://github.com/user-attachments/assets/3768de21-f07f-4fd0-8a54-8b2659c2fcd0)


---

We receive a file `challenge`, when we run file against it we see it is a PDF:
```bash
┌──(root㉿kali)-[/home/kali/NOPS]
└─# file challenge
challenge: PDF document, version 1.6, 1 page(s) (zip deflate encoded)
```

We can check for visible strings:
```bash
┌──(root㉿kali)-[/home/kali/NOPS]
└─# strings challenge                           
%PDF-1.6
2 0 obj
<</Length 3 0 R/Filter/FlateDecode>>
stream
Lw3A
...
```

We don't see anything valuable. Let's change this to a PDF file:
```bash
┌──(root㉿kali)-[/home/kali/NOPS]
└─# cp challenge challenge.pdf
```

We can open it:
```bash
┌──(root㉿kali)-[/home/kali/NOPS]
└─# open challenge.pdf 
```

We get the flag:

![image](https://github.com/user-attachments/assets/4494cfca-9f5e-439f-819b-b4d154cd6359)

# Challenge 4 - Read the Bytes!

![image](https://github.com/user-attachments/assets/f6aa0992-b8da-4de0-8e69-fb56de0012fd)


---

We get a file `challenge.py`, a Python file we can presume:
```python
from flag import flag

# flag = b"XXXXXXXXXX"

for char in flag:
    print(char)

# 66
# 52
# 66
# 89
# 123
# 52
# 95
# 67
# 104
# 52
# 114
# 97
# 67
# 55
# 51
# 114
# 95
# 49
# 115
# 95
# 74
# 117
# 53
# 116
# 95
# 52
# 95
# 110
# 85
# 109
# 56
# 51
# 114
# 33
# 125
```

This looks like the flag is in an encoded byte format, we can reverse this using built in Python functions.

We will create a dictionary of values containing the bytes that we will convert to ASCII text:
```python
#!/usr/bin/env python3

ascii_values = [
    66, 52, 66, 89, 123, 52, 95, 67, 104, 52, 114, 97, 67, 55, 51, 114, 95, 
    49, 115, 95, 74, 117, 53, 116, 95, 52, 95, 110, 85, 109, 56, 51, 114, 33, 125
]

flag = ''.join(chr(num) for num in ascii_values)
print(flag)
```

The flag we get from running our script:
```bash
┌──(root㉿kali)-[/home/kali/NOPS]
└─# ./reverse.py 
B4BY{4_Ch4raC73r_1s_Ju5t_4_nUm83r!}
```

# Challenge 5 - Break My Stream

![image](https://github.com/user-attachments/assets/5e010c6a-079f-4cdb-b946-ba8487acc717)


---

The script we can analyze:
```python
import os

class CrypTopiaSC:

    @staticmethod
    def KSA(key, n):
        S = list(range(n))
        j = 0
        for i in range(n):
            j = ((j + S[i] + key[i % len(key)]) >> 4 | (j - S[i] + key[i % len(key)]) << 4) & (n-1)
            S[i], S[j] = S[j], S[i]
        return S

    @staticmethod
    def PRGA(S, n):
        i = 0
        j = 0
        while True:
            i = (i+1) & (n-1)
            j = (j+S[i]) & (n-1)
            S[i], S[j] = S[j], S[i]
            yield S[((S[i] + S[j]) >> 4 | (S[i] - S[j]) << 4) & (n-1)]

    def __init__(self, key, n=256):
        self.KeyGenerator = self.PRGA(self.KSA(key, n), n)

    def encrypt(self, message):
        return bytes([char ^ next(self.KeyGenerator) for char in message])

def main():
    flag = b"XXX"
    key = os.urandom(256)
    encrypted_flag = CrypTopiaSC(key).encrypt(flag)
    print("Welcome to our first version of CrypTopia Stream Cipher!\nYou can here encrypt any message you want.")
    print(f"Oh, one last thing: {encrypted_flag.hex()}")
    while True:
        pt = input("Enter your message: ").encode()
        ct = CrypTopiaSC(key).encrypt(pt)
        print(ct.hex())

if __name__ == "__main__":
    main()
```

----
## What the code does

- Implements a custom stream cipher class `CrypTopiaSC`.
    
- Uses a key scheduling algorithm (`KSA`) with some custom bit rotations and swaps.
    
- The pseudo-random generation algorithm (`PRGA`) outputs a keystream based on the state `S`.
    
- `encrypt()` XORs your input with the keystream to produce ciphertext.
    
- The key is **random**: `key = os.urandom(256)`.
    
- The flag is encrypted and printed as hex at startup.
    
- Then you can encrypt any message you want by inputting plaintext; it returns ciphertext.

---

When we run the script:
```bash
┌──(root㉿kali)-[/home/kali]
└─# python3 main.py   
Welcome to our first version of CrypTopia Stream Cipher!
You can here encrypt any message you want.
Oh, one last thing: 6307b3
Enter your message: test
4f3a98e2
Enter your message: 
```

So when we go to the server endpoint with netcat:
```bash
┌──(root㉿kali)-[/home/kali/NOPS]
└─# nc 0.cloud.chals.io 31561
Welcome to our first version of CrypTopia Stream Cipher!
You can here encrypt any message you want.
Oh, one last thing: bb87de50bb57d0895606045a5506390f6bfc8f3529b4db
Enter your message: 
```

We have the encrypted flag.

I will send a message of the same length in this case, 24 A characters to the server to see the response and use that for a 24 A encrypted cipher text comparison:
```bash
┌──(root㉿kali)-[/home/kali/NOPS]
└─# nc 0.cloud.chals.io 31561
Welcome to our first version of CrypTopia Stream Cipher!
You can here encrypt any message you want.
Oh, one last thing: bb87de50bb57d0895606045a5506390f6bfc8f3529b4db
Enter your message: AAAAAAAAAAAAAAAAAAAAAAAA
b4f6cf428163a4bd230b1a5625342c7a418e9d5a46dbe7e8
Enter your message: 
```

We tested with 24 `A`s because the encrypted flag ciphertext is 24 bytes long, and the stream cipher encrypts data byte-by-byte by XORing plaintext with a keystream. By sending a known plaintext of the same length, we obtain ciphertext that, when XORed with the encrypted flag ciphertext and our known plaintext, cancels out the keystream and reveals the original flag. Using `A`s is practical since it's a simple, printable character easy to input, ensuring the XOR calculations work correctly to recover the flag.

We can create a script to decode this encrypted output:
```python
#!/usr/bin/env python3

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

encrypted_flag_hex = "bb87de50bb57d0895606045a5506390f6bfc8f3529b4db"
ciphertext_for_A_hex = "b4f6cf428163a4bd230b1a5625342c7a418e9d5a46dbe7e8"

encrypted_flag = bytes.fromhex(encrypted_flag_hex)
ciphertext_for_A = bytes.fromhex(ciphertext_for_A_hex)
plaintext_A = b"A" * 24

temp = xor_bytes(encrypted_flag, ciphertext_for_A)
flag = xor_bytes(temp, plaintext_A)

print("Recovered flag bytes:", flag)
print("Flag as string:", flag.decode(errors='ignore'))
```

When we run our script we are returned with the flag:
```bash
┌──(root㉿kali)-[/home/kali]
└─# ./test.py 
Recovered flag bytes: b'N0PS{u5u4L_M1sT4k3S...}'
Flag as string: N0PS{u5u4L_M1sT4k3S...}
```

# Challenge 6 - Press Me If U Can

![image](https://github.com/user-attachments/assets/af7ebb68-8582-432d-a5e5-876f4fc22c59)

We can not click the button, the button will run away from us:

![image](https://github.com/user-attachments/assets/2f607204-2f36-46c5-bb53-76ddd33822d1)

The JavaScript:
```javascript
const btn = document.querySelector("button");
const OFFSET = 100;

const testEdge = function (property, axis) {
if (endPoint[property] <= 0) {
    endPoint[property] = axis - OFFSET;
} else if (endPoint[property] >= axis) {
    endPoint[property] = OFFSET;
}
};

let endPoint = { x: innerWidth / 2, y: innerHeight * 2 / 3 };

addEventListener("mousemove", (e) => {
const btnRect = btn.getBoundingClientRect();

const angle = Math.atan2(e.y - endPoint.y, e.x - endPoint.x);

const distance = Math.sqrt(
    Math.pow(e.x - endPoint.x, 2) + Math.pow(e.y - endPoint.y, 2)
);

if (distance <= OFFSET) {
    endPoint = {
    x: OFFSET * -Math.cos(angle) + e.x,
    y: OFFSET * -Math.sin(angle) + e.y
    };
}

btn.style.left = endPoint.x + "px";
btn.style.top = endPoint.y + "px";

btn.disabled = true;

testEdge("x", innerWidth);
testEdge("y", innerHeight);
});



// Select all pupils
const pupils = document.querySelectorAll('.pupil');

// Add an event listener for mouse movement
document.addEventListener('mousemove', (event) => {
    const { clientX: mouseX, clientY: mouseY } = event;

    // Adjust each pupil position
    pupils.forEach((pupil) => {
        const eye = pupil.parentElement;

        // Get the bounding box of the eye
        const { left, top, width, height } = eye.getBoundingClientRect();

        // Calculate the center of the eye
        const eyeCenterX = left + width / 2;
        const eyeCenterY = top + height / 2;

        // Calculate the offset for the pupil based on the eye center
        const dx = mouseX - eyeCenterX;
        const dy = mouseY - eyeCenterY;

        // Normalize the movement within a range
        const maxOffsetX = width * 0.25; // Adjust range for horizontal movement
        const maxOffsetY = height * 0.25; // Adjust range for vertical movement

        const offsetX = Math.max(-maxOffsetX, Math.min(maxOffsetX, dx * 0.1));
        const offsetY = Math.max(-maxOffsetY, Math.min(maxOffsetY, dy * 0.1));

        // Set the pupil position
        pupil.style.transform = `translate(${offsetX}px, ${offsetY}px)`;
    });
});
```

This is how we can interact:
```javascript
btn.disabled = false;
btn.click();
```

We have to go into the inspection tools (console) and send a command to break the JavaScript:

![image](https://github.com/user-attachments/assets/495da727-b16f-42d5-800c-8c8681a44bb7)




