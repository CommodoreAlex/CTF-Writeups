# DOD Cyber Sentinel June 2025 CTF

This CTF was a lot of fun, below is the placing that I received during the competition:

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




---

# Recon Category


---

# Reverse Engineering and Malware


---


# Web Application Security
