---
date:   2020-07-25 00:00:00 +0200
tags: [posts]
excerpt: "Analysis of the EKANS ransomware"
title:  "Malware analysis of EKANS ransomware"
---
# Table of Contents  
---
[1. Summary](#1_summary)  
[2. Analysis](#2_analysis)  
[2.1. Basic static analysis](#21_basic_static_analysis)  
[2.2. Encrypted strings](#22_encrypted_strings)  
[2.3. Environmental awareness](#23_environmental_awareness)  
[2.4. Ransom note](#24_ransom_note)  
[2.5. Blocking network communication](#25_network)  
[2.6. Service and process termination](#26_services)  
[2.7. Deleting Volume Shadow Copies](#27_vsc)  
[2.8. Encryption](#28_encryption)  
[2.9. Encrypted files](#29_encrypted_files)  
[3. Conclusions](#3_conclusions)  
[4. Recommendations](#4_recommendations)  
[5. References](#5_references)  

# <a name="1_summary"></a> 1. Summary  
---
EKANS malware is a ransomware which was first detected in December 2019 and while ransomware attacks are nothing new, EKANS had a functionality which made it stand out. In the list of processes, that it tries to terminate, there were some which are related to Industrial Control Systems (ICS).[1]  

During the security incidents last month, that hit the news, about the EKANS Ransomware, I decided to look at the inner workings of the malware and share my findings with the security community. My analysis was part of a research done in our [ASOC](https://www.tbs.tech/product/asoc/) team, part of [TBS](https://www.tbs.tech)

We intended to publish the results earlier, but for various reasons, this blog post was delayed quite a bit. Nevertheless I think the information is still worth publishing.

The analyzed sample was obtained from the [abuse.ch](https://abuse.ch/) project, [MalwareBazaar](https://bazaar.abuse.ch/). Although the sample is publicly available, some parts of the analysis are anonymized to prevent harming victims reputation in any way.

If you're interested, you can check the EKANS string decrypton tool I wrote:  
[https://github.com/idafchev/EKANS-String-Decryptor](https://github.com/idafchev/EKANS-String-Decryptor)

# <a name="2_analysis"></a> 2. Analysis  
---

## <a name="21_basic_static_analysis"></a> 2.1. Basic static analysis  
---
The binary contains lots of strings referencing Go source files. The reason for this is that the EKANS malware is written in the Go programming language.  
![bintext](https://idafchev.github.io/blog/assets/images/ekans/ekans_screenshot01.png){: .align-center}  

I wasn't familiar with Go, so before proceeding with the analysis, I had to learn to program in Go, read about the specific features that the language provides and understand how they're implemented on the assembly level.  

If you're not familiar with Go, I recommend GOing through the official tutorial [A Tour of Go](https://tour.golang.org/welcome/1). I went through all exercises to get some basic understanding of the language. Then, I compiled them locally and loaded them in a disassembler in order to compare the assembly with the actual code. Several online resources and blog posts explaning low level details about the Go compiler and how to reverse Go binaries also proved really helpful. 

Information about the debugging symbols in Go binaries cannot easily be stripped completely, and so the original function names can be recovered.
I used the [Go Reverse Engineering Toolkit](https://go-re.tk/gore/) library to write a script with which to restore the symbol names.
Unfortunately, EKANS has all its non-library functions obfuscated.  
![bintext](https://idafchev.github.io/blog/assets/images/ekans/ekans_screenshot02.png){: .align-center}  

Another thing that can be seen from the strings is the Go project folder, which sits under the path `C:\Users\Admin3\\`, meaning that the username the attackers used on their development machine was `Admin3`.  
![bintext](https://idafchev.github.io/blog/assets/images/ekans/ekans_screenshot03.png){: .align-center}  

Checking the entropy with Detect It Easy, we can make an assumtion that the binary is not packed.  
![redress](https://idafchev.github.io/blog/assets/images/ekans/ekans_screenshot04.png){: .align-center}  

With the help of [redress](https://go-re.tk/redress/) we check that it was compiled with go1.10.8.
![entropy](https://idafchev.github.io/blog/assets/images/ekans/ekans_screenshot05.png){: .align-center}  

## <a name="22_encrypted_strings"></a>2.2. Encrypted strings  
---
Almost all strings which are used by the program logic of EKANS are encrypted using a simple XOR cipher.
Every string is encrypted using different key and has its own dedicated function which decrypts that string specifically. This means that there are as many string decryption functions as there are strings (over 2000).

Below is the disassembly of the string decryption function used by EKANS.  
![string decryption](https://idafchev.github.io/blog/assets/images/ekans/ekans_screenshot07.png){: .align-center}  

And here's the implementation in python:  
![string decryption](https://idafchev.github.io/blog/assets/images/ekans/ekans_screenshot08.png){: .align-center}  

I wrote a string decryption tool which decrypts all the strings in the binary. It can also create an IDA IDC script in order to rename all decryption routines. The script is available at: [https://github.com/idafchev/EKANS-String-Decryptor](https://github.com/idafchev/EKANS-String-Decryptor)

## <a name="23_environmental_awareness"></a> 2.3 Environmental awareness  
---
One of the first things EKANS ransomware does is to lookup the IP address of a hardcoded domain name, which belongs to the victim. Unlike other strings, the domain name is stored in plaintext.
![ip lookup](https://idafchev.github.io/blog/assets/images/ekans/ekans_screenshot09.png){: .align-center}  

The resolved IP address of the domain is then compared to a hardcoded IP address. In this specific sample the IP address was a private address, possibly belonging to an internal host.  
If the resolved address does not match the hardcoded one, the ransomware terminates without doing anything.  
![ip compare](https://idafchev.github.io/blog/assets/images/ekans/ekans_screenshot10.png){: .align-center}  

After that, EKANS checks if the host it’s executing on is a domain controller. To do this it queries information from the `Win32_ComputerSytem` Windows Management Instrumentation (WMI) class, using the WQL query `select DomainRole FROM Win32_ComputerSytem`.  

According to the Microsoft documentation `DomainRole` property can have the following values:  
0 – Standalone Workstation  
1 – Member Workstation  
2 – Standalone Server  
3 – Member Server  
4 – Backup Domain Controller  
5 – Primary Domain Controller  

In order to check if the host is a domain controller, EKANS compares if the value of `DomainRole` property is larger than 3.
![wmi query](https://idafchev.github.io/blog/assets/images/ekans/ekans_screenshot11.png){: .align-center}  

If the host is a domain controller the malware does not encrypt the files. Instead it drops the ransom note and exits. If the host is not a domain controller, then it proceeds with encrypting the files and without leaving a ransom note.  
![domain controller check](https://idafchev.github.io/blog/assets/images/ekans/ekans_screenshot12.png){: .align-center}  

It also creates a global mutex called `EKANS` in order to prevent several instances of the malware to run at the same time. If another instance is already running, the string `There can be only one`, is decrypted and execution stops. The string looks like a reference to the movie Highlander, though it might not be intentional.  
![there can be only one](https://idafchev.github.io/blog/assets/images/ekans/ekans_screenshot13.png){: .align-center}  

## <a name="24_ransom_note"></a> 2.4 Ransom note  
---
The ransom note is dropped only on domain controllers. It’s written in the paths `C:\Users\Public\Desktop\Decrypt-Your-Files.txt` and `C:\Decrypt-Your-Files.txt`  
Interestingly it does not contain how much ransom the attackers want.  
![ransom note](https://idafchev.github.io/blog/assets/images/ekans/ekans_screenshot06.png){: .align-center}  

## <a name="25_network"></a> 2.5 Blocking network communication  
---
Before proceeding further, the malware blocks all inbound and outbound network communication.  In order to do this, it executes the following two commands:  
```
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound
netsh advfirewall set allprofiles state on
```

Below you can see the strings which get decrypted and then concatenated in order to construct the commands.  
![firewall off](https://idafchev.github.io/blog/assets/images/ekans/ekans_screenshot14.png){: .align-center}  

The resulting command is then executed with os.exec.Command().Run()  
![firewall off](https://idafchev.github.io/blog/assets/images/ekans/ekans_screenshot15.png){: .align-center}  

This behaviour can also be seen with Process Monitor, during basic dynamic analysis:  
![firewall off](https://idafchev.github.io/blog/assets/images/ekans/ekans_screenshot16.png){: .align-center}  

![firewall off](https://idafchev.github.io/blog/assets/images/ekans/ekans_screenshot17.png){: .align-center}  

## <a name="26_services"></a> 2.6 Service and process termination  
---
Once all network communication is blocked, it starts searching for specific service and process names running on the host. If a match is found it tries to terminate them.  

It contains an exhaustive list of services and processes. The number of services which are searched for is over 300 and the number of processes is over 1100. Only a very small subset of those are included in this blog post. Many of those are services/processes related to anti-malware software, backup and database software, log collectors and forwarders, etc. There are also some ordinary user processes in the list, like steam.exe, MS Office applications and web browsers.  

If you're interested, the full lists of processes and services which EKANS tries to stop are avaiable below:  
[Decrypted process names](https://github.com/idafchev/EKANS-String-Decryptor/blob/master/ekans_decrypted_process_names.txt)  
[Decrypted service names](https://github.com/idafchev/EKANS-String-Decryptor/blob/master/ekans_decrypted_service_names.txt)  

Services are stopped using the WinAPI functions `OpenServiceW` and `ControlService`, while processes are terminated using `OpenProcess` and `TerminateProcess`.  

Subset of the services:  
```
Sophos File Scanner Service
BackupExecAgentBrowser
MSExchangeMTA
MSSQLSERVER
avast! Antivirus
SentinelAgent
Eventlog
NtLmSsp
AdobeARMservice
MySQL80
FireEye Endpoint Agent
nxlog
SplunkForwarder
```

Subset of the processes:  
```
firefox.exe
chrome.exe
excel.exe
mysqld.exe
steam.exe
avastsvc.exe
avguard.exe
fortisslvpndaemon.exe
nortonsecurity.exe
auth8021x.exe
clamscan.exe
fortifw.exe
msmpeng.exe
```

## <a name="27_vsc"></a> 2.7 Deleting Volume Shadow Copies  
---
EKANS then queries WMI using the WQL query `SELECT * FROM Win32_ShadowCopy` to enumerate any existing volume shadow copies (VSC). After the VSC enumeration, it proceeds with their deletion, again using WMI.

This can be seen from the output from API Monitor during dynamic analysis.  
![api monitor](https://idafchev.github.io/blog/assets/images/ekans/ekans_screenshot21.png){: .align-center}  

We're approaching the end of EKANS. The final function calls in the main function are shown below:  
![end of main function](https://idafchev.github.io/blog/assets/images/ekans/ekans_screenshot20.png){: .align-center}  

## <a name="28_encryption"></a> 2.8 Encryption  
---
Before the actual encryption, strings representing file extensions, folders and files are decrypted. These are used to check which files to encrypt and which files or folder to exclude.  

Some system files and folders are excluded from encryption to prevent the system from crashing and thus interrupting the encryption process.  

EKANS enumerates the logical drives and then starts walking the filesystem on each drive. Each file is checked against the above-mentioned lists with extensions, filenames and folders in order to determine whether it should be encrypted.
![drive enumeration](https://idafchev.github.io/blog/assets/images/ekans/ekans_screenshot22.png){: .align-center}  

When the encryption starts, EKANS waits for all encryption threads to finish and all files to be encrypted. After that it iterates through all encrypted files and starts renaming them.  
![rename files](https://idafchev.github.io/blog/assets/images/ekans/ekans_screenshot36.png){: .align-center}  

Each file is checked if it is already encrypted by checking whether it has the `EKANS` signature at the end of the file. Files which are already encrypted are skipped.  

New `16-byte` Initialization Vector (IV) and `256bit` key are generated for **each** file, so each file is encrypted using different key. The IV and key are generated using the `rand.Read()` function which on Windows systems uses the `CryptGenRandom` WinAPI function internally.[2]

Files which are already encrypted are skipped:  
![skip encrypted files](https://idafchev.github.io/blog/assets/images/ekans/ekans_screenshot24.png){: .align-center}  

Generating 16-byte IV using rand.Read():  
![generating IV](https://idafchev.github.io/blog/assets/images/ekans/ekans_screenshot25.png){: .align-center}  

Generating 256bit AES key using rand.Read():  
![generating AES Key](https://idafchev.github.io/blog/assets/images/ekans/ekans_screenshot26.png){: .align-center}  

The AES algorithm is used in CTR mode and the contents of the files are encrypted using the method `ctr.XORKeyStream()`. The contents of the files are read in chunks of 0x19000 bytes and when all data in the file is encrypted, they get overwritten with the new content.

AES in CTR mode:  
![aes ctr mode](https://idafchev.github.io/blog/assets/images/ekans/ekans_screenshot27.png){: .align-center}  

Files are read in 0x19000 byte chunks:  
![aes chunks](https://idafchev.github.io/blog/assets/images/ekans/ekans_screenshot28.png){: .align-center}  

Encrypting the buffer with ctr.XORKeyStream method:  
![aes ctr encrypt](https://idafchev.github.io/blog/assets/images/ekans/ekans_screenshot29.png){: .align-center}  

After the file is encrypted, the AES key gets encrypted using the `rsa.EncryptOAEP` function. OAEP stands for Optimal Asymmetric Encryption Padding which is a padding scheme for RSA which adds a level of randomness to the algorithm. 

EKANS then appends a structure to the end of the file containing the original filename, IV and encrypted AES key. The structure is in a gob encoding which is a binary go-specific encoding used for serialization. The low level details about the encoding are described in the go documentation.[3][4]

The encryption of the AES key with the rsa.EncryptOAEP function:  
![rsa](https://idafchev.github.io/blog/assets/images/ekans/ekans_screenshot32.png){: .align-center}  

Data is appended at the end of the file using gob:  
![gob](https://idafchev.github.io/blog/assets/images/ekans/ekans_screenshot34.png){: .align-center}  

When encryption is finished, before the ransomware process terminates it restores network communication with to following commands:  
```
netsh advfirewall set allprofiles state off
```

## <a name="29_encrypted_files"></a> 2.9 Encrypted files  
---
The structure which is appended to the end of the encrypted files is shown below. At the end the “EKANS” signature is appended and before that is the size of the gob structure in little-endian format.  
![file format](https://idafchev.github.io/blog/assets/images/ekans/ekans_screenshot37a.png){: .align-center}  

The coloured regions in the picture are as follows:  
1.	The “EKANS” Signature  
2.	Length of the gob structure in little-endian format  
3.	The RSA encrypted AES key  
4.	The original filename before encryption.  

# <a name="3_conclusions"></a> 3. Conclusions  
---
No privilege escalation, network communication or spreading mechanisms were found. This means that the attackers who wrote EKANS, compromise the environment manually and probably make sure they have the necessary privileges to execute the malware.  

The ransom note is dropped only on domain controllers which could mean that the attackers try to compromise the whole domain before deploying the malware.  
The AES keys used to encrypt the files are encrypted with the public RSA key of the attackers. Decryption is not possible without the private RSA key. 

# <a name="4_recommendations"></a> 4. Recommendations  
---
It is not known how the attackers compromise the victims initially, but it is suspected that it’s probably through Internet exposed RDP. The general recommendations when it comes to a ransomware attack are:  
- Maintain offline backups for critical systems.  
- Use strong passwords.  
- Monitor the servers and network environment for suspicious security events.  
- Update software versions and apply patches whenever possible.  
- Do regular vulnerability scans.  
- Disable any services used for administration (SSH, RDP, etc.) accessible from the internet. Use VPN to connect to the internal network and then connect to the intended services.  

# <a name="5_references"></a> 5. References  
---
1.	[https://www.dragos.com/blog/industry-news/ekans-ransomware-and-ics-operations/](https://www.dragos.com/blog/industry-news/ekans-ransomware-and-ics-operations/)  
2.	[https://golang.org/src/crypto/rand/rand.go](https://golang.org/src/crypto/rand/rand.go)  
3.	[https://blog.golang.org/gob](https://blog.golang.org/gob)  
4.	[https://golang.org/src/encoding/gob/doc.go](https://golang.org/src/encoding/gob/doc.go)  
