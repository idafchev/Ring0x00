---
date:   2019-03-24 00:00:00 +0200
tags: [posts]
excerpt: "Microsfot fixed their detection logic, so this doesn't work anymore."
title:  "Office 365 AMSI Bypass (fixed)"
---
# Introduction  
---
While I was playing around with the publicly available AMSI bypass PoCs for powershell I got curious if such bypass was available for Office 365. Google didn't show anything useful, so that's when I decided to try and port one of the powershell PoCs to VBA macro and see if it works.

If you aren't familiar with AMSI and the way to "bypass" it, I recommend reading the following resources first (in this order):
1. [https://www.cyberark.com/threat-research-blog/amsi-bypass-patching-technique/](https://www.cyberark.com/threat-research-blog/amsi-bypass-patching-technique/)
2. [https://www.cyberark.com/threat-research-blog/amsi-bypass-redux/](https://www.cyberark.com/threat-research-blog/amsi-bypass-redux/)
3. [https://0x00-0x00.github.io/research/2018/10/28/How-to-bypass-AMSI-and-Execute-ANY-malicious-powershell-code.html](https://0x00-0x00.github.io/research/2018/10/28/How-to-bypass-AMSI-and-Execute-ANY-malicious-powershell-code.html)
4. [https://rastamouse.me/2018/10/amsiscanbuffer-bypass---part-1/](https://rastamouse.me/2018/10/amsiscanbuffer-bypass---part-1/)
5. [https://rastamouse.me/2018/10/amsiscanbuffer-bypass---part-2/](https://rastamouse.me/2018/10/amsiscanbuffer-bypass---part-2/)
6. [https://rastamouse.me/2018/11/amsiscanbuffer-bypass-part-3/](https://rastamouse.me/2018/11/amsiscanbuffer-bypass-part-3/)
7. [https://rastamouse.me/2018/12/amsiscanbuffer-bypass-part-4/](https://rastamouse.me/2018/12/amsiscanbuffer-bypass-part-4/)
8. [https://www.microsoft.com/security/blog/2018/09/12/office-vba-amsi-parting-the-veil-on-malicious-macros/](https://www.microsoft.com/security/blog/2018/09/12/office-vba-amsi-parting-the-veil-on-malicious-macros/)

# Porting the AMSI Bypass to VBA  
---
First, I ported the patch from the "[AmsiScanBuffer Bypass - Part 3](https://rastamouse.me/2018/11/amsiscanbuffer-bypass-part-3/)" blog post of rastamouse. This implementation patched the beginning of `AmsiScanBuffer` function with the bytes `0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3` which are equivalent to:  
```nasm
mov eax, 80070057h
ret
```

The resulting macro is shown below:  
```vb
Private Declare PtrSafe Function GetProcAddress Lib "kernel32" (ByVal hModule As LongPtr, ByVal lpProcName As String) As LongPtr
Private Declare PtrSafe Function LoadLibrary Lib "kernel32" Alias "LoadLibraryA" (ByVal lpLibFileName As String) As LongPtr
Private Declare PtrSafe Function VirtualProtect Lib "kernel32" (lpAddress As Any, ByVal dwSize As LongPtr, ByVal flNewProtect As Long, lpflOldProtect As Long) As Long
Private Declare PtrSafe Sub CopyMemory Lib "kernel32" Alias "RtlMoveMemory" (Destination As Any, Source As Any, ByVal Length As LongPtr)

Private Sub Document_Open()
    Dim AmsiDLL As LongPtr
    Dim AmsiScanBufferAddr As LongPtr
    Dim result As Long
    Dim MyByteArray(6) As Byte
    Dim ArrayPointer As LongPtr

    MyByteArray(0) = 184 ' 0xB8
    MyByteArray(1) = 87  ' 0x57
    MyByteArray(2) = 0   ' 0x00
    MyByteArray(3) = 7   ' 0x07
    MyByteArray(4) = 128 ' 0x80
    MyByteArray(5) = 195 ' 0xC3

    AmsiDLL = LoadLibrary("amsi.dll")
    AmsiScanBufferAddr = GetProcAddress(AmsiDLL, "AmsiScanBuffer")
    result = VirtualProtect(ByVal AmsiScanBufferAddr, 5, 64, 0)
    ArrayPointer = VarPtr(MyByteArray(0))
    CopyMemory ByVal AmsiScanBufferAddr, ByVal ArrayPointer, 6
    
End Sub
```

I created a Word document with the embedded macro, saved it, opened it again and clicked "Enable Content". The following popup message showed, saying that the bypass was detected as malicious macro.  

![macro](https://idafchev.github.io/blog/assets/images/office365_amsi_bypass/malicious_macro_popup.png){: .align-center}  

I tried obfuscating the code by splitting the strings, but while this works in powershell it didn't work with VBA. If you've read the 8th resource I gave in the introduction, you probably remember the following picture:  
![amsi_vba.png](https://idafchev.github.io/blog/assets/images/office365_amsi_bypass/amsi_vba.png){: .align-center}  
*source:[https://www.microsoft.com/security/blog/2018/09/12/office-vba-amsi-parting-the-veil-on-malicious-macros/](https://www.microsoft.com/security/blog/2018/09/12/office-vba-amsi-parting-the-veil-on-malicious-macros/)*

VBA has a behavior log and the contents of this behavior log are passed to AMSI, which then passes them to the installed AV for scanning. This means that obfuscating the macro isn't going to work, thus I tried another approach. I took the address of `AmsiCloseSession` function and then added an offset to it, so I can get the address of `AmsiScanBuffer`. That way I used `"AmsiCloseSession"` string instead of `"AmsiScanBuffer"` in the `GetProcAddress` function, but this also got detected.

```vb
AmsiDLL = LoadLibrary("amsi.dll")
AmsiCloseSessionAddr = GetProcAddress(AmsiDLL, "AmsiCloseSession")
AmsiScanBufferAddr = AmsiCloseSessionAddr + 80
```

I needed to see what exactly was triggering the detection and for that purpose I used the API Monitor tool. In the picture below, you can see that the `AmsiScanString` function is used, not `AmsiScanBuffer`, and the final contents of the scanned buffer right before the detection. *Open the screenshot in a new tab to view in bigger format.*

![vba_behavior_log.png](https://idafchev.github.io/blog/assets/images/office365_amsi_bypass/vba_behavior_log.png){: .align-center}  

Note: You should be aware that API Monitor might interfere with the code. When I attached API Monitor before running the macro, `GetProcAddress` returned wrong address. As a workaround I used a `MsgBox` to pause execution right after `GetProcAddress` and then proceeded with attaching API Monitor.

If you disassemble `AmsiScanString` you'll notice that it calls `AmsiScanBuffer`, so I decided to patch both functions just to be sure. The patch is the same for both of them. Their disassembly can be seen in the following two pictures.

![amsi_scan_string.png](https://idafchev.github.io/blog/assets/images/office365_amsi_bypass/amsi_scan_string.png){: .align-center}  
![amsi_scan_buffer.png](https://idafchev.github.io/blog/assets/images/office365_amsi_bypass/amsi_scan_buffer.png){: .align-center}  

My theory was that the detection was based on the `"amsi.dll"` and `"kernel32.RtlMoveMemory()"` strings in the behavior log. To test this I did the following things:
1. Removed `RtlMoveMemory` from the code. This resulted in no detection.
2. Kept `RtlMoveMemory`, but changed `LoadLibrary` to load `"kernel32.dll"` instead. This of course crashed after `RtlMoveMemory`, but I verified with API monitor that everything including `RtlMoveMemory` was in the behavior log and passed to AMSI before crashing. Also no detection.
3. Removed `RtlMoveMemory`, used `LoadLibrary("kernel32.dll")` and `GetProcAddress(TargetDLL,"amsi.dll kernel32.RtlMoveMemory(123,123,123)")`. This showed up in the behavior log and was detected as malicious, although `LoadLibrary` didn't load `"amsi.dll"` and `RtlMoveMemory` was never called. The macro was blocked before execution so the invalid `GetProcAddress` was never actually called.

The result of the third step can be seen below:  
![detection_logic_test.png](https://idafchev.github.io/blog/assets/images/office365_amsi_bypass/detection_logic_test.png){: .align-center}  

This proved my theory that the detection was based on both `"amsi.dll"` and `"kernel32.RtlMoveMemory()"` strings when present in the behavior log. 

To get around this I tried using another function to patch memory. I used `RtlFillMemory` to patch one byte at a time and with it I successfully bypassed detection. I also verified with windbg that the functions were successfully patched. 

There was a problem though. If after the bypass code I added another WinAPI function then Word crashed. I figured that this might be caused by the rastamouse variant of the patch. I didn't know why and was too lazy to debug the issue so I just tried the patch from CyberArk which worked fine and didn't crash Word when I added more code after the bypass.

`AmsiScanStringAddr + 5` was patched with:  
```nasm
nop
xor edx, edx
```

`AmsiScanBufferAddr + 66` was patched with:  
```nasm
nop
xor eax, eax
```

PoC Video:  
[https://www.youtube.com/watch?v=9jXzP3UusD0](https://www.youtube.com/watch?v=9jXzP3UusD0)

# Contacting Microsoft  
---
This bypass isn't anything serious or groundbreaking, after all it's widely known that AMSI can be patched in memory. It's also known that this isn't a vulnerability according to Microsoft and probably it wouldn't get fixed, because the ability to patch AMSI is a by design weakness. I also wasn't sure if the Office 365 AMSI bypas was actually new or I didn't google enough.

But I still didn't feel comfortable sharing the code while someone could potentially use it in a macro malware... So I decided to contact Microsoft and suggest they add a detection for when `"amsi.dll"` is used with other memory modifying functions and not only `RtlMoveMemory`. Their response was that they modified their detection logic to address this issue :)

I'm still not sharing my final code, but by reading this blog post you should be able to write it yourself. Don't expect it to run if your Defender definitions are up to date!
