---
title: "Bypassing AMSI (Antimalware Scan Interface) With CSharp 0x00"
date: 2021-10-23T14:20:04Z
draft: false
tags: ["offensive-sekurity", "windoz", "reverse-engineering"]
categories: ["guide"]
---

Ah yes. Windoz, the most popular desktop operating system solution out there. And, the most attacker friendly operating system out there. At least, `was`.

Windows has a really good reputation in the malware industrustry. Red teamers often use this to their advantage and use malware to maintain persistence access to the victim machine.

Out of the tools that they use to fulfill this task, Windows powershell is important. Windows powershell is a powerful administrative tool mostly used by sys admins. And mainly because of that reason, hackers often utilize this tool. Another most important sofware when it comes to windows malware is, microsoft office software. It is a proven fact that most notable malware outbreaks in past few years has something to do with VBA macros. in 2007 microsoft shipped office package with macro disabled by default. Yet those type of malware is still alive and well.

And as a result, microsoft and antimalware vendors has developed many security machanisms to deal with those threats. For example, modern anti malware solutions are able statically analyze scripts, binaries and detect whether they are malicious or not using signatures such as strings.

And because of that, malware authors use various techniques to bypass those defense machanisms. One of major technique is code obfuscation.

consider the following example, that i took from msdn.

```bash
    function displayEvilString
    {
        Write-Host 'pwnd!'
    }
```

Assuming the above powershell snippet as malicous, we can write a signature to 
detect the malware. this signature can be `Write-Host 'pwnd!'` or simply `'pwnd!'`.

So to avoid signature based detection, above snippet can be obfuscated like shown below.

```bash
    function obfuscatedDisplayEvilString
    {
        $xorKey = 123
        $code = "LHsJexJ7D3see1Z7M3sUewh7D3tbe1x7C3sMexV7H3tae1x7"
        $byte = [Convert]::FromBase64String($code)
        $newBytes = foreach($byte in $bytes) {
            $byte -bxor $xorKey
        }
        $newCode = [System.Text.Encoding]::Unicode.GetString($newBytes)
    }
```

And this is a win for malware authors, since this is beyond what anti malware solutions can emulate or detect, until AMSI joins the conversation.

## Antimalware Scan Interface (AMSI)

AMSI is a standard interface that allows applications to interact with anti malware products installed on the system. Which means is that it provides
an API for Application developers. Application developers can use the API to implement security features to make sure that end user is safe. According
to microsoft, thats why they consider Application developers as a target audience of this standard interface.

The other one is Anti malware vendors. Any anti malware vendor can provide an interface for AMSI to work with. By doing that, they can detect large 
number of malicous activity that they could not.  By default AMSI uses Windows defender as the backing detection engine.

According to microsoft, AMSI provides following features by default.

-   User Account Control
-   PowerShell
-   WIndows Script Host
-   JScript && VBScript
-   Office VBA macros

As it is clear from those default features, AMSI specifically provides anti malware security machanisms to defend against dynamic script-base malware. 

when running a script, eventhough the code is initially obfuscated, it has to be de obfuscated and demartialled in order to go through the scripting engine. At this point, AMSI APIs can be used to scan the script and determine whether it is malicious or not.

AMSI can also be useful in scenarios like invoking malicious powershell commands. 

In this article Im going to focus only on windows powershell.

## Demo

So lets take SafeSploit as our example.

When we run the binary, the result we get is.
![AMSI](/img/CSharpLoader/AMSI.png)

See, as we expected, powershell stops the execution of the program once it has detected the program is suspecious using AMSI.
So, how can we bypass this?, well before that, we have to dive deep into AMSI internals to understand how things work.

## AMSI internals

As i previously mentioned, any anti malware vendor can become an AMSI provider and inspect data sent by applications via the AMSI interface. If the content submitted for scan is detected as malicious, the consuming application will be alerted. In our case, Windows powershell uses Windows defender as the AMSI provider.
When we input a malicous command or execute a malicous program, powershell will pass everything to windows defender before doing any execution.
It is anti malware vendor's duty to do all the scans and detect whether recieved input is malicous or not.

For application programmers to interact with the AMSI, it provides a dll called, amsi.dll. Let's examine powershell from process hacker to check whether this dll is loaded.

![PoweshellProperties](/img/CSharpLoader/powershellProperties.png)

as we can see, amsi.dll has been loaded into powershell.exe. Now, let's take a look at this dll in depth and see if we can find anything interesting.
Even without looking at the dll, we can think of a technique to bypass AMSI, using dll injection and inpersonating several functions exported by the dll. Anyway lets choose the hard way and before dive deep into disassembly, lets examine the export table of amsi.dll.

![Exports](/img/CSharpLoader/Exports.png)

Out of the above exported functions, only two are important to us.

-   AmsiScanBuffer
-   AmsiScanString

## AmsiScanBuffer

[here](https://docs.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsiscanbuffer), check out the documentation first. According to the msdn and as well as the name suggests, `AmsiScanBuffer` function scans a buffer that is filled for malware.

As msdn says, this function returns `S_OK` if the call is successful. However return value does not idicate whether the buffer is malicous. instead, function uses an output parameter of type `AMSI_RESULT` to send the scan results.

```c
    typedef enum AMSI_RESULT {
        AMSI_RESULT_CLEAN,
        AMSI_RESULT_NOT_DETECTED,
        AMSI_RESULT_BLOCKED_BY_ADMIN_START,
        AMSI_RESULT_BLOCKED_BY_ADMIN_END,
        AMSI_RESULT_DETECTED
    } ;
```
And heres how this function looks like in disassembly.

![](/img/CSharpLoader/AmsiScanBufferPrologue.png)

here we can see stack pointer is stored in `r11` register and since this is x64 _stdcall, first four parameters are stored in rcx, rdx, r8 and r9 registers. Rest are stored in the stack. With that information, we can assume a pointer to the `AMSI_RESULT` enum is stored in the stack. 

then we can see a series of comparisons around global data.

![](/img/CSharpLoader/AmsiScanBuffer2.png)

followed by,

![](/img/CSharpLoader/AmsiScanBuffer4.png)

which can be decompiled down into,

```cpp
    HRESULT __stdcall AmsiScanBuffer(
            HAMSICONTEXT amsiContext, 
            PVOID buffer, ULONG length, 
            LPCWSTR contentName, 
            HAMSISESSION amsiSession, 
            AMSI_RESULT *result)
    {
        if ((handle == &handle) || (handle[0x1c] == 4))
        {
            if (buffer == NULL || result == NULL || amsiContext == NULL || 
                (*amsiContext) == 0x49534D41 || amsiContext[8] == 0x0) 
            {
                goto end;
                ///
            } else {
                var_30 = amsiContext[8];
                var_48 = someGlobal;
                var_40 = buffer;

            }
        }else 
        {
            SomeFunc(handle[16], buffer, length, amsiSession, result)
        }
    }
```

Let's just attach powershell to windbg, place a breakpoint in `AmsiScanBuffer` and see if we can find anything more.

![breakpoint at AmsiScanBuffer](/img/CSharpLoader/breakpoint.png)

and here we go! a hit.

![breakpoint hit](/img/CSharpLoader/bphit.png)

