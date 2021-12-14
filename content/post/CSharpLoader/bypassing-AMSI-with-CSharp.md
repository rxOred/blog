---
title: "From AMSI to Reflection"
date: 2021-10-23T14:20:04Z
draft: false
cover: "img/CSharpLoader/windowsdefender.jpg"
description: "Reverse engineering AMSI internals"
tags: ["offensive-sekuruty", "windoz", "reverse-engineering"]
categories: ["guide"]
---

Ah yes. Windoz, the most popular desktop operating system solution out there. And, the most attacker-friendly operating system out there. At least, `was`.

Windows has a really good reputation in the malware industry. Red teamers often use this to their advantage and use malware to maintain persistent access to the victim machine.

Out of the tools that they use to fulfill this task, script-based malware and payloads play a major role. And to execute those stuff, they mostly use Windows PowerShell, a powerful administrative tool mostly used by sysadmins. Another most important software when it comes to windows malware is Microsoft office software. It is a proven fact that the most notable malware outbreaks in the past few years have something to do with VBA macros. in 2007 Microsoft shipped office packages with macro disabled by default. Yet those type of malware is still alive and well.

And as a result, Microsoft and antimalware vendors have developed many security mechanisms to deal with those threats. For example, modern anti-malware solutions can statically analyze scripts, binaries and detect whether they are malicious or not using signatures such as strings.

And because of that, malware authors use various techniques to bypass those defense mechanisms. One of the major techniques is code obfuscation.

consider the following example, that I took from MSDN.

```bash
    function displayEvilString
    {
        Write-Host 'pwnd!'
    }
```

Assuming the above PowerShell snippet is malicious, we can write a signature to detect the malware. this signature can be `Write-Host 'pwnd!'` or simply `'pwnd!'`.

So to avoid signature-based detection, the above snippet can be obfuscated like shown below.

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

And this is a win for malware authors since this is beyond what anti-malware solutions can emulate or detect until AMSI joins the conversation.

## Antimalware Scan Interface (AMSI)

AMSI is a standard interface that allows applications to interact with anti-malware products installed on the system. This means is that it provides
an API for Application developers. Application developers can use the API to implement security features to make sure that the end-user is safe. According
to Microsoft, that's why they consider Application developers as a target audience of this standard interface.

The other one is Anti-malware vendors. Any anti-malware vendor can provide an interface for AMSI to work with. By doing that, they can detect a large number of malicious activities that they could not.  By default, AMSI uses Windows defender as the backing detection engine.

According to Microsoft, AMSI provides the following features by default.

-   User Account Control
-   PowerShell
-   Windows Script Host
-   JScript && VBScript
-   Office VBA macros

As it is clear from those default features, AMSI specifically provides anti-malware security mechanisms to defend against dynamic script-based malware. 

when running a script, even though the code is initially obfuscated, it has to be deobfuscated to go through the scripting engine. At this point, AMSI APIs can be used to scan the script and determine whether it is malicious or not.

AMSI can also be useful in scenarios like invoking malicious PowerShell commands. 

In this article I'm going to focus on the internals of AMSI. in the next one, I'll provide y'all with some bypass techniques.

## Demo

So let's take SafeSploit as our example.

When we run the binary, the result we get is.
![AMSI](/img/CSharpLoader/AMSI.png)

See, as we expected, PowerShell stops the execution of the program once it has detected the program is suspicious using AMSI.
So, how can we bypass this?, well before that, we have to dive deep into AMSI internals to understand how things work.

## AMSI internals

As I previously mentioned, any anti-malware vendor can become an AMSI provider and inspect data sent by applications via the AMSI interface. If the content submitted for the scan is detected as malicious, the consuming application will be alerted. In our case, Windows PowerShell uses Windows defender as the AMSI provider.
When we input a malicious command or execute a malicious program, PowerShell will pass everything to windows defender before doing any execution.
Anti-malware vendors must do all the scans and detect whether the received input is malicious or not.

For application programmers to interact with the AMSI, it provides a dll called, amsi.dll. Let's examine PowerShell from a process hacker to check whether this dll is loaded.

![PoweshellProperties](/img/CSharpLoader/powershellProperties.png)

as we can see, amsi.dll has been loaded into powershell.exe. Now, let's take a look at this dll in-depth and see if we can find anything interesting.
Even without looking at the dll, we can think of a technique to bypass AMSI, using dll injection and impersonating several functions exported by the dll. Anyway, let's choose the hard way, and before diving deep into disassembly, let's examine the export table of amsi.dll.

![Exports](/img/CSharpLoader/Exports.png)

Out of the above exported functions, only two are important to us.

-   AmsiScanBuffer
-   AmsiScanString

## AmsiScanBuffer

[here](https://docs.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsiscanbuffer), check out the documentation first. According to the MSDN and as well as the name suggests, the `AmsiScanBuffer` function scans a buffer that is filled for malware.

As MSDN says, this function returns `S_OK` if the call is successful. However, the return value does not indicate whether the buffer is malicious. instead, the function uses an output parameter of type `AMSI_RESULT` to send the scan results.

```c
    typedef enum AMSI_RESULT {
        AMSI_RESULT_CLEAN,
        AMSI_RESULT_NOT_DETECTED,
        AMSI_RESULT_BLOCKED_BY_ADMIN_START,
        AMSI_RESULT_BLOCKED_BY_ADMIN_END,
        AMSI_RESULT_DETECTED
    } ;
```
And here's how this function looks like in disassembly.

![](/img/CSharpLoader/AmsiScanBufferPrologue.png)

here we can see stack pointer is stored in `r11` register and since this is x64 _stdcall, the first four parameters are stored in rcx, rdx, r8 and r9 registers. Rest are stored in the stack. With that information, we can assume a pointer to the `AMSI_RESULT` enum is stored in the stack. 

then we can see a series of comparisons around global data.

![](/img/CSharpLoader/AmsiScanBuffer2.png)

followed by,

![](/img/CSharpLoader/AmsiScanBuffer4.png)

which can be decompiled down into,

```cpp
    HRESULT __stdcall AmsiScanBuffer
    (
            HAMSICONTEXT amsiContext, 
            PVOID buffer, 
            ULONG length, 
            LPCWSTR contentName, 
            HAMSISESSION amsiSession, 
            AMSI_RESULT *result
    )
    {
        auto var;
        if ((handle != &handle) && (*(handle + 0x1c)) != 4))
        {
            SomeFunc(*(handle + 4), buffer, lengthm amsiSession, result);
        }

        if (buffer == NULL || result == NULL || amsiContext == NULL || 
            (*amsiContext) == 0x49534D41 || *(amsiContext + 2) == 0x0 ||
            *(amsiContext + 4) == 0x0) 
        {
            var = 0x80070057;    
        } 
        else 
        {
            /* ################################ */
            var = *(*(amsiContext + 0x4) + 0x18)();
        }
    }
```

So the function takes 6 parameters. One of which is the pointer to the `AMSI_RESULT` structure as I explained above - `*result`. According to MSDN, others include a buffer, which will be 
scanned by the anti-malware vendor - `buffer`, length of the buffer - `length`, filename, URL, unique script ID - `contentName` and a handler to the session - `HAMSISESSION` structure.

then the function does some checks against the handle, if the checks turn out to be false, it calls a random function which I haven't analyzed, and continues the execution from the next if condition. else, it continues execution without ever calling that random function. (i named that 'random function' `SomeFunc` :3 ).

then there is a pretty huge if condition, which I'm not gonna go through (read the decompiled version and understand it :3 ). And if the condition fails, we call another random function but this time, it's not a random function. it is a function pointer that is extracted from the `amsiContext` parameter. And I'm pretty much sure that this function pointer is some kind of a handler to the anti-malware vendor's scanning interface.

This makes sense because to call `AmsiScanBuffer`, one has to initialize amsi with `AmsiInitialize` and open a session if required with `AmsiOpenSession`. And `AmsiInitialize` returns a handler and that handler is then passed down to this function as the first parameter (amsiContext). 

So the conclusion is, when `AmsiInitialize` function gets called, it initializes the anti-malware vendor, registers it, and returns a handler that contains a pointer to a registered function.`AmsiScanBuffer` function is responsible for doing some basic checks on the handler, extracting registered function from the handler and calling it with necessary parameters.

## AmsiScanString

this is pretty much the same as the previous function except this one scan for strings. let's just do a small analysis on this one too for the sake of completeness.

![](/img/CSharpLoader/AmsiScanString.png)

Function check if the string is empty or not.

![](/img/CSharpLoader/AmsiScanString1.png)

here is how the rest of the function looks like.

Without much analysis, we can clearly say that this one calls `AmsiScanString` internally. before that, it checks whether the enum pointed by `target` is empty.

Then there is a loop that increases `rax` register until it finds a null byte. This is a strlen. After that, `rax` is added to `rax` and gets compared to `r11`, which holds value `0xFFFFFFFF`, if the value in `rax` is above `0xFFFFFFFF`, it moves `0x80070057` to `rax` register and returns. else, it calls `AmsiScanBuffer`.

And what this function does is pretty simple. it checks if the string length is higher than some value and if yes, it returns after some random value loaded into rax, and else, it simply calls `AmsiScanBuffer`.

## that's it, kids!

So yeah that's it for now... we explored AMSI in-depth in this article. In the next one, We will go through some common AMSI bypass techniques.

