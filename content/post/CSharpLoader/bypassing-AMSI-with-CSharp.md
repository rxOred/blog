---
title: "From AMSI to Reflection 0x0"
date: 2021-10-23T14:20:04Z
draft: false
cover: "img/CSharpLoader/cover.png"
description: "Reverse engineering AMSI internals"
tags: ["offensive-sekuruty", "windoz", "reverse-engineering"]
readingTime: true
---

In Windows environments, in both initial access and post-exploitation phases, script-based malware plays a major role. Often, hackers utilize microsoft 
office suite to gain initial access (using droppers, loaders) to the victim and Windows powershell to explore internal network, perform scans... basically to
do the post exploitation stuff. (well of course, there are powershell based droppers.)

There is something that is common to both of these tools. Windows scripting engine.

And as a result, Microsoft and antimalware vendors have developed many security mechanisms to deal with those threats that utilize script-based malware. 
For example, modern anti-malware solutions can statically analyze scripts, binaries and detect whether they are malicious or not using signatures such as 
strings.

And because of that, malware authors use various techniques to bypass those defense mechanisms. One of the major techniques is code obfuscation.

consider the following example, that I took from MSDN.

```bash
    function displayEvilString
    {
        Write-Host 'pwnd!'
    }
```

Assuming the above PowerShell snippet is malicious, we can write a signature to detect the malware. this signature can be `Write-Host 'pwnd!'` or simply 
`'pwnd!'`.

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

The other one is Anti-malware vendors. Any anti-malware vendor can provide an interface for AMSI to work with. By doing that, they can detect a large 
number of malicious activities that they could not. By default, AMSI uses Windows defender as the backing detection engine.

According to Microsoft, AMSI provides the following features by default.

    -   User Account Control
    -   PowerShell
    -   Windows Script Host
    -   JScript && VBScript
    -   Office VBA macros

As it is clear from those default features, AMSI specifically provides anti-malware security mechanisms to defend against dynamic script-based malware. 

when running a script, even though the code is initially obfuscated, it has to be deobfuscated to go through the scripting engine. At this point, AMSI APIs
can be used to scan the script and determine whether it is malicious or not.

AMSI can also be useful in scenarios like invoking malicious PowerShell commands. 

In this article we'll be focusing on AMSI internals. in the next few, we'll go over some bypass techniques.

## Demo

So let's take Safetykatz as our example.

When we run the binary, the result we get is.
![AMSI](/img/CSharpLoader/AMSI.png)

See, as we expected, PowerShell stops the execution of the program once it has detected the program is suspicious using AMSI.
So, how can we bypass this?, well before that, we have to dive deep into AMSI internals to understand how things work.

## AMSI internals

As I previously mentioned, any anti-malware vendor can become an AMSI provider and inspect data sent by applications via the AMSI interface. If the content s
ubmitted for the scan is detected as malicious, the consuming application will be alerted. In our case, Windows PowerShell uses Windows defender as the AMSI 
provider.
When we input a malicious command or execute a malicious program, PowerShell will pass everything to windows defender before doing any execution.
Anti-malware vendors must do all the scans and detect whether the received input is malicious or not.

For application programmers to interact with the AMSI, it provides a dll called, amsi.dll. Let's examine PowerShell from a process hacker to check whether th
is dll is loaded.

![PoweshellProperties](/img/CSharpLoader/powershellProperties.png)

as we can see, amsi.dll has been loaded into powershell.exe. Now, let's take a look at this dll in-depth and see if we can find anything interesting.
Even without looking at the dll, it is possible to think of some techniques to bypass AMSI, Anyway, its time to dig deep.

Before start reading disassembly, let's examine the export table of amsi.dll.

![Exports](/img/CSharpLoader/Exports.png)

Out of the above exported functions, only two are important to us.

    -   AmsiInitialize
    -   AmsiScanBuffer
    -   AmsiScanString

maybe `AmsiUacInitialize` is interesting to us. but we are not going to take a look at that in this post.

First we'll go through AmsiScanBuffer and AmsiScanString.

### AmsiScanBuffer

According to the MSDN and as well as the name suggests, the `AmsiScanBuffer` function scans a buffer for malicous content.

here is the function prototype [msdn](https://docs.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsiscanbuffer)
```c 
    HRESULT AmsiScanBuffer(
      [in]           HAMSICONTEXT amsiContext,
      [in]           PVOID        buffer,
      [in]           ULONG        length,
      [in]           LPCWSTR      contentName,
      [in, optional] HAMSISESSION amsiSession,
      [out]          AMSI_RESULT  *result
    );
```

First parameter is a handle to amsi context, which is probably a handle caller recieved from `AmsiInitialize` call. 
Second and third paramters describe the buffer that amsi should scan and it's length.

fourth parameter is a long pointer to a wide character string for the content name and the fifth is the handle to the amsi session.

As MSDN says, this function returns `S_OK` if the call is successful. However, the return value does not indicate whether the buffer is malicious. instead,
the function uses an output parameter, the sixth one of type `AMSI_RESULT` to send the scan results to caller.

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

here we can see stack pointer is stored in `r11` register and since this is x64 _stdcall, the first four parameters are stored in rcx, rdx, r8 and r9 
registers. Rest are stored in the stack. With that information, we can assume a pointer to the `AMSI_RESULT` enum is stored in the stack. 

then we can see a series of comparisons around global data.

![](/img/CSharpLoader/AmsiScanBuffer2.png)

followed by,

![](/img/CSharpLoader/1.png)

![](/img/CSharpLoader/2.png)

which can be roughly decompiled down into,

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
            SomeFunc(
                *((BYTE*)handle + 16), 
                buffer, 
                length, 
                amsiContext, 
                buffer, 
                amsiSession, 
                result
            );
        }

        if (buffer == NULL || result == NULL || amsiContext == NULL || 
            amsiContext->firstMember != 0x49534D41 || amsiContext->secondMember == 0x0 ||
            amsiContext->fourthMember == 0x0) 
        {
            return 0x80070057;    
        } 
        else 
        {
            return (*(amsiContext->thirdMember) + 0x18)(
                amsiContext->thirdMember,
                funcptr,  // a global function pointer
                result,
                0
            );
        }
    }
```

So as discussed earlier, the function takes 6 parameters. One of which is the pointer to the `AMSI_RESULT` structure as I explained above - `*result`. 
According to MSDN, others include a buffer, which will be scanned by the anti-malware vendor - `buffer`, length of the buffer - `length`, filename, URL, 
unique script ID - `contentName` and a handler to the session - `HAMSISESSION` structure.

Then the function does some checks against the handle, if the checks turn out to be true, it calls a random function, and continues 
the execution from the next if condition. else, it continues execution without ever calling that random function. (named to `SomeFunc`).

then there is a pretty huge if condition, which is essentially checks if any of the above parameters does not fullfill specific conditions.
And if the condition fails, it calls another function. It is a function pointer that is extracted from the `amsiContext` parameter. And it's pretty much 
clear that this function pointer is some kind of a handler to the anti-malware vendor's scanning interface.

This makes sense because to call `AmsiScanBuffer`, one has to initialize amsi with `AmsiInitialize` and open a session if required with `AmsiOpenSession`. 
And `AmsiInitialize` returns a handler and that handler is then passed down to this function as the first parameter (amsiContext). 

To make sure our assumptions so far are correct, we'll go over this function using windbg.

Since we already know interesting parts of the function, we can place breakpoints easily.



So the conclusion is, when `AmsiInitialize` function gets called, it initializes the anti-malware vendor, registers it, and returns a handler that contains a
pointer to a registered function.`AmsiScanBuffer` function is responsible for doing some basic checks on the handler, extracting registered function from the
 handler and calling it with necessary parameters.

### AmsiScanString

This is pretty much the same as the previous function except this one scan for strings. let's just do a small analysis on this one too for the sake of comple
teness.

![](/img/CSharpLoader/AmsiScanString.png)

Function check if the string is empty or not.

![](/img/CSharpLoader/AmsiScanString1.png)

here is how the rest of the function looks like.

Without much analysis, we can clearly say that this one calls `AmsiScanString` internally. before that, it checks whether the enum pointed by `target` is 
empty.

Then there is a loop that increases `rax` register until it finds a null byte. This is essentially a strlen. After that, `rax` is added to `rax` and gets 
compared to `r11`, which holds value `0xFFFFFFFF`, if the value in `rax` is above `0xFFFFFFFF`, it moves `0x80070057` to `rax` register and returns. else, it
 calls `AmsiScanBuffer`.

And what this function does is pretty simple. it checks if the string length is higher than some value and if yes, it returns after some random value 
loaded into rax, and else, it simply calls `AmsiScanBuffer`.

Now it is time to conclude our assumptions on AmsiInitialize.

### AmsiInitialize



## The End.

So yeah that's it for now... we explored AMSI in-depth in this article. In the next one, We will go through some common AMSI bypass techniques.


#Spread Anarchy!
