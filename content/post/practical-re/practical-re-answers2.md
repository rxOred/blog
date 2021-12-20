---
title: "sample_j DllMain"
date: 2021-10-02T00:40:06Z
draft: false
cover: "/img/practicalre/re2.png"
description: "Practical Reverse Engineering Answers 2 - sample_J DllMain"
tags: ["reverse-engineering"]
categories: ["write-up"]
---

So last time we finished some exercises from the book pratical reverse engineering. Now, we have page 35 exercises. I wont cover exercise here because some are really straight forward.

without useless intros lets get started.

# Chaper 1, page 35

We are starting with the second one, because first one is pretty easy. 2nd question asks us to decompile DllMain.


![dllmain, DllMain](/img/dllmain.png)


as we can see, IDA has generated us some information of the stack as well as a nice graph view. From that, we can decompile it down to,

```c
   BOOL __stdcall APIENTRY DllMain(HMODULE *hModule, 
                           DWORD ul_reason_for_call, 
                           LPVOID lpReserved)
   {
      IDTR idtr;
      PROCESSENTRY32 pe;
      HANDLE handle;
   }
```

![prologue](/img/sidt.png)

next we can the function prologue, where stack frame is initialized. using `sub esp, 130h` instruction, we can confirm that stack will be 0x130 bytes large. next we can see a `sidt fword[ebp+idtr]`.

if you have some low level debugging/development experience, you might know what `sidt` does. in case you dont, it reads idtr register to the operand location. in this case, `fword[ebp+idr]`will be filled with idtr register. So whats this idtr register? well, idtr register is a 6byte sized register. it stores length of the interrupt desciptor table in the last 2 bytes and base of interrupt desciptor table in the top 4 bytes. Now, how can we call `sidt` from C/C++?

before that, here we build the idtr structure
```c
   typedef struct idtr {
      DWORD idt_base;
      short idt_size;
   } IDTR, *PIDTR;
```

inside DllMain we do this.

```c
   IDTR idtr;
   __sidt(&idtr);
```

then DllMain compares `idtr+2` with some 2 random hex values that looks like memory addresses. Using the above explaination, it is pretty clear that whoever wrote this malware compares base address of interrupt desciptor table with 2 hardcoded memory addresses, first as we can see in the above image, 0x8003f400 and 0x80047400 in the below image. Tbh, this is bad. Reason is that, in multi core processors each core gets a different base address for interrupt desciptor table. And when using hardcoded addresses... Anyway. lets decompile that part too.

![idt address range](/img/checkidt.png)

```c
   if (idtr.idt_base > 0x8003f400 && idtr.idt_base < 0x80047400){
      return FALSE;
   }
```

From above snippet it is clear that it does check for some range. looks like it validates IDT base...

After the comparision if the range requirements are satisfied, we can see that DllMain creates a snapshot of all the running processes.

![CreateToolhelp32Snapshot](/img/snapshot.png)

we can decompile that stub into

```c
   handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
   if (handle == INVALID_HANDLE_VALUE) {
      return FALSE;
   }
```

it also zero out `pe` using `stosd` instruction.

```c
   memset(&pe.cntUsage, 0, 0x49);
```

Next, DllMain calls `Process32First` with arguements `&pe`(eax) and `handle`(edi), a string comparison with `explorer.exe` and then if comparison fails, we can see a call to `Process32Next`.
Basically this stub go through each process of the snapshot until it finds `explorer.exe`.

![Process32First](/img/getexplorer.png)

decompiled version of that stub may look like
```c
   pe.dwSize = sizeof(PROCESSENTRY32);
   if (Process32First(handle, &pe) != 0) {
      // code here
   }
   else {
      while (Process32Next(handle, &pe) != 0) {
         if (wcscmp(pe.szExeFile, L"explorer.exe") == 0) {
            // code here
         }
         continue;
      }
      return FALSE;
   }
```

Once it found the explorer.exe, it compares the process's pid to it's parents pid.

![check process ids](/img/checkpid.png)

here if they are equal, we simply exit out.

![exit](/img/exit.png)

else, we create a thread in the current virtual memory space with start address set to `0x100032d0`.

![evil stuff](/img/evil.png)

```c
   do_evil_stuff:
      if (pe.th32ParentProcessID == pe.th32ProcessID) {
         return FALSE;
      }
      else {
         if (ul_reason_for_call == DLL_PROCESS_ACCESS) {
            CreateThread(
               NULL, NULL, (LPTHREAD_START_ROUTINE)0x100032d0, NULL, NULL, NULL
            );
            return TRUE;
         }
         return TRUE:
      }
```

with that info, we can fill out the stub that searches for explorer.exe like this

```c
   pe.dwSize = sizeof(PROCESSENTRY32);
   if (Process32First(handle, &pe) != 0) {
      if (wcscmp(pe.szExeFile, L"explorer.exe") == 0)
         goto do_evil_stuff;
      else {
         while (Process32Next(handle, &pe) != 0) {
            if (wcscmp(pe.szExeFile, L"explorer.exe") == 0) {
               goto do_evil_stuff;
            }
            continue;
         }
         return FALSE;
      }
   }

```

combining all into a single stub, we will get something like this as the DllMain

```cpp
   typedef struct idtr {
      DWORD idt_base;
      short idt_size;
   } IDTR, *PIDTR;

   BOOL __stdcall APIENTRY DllMain(HMODULE *hModule, 
                           DWORD ul_reason_for_call, 
                           LPVOID lpReserved)
   {
      IDTR idtr;
      PROCESSENTRY32 pe;
      HANDLE handle;

      __sidt(&idtr);
      if (idtr.idt_base < 0x80047400 && idtr.idt_base > 0x8003f400){
         return FALSE;
      }

      handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
      if (handle == INVALID_HANDLE_VALUE) {
         return FALSE;
      }
      memset(&pe.cntUsage, 0, 0x49);
      pe.dwSize = sizeof(PROCESSENTRY32);
      if (Process32First(handle, &pe) != 0) {
         if (wcscmp(pe.szExeFile, L"explorer.exe") == 0)
            goto do_evil_stuff;
         else {
            while (Process32Next(handle, &pe) != 0) {
               if (wcscmp(pe.szExeFile, L"explorer.exe") == 0) {
                  goto do_evil_stuff;
               }
               continue;
            }
            return FALSE;
         }
      }

   do_evil_stuff:
      if (pe.th32ParentProcessID == pe.th32ProcessID) {
         return FALSE;
      }
      else {
         if (ul_reason_for_call == DLL_PROCESS_ACCESS) {
            CreateThread(
               NULL, NULL, (LPTHREAD_START_ROUTINE)0x100032d0, NULL, NULL, NULL
            );
            return TRUE;
         }
         return TRUE:
      }
   }

```

#Spread Anarchy!
