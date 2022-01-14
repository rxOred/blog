---
title: "From AMSI to Reflection 0x01"
date: 2021-11-02T12:20:27+05:30
draft: true
cover: "/img/CSharpLoader/CSharpLoader2/cover.jpg"
description: "Bypassing amsi using windbg"
tags: ["offensive-sekurity", "windoz", "reverse-engineering"]
readingTime: true
---

Here we go with the second part of the series. In this article, we will try to bypass amsi with windbg using the knowledge gained from the
previous article.

# Why dont we just ret?

This is not a super cool + super hacky trick but it is indeed, really simple. Core idea is **why dont we just ret**. In case you dont know, 
`ret` instruction is used to return from a subroutine. It indirecly pops return address stored in `rsp` into the `rip` register. So if we can replace 
few instructions of the `AmsiScanBuffer` with `ret`, we can bypass it.

To analyze the function, let's place a breakpoint at the `AmsiScanBuffer` function, and continue execution using following commands

```
bp amsi!AmsiScanBuffer 
g
```

// windbg image here

As we can see, when we input that random string, we will have to go through AmsiScanBuffer function. Lets try patching first few bytes with a 
`ret` instruction.

// patched PoC here

