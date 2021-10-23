---
title: "Bypassing AMSI With CSharp"
date: 2021-10-23T14:20:04Z
draft: true
tags: ["off-sekurity", "windoz", "cs"]
categories: ["guide"]
---

Ah yes. Windoz, the most popular desktop operating system solution out there. And, the most attacker friendly operating system out there. At least, `was`.

Windows is has a really good reputation in the malware industrustry. Red teamers often use this for their advantage and use malware to maintain persistence access to the victim machine.
Out of the tools that they use to fulfill this task, Windows powershell is important.

Windows powershell is a powerful administrative tool mostly used by sys admins. And mainly because of that reason, hackers often utilize this tool. Another most important sofware when it comes to windows malware is, microsoft office software. It is a proven fact that most notable malware outbreaks in past few years has something to do with VBA macros. in 2007 microsoft shipped office package with macro disabled by default. Yet those type of malware is still alive and well.

And as a result, microsoft and antimalware vendors has developed many security machanisms to deal with those threats. For example, modern anti malware solutions are able statically analyze scripts, binaries and detect whether they are malicious or not using signatures such as strings. As a reply malware authors employed objfuscation techniques to protect their malware from static scanners.

And this is a win for malware authors, since this is beyond what anti malware solutions can emulate or detect, until AMSI joins the conversation.

## AntiMalware Scan Interface (AMSI)

AMSI is a standard interface that allows applications to interact with anti malware products installed on the system. According to microsoft, AMSI provides following features by default.

-   User Account Control
-   PowerShell
-   WIndows Script Host
-   JScript && VBScript
-   Office VBA macros

As it is clear from those default features, AMSI specifically provides anti malware security machanisms to defend against dynamic script-base malware. In this article Im going to focus only on windows powershell.

So lets take SafeSploit as our example .net assembly.

![main](/img/CSharpLoader/AMSI.png)