---
title: "Anubis, the banking trojan"
date: 2021-12-13T11:50:35Z
draft: false
cover: "/img/anubis/anubis.jpg"
description: "reverse engineering the notorious android banking trojan"
tags: ["reverse-engineering", "android", "malware"]
---

# Samples 

[github](https://github.com/sk3ptre/AndroidMalware_2020/blob/master/anubis.zip)

# Environment

    - linux host
    - android vm (API version 23) (no google services)

# Tools 
    - apktool
    - adb
    - frida
    - mobsf
    - jd-gui

# Setting things up

First of all, finding the compiled/supported SDK versions is essential to continue dynamic analysis. This can be extracted from AndroidManifest.xml.

![extracting with apktool](/img/anubis/anubis_apktool.png) 

```xml
<?xml version="1.0" encoding="utf-8" standalone="no"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" android:compileSdkVersion="23" android:compileSdkVersionCodename="6.0-2438415" package="wocwvy.czyxoxmbauu.slsa" platformBuildVersionCode="23" platformBuildVersionName="6.0-2438415">
```

as it is shown, the SDK version is 23.

However, since frida will be used in dynamic analysis, it is easier to use 
an image without Google services. (because root access can be easily gained
in those images + running frida without root access is pain in the ass work)

![installing a new emulator](/img/anubis/anubis_newemulator.png)

```bash
rxOred-aspiree :: Analysis/android/anubis » adb shell
root@generic_x86_64:/ # 

```

Now it is straight forward to install frida on the device. Im not going to 
do that here.

# Analysis 

## The manifest 

```xml
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
    <uses-permission android:name="android.permission.GET_TASKS"/>
    <uses-permission android:name="android.permission.RECEIVE_SMS"/>
    <uses-permission android:name="android.permission.READ_SMS"/>
    <uses-permission android:name="android.permission.WRITE_SMS"/>
    <uses-permission android:name="android.permission.PACKAGE_USAGE_STATS"/>
    <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>
    <uses-permission android:name="android.permission.CALL_PHONE"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.SEND_SMS"/>
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
    <uses-permission android:name="android.permission.RECORD_AUDIO"/>
    <uses-permission android:name="android.permission.READ_CONTACTS"/>
    <uses-permission android:name="android.permission.READ_PHONE_STATE"/>
    <uses-permission android:name="android.permission.WAKE_LOCK"/>
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/>
    <uses-permission android:name="android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"/>
```

As we can see, this malware can send, recieve SMS, read contacts, access location, read and write 
to external storage. It is also requesting permission to get notified once when the system boots 
up.

Now we have a very basic idea of what malware is capable of, its time for some dynamic analysis

before running the sample on the vm, it wwould be better to run it on a automated framework. Then 
we can focus on the specific details. Here im going to use MobSF.

![automated analysis](/img/anubis/anubis_mobsf.png)

![mobsf results](/img/anubis/anubis_mobsfstatic.png)

here we can see that the application has 17 activities, 24 services, 4 recievers and 0 providers.

![apis](/img/anubis/anubis_mobsfapi.png)

However when i try to run a dynamic analysis on the apk, MobSF failed with few errors. 

![androguard results](/img/anubis/anubis_androgaurd.png)

with the above result, we can confirm our assumptions on receivers, activities and services we made
considering the result of MobSF.

![androguard results](/img/anubis/anubis_androguard.png)

here androguard shows us recievers, main activity and the services. 

However all the above names seemed to be obfuscated.

Lets try to identify the obfuscator by analyzing the smali code.

## Identifying the obfuscator

It is possible to identify the obfuscator just by looking at smali code. For example, ProGuard,
which is one of the most popular android obfuscators out there, can be idenitified if the smali 
code contains variable names, strings with `d`, `a`, `a;->a` characters. (However ProGuard accepts different sets of characters for this, and it is not a good idea to make decision just based ont this).

first lets check for DexGuard, another common obfuscator. DexGuard is known to use non ascii 
chars for obfuscation. 

```python
import re, os
from pathlib import Path

def non_ascii_in_string(string):
    regexp = re.compile(r'[^\00-\xff]')
    if regexp.search(string):
        return True
    else:
        return False

def scan_file(filepath):
    try:
        with open(filepath, mode='r') as f: 
            i = 0
            for line in f:
                i+=1
                if non_ascii_in_string(line):
                    print "line [{lno}] {line} - {file}".format(lno=i, line=line, file=filepath)
    except:
        return

def main():
    pathlist = Path("smali").rglob("*.smali")
    for path in pathlist:
        scan_file(str(path))

if __name__ == '__main__':
    main()
```

above python script scans the smali directory generated by apktool for strings that contain non 
ascii characters.

![DexGuard detection](/img/anubis/anubis_notdexguard.png)

so its no harm to conclude that this sample is not obfuscated with DexGuard. 

we can use the same script to detect ProGuard by replacing the regular expression with `a/a;->a`. ()

here is the result.

![detecting obfuscation](/img/anubis/anubis_proguard.png)

from that, we can conclude that this sample is obfuscated using ProGuard. 

There are few projects that are capable of deobfuscating ProGuard. dex-oracle, simplify
are two of such projects.

![simplify](/img/anubis/anubis_simplify.png)

simplify get to somewhere but then horribly fails.

```
(4 / 7) Executing top level method: Lwocwvy/czyxoxmbauu/slsa/ncec/pltrfi;->onStart()V
23:43:18.370 WARN  InvokeOp     - org.cf.smalivm.exception.MaxAddressVisitsExceededException: Exceeded max address visits @0 ExecutionNode{signature=Lwocwvy/czyxoxmbauu/slsa/b;->b(Ljava/lang/String;)[B, op=invoke-virtual {r8}, Ljava/lang/String;->length()I, @=0} in Lwocwvy/czyxoxmbauu/slsa/b;->b(Ljava/lang/String;)[B
23:45:46.813 WARN  InvokeOp     - org.cf.smalivm.exception.MaxAddressVisitsExceededException: Exceeded max address visits @0 ExecutionNode{signature=Lwocwvy/czyxoxmbauu/slsa/oyqwzkyy/a;->b([B)[B, op=array-length r0, r7, @=0} in Lwocwvy/czyxoxmbauu/slsa/oyqwzkyy/a;->b([B)[B
23:45:46.923 WARN  InvokeOp     - org.cf.smalivm.exception.MaxAddressVisitsExceededException: Exceeded max address visits @0 ExecutionNode{signature=Lwocwvy/czyxoxmbauu/slsa/b;->b(Ljava/lang/String;)[B, op=invoke-virtual {r8}, Ljava/lang/String;->length()I, @=0} in Lwocwvy/czyxoxmbauu/slsa/b;->b(Ljava/lang/String;)[B
23:48:14.474 WARN  InvokeOp     - org.cf.smalivm.exception.MaxAddressVisitsExceededException: Exceeded max address visits @0 ExecutionNode{signature=Lwocwvy/czyxoxmbauu/slsa/oyqwzkyy/a;->b([B)[B, op=array-length r0, r7, @=0} in Lwocwvy/czyxoxmbauu/slsa/oyqwzkyy/a;->b([B)[B
23:48:15.842 WARN  ExecutionContext - org.cf.smalivm.exception.MaxAddressVisitsExceededException: Exceeded max address visits @0 ExecutionNode{signature=Landroid/util/StateSet;-><clinit>()V, op=const/4 r13, 0x1, @=0} in Landroid/util/StateSet;-><clinit>()V
23:48:15.842 ERROR NodeExecutor - ExecutionNode{signature=Landroid/util/StateSet;->get(I)[I, op=array-length r0, r0, @=2} unhandled virtual exception: 
java.lang.NullPointerException: Attempt to get length of null array
	at java.base/jdk.internal.reflect.GeneratedConstructorAccessor6.newInstance(Unknown Source)
	at java.base/jdk.internal.reflect.DelegatingConstructorAccessorImpl.newInstance(DelegatingConstructorAccessorImpl.java:45)
	at java.base/java.lang.reflect.Constructor.newInstance(Constructor.java:490)
	at org.cf.smalivm.ExceptionFactory.build(ExceptionFactory.java:28)
	at org.cf.smalivm.opcode.ArrayLengthOp.<init>(ArrayLengthOp.java:28)
	at org.cf.smalivm.opcode.ArrayLengthOpFactory.create(ArrayLengthOpFactory.java:19)
	at org.cf.smalivm.opcode.OpCreator.create(OpCreator.java:29)
	at org.cf.smalivm.context.ExecutionGraph.buildLocationToNodePile(ExecutionGraph.java:89)
	at org.cf.smalivm.context.ExecutionGraph.<init>(ExecutionGraph.java:62)
	at org.cf.smalivm.VirtualMachine.updateInstructionGraph(VirtualMachine.java:180)
	at org.cf.smalivm.VirtualMachine.spawnInstructionGraph(VirtualMachine.java:131)
	at org.cf.smalivm.MethodExecutorFactory.build(MethodExecutorFactory.java:62)
	at org.cf.smalivm.VirtualMachine.execute(VirtualMachine.java:75)
	at org.cf.smalivm.opcode.InvokeOp.executeLocalMethod(InvokeOp.java:434)
	at org.cf.smalivm.opcode.InvokeOp.execute(InvokeOp.java:136)
	at org.cf.smalivm.context.ExecutionNode.execute(ExecutionNode.java:53)
	at org.cf.smalivm.NodeExecutor.execute(NodeExecutor.java:81)
	at org.cf.smalivm.MethodExecutor.step(MethodExecutor.java:50)
	at org.cf.smalivm.NonInteractiveMethodExecutor.execute(NonInteractiveMethodExecutor.java:54)
	at org.cf.smalivm.VirtualMachine.execute(VirtualMachine.java:76)
	at org.cf.smalivm.context.ExecutionContext.staticallyInitializeClassIfNecessary(ExecutionContext.java:205)
	at org.cf.smalivm.context.ExecutionContext.staticallyInitializeClassIfNecessary(ExecutionContext.java:182)
	at org.cf.smalivm.context.ExecutionContext.staticallyInitializeClassIfNecessary(ExecutionContext.java:182)
	at org.cf.smalivm.context.ExecutionContext.readClassState(ExecutionContext.java:132)
	at org.cf.smalivm.opcode.NewInstanceOp.execute(NewInstanceOp.java:37)
	at org.cf.smalivm.context.ExecutionNode.execute(ExecutionNode.java:53)
	at org.cf.smalivm.NodeExecutor.execute(NodeExecutor.java:81)
	at org.cf.smalivm.MethodExecutor.step(MethodExecutor.java:50)
	at org.cf.smalivm.NonInteractiveMethodExecutor.execute(NonInteractiveMethodExecutor.java:54)
	at org.cf.smalivm.VirtualMachine.execute(VirtualMachine.java:76)
	at org.cf.smalivm.VirtualMachine.execute(VirtualMachine.java:63)
	at org.cf.smalivm.VirtualMachine.execute(VirtualMachine.java:59)
	at org.cf.simplify.Launcher.executeMethods(Launcher.java:195)
	at org.cf.simplify.Launcher.run(Launcher.java:141)
	at org.cf.simplify.Main.main(Main.java:14)
```

I tried running dex-oracle and it failed too.

## Behavioral analysis 

first, im going to stop the emulator and restart it with following parameters

`-show-kernel -tcpdump dump.cap`

so we can take a look at network traffic later on, in case. (I've also setup mitmproxy)

![installing the malware](/img/anubis/anubis_installapk.png)

running the sample, its asking to enable 'accessibility permissions'. And the user is forced to grant the permission. This enables application run in the background.

![accessibility permissions](/img/anubis/anubis_accessibilities.png)

Here's the network traffic.

![network traffic](/img/anubis/anubis_requeststorandom.png)

![request](/img/anubis/anubis_request.png)

when granted the requested permission, the malware seemed to be deleted from the devic.
However, its listed in the packages.

```
root@generic_x86_64:/ # pm list packages | grep slsa                           
package:wocwvy.czyxoxmbauu.slsa
root@generic_x86_64:/ # 
```

which means that it has only deleted the icon from the application launcher not 
the app itself.

## Diving deep

To do a code analysis, first, the apk should be converted into jar format.

```
rxOred-aspiree :: Analysis/android/anubis » enjarify anubis.apk
Using python3 as Python interpreter
Output written to anubis-enjarify.jar
136 classes translated successfully, 0 classes had errors
rxOred-aspiree :: Analysis/android/anubis » 
```
Then, using the jd-gui decompiler, we can analyse the code.


