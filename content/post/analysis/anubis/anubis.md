---
title: "Anubis, the android trojan"
date: 2021-12-13T11:50:35Z
draft: true
cover: "/img/anubis/anubis.jpg"
description: "reverse engineering the notorious android banking trojan"
tags: ["reverse-engineering", "android", "malware"]
---

# Samples 

https://github.com/sk3ptre/AndroidMalware_2020/blob/master/anubis.zip

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

First of all, finding the SDK version is essential to continue dynamic analysis. This can be extracted from AndroidManifest.xml.

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

# Permissions 

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

![androguard results](/img/anubis/anubis_androgaurd.png)

here we can see that the application has 17 activities.

![androguard results](/img/anubis/anubis_androguard.png)

here androguard shows us recievers, main activity and the services. 

However all the above stuff are obfuscated.

Lets try to identify the obfuscator by analyzing the smali code.


Now we have a very basic idea of what malware is capable of, its time for some dynamic analysis

before running the sample on the vm, it wwould be better to run it on a automated framework. Then 
we can focus on the specific details. Here im going to use MobSF.

![automated analysis](/img/anubis/anubis_mobsf.png)

![mobsf results](/img/anubis/anubis_mobsfstatic.png)

with the above result, we can confirm our assumptions on receivers, activities and services we made
considering the result of androguard.

MobSF also provides us with some other useful information like, which activities, services use 
which APIs, which classes makes use of requested permissions and so on.

![apis](/img/anubis/anubis_mobsfapi.png)



first, im going to stop the emulator and restart it with following parameters

`-tcpdump dump.cap`

so we can take a look at network traffic later on, in case. Im also going to setup burp-suite to analyze http traffic.


