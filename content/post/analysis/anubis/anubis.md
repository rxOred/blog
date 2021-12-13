---
title: "Anubis"
date: 2021-12-13T11:50:35Z
draft: false
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
