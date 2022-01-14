---
title: "Simplelocker, an android ransomware"
date: 2021-11-18T13:07:00Z
draft: false
cover: "/img/simplelocker/pentacle.png"
description: "dissecting simple-locker android ransomware"
tags: ["reverse-engineering", "ransomware", "android"]
readingTime: true
---

# Table of Content

1. [Introduction](#introduction)
    1. [Samples](#samples)
2. [Environment](#environment)
    1. [Tools](#tools)
3. [Dynamic analysis](#dynamic-analysis)
4. [Static analysis](#static-analysis)
    1. [Main](#main)
    2. [What we know so far](#what-we-know-so-far)
    3. [Encryption](#encryption)
    4. [Decryption](#decryption)
    5. [Other stuff](#other-stuff)
5. [Writing a decrypter](#writing-a-decrypter)
6. [The end](#the-end)

# Introduction

## Samples

samples can be obtained from various android malware repositories. I had the dex one but 
had to get an apk version from the koodous website.

# Environment

    - linux host with analysis tools
    - android vm (API version 16)
    
## Tools
    - bytecodeviewer
    - apktool
    - androgaurd
    - adb
    - jd-gui 
    - enjarify


# Dynamic analysis

Before any analysis, I have created some external storages in my VM so we can confirm thisransomware encrypts those files. 

![creating external storage](/img/simplelocker/creating-external-storage.png)

Now, we can install the malware on the VM.

![installing malware](/img/simplelocker/installing-malware.png)

![installed malware](/img/simplelocker/installed-malware.png)

after clicking on the installed malware, we get a prompt which contains some text from a
language which i beleive to be alien. :) (nah its probably russian...)

![alien text](/img/simplelocker/alien-text.png)

Lets try removing the malware using adb.

![uninstalling malware](/img/simplelocker/uninstalling-malware.png)

whoaa whoaa? did we just uninstalled the ransomeware? wow. we are sooo cool.
no. not really. remember kid. this is a ransomware. it has probably encrypted every damn
file on the device. To make sure, lets check the external storages we created earlier.

![encrypted files](/img/simplelocker/encrypted-files.png)

# Static analysis

## Decompiling

first, let's run apktool on the apk and get the smali code.

![apk tool fails](/img/simplelocker/apk-tool-fails.png)

I think the issue is with the charset, cause the app uses some weird alien language which i beleived to be russian. I dont know a specific way to solve this problem so im gonna try updating the tool.

Well it didnt work.

Dont lose your hopes comrad i got a way around this. we can use jd-gui!!! However to do 
so, we need to convert .apk file to a .jar file. 

enjarify is a nice tool to do this. here's a link to the github repo : 
https://github.com/google/enjarify.git 

``` sh
λ rxOred-aspiree simplelocker → enjarify simplelocker.apk 
Using python3 as Python interpreter
1000 classes processed
2000 classes processed
Output written to simplelocker-enjarify.jar
2693 classes translated successfully, 0 classes had errors
```

here is the result :)

Now, lets see what jd-gui got for us.

![decompiled source code](/img/simplelocker/decompiled.png)

## Main

here we can see `Main`, which i think is the main activity. if you dont know what it is, refer an android development guide.

![onCreate function](/img/simplelocker/onCreate.png)

here we can see a call to `requestWindowFeature()` function, which is used to exclude or include various window features such as toolbar, actionbar and so on. In this case, i honestly dont know what the parameter means (well yes ik its a constant).

then `onCreate` invokes `setFlags()` with `E` as an argument. then it sets content view to some random looking value.

Then there is a juicy part. it calls `startService` function, which is used to start a long running service as the name implies.

we can see the definition of that function right above the `onCreate()`.

![start service](/img/simplelocker/startService.png)

Here it checks if `MainService.isRunning` is true, and then it does some calls to constructors and stuff like that. we'll come back to this later

Now let's examine whats in the `MainService()`.

![MainService](/img/simplelocker/MainService.png)

whoa whoa whoaaa. this is scary ryt? we got some tor shit going on 
here.

Let's examine, onCreate function.

as we can see, this one creates a `ScheduleExecutorService` class and calls `newSingleThreadScheduledExecutor`

```java
ScheduledExecutorService scheduledExecutorService = Executors.newSingleThreadScheduledExecutor();
```

`ScheduleExecutorService` is an ExecutorService which can schedule different tasks to run
periodically. This makes sense cause when we first run the malware, we get that ugly windo
w and it was continuasly displayed on the screen periodically until we uninstall the malwa
re.

```java
MainService$3 mainService$3 = new MainService$3();
this(this);
TimeUnit timeUnit = TimeUnit.SECONDS;
scheduledExecutorService.scheduleAtFixedRate(mainService$3, 0L, 180L, timeUnit);
```

here, onCreate function creates `mainService$3` and schedule it to execute repeatedly for 
a fixed rate.

Just like the one above, onCreate creates `mainService4` and do the same with it.

then..

```java
Thread thread = new Thread();
MainService$5 mainService$5 = new MainService$5();
this(this);
this(mainService$5);
thread.start();
```

here, onCreate function creates a thread, another service called `mainService$5` and start
new service within the newly created thread.


## What we know so far

Summurizing what we know so far, first we finds out that this apk cant be decompiled into smali code using 
apktool. Then we tried with jd-gui and we were successful. 

About the code, we found out that `Main` function calls `startService` which in turn initialize `MainService`.
There, `MainService` initialize `MainService$3` && `mainService$4` to run periodically. Then it starts another 
thread and run `MainService$5`.

## Encryption

Now let's look at MainService$5.

![encryption](/img/simplelocker/encryption.png)

See? we got what we wanted. This is the class that encrypts our files.

First it creates a `FilesEncryptor` object. Then it calls `filesEncryptor.encrypt()`.
There's some exception handling too. if the encryption fails, it sets up some debugging
messages and call `Log.d`

lets take a look at `FilesEncryptor` class.

![FilesEncryptor](/img/simplelocker/FileEncrypter.png)

ah yes! the files my friend, the files. here we can see the class has 
two array members, first one for files-to-be-decrypted and second one 
for the files-to-be-ecrypted.

then there is another member for shared preferences.

![FilesEncryptorContructor](/img/simplelocker/FileEncrypterConstructor.png)

here the function creates an `ArrayList` and asign it to `filesToEncrypt` && 
`filesToDecrypt` we previously saw. next few lines 

```java
String[] arrayOfString = new String[1];
arrayOfString[0] = "enc";
List<String> list = Arrays.asList(arrayOfString);
this.extensionsToDecrypt = list;
SharedPreferences sharedPreferences = paramContext.getSharedPreferences("AppPrefs", 0);
this.settings = sharedPreferences;
String str = Environment.getExternalStorageDirectory().toString();
File file = new File();
this(str);
```

what the above snippet does is, fist it creates a string array and then set 1st element (0) to "enc". Then the string array is assigned to `List<String> list`, which then assigned to `extensionsToDecrypt`. So all above snippet does is, creating assigning a List of extensions so that malware can decrypt only those that it previously encrypted.

then we can see `FilesEncryptor` calls `getFileNames()`.

Well..Im not gonna take a look at that one cause, all it does is get filenames. And we dont have to give a shit how it does that. However keep in mind that this is the one 
that appends `filesToEncrypt` ArrayList.

Now lets go back to `mainService$5`. As we saw earlier, this is the function which calls
`FilesEncryptor.encrypt()`.

![encrypt function](/img/simplelocker/encrypt.png)

I mean dude, i you got two holes in your face filled with two testical like balls, you 
can clear see the key and the algorithm. And that's all you want to decrypt your files.

Anyway, lets analyze this one... first there is an if statement which check if 
`sharedPreferences` contains `str1`, which is "FILES_WAS_ENCRYPTED". then the next if
statement checks whether is it possible to write to external storages using 
`isExternalStorageWritable()`.

```java
AesCrypt aesCrypt = new AesCrypt();
this("jndlasf074hr");
```

then we can see above snippet, which initialize an `AesCrypt` object and pass the key 
`jndlasf074hr`.

then it creates an iterator to `filesToEncrypt` and iterates through each file.

in the loop, if current one does not have a next, function sets `sharedPreferences` to 
"FILES_WAS_ENCRYPTED".

```java
str2 = ".enc";
String str3 = stringBuilder.append(str2).toString();
aesCrypt.encrypt(str4, str3);
File file = new File();
this(str4);
file.delete();
```
Again, a string is assigned with ".enc". Now this looks like an extension too. So my guess
previous one is for folders/directories and this one is for files.

then `str3` is assigned with a string with `str2` appended and is passed to `aesCrypt.encrypt()` function alongside with `str4`

```java 
String str4 = sharedPreferences1.next();
```

which is shown in the above snippet.

then a new file is created passing `str4` as the argument and then deleted.
So this one is basically a loop that encrypts every file that is specified in the 
`filesToEncrypt` ArrayList and deletes the original one.

Cool. Now we have dissected the encryption part. Now lets take a look at decryption part.

## Decryption

![decryption](/img/simplelocker/decryption.png)

Since we have already analyzed main parts of the code, this is going 
to be easy.

Just like the `encrypt`, this one too, check whether external storagesis writable. if true, an `AesCrypt` object is constructed and passed 
the key as an argument.

oh yeah an iterator is also created.

then there is a while loop, which again checks whether if `iterator.hasNext()` is true. if true, `str1` is assigned with `iterator.next()` and `str2` is with ".".

then we have `int i`, which is initialized with `str1.substring(0, i)`
both are then passed to `aesCrypt.decrypt()` function to decrypt the 
file.

then the file named with `str1` is deleted and loop continued.

Now, that's all we need to decrypt the files!!!. However feel free to take a look at 
AesCrypt if you want.

## Other stuff

Since we are done with the encryption part, let's see what does this thing do with tor.
First of all, goal here is not to dissect everything but to find anything useful for 
host-based / network signatures.

So what looks juicy for me is `Constants.class`

![constants](/img/simplelocker/constants.png)

Holy shit. i should have analyzed this one before the other functions. this one gives us the key in plain.

![constants](/img/simplelocker/constants1.png)

see? we got the file extensions that this ransomware encrypts (if you
have analyzed `getFileNames`, this must be familiar to you...

Now pay your attention to the first constant defined in the class `ADMIN_URL`. This sounds
like a CnC server address. this is a good network based indicator. 
`http://xeyocsu7fu2vjhxs.onion/`.

# Writing a decrypter

Since we know how the ecnryption and decryption works, we can write an app that can decrypt all the files. I'll leave a snippet down below
and you can copy it to android studio.

```java
package com.example.decrypter;

import androidx.appcompat.app.AppCompatActivity;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.Environment;
import android.view.View;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import javax.crypto.NoSuchPaddingException;

public class MainActivity extends AppCompatActivity {

    private ArrayList filesToDecrypt;
    private List<String> extensionsToDecrypt;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }

    public void onClick(View view) {
        this.filesToDecrypt = new ArrayList();
        String[] arrayOfString = new String[1];
        arrayOfString[0] = "enc";
        this.extensionsToDecrypt = Arrays.asList(arrayOfString);
        File file = new File(Environment.getExternalStorageDirectory().toString());
        getFileNames(file);
        try {
            decrypt();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    private void getFileNames(File paramFile) {
        File[] arrayOfFile = paramFile.listFiles();
        for (int i = 0;; i++) {
            int k = arrayOfFile.length;
            if (i >= k)
                return;
            String absolutePath = paramFile.getAbsolutePath();
            String fileName = arrayOfFile[i].getName();
            File file = new File(absolutePath, fileName);
            boolean isDirectory = file.isDirectory();
            if (isDirectory) {
                File[] arrayOfFile1 = file.listFiles();
                if (arrayOfFile1 != null) {
                    // if a directory, get names of files inside it recursively
                    getFileNames(file);
                    continue;
                }
            }
            // if not a directory
            String str3 = file.getAbsolutePath();
            String subStr = str3.substring(str3.lastIndexOf(".") + 1);
            List<String> list = this.extensionsToDecrypt;
            // if pathname contains .enc
            boolean bool1 = list.contains(subStr);
            if (bool1) {
                list = this.filesToDecrypt;
                fileName = file.getAbsolutePath();
                list.add(fileName);
            }
            continue;
        }
    }

    private boolean isExternalStorageWritable() {
        String ext = Environment.getExternalStorageState();
        String mounted = "mounted";
        boolean isMounted = mounted.equals(ext);
        if (isMounted)
            return true;
        isMounted = false;
        mounted = null;
        return isMounted;
    }

    public void decrypt() throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, InvalidAlgorithmParameterException, InvalidKeyException {
        boolean isWritable = isExternalStorageWritable();
        if (isWritable) {
            AesCrypt aesCrypt = new AesCrypt("jndlasf074hr");
            Iterator<String> iterator = this.filesToDecrypt.iterator();
            while (true) {
                boolean hasNext = iterator.hasNext();
                if (hasNext) {
                    String inputFileName = iterator.next();
                    hasNext = false;
                    int i = inputFileName.lastIndexOf(".");
                    String outputFileName = inputFileName.substring(0, i);
                    aesCrypt.decrypt(inputFileName, outputFileName);
                   File file = new File(inputFileName);
                    file.delete();
                    continue;
                }
                return;
            }
        }
    }
} 
```

oh and just copy the contents of the `AesCrypt.class` from jd-gui. then build it and install the app on the android VM.

![decrypter app](/img/simplelocker/decrypter.png)

yae yae ik. Im not a UI designer or an android developer. 

![files decrypted!!](/img/simplelocker/decryted.png)


# The end

So yeah i think that's it.

#Speard Anarchy!
