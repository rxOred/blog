---
title: "Setting Up Kdnet"
date: 2021-11-08T21:55:11+05:30
<<<<<<< HEAD
draft: false
=======
draft: true 
>>>>>>> 77211eb (.)
tags: ['windoz']
category: ['guide']
---

Aight kids. this is going to be a short article on how to setup kdnet for windows kernel debugging. 

So, kernel debugging is very different from debugging a userland program. You cant just fire up gdb or windbg and start debugging your own kernel. What you gotta do is, setup a virtual machine. 

Im going over my setup here for windows kernel debugging, which contains following stuff.

- 2 windows 10 virtual machines
- Wdk installed on both (not necessary)
- windows debugging tools installed on both (which includes, windbg)

Assuming yall have all that up and running, lets get into some action. no not really...

![my lab](/img/WindowsInternals/my-lab.png)

yae yae ik, that's alot of shit i got here. Dont focus on any other bullshit but only on those that are highlighted (or whatever i have done with red color).

![Flare Vm](/img/WindowsInternals/flareVM.png)

Aaand yes, those are 'flare-vm', 'VMs' cause i just cloned those two from my malware lab. Again, yes I run a windows on my host machine and I havent activated it. AND PLEASE DONT CAUSE FUCK MICROSOFT AND FUCK WINDOWS. And those are my employer's opinions (which i dont have, and you are welcome if you are interested in becoming my employer :3 )

SO enough with bullshit. Now we gotta setup windbg on host machine...

[windbg](/img/WindowsInternals/windbg.png)

See? windbg looks worse that shit when you open it up for the first time (windbg for windows 10 looks kinda cute though :3 ). lets make this thing bit more useful.

