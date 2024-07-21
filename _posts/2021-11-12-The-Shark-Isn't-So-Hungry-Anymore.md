---
layout: post
title:  "The Shark Isn't So Hungry Anymore"
---

## Introduction
It was a quite weekend and I was chilling at home enjoying the mobile game [Hungry Shark World](https://www.ubisoft.com/en-gb/game/hungry-shark/world) on my Android phone while also trying to think of new fun side projects.<br/>
Hungry Shark World is a game where you play as a shark swimming in the ocean eating fish, and even people, to gain coins and gems.

With these coins and gems, you can later purchase advancements and unlock new worlds and oceans, sounds like a lot of fun right? And indeed it was, but then it hit me.<br/>
Why not reverse engineer the game and cheat my way to victory? and of course have a great time and learn a lot while doing so.<br/>
In this article I explained how I reverse engineered the Android game and how I managed to have as much coins and gems as I desired, enjoy!.

## First Steps 🚶‍♂️
All android apps are shipped as APK files, therefore the first step was to download the APK and be able to examine it in an isolated research environment, this can be easily done using APK mirror sites like apkpure or apkmirror.<br/>
An APK is the final product of the Android application build workflow. It’s a zip file that contains the application’s code, resources, and configurations.

![AndroidApplicationBuildWorkflow](/assets/img/AndroidApplicationBuildWorkflow.png)

To examine the APK, I used [Apktool](https://ibotpeaches.github.io/Apktool/) to unpack it and access the .dex files. Then, I decompiled the .dex files back to Java using [Dex2Jar](https://github.com/pxb1988/dex2jar) and viewed the code using [JD-GUI](http://java-decompiler.github.io/).

Reading the java sources, I saw that the Java code was nearly a wrapper for calls to native functions throughout the apps life cycle via [JNI](https://en.wikipedia.org/wiki/Java_Native_Interface#:~:text=JNI%20enables%20programmers%20to%20write,specific%20features%20or%20program%20library.).<br/>
JNI stands for Java Native Interface, which enables programmers to write native code in C or C++ and call it from Java code.

![JNITransition](/assets/img/JNITransition.png)

Based on my reading of the Java sources, it appeared that the game was implemented in native code and called through JNI during the app’s lifecycle. I went on and researched about the game, turns out it was developed using [Unity](https://unity.com/) a well known cross-platform game engine used to create 2D, 3D and as of today also VR games that support more than 25 platforms! 😯<br/>
The Unity engine offers a primary scripting API in C#.<br/>
Hold on, C# and Android? How? 🤨

## IL2CPP 🤯
IL2CPP (Intermediate Language To C++) is a Unity-developed scripting backend, when building a project using IL2CPP, Unity converts IL code from assemblies to C++, before creating a native binary file for your chosen platform.<br/>
Some of the uses for IL2CPP include increasing the performance, security, and platform compatibility of your Unity projects.

![IL2CPPWorkflow](/assets/img/IL2CPPWorkflow.PNG)

And the output binary is saved under the app’s lib directory as `libil2cpp.so`.

![libil2cpp.so](/assets/img/libil2cpp.so.png)

I was intrigued, not every day do you get to see a custom built `compiler`, if I can even call this that, from high-level language to native code.<br/>
Taking a deeper look into the binary it seemed like a regular shared-object file compiled for the ARM64 ABI, however when investigating the loaded sections I saw that Unity has added a special section of their own named `il2cpp` mapped to load within the TEXT segment of the ELF.

![il2cppsectionmapping](/assets/img/il2cppsectionmapping.png)

The il2cpp section contains all of the code which was converted from C# to C++ and compiled to machine code, in other words, all of the interesting logic.<br/>
I used [Il2CppDumper](https://github.com/Perfare/Il2CppDumper) a reverse engineering tool for the il2cpp compiler, in order to restore the .NET dlls, unfortunately the code itself couldn’t be restored as it has been compiled to machine code, however the tool is able to restore the names and signatures of the original C# functions using remaining metadata, which gave me some insight before diving deeper.<br/>
Having the .NET dlls allowed me to use regular .NET decompilation tools like [dnSpy](https://github.com/dnSpyEx/dnSpy) in order to view the functions signatures.<br/>
For example the `EquipPet` function’s full signature is as follows (You could buy a pet in the game which would help you gain coins and I assume this function is related to that feature):

![dnSpyView](/assets/img/dnSpyView.PNG)

Notice the `Offset` attribute, letting me know the function’s offset within the native binary `libil2cpp.so`.

![IDAview](/assets/img/IDAview.PNG)

Having a better grasp of the game’s building blocks I was ready to get my infinite amount of coins and gems.

## Pay2Win 💵 ?? Reverse2Win 🔍🏆 !!

So my target was to get infinite Gold 💰<br/>
I started by using dnSpy’s search utility for methods containing usefull text like `AddGold` and found the `AddGoldRushPot` method within the `SessionDataManager` class.<br/>
Okay now this class name sounded very interesting, having a closer look and it seemed `SessionDataManager` contained a SessionData private struct member.

![PrivateSessionDataMember](/assets/img/PrivateSessionDataMember.png)
And **Jackpot**! this struct held session information about the playing user, including his **Total Coins** and his **Total Gems**.

```c#
public struct SessionData {
    public int m_totalCoins;
    public int m_totalScore;
    public int m_totalGems;
    // ...

}
```

The next thing to look for was usages of this struct so I could manipulate it in runtime and get my precious coins and gems! I found the function `UpdateSessionData` which seemed promising.

![UpdateSessionData](/assets/img/UpdateSessionData.png)

I wanted to set a breakpoint at the UpdateSessionData function, so I attached my IDA debugger to my android device.<br/>
As I’ve seen before the il2cpp section is mapped to the TEXT segment of the ELF file, I had calculated the `UpdateSessionData` function memory address by adding its offset to the start address of the loaded `libil2cpp` shared object set by ASLR, set a breakpoint and started playing 📱.

![libil2cppSegments](/assets/img/libil2cppSegments.png)

After a minute or so the breakpoint was hit, and I took note of my current session state with **0x17c** total score and **0x0E** total coins.<br/>
Catching the breakpoint in IDA I saw the X0 register was holding a pointer with a memory address into the heap.

![BreakPointView](/assets/img/BreakPointView.png)

Further investigating the heap memory I saw it was pointing to a memory region containing the `SessionData` struct!

![SessionDataStructInMemory](/assets/img/SessionDataStructInMemory.PNG)


Awesome, from here it was a matter of patching some bytes on the heap, using IDA’s patch bytes functionality I patched the `m_totalCoins` and `m_totalGems` to be 0xFFFFFF, which is 16777215 in decimal.

![GG](/assets/img/GG.png)

## Machine Code Patching

Even though I now had more points and gems than I could ever use I was not finished.<br/>
The solution I had given was a runtime solution, what about a persistant one aswell? It was time to patch the binary.<br/>
Reading the ARM machine code I saw that `UpdateSessionData` eventually calls `UpdateSessionDataWithoutMultipliers` which does the addition of the coins, gems and so on.

![MachineCodePrePatch](/assets/img/MachineCodePrePatch.png)

So instead of adding why not multiplying? 😎 I modified the machine code and patched the binary, finally using APKTool again this time to build the patched APK, signed the APK using [jarsigner](https://docs.oracle.com/javase/7/docs/technotes/tools/windows/jarsigner.html) and reinstalled it using adb.

And here is the final outcome (with an additional touch of an integer overflow):

![FinalOutcome](/assets/img/FinalOutcome.gif)
I hope you had enjoyed reading this article as much as as I had creating it.
