---
layout: post
title:  "MBE Lab8C Writeup"
---

## Introduction
In this article I will summaries how I solved [MBE](https://github.com/RPISEC/MBE) Lab8C CTF Challenge.

## Writeup
In this MBE’s CTF challenge I am confronted with a program that claims to perform a lexicographical comparison between two files.<br/>
Running the program I am given the following line:

```shell
root@warzone:/levels/lab08# ./lab8C
Hi. This program will do a lexicographical comparison of the contents of two files. It has the bonus functionality of being able to process either filenames or file descriptors.
Usage: ./lab8C {-fn=<filename>|-fd=<file_descriptor>} {-fn=<filename>|-fd=<file_descriptor>}
```

The program takes in two files, a file argument can be either a file name using the format:

```shell
./lab8C -fn=<File Path>
```

```shell
./lab8C -fd=<File Descriptor>
```

Running the program with two temporary files, A and B:<br/>
A's contents: `AAAAAAAAAA` and B's contents: `AAAAAAAAAB`

Will yield the following result:

```shell
root@warzone:/levels/lab08# ./lab8C -fn=/tmp/a -fn=/tmp/b
"AAAAAAAAAA" is lexicographically before "AAAAAAAAAB"
```

Looking at the parsing function `getfd`, with the File-Path mode it will use the open function to open the file and retrieve its fd, while with the File-Descriptor mode, it will just convert it to an integer using `atoi`.

The first primitive I found was that with the File-Descriptor mode there is no check wether such fd actually exists within the process, while with the open function the return value is verified.

So in essence, one can provide any fd he wants to.

I continued to reverse the binary, and found that to prevent you from reading the next level’s user password it used a securityCheck function. All that function did was to see if the string `".pass"` (the name of the password file for each user in MBE) was present in the argument you have given for the file argument, and if it did it will replace it with some constant string:

The thing is that only files given with the File-Path mode are vulnerable to this kind of security checking. Files given with the File-Descriptor mode aren’t.

If only I could some how point to the .pass file using an fd. Oh wait I can, I can use the first file argument to open the .pass file, therefore creating a file descriptor within the process pointing to the .pass file. I could then use the fd 3 to point to it (fds are created incrementally, 0, 1 and 2 are open by default). Letting me read the .pass file for the next user and passing the level:


```shell
root@warzone:/levels/lab08# ./lab8C -fn=/home/lab8B/.pass -fd=3
"<<<For security reasons, your filename has been blocked>>>" is lexicographically equivalent to "3v3ryth1ng_Is_@_F1l3"
```

And I’m done.