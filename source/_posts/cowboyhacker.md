---
title: THM Bounty Hacker Write-up
tags: [Write-up, CTF]
category: CTF
index_img: /img/cowboyhacker/thumbnail.jpeg
banner_img: /img/cowboyhacker/thumbnail.jpeg
date: 2020-08-22
---
This post is a write-up from [tryhackme Bounty Hacker room](https://tryhackme.com/room/cowboyhacker).

First of all scan the machine using nmap.

![port-scan](/img/cowboyhacker/port-scan.png)

You will get 3 open ports, 21:ftp, 22:ssh and 80:http.

The web application running on port 80 is just a chat history where some people challenge you to root the system.

![home](/img/cowboyhacker/home.png)

The ftp running on port 21 allows anonymous login and there's 2 interesting txt files.

![fpt-output](/img/cowboyhacker/ftp-output.png)

Inside task.txt there's 2 random useless instructions writed by someone called "lin".

![task.txt](/img/cowboyhacker/task.png)

The another one is a wordlist with some passwords. Now you have one possible user and a wordlist to brute force something.

![passwords](/img/cowboyhacker/passwords.png)

Running a brute force on ssh you will get the credentials.

![ssh-brute-force](/img/cowboyhacker/ssh-brute-force.png)

Now you have the user flag, let's scale privileges.

![user-flag](/img/cowboyhacker/user-flag.png)

You can run /bin/tar as root, but what could you do with this?

![sudo](/img/cowboyhacker/sudo.png)

After some search I found how to run commands with tar, now you are root.

![privilege-escalation](/img/cowboyhacker/privilege-escalation.png)

And now you have the root flag.

![root-flag](/img/cowboyhacker/root-flag.png)

This was my first ctf write up, sorry anything I did wrong, thanks for read and see you space cowboy…
