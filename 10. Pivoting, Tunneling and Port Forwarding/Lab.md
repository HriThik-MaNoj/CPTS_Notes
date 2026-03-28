A team member started a Penetration Test against the Inlanefreight environment but was moved to another project at the last minute. Luckily for us, they left a `web shell` in place for us to get back into the network so we can pick up where they left off. We need to leverage the web shell to continue enumerating the hosts, identifying common services, and using those services/protocols to pivot into the internal networks of Inlanefreight. Our detailed objectives are `below`:

## Objectives

- Start from external (`Pwnbox or your own VM`) and access the first system via the web shell left in place.
- Use the web shell access to enumerate and pivot to an internal host.
- Continue enumeration and pivoting until you reach the `Inlanefreight Domain Controller` and capture the associated `flag`.
- Use any `data`, `credentials`, `scripts`, or other information within the environment to enable your pivoting attempts.
- Grab `any/all` flags that can be found.

**Note:**

Keep in mind the tools and tactics you practiced throughout this module. Each one can provide a different route into the next pivot point. You may find a hop to be straightforward from one set of hosts, but that same tactic may not work to get you to the next. While completing this skills assessment, we encourage you to take proper notes, draw out a map of what you know of already, and plan out your next hop. Trying to do it on the fly will prove `difficult` without having a visual to reference.

## Connection Info

`Foothold`:

`IP`:

You will find the web shell pictured below when you browse to support.inlanefreight.local or the target IP above.



###### Once on the webserver, enumerate the host for credentials that can be used to start a pivot or tunnel to another host in the network. In what user's directory can you find the credentials? Submit the name of the user as the answer.

- Lets first add the target ip address to /etc/hosts
![[Pasted image 20260328113152.png]]

- Opened our target in the browser, we can see the shell that the previous team left behind:
![[Pasted image 20260328113326.png]]
- Lets move around a little bit and see if we can find anything interesting.
- Found something interesting!!
![[Pasted image 20260328113452.png]]

![[Pasted image 20260328113551.png]]
- we've got the credentials for the user `mlefay` and the ssh key which we can use to connect as the user `webadmin`
```python
mlefay:Plain Human work!
```
- Lets copy the id_rsa key to our attack box and then ssh into this machine
![[Pasted image 20260328113818.png]]
- we've logged in via ssh
- Let's check if there are any other network interfaces in this machine which are connected to different networks which our attack box does not have access to
![[Pasted image 20260328114026.png]]
- we can see that the network interface `ens192` connects our host to a different network.
- Let's transfer ligolo-ng and try if we can get access to the new network and enumerate active hosts on that network

#### Using ligolo-ng
- Refer to [[Ligolo-ng]] for additional details regarding the installation and usage of Ligolo-ng tool.
## Connected the first agent
![[Pasted image 20260328115143.png]]
![[Pasted image 20260328115156.png]]

- now we are able to ping the hosts in the 172.16.5.0/24 subnet.
- Let's try a ping sweep on the new network that we just got access to and identify active hosts.
###### ping sweep

```python
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
```

![[Pasted image 20260328115735.png]]
- we found a new host:
```python
172.16.5.35
```

##### Enumerating the new host we found
- Refer to [[Rust scan Installation]] for a one liner to install rustscan.
```python
rustscan -a 172.16.5.35 --ulimit 10000  -- -A -sC -sV -oA full_port_scan
```
 ![[Pasted image 20260328120538.png]]
 - Looks like a windows machine..

![[Pasted image 20260328120814.png]]
Turns out rdp is also running..

- Remember we had some credentials for the user `mlefay` we can try rdping into this box using those credentials.
##### RDP-ing in to the windows box
```python
xfreerdp /u:mlefay /p:"Plain Human work!" /v:172.16.5.35 /cert:ignore
```
![[Pasted image 20260328121115.png]]
### Flag inside C:
![[Pasted image 20260328121151.png]]
- Let's check if this machine has access to any networks that we did not have access to previously.

##### The machine has a second network interface which has access to a different network

![[Pasted image 20260328121338.png]]
5. In previous pentests against Inlanefreight, we have seen that they have a bad habit of utilizing accounts with services in a way that exposes the users credentials and the network as a whole. **What user is vulnerable?**

To get the user who is vulnerable, I used the technique of **Extracting Passwords from Windows Systems through dumping LSASS.**

**LSASS** is a core Windows process responsible for enforcing security policies, handling user authentication, and storing sensitive credential material in memory.

Upon initial logon, LSASS will:

- _Cache credentials locally in memory_
- _Create_ [_access tokens_](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- _Enforce security policies_
- _Write to Windows’_ [_security log_](https://docs.microsoft.com/en-us/windows/win32/eventlog/event-logging-security)

### Dumping LSASS process memory

### Task Manager method

With access to an interactive graphical session on the target, we can use the **task manager** to create a memory dump. This requires us to:

1. Open `Task Manager`
2. Select the `Processes` tab
3. Find and right click the `Local Security Authority Process`
4. Select `Create dump file`

A file called `lsass.DMP` is created and saved in `%temp%`. This is the file we will transfer to our attack host.

I disconnected the connection to 172.16.5.35 and connected again with the shard Folder command with my RDP syntax. This will give the opportunity to be able to copy lsass.DMP file to the shared folder and have access to it on my Kali Linux machine for further processing.

proxychains4 -f /home/kali/Tools/proxychains4.conf xfreerdp3 /u:mlefay  /p:'Plain Human work!' /v:172.16.5.35 /cert:ignore /dynamic-resolution "/drive:sf_kalifolder,/media/sf_kalifolder"

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:700/1*1LDRXFIUwHx3B9LJ-xYltQ.png)

shared folder!

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:700/1*YuN2yls2JwnRVW2X9Mnvww.png)

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:700/1*n1a-clS3gvt4mY6RGiuviA.png)

The next is to navigate to the location of the file, **C:\Users\mlefay\AppData\Local\Temp**

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:700/1*Ri0YA1FbYRhCMH4wKJxYjA.png)

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:700/1*DebVvAgUOnYW5wILMTUWew.png)

Right click and copy

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:700/1*euIZZPxZmmjuYS6Iw8WA7g.png)

copied

The next is to extract the credentials using **Pypykatz.**

### Using Pypykatz to extract credentials

Now, on the attack machine, we can make use of **Pypykatz** to extract credentials.

pypykatz lsa minidump /<path of the file>/lsass.dmp 

kali@kali ~ % pypykatz lsa minidump lsass.DMP

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:700/1*C-qgbgIdtAmW7UWOnVJMQA.png)

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:700/1*oSD_3fk3SEMECnSktk3oZA.png)

vfrank credentials captured!

**vfrank:Imply wet Unmasked!**

Therefore, the user who is vulnerable is **vfrank.**

6. For your next hop, enumerate the networks and then utilize a common remote access solution to pivot. Submit the **C:\Flag.txt** located on the workstation.

Remember on **172.16.5.35**, we discovered another ethernet adapter with ip address **172.16.6.35,** which is another subnet. That is, the host is dual NICd.

It is so we need to identify hosts on the same network using **PowerShell**.

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:700/1*Y9UrNfWXjUcUsSmxo_xpSQ.png)

1..254 | % {"172.16.6.$($_): $(Test-Connection -count 1 -comp 172.16.6.$($_) -quiet)"}

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:700/1*-n9CNhUAclTCYRyyxGACaQ.png)

172.16.6.25

Remember the vulnerable user….

**vfrank:Imply wet Unmasked!**

I used his credentials to RDP to **172.16.6.25** right from **172.16.5.35.** Remember the hint: _“…utilize a common remote access solution to pivot. Submit the C:\Flag.txt located on the workstation.”_

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:700/1*Lbwa_S2-mfdNyBFd2ZWgLA.png)

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:700/1*DEH9atlQbXjQj48N2UhXzw.png)

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:700/1*CX_TWIzyODQNDREVsUxSoA.png)

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:700/1*EkXDsxe8EnyH7QocCMgvfg.png)

Get ready to encounter this failed attempt…enter the same password again and press Ok.

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:700/1*iLpnErYCdEu7cIh2Uj0AHg.png)

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:700/1*5H7OG2rs63y0FpuSxHuw0Q.png)

click **Yes**

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:700/1*YaoI2dCS6brBkZI_dSsTXw.png)

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:700/1*7eutDbI6FubPLRy2eHggNQ.png)

172.16.6.25 desktop

![](https://miro.medium.com/v2/resize:fit:669/1*yk4a0q0zWXtVE6GMB-lLTg.png)

The next is to navigate to the C drive and capture the flag….

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:700/1*P6jRwS3W9YG0GFhuGfrL4Q.png)

**Two Drives C and Z**

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:700/1*rUg6pnzD8sNIuqpkOWi-6Q.png)

Answer: **N3tw0rk-H0pp1ng-f0R-FuN**

7. Submit the contents of C:\Flag.txt located on the Domain Controller.

I tried to open the second drive, **drive Z,** and see what was inside; behold, I was able to capture the last flag for question 7. Which I don’t even need to get access to DC…remember the drive name, **AutomateDCAdmin.** Means the information inside the drive is related to **DC**.

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:700/1*S_hs-dALXJZXxlUZE4MfRg.png)

Answer: **3nd-0xf-Th3-R@inbow!**

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:700/1*8tdC2GvvO7-onoaQqv2CeA.png)

End!!!!
