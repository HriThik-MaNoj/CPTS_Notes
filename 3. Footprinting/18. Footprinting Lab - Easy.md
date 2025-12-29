**Given :** 
- our teammates have found the following credentials "`ceil:qwer1234`".
- we don't know what these credentials are for.
- we need to find flag.txt to complete this lab.

## Nmap
![[Pasted image 20251229085734.png]]
- From the nmap scan results, we can see that we have 4 open ports, and all of them look promising.
- We have ports 21 and 2121 for ftp, 22 for ssh and 53 for DNS.
- We have 2 ftp services running on the same server.. that's interesting..
- Let's try anonymous login on both of them

![[Pasted image 20251229090201.png]]
- So anonymous login is not supported.
- Let's try logging in using the credentials provided in the beginning of the lab.
![[Pasted image 20251229090428.png]]
- Hurray! We're In..
- Now let's check if we can find the flag here..
![[Pasted image 20251229090659.png]]
- The flag is not here but we found the .ssh directory, let's see if we can find the ssh key in that folder, and using that we can login using ssh (as we previously saw that ssh is also open)
![[Pasted image 20251229090827.png]]
- Yes, we got it, now we can just download that file to our local machine..
![[Pasted image 20251229090935.png]]
- now let's login via ssh using the `id_rsa` file.
![[Pasted image 20251229091157.png]]

- We got the bad permissions error when we first tried to login using the id_rsa file. so we modified the file permissions using the command: 
```
chmod 600 id_rsa
```
- Then we were able to log in.
- ![[Pasted image 20251229091404.png]]
- After a bit of moving around.. we got the flag!!.
