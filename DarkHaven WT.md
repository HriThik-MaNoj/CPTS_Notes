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
