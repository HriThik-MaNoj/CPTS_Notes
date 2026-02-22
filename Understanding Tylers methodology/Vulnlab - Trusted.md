
## Port Scan

- In this particular machine we got two machines in the AD environment and we got the IP addresses for both of them.
- Initially we chose one IP and that turns out to be the IP of the Domain controller from what we can see in the scan results.
```
# Use rustscan to scan for open ports and then feed those open ports to Nmap for Aggressive scan

rustscan -a $IP -- -A
```

![[Pasted image 20260222210618.png]]

- Scan the second machine with rust scan similar to what we did for the first machine. 
- Since the first one is the DC, it wont be our initial way in most probably.

![[Pasted image 20260222210907.png]]

![[Pasted image 20260222210948.png]]

- Hmm.. this one also seems to be running AD stuff.. Interesting..
- Both of these machines are domain controllers, One is the child and One is the parent.

- We'll find the domain names of both the machines through Nmap scan, make sure to add those domain names and their associated IP addresses in the /etc/hosts file : 
![[Pasted image 20260222211926.png]]
![[Pasted image 20260222212400.png]]
- we saw that we have a web server running on the .54 machine, often when you see a web server, it's gotta be the low hanging fruit, let's try enumerate that web server.


### Words of Wisdom from Tyler
Anytime I see a webserver, there's always a bunch of things that I would like to check: 
- Use Dirsearch to bruteforce for hidden directories.
- Vhost Fuzzing.
- Version Enumeration ( In exams like the OSCP, always check for version numbers because there's a high chance that particular version is vulnerable to a CVE)
- App functionality (using the website as a normal user)

- Used the application like a normal user would and foud that phpmyinfo.php is accessible:
![[Pasted image 20260222213739.png]]

