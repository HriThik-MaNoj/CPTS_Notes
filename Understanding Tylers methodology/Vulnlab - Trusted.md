
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

