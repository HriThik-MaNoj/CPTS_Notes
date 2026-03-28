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
