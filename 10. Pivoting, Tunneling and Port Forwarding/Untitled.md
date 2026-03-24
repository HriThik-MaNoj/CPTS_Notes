# SocksOverRDP — Windows Pivoting via RDP Tunneling

## Overview

During a penetration test, you may be restricted to a **Windows-only environment** where typical pivoting tools (like SSH tunnels) are unavailable. **SocksOverRDP** solves this by tunneling SOCKS5 traffic through an existing RDP session using Windows' built-in **Dynamic Virtual Channels (DVC)** , a feature of Remote Desktop Services that allows custom data streams to ride alongside a normal RDP connection.

---

## Tools Required

|Tool|Purpose|
|---|---|
|`SocksOverRDP-Plugin.dll`|Loaded into the RDP client on your attack machine; intercepts and tunnels traffic|
|`SocksOverRDP-Server.exe`|Deployed on the pivot target; receives tunneled traffic and routes it onward|
|**Proxifier (portable)**|Forces all outbound traffic through `127.0.0.1:1080` on your attack machine|
|`mstsc.exe`|Windows' built-in RDP client; carries the SOCKS tunnel transparently|

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases)
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

---

## Key Concepts

- **Dynamic Virtual Channels (DVC)** — A Windows RDS feature that allows custom application data to be embedded inside an RDP stream. SocksOverRDP exploits this to carry SOCKS5 traffic without raising suspicion.
- **SOCKS5 proxy** — A general-purpose proxy protocol that can forward any TCP/UDP traffic, unlike HTTP proxies which only handle web requests.
- **`regsvr32`** — A Windows utility for registering COM DLLs. Used here to hook the SocksOverRDP plugin into the RDP client.
- **Pivoting** — Using a compromised machine as a relay to reach network segments you can't directly access from your attack machine.

---

## Attack Chain — Step by Step

### Step 1 — Register the SocksOverRDP plugin on your attack machine

On your Windows foothold machine, register the DLL using `regsvr32`. This loads the plugin into the RDP client so it can intercept and tunnel traffic over the RDP connection.

```python
C:\Users\htb-student\Desktop\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```

> A popup will confirm the plugin is enabled and that it is listening on `127.0.0.1:1080`.

---

### Step 2 — Connect via RDP to the pivot target

Use `mstsc.exe` to connect to `172.16.5.19` with the following credentials:

- **Username:** `victor`
- **Password:** `pass@123`

Because the plugin is now loaded, the RDP connection automatically carries the SOCKS tunnel — no extra configuration needed in `mstsc.exe`.

---

### Step 3 — Deploy the server component on 172.16.5.19

Transfer `SocksOverRDP-Server.exe` (from `SocksOverRDPx64.zip`) to `172.16.5.19` — the machine you just connected to via RDP. Run it with **Administrator privileges**.

> The server component listens locally and receives the tunneled traffic coming through the RDP plugin on your side.

---

### Step 4 — Confirm the SOCKS listener is active

On `172.16.5.19`, verify the listener started correctly:

```cmd
netstat -antb | findstr 1080
```

You should see `127.0.0.1:1080` in a `LISTENING` state before proceeding.

---

### Step 5 — Configure Proxifier on your attack machine

Transfer **Proxifier (portable)** to your Windows 10 attack machine (on the `10.129.x.x` network). Configure it to forward **all traffic** through `127.0.0.1:1080`.

Once Proxifier is running, any tool you launch — not just RDP — will have its traffic automatically routed through the tunnel to the internal network. No per-tool configuration needed.

---

## Full Traffic Flow

```
Your tool (e.g. mstsc.exe, nmap, etc.)
  → Proxifier intercepts all outbound traffic
  → Sends to 127.0.0.1:1080
  → SocksOverRDP Plugin tunnels it over the RDP session
  → SocksOverRDP-Server.exe on 172.16.5.19 receives it
  → Routes onward to 172.16.6.155 (final internal target)
```

---

## Performance Tip

Managing multiple RDP sessions simultaneously can degrade performance noticeably. To improve responsiveness:

1. Open `mstsc.exe`
2. Go to the **Experience** tab
3. Set **Performance** to `Modem`

> This is especially important when chaining RDP pivots — each hop adds latency, and high-quality rendering compounds the slowness.