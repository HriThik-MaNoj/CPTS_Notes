# {{title}}

Brief one-line description of what this service/protocol is and its primary purpose.

- Default Port: `{{port}}`
- Protocol: TCP/UDP

---

## Overview

- Key characteristic 1
- Key characteristic 2
- Security considerations

## Footprinting the Service

```bash
sudo nmap <ip-address> -sV -sC -p{{port}}
```

```bash
# Additional nmap scripts if available
sudo nmap --script {{service}}* <ip-address> -sV -p{{port}}
```

## Interacting with the Service

### Basic Connection

```bash
# Command to connect to the service
```

### Common Commands

| Command | Description |
|---------|-------------|
| `command1` | What it does |
| `command2` | What it does |

## Enumeration Tools

### Tool 1

```bash
# Example command
```

### Tool 2

```bash
# Example command
```

## Exploitation / Misconfigurations

- Common misconfiguration 1
- Common misconfiguration 2

## Resources

- [Official Documentation](URL)
- [HackTricks - {{title}}](https://book.hacktricks.xyz/)

---

See also: [[Related Note 1]], [[Related Note 2]]
