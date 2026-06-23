# SSH Battle Card

## What to Check First
```
1. PORT 22? → nmap -sV -p 22 target
2. VERSION → nc target 22 | tee ssh-banner.txt
3. ENUM → netexec ssh target -u users.txt -p passwords.txt
4. DEFAULT CREDS → netexec ssh target -u root -p root
```

## High-Value Findings
- **Default/weak creds** → root:root, admin:admin, user:user
- **SSH key in config files** → Found during SMB/FTP/web enumeration
- **Password reuse** → Creds from DB/web = same SSH password
- **Key-based auth with found key** → SSH access without password
- **Vulnerable version** → OpenSSH exploits (rare but possible)
- **Internal only** → SSH used after initial foothold for lateral movement
- **Authorized_keys write** → Via NFS or misconfig → SSH access

## Immediate Commands
```
# SSH with password
ssh user@target

# SSH with key
ssh -i private_key user@target
chmod 600 private_key && ssh -i private_key user@target

# Brute force (if you have user list)
hydra -L users.txt -P passwords.txt ssh://target -t 4
netexec ssh target -u users.txt -p passwords.txt
medusa -u user -P passwords.txt -M ssh -h target

# Key generation for authorized_keys write
ssh-keygen -t rsa -f key -N ""
cat key.pub | tee -a >> we need to add to authorized_keys
# Then via NFS upload or SMB write or direct file write

# Check version for CVEs
searchsploit openssh <version>
nmap --script ssh-auth-methods -p 22 target
nmap --script ssh2-enum-algos -p 22 target

# SSH tunneling (after access)
ssh -D 1080 user@target          # SOCKS proxy
ssh -L 8080:localhost:80 user@target  # Local port forward
ssh -R 8080:localhost:80 user@target  # Remote port forward
```

## Common Attack Paths
```
FOUND SSH KEY → SSH Access → Shell → Full Host Control
CRED REUSE → SSH creds from DB/Web → Shell → Privesc
DEFAULT CREDS → Root SSH → Full Root Shell
AUTHORIZED_KEYS WRITE → Upload Key → SSH Access
WEAK PASSWORD → Brute Force → User Access → Privesc
SSH + SAME PASSWORD → Lateral Movement Across Hosts
```

## Escalation Paths
- **SSH as user** → sudo -l → Check sudo permissions → Root
- **SSH as user** → SUID binaries → Privesc → Root
- **SSH as root** → Full system control → Dump creds → Pivot
- **SSH key found** → Check all hosts in subnet (key reuse)
- **SSH with forwarded agent** → Agent hijacking → Pivot

## When to Stop
- No creds available → Don't brute force blindly (noisy)
- Version scan shows no CVEs
- DNS/network scanning → more likely to find other attack surfaces
- SSH is usually a destination, not an initial vector (unless weak creds)

## Common Mistakes
- Trying to brute force SSH without valid usernames
- Forgetting to check default creds (root:root, admin:admin)
- Not reusing SSH keys found in other enumeration
- Not checking same password across hosts (password reuse)
- Forgetting chmod 600 on private keys (SSH will refuse)
- Not using netexec's parallel SSH testing for password reuse sweep
