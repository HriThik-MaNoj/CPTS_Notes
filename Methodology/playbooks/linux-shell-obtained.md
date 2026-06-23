# Playbook: Linux Shell Obtained

## Minute 0: Shell Confirmation

```
[ ] whoami / id → Confirm current user
[ ] hostname → Confirm target
[ ] pwd → Current directory
[ ] ip addr → Network interfaces
[ ] ss -tulpn → Listening services
[ ] sudo -l → SUDO permissions
[ ] id → Group membership
```

## Minute 5: Immediate Credential Harvesting

```
[ ] cat ~/.bash_history → Commands + creds
[ ] cat ~/.ssh/id_rsa → SSH keys (check exist)
[ ] cat ~/.ssh/authorized_keys → Authorized keys
[ ] cat /etc/passwd → Users
[ ] cat /etc/shadow → Hashes (if readable)
[ ] find / -type f -name "*.conf" 2>/dev/null | xargs grep -l "password" 2>/dev/null
[ ] find / -type f -name ".env" 2>/dev/null -exec cat {} \;
```

## Minute 15: Privilege Escalation

```
[ ] sudo -l → ALL? → sudo -i → ROOT
[ ] find / -perm -4000 -type f 2>/dev/null → SUID binaries
[ ] cat /etc/crontab → Cron jobs
[ ] ls -la /etc/cron* → Cron directories
[ ] Upload linpeas.sh → ./linpeas.sh | tee linpeas.log
[ ] uname -a → Kernel version for exploits
```

## Minute 30: Lateral Movement Prep

```
[ ] cat /etc/hosts → Known hosts
[ ] arp -a → ARP cache (recent connections)
[ ] netstat -anp → Active connections
[ ] find / -name "id_rsa" -o -name "*.pem" 2>/dev/null → SSH key sweep
[ ] grep -r "password\|PASSWORD\|passwd" /var/www/html/ 2>/dev/null
[ ] cat ~/.my.cnf → MySQL creds
[ ] docker ps → Docker access?
```

## Milestone Checks
- [ ] ROOT obtained? → Dump all hashes, all SSH keys, all configs
- [ ] User + no privesc? → Upload pspy, check cron timers
- [ ] SSH keys found? → Test on ALL known hosts
- [ ] Database creds? → Test on local MySQL/MSSQL + remote
