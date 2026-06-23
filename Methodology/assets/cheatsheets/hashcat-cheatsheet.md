# Hashcat Cheat Sheet

```bash
# Common hash modes (-m)
# 1000  = NTLM
# 5600  = NetNTLMv2
# 13100 = Kerberos TGS-REP
# 18200 = Kerberos AS-REP
# 1800  = SHA-512 (Unix)
# 500   = MD5 (Unix)
# 3200  = bcrypt
# 5500  = NetNTLMv1
# 2100  = MS Office (2007-2019)
# 6211  = PBKDF2 (TrueCrypt)
# 1410  = sha256($pass.$salt)

# Benchmark
hashcat -b

# Dictionary attack
hashcat -m <mode> hash.txt /usr/share/wordlists/rockyou.txt

# Dictionary + rules
hashcat -m <mode> hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m <mode> hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/d3ad0ne.rule

# Mask attack (brute force)
# ?l = lower, ?u = upper, ?d = digit, ?s = special, ?a = all
hashcat -m <mode> hash.txt -a 3 ?u?l?l?l?l?l?d?d?d

# Show results
hashcat -m <mode> hash.txt --show

# Append rules to wordlist
hashcat -m <mode> hash.txt wordlist.txt -r rule.rule
```
