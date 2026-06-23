# Credential Tracking Guide

## Goal

Never test the same credential twice. Never forget where a credential came from. Never forget where it succeeded.

---

## File Structure

Create a single CSV file at the start of the exam:

```
exam-credentials.csv
```

Use the template at `credential-tracker-template.csv`.

Copy the template before starting:

```bash
cp operator/credential-tracker-template.csv exam-credentials.csv
```

---

## Columns Reference

| Column | What to put | Example |
|--------|-------------|---------|
| `id` | Auto-incrementing number | 1, 2, 3 |
| `username` | The username | `administrator`, `john.doe`, `SVC_SQL` |
| `password_or_hash` | Cleartext password or hash marker | `Spring2025!`, `<NTLM:hash>`, `<NETNTLMv2:hash>` |
| `cred_type` | One of: `cleartext`, `ntlm_hash`, `netntlmv2_hash`, `kerb_tgs`, `kerb_asrep`, `ssh_key`, `cert_pfx`, `browser_cred` | `cleartext` |
| `domain` | Domain or `WORKGROUP` | `DOMAIN`, `WORKGROUP`, `LOCAL` |
| `source_host` | IP where it was found | `10.10.10.20` |
| `source_method` | How it was obtained | `SAM_dump`, `LSASS_dump`, `Responder`, `config_file`, `SQLi`, `Kerberoast` |
| `access_level` | Best guess at privilege | `domain_admin`, `domain_user`, `local_admin`, `service_account`, `user`, `unknown` |
| `works_on_hosts` | Comma-separated IPs where it succeeded | `10.10.10.10,10.10.10.11` |
| `works_on_services` | Comma-separated services that accepted it | `SMB,WinRM` |
| `sweep_status` | `untested`, `pending`, `testing`, `tested`, `partial` | `tested` |
| `crack_status` | `N/A`, `pending`, `cracking`, `cracked`, `uncrackable` | `cracked` |
| `notes` | Free text | `local admin on 2 hosts, BH collected` |

---

## Status Workflow

Every credential follows this lifecycle:

### 1. Discover

When you find a new credential, add a row immediately:

```bash
# Add to CSV — no format requirement, just get it in
echo "6,svc_backup,S3cur3P@ss!,cleartext,DOMAIN,10.10.10.30,config_file,service_account,,,,pending,N/A,crack in bg"
```

Set `sweep_status = pending`, `crack_status = N/A` (for cleartext) or `pending` (for hashes).

### 2. Validate

For cleartext passwords, test on the originating host first, then sweep:

```bash
# Mark as testing
# Run sweep
netexec smb <subnet>/24 -u user -p pass --continue-on-success
netexec winrm <subnet>/24 -u user -p pass --continue-on-success
netexec ssh <subnet>/24 -u user -p pass --continue-on-success
netexec mssql <subnet>/24 -u user -p pass --continue-on-success

# Update CSV with results
```

### 3. Document Results

Update the row:

- `works_on_hosts` = IPs where it worked
- `works_on_services` = services that accepted it
- `sweep_status` = `tested` (all hosts checked) or `partial` (some checked, interrupted)
- `notes` = any follow-up needed

### 4. Act

Based on results:

| If credential... | Then... |
|-----------------|---------|
| Works on new hosts | Post-exploitation on each new host (more creds!) |
| Is a domain credential | BloodHound immediately |
| Is a local admin | LSASS/SAM dump on each host |
| Is a service account | Check delegation + SPN |
| Is a hash | PTH (if NTLM) or crack (if NetNTLMv2/Kerberos) |

Reference: [CREDENTIAL_DECISION_TREE.md](CREDENTIAL_DECISION_TREE.md)

---

## Validation Rules

- **Every cleartext password** gets swept against ALL hosts on ALL protocols. No exceptions.
- **Every NTLM hash** gets PTH'd immediately. Cracking runs in background.
- **Every NetNTLMv2 hash** gets checked for relay opportunity. If no relay, crack in background.
- **Every Kerberos ticket** gets PTT'd or cracked.
- **Every SSH key** gets tested against its originating host first, then swept.
- **Every credential that succeeds on any host** spawns a new post-exploitation loop on that host.

---

## Reuse Workflow

If a credential works on 3+ hosts:

1. Check if the SAME credential works on remaining hosts (probable pattern).
2. If the password has a pattern (e.g., `CompanyName1!`), try variations.
3. Test the password against DIFFERENT users (password spray).
4. Log all results in the CSV — don't assume you'll remember.

```bash
# Quick password spray from a cracked password
netexec smb DC -u all_users.txt -p 'cracked_password' --continue-on-success
```

---

## Lateral Movement Tracking

When a credential enables lateral movement to a new host:

1. Add a note in the credential's `notes` column: `→ new host 10.10.10.50`
2. Create a new row for that host once post-exploitation yields new creds.
3. Link related credentials by referencing IDs in notes: `related: id=3`

---

## When to Stop Tracking a Credential

| Condition | Action |
|-----------|--------|
| Swept all hosts, zero successes | Set `sweep_status = tested`. Don't retest. |
| Hash won't crack (rockyou + best64 + d3ad0ne) | Set `crack_status = uncrackable`. Don't retry. |
| PTH failed on all hosts | Set `sweep_status = tested`. Don't retry. |
| Credential overtaken by higher-privilege cred | Leave in CSV. Note in comments. Don't delete. |

---

## Quick Start

```bash
# 1. Copy template
cp operator/credential-tracker-template.csv exam-credentials.csv

# 2. Every time you find a credential:
echo "<id>,<user>,<pass_or_hash>,<type>,<domain>,<src_ip>,<method>,<level>,,,,pending,N/A,<notes>" >> exam-credentials.csv

# 3. Sweep command (update CSV after):
netexec smb <subnet>/24 -u <user> -p <pass> --continue-on-success | tee sweep-output.txt

# 4. View all untested credentials:
grep ",pending," exam-credentials.csv

# 5. View all working credentials:
grep -v ",,," exam-credentials.csv | grep -v "pending,"
```

## Cross-References
- Credential decision flow → [CREDENTIAL_DECISION_TREE.md](CREDENTIAL_DECISION_TREE.md)
- Cracking methodology → [Module 06: Password Attacks](06-password-attacks.md)
- Post-exploitation harvesting → [Module 13: Post-Exploitation](13-post-exploitation.md)
- Lateral movement → [Module 12: Lateral Movement & Pivoting](12-lateral-pivot.md)
