# Attack Path Prioritization Engine

## Decision Framework

### The Core Question
> "I have 10 possible things to try. Which one should I do first?"

### Decision Matrix

Score each possible action on 5 axes (1-5):

| Criterion | Weight | 1 | 2 | 3 | 4 | 5 |
|-----------|--------|---|---|---|---|---|
| Probability of Success | 3x | <5% | 5-15% | 15-30% | 30-50% | >50% |
| Time Required (Inverted) | 2x | >2hr | 1-2hr | 30-60min | 10-30min | <10min |
| CPTS Usefulness | 2x | Low-value | Minor info | Medium gain | Good foothold | Direct shell |
| Credential Yield | 2x | None | Minor info | Single hash | Password | Domain creds |
| Escalation Potential | 3x | None | Info only | Lateral path | Priv to admin | Domain admin |

### Priority Score Calculation

```
Score = (Prob × 3) + (Time_Inv × 2) + (Usefulness × 2) + (Cred_Yield × 2) + (Esc_Potential × 3)
Maximum = 25 + 10 + 10 + 10 + 15 = 70
```

---

## Ranked Attack Paths (Pre-Scored)

### Tier 1: CRITICAL (Score 55-70) — Do these FIRST

| # | Path | Score | Why |
|---|------|-------|-----|
| 1 | **SMB signing disabled → NTLM relay → ADCS → DA** | 65 | 5min setup, >50% success, DA outcome |
| 2 | **MSSQL SA → xp_cmdshell → SYSTEM** | 62 | 1min exploit, >50% success, full host control |
| 3 | **GPP Password found → Decrypt → Domain creds** | 60 | 1min, guaranteed success, domain access |
| 4 | **SMB null session → Users → Password spray** | 58 | 5min enum, 30%+ success, domain user |
| 5 | **Local admin → LSASS dump → Domain creds** | 58 | 5min, high success, credential yield |
| 6 | **Writable SMB share → Web shell → RCE** | 55 | 2min, >50% success if writable + web |
| 7 | **AS-REP Roast → Crack → Domain User** | 55 | 10min enum, 30%+ crack, domain access |
| 8 | **LAPS readable → Local admin passwords** | 55 | 1min read, 100% success, admin access |

### Tier 2: HIGH (Score 40-54) — Do immediately after Tier 1

| # | Path | Score | Why |
|---|------|-------|-----|
| 9 | **SQL Injection → DB dump → Admin creds** | 52 | 15min, high success, admin panel login |
| 10 | **LFI → Config files → DB creds** | 50 | 10min, medium success, credential yield |
| 11 | **Password spray found → Domain user** | 50 | 10min, moderate success, AD foothold |
| 12 | **Kerberoast → Crack → Service account** | 48 | 30min, 20%+ crack, lateral access |
| 13 | **BloodHound → DA path → ACL abuse** | 48 | 30min, high success with path, DA |
| 14 | **Responder → NetNTLMv2 → Crack** | 45 | 30min-2hr, variable success, hash |
| 15 | **LDAP anonymous → Full user dump → Spray** | 45 | 5min enum, 30%+ success, domain user |
| 16 | **WinRM password spray → Shell** | 42 | 10min, 20%+ success, interactive shell |
| 17 | **MSSQL linked server → Lateral jump** | 42 | 15min, 40%+ success if linked, lateral |
| 18 | **SMB writable → SCF attack → Hash capture** | 40 | 10min, hash yield, relay/crack option |
| 19 | **NFS exports → SSH keys → SSH shell** | 40 | 10min, 30%+ success if keys, shell |

### Tier 3: MEDIUM (Score 25-39) — Secondary options

| # | Path | Score | Why |
|---|------|-------|-----|
| 20 | **Web app CMS exploit → Known CVE → RCE** | 38 | 30min detection, 20%+ exploit, shell |
| 21 | **FTP anonymous → Config files → Creds** | 35 | 10min, 20%+ yield, password reuse |
| 22 | **Docker group → Mount host → Root** | 35 | 5min, 100% if in docker group, root |
| 23 | **SSH key reuse sweep** | 35 | 15min, 20%+ success, additional shells |
| 24 | **Web admin → File upload → Shell** | 32 | 20min, 30%+ if upload, RCE |
| 25 | **Unconstrained delegation → Ticket theft** | 30 | 1hr, needs server compromise first, DA |
| 26 | **SeImpersonate → PrintSpoofer → SYSTEM** | 30 | 5min, 100% if priv, SYSTEM |
| 27 | **Cron writable → Root execution** | 28 | 30min, 20%+ success, root |
| 28 | **AlwaysInstallElevated → MSI → SYSTEM** | 28 | 15min, 50%+ if enabled, SYSTEM |
| 29 | **MS17-010 (EternalBlue) → SYSTEM** | 25 | 10min, 10-20% patched, SYSTEM |
| 30 | **Responder → NetNTLM relay** | 25 | 5min setup, 10%+ relay success, shell |

### Tier 4: LOW (Score <25) — Do only when stuck

| # | Path | Score | Why |
|---|------|-------|-----|
| 31 | **SMTP user enum → VRFY** | 20 | Info gathering only |
| 32 | **SNMP public → Version enum** | 18 | Info only |
| 33 | **DNS zone transfer** | 15 | <5% success, info only |
| 34 | **Brute force SSH** | 12 | Slow, noisy, low success |
| 35 | **Kernel exploit (blind)** | 10 | Destructive risk, 5% success |
| 36 | **Brute force RDP** | 8 | Very noisy, locked accounts risk |

---

## Phase-Based Priority Decisions

### Phase 1: Foothold Hunting (First 60 minutes)

```
PRIORITY ORDER:
1. SMB Signing Check (2 min → relay path)
2. SMB Null Session (5 min → users/policy)
3. LDAP Anonymous Bind (2 min → users)
4. Web Applications (30 min per app)
5. Responder (background)
6. FTP/NFS Anonymous (5 min each)

DO NOT WASTE TIME ON:
- SSH brute force
- SNMP deep enumeration
- DNS zone transfer loop
- Banner grabbing everything
```

### Phase 2: After First Shell (Post-foothold)

```
PRIORITY ORDER:
1. Credential access (LSASS/SAM/bash_history)
2. Password sweep with new creds
3. BloodHound (if domain)
4. Kerberoast (if domain)
5. Pivoting setup
6. Lateral movement
```

### Phase 3: Domain Access

```
PRIORITY ORDER:
1. BloodHound → DA path identification
2. AS-REP Roast (if not done)
3. Kerberoast (if not done)
4. DCSync (if DA)
5. GPP / LAPS check
```

---

## "I'm Stuck" Framework

When nothing is working, follow this exact re-prioritization:

| Scenario | Reset Priority |
|----------|----------------|
| No foothold, no web | Go back to L2 scan, check UDP, check all ports |
| Web apps all filtered | Check alternate ports (8080, 8443, 8000, 8888) |
| No SMB/LDAP access | FTP, NFS, SNMP, SMTP for info leaks |
| Shell but no lateral | Check ALL hosts with same creds, SSH key sweep |
| Domain user but stuck | Run BloodHound (you might be 1 ACL away) |
| Privileges limited | Kernel check, always elevate check, potato check |
| No AD present | Pivot deeper, check internal DNS, scan new subnets |

---

## Time Budget Guidelines

```
┌────────────────────────────────────────────────────┐
│ TOTAL EXAM TIME: 10 DAYS (240 HOURS)              │
│                                                    │
│ Phase 1: Foothold                   ~4-8 hours     │
│ Phase 2: Post-exploit + creds       ~2-4 hours     │
│ Phase 3: Lateral + escalation       ~4-8 hours     │
│ Phase 4: Domain admin                ~4-8 hours     │
│ Phase 5: Documentation + reporting  ~2-4 hours     │
│                                                    │
│ KEY RULE: If 2 hours on path with no progress     │
│ → PIVOT to next priority path                     │
└────────────────────────────────────────────────────┘
```

## Quick Priority Reference Card

```
┌──────────────┬──────────────────────────────────────┐
│ SITUATION    │ DO THIS FIRST                        │
├──────────────┼──────────────────────────────────────┤
│ Found SMB    │ Check null session + signing         │
│ Found web    │ Dir brute + tech detect              │
│ Found creds  │ Test everywhere immediately          │
│ Found hash   │ PTH if NTLM, crack if NetNTLMv2     │
│ Got shell    │ Extract creds first                  │
│ Got DA creds │ DCSync immediately                   │
│ Got user on AD│ BloodHound + Kerberoast             │
│ Stuck        │ Re-scan deeper, check UDP, alt ports │
└──────────────┴──────────────────────────────────────┘
```
