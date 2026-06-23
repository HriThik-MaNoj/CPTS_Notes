# Active Directory Attack Flow

```
Domain identified in scope?
│
├── Have domain credentials?
│   ├── YES → BloodHound enumeration
│   │   │
│   │   ├── Find DA sessions on hosts
│   │   │   ├── Host with DA session accessible?
│   │   │   │   ├── YES → Coerce auth, steal token/TGT
│   │   │   │   └── NO → Continue to next path
│   │   │
│   │   ├── Find Kerberoastable accounts
│   │   │   ├── Weak password?
│   │   │   │   ├── YES → Crack TGS → Service account creds
│   │   │   │   │   └── Use for lateral movement (Module 12)
│   │   │   │   └── NO → Continue to next path
│   │   │
│   │   ├── Find ACL attack paths (GenericAll, WriteOwner, ForceChangePassword)
│   │   │   ├── Exploitable?
│   │   │   │   ├── YES → Escalate via ACL abuse
│   │   │   │   └── NO → Continue to next path
│   │   │
│   │   ├── Find delegation attacks (Unconstrained, Constrained, RBCD)
│   │   │   ├── Exploitable?
│   │   │   │   ├── YES → Impersonate DA
│   │   │   │   └── NO → Continue to next path
│   │   │
│   │   ├── Find ADCS vulnerabilities (ESC1-ESC8)
│   │   │   ├── Exploitable?
│   │   │   │   ├── YES → Certificate theft → DA
│   │   │   │   └── NO → Continue to next path
│   │   │
│   │   ├── Check for DCSync rights
│   │   │   ├── Have DCSync?
│   │   │   │   ├── YES → secretsdump → Full compromise
│   │   │   │   │   ├── KRBTGT hash → Golden Ticket
│   │   │   │   │   └── All hashes → Full lateral movement
│   │   │   │   └── NO → Continue
│   │   │
│   │   └── Still no DA?
│   │       ├── Iterate: find more hosts to compromise
│   │       ├── Check trust relationships (child→parent, cross-forest)
│   │       └── Combine multiple low-priv paths
│   │
│   └── NO → Unauthenticated enumeration
│       │
│       ├── Run Responder to capture NetNTLMv2 hashes
│       │   ├── Hash captured?
│       │   │   ├── YES → Crack with hashcat -m 5600
│       │   │   │   ├── Cracked? → Now have credentials → Go to top
│       │   │   │   └── Not cracked → Continue
│       │   │   └── NO → Continue
│       │
│       ├── Check for SMB null session / LDAP anonymous bind
│       │   ├── Success?
│       │   │   ├── YES → Enumerate users via RPC/SMB/LDAP
│       │   │   └── NO → Continue
│       │
│       ├── Enumerate usernames (Kerbrute, LinkedIn, common patterns)
│       │   ├── Users found?
│       │   │   ├── YES → Password spraying
│       │   │   │   ├── Success? → Now have credentials → Go to top
│       │   │   │   └── Failed → Try more passwords conservatively
│       │   │   └── NO → Continue
│       │
│       ├── AS-REP Roasting
│       │   ├── User without pre-auth?
│       │   │   ├── YES → Crack AS-REP hash → Credentials → Go to top
│       │   │   └── NO → Continue
│       │
│       └── Still nothing?
│           ├── Check for SMB relay (no signing)
│           ├── Check for MS17-010 (EternalBlue)
│           └── Move to service/web attacks on domain hosts
└── Not domain-joined → Use Module 09/10 for privesc
```
