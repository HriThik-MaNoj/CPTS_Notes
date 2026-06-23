# Foothold Playbooks

## Purpose
Each playbook is a minute-by-minute operational guide for what to do after gaining a specific type of access. Designed to eliminate "what next?" hesitation and ensure you don't miss critical steps under time pressure.

## How To Use
1. Identify which playbook matches your current access level
2. Follow the timeline: Minute 0 → 5 → 15 → 30
3. Each section has checkboxes — track completion
4. At each milestone, check the Milestone Checks section
5. Move to next playbook based on outcomes

## Available Playbooks

| Playbook | When To Use |
|----------|-------------|
| linux-shell-obtained.md | First interactive shell on Linux |
| windows-shell-obtained.md | First interactive shell on Windows |
| domain-user-obtained.md | First domain user credentials |
| local-admin-obtained.md | Local admin access on Windows |
| mssql-access-obtained.md | MSSQL database access (SA/user) |
| winrm-access-obtained.md | WinRM remote access confirmed |
| ssh-access-obtained.md | SSH access confirmed |

## Chain Flow

```
              ┌─ Linux Shell
First Access ─┤
              └─ Windows Shell ─┬─ Local Admin ─┬─ Domain User
                                └─ User         └─ MSSQL Access
                                                    │
                                                    └─ WinRM Access
                            SSH Access ──────────────┘

Domain User → BloodHound → DA Path → DCSync → Complete
```

## Key Principle
**Time is the most limited resource.** Every playbook is optimized to get you from access to escalation in under 30 minutes. If you're stuck after 30 minutes on any playbook, pivot to a different playbook or re-enumerate.

## Always Remember
- Every shell → dump creds first
- Every cred → test everywhere
- Every hash → PTH before crack
- Every key → test all hosts
- Every subnet → pivot
