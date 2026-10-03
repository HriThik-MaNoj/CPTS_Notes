
## Admin on Paper, but No Admin in the Shell

### Symptom

`net localgroup administrators` shows your account as a member, but the current shell does **not** have an effective Administrator token:

```
net localgroup administrators
```

Yet:

```
whoami /groups
```

shows no `Administrators` group, or shows it as **Deny Only** at **Medium Integrity**.

Also:

```
whoami /priv
```

does not show privileges such as:

- `SeImpersonatePrivilege`
- `SeDebugPrivilege`

### Cause

Adding an account to a local group **mid-session does not update the existing access token**.

Windows creates the user's token when they log on. If the account is added to `Administrators` afterward, the existing session continues using the old token.

With **UAC split tokens**, an administrator can also have:

- **Filtered token** → Medium Integrity
- **Elevated token** → High Integrity

So being listed in the Administrators group does not automatically mean the current shell is elevated.

---

## Fix

### 1. Create a fresh logon session

Without disconnecting RDP:

```
runas /user:ilfserveradm cmd
```

Enter the password when prompted.

> Simply disconnecting/reconnecting RDP may not be sufficient. A full logoff (`shutdown /l`) followed by signing in again also works.

---

### 2. Confirm Administrators membership

```
whoami /groups | findstr /i "Administrators"
```

You may see:

```
BUILTIN\Administrators
Group used for deny only
```

at **Medium Integrity**.

This is normal for a filtered UAC token.

---

### 3. Elevate to High Integrity

Normal UAC elevation:

```
Start-Process cmd -Verb RunAs
```

Then verify:

```
whoami /groups
```

You should now see the token running at:

```
High Mandatory Level
```

---

### 4. Verify privileges

```
whoami /priv
```

After elevation, privileges such as:

```
SeImpersonatePrivilege
SeDebugPrivilege
```

may become available, depending on the account and Windows configuration.