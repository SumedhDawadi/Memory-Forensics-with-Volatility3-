# Windows Memory Forensics Cheat Sheet

A comprehensive Volatility 3 command reference for Windows memory dump analysis, organized by investigation category.

# Table of Contents

- [Core System Identification & Triage](#core-system-identification--triage)
- [Hidden Process & Process Analysis](#hidden-process--process-analysis)
- [Malware & Code Injection Detection](#malware--code-injection-detection)
- [Network & C2 Artifacts](#network--c2-artifacts)
- [Persistence, Registry & Service Analysis](#persistence-registry--service-analysis)
- [Kernel & Rootkit Detection](#kernel--rootkit-detection)
- [Advanced Scanning & Artifact Extraction](#advanced-scanning--artifact-extraction)
- [Recommended Investigation Workflow](#recommended-investigation-workflow)
  

## Core System Identification & Triage

| Command | Description |
|---------|-------------|
| `windows.info` | Identifies OS version, build number, architecture, kernel base, DTB, and system uptime. **Always run first.** |
| `windows.pslist` | Lists active running processes (PID, PPID, creation time, threads). |
| `windows.pstree` | Displays process tree with parent-child relationships. Great for detecting suspicious ancestry. |
| `windows.cmdline` | Shows full command-line arguments for processes. Reveals malicious execution and encoded commands. |

## Hidden Process & Process Analysis

| Command | Description |
|---------|-------------|
| `windows.psscan` | Pool tag scanning to find hidden, terminated, or unlinked EPROCESS structures. |
| `windows.malware.psxview` | Cross-compares multiple process listing methods to detect hidden/manipulated processes. |
| `windows.dlllist --pid <PID>` | Lists loaded DLLs per process. Helps identify injected or anomalous modules. |
| `windows.handles --pid <PID>` | Shows open handles (files, registry, mutexes). Useful for mutex detection and persistence artifacts. |

## Malware & Code Injection Detection

| Command | Description |
|---------|-------------|
| `windows.malfind --dump` | Detects process injection by scanning for suspicious VAD memory permissions (RWX pages). |
| `windows.memmap --dump --pid <PID>` | Dumps process memory regions to disk for further analysis. |
| `windows.dumpfiles --pid <PID> -o output_dir` | Extracts files, DLLs, and executables from memory. |
| `windows.malware.ldrmodules --pid <PID>` | Detects hidden or unlinked DLLs by comparing InLoad/InInit/InMemoryOrder lists. |
| `windows.malware.hollowprocesses` | Detects Process Hollowing technique. |
| `windows.malware.processghosting` | Detects Process Ghosting (file deleted on disk but running in memory). |
| `windows.malware.pebmasquerade` | Detects PEB Masquerading (hiding real executable path/name). |
| `windows.malware.suspicious_threads` | Identifies threads with anomalous start addresses (APC injection, thread hijacking, reflective loading). |

## Network & C2 Artifacts

| Command | Description |
|---------|-------------|
| `windows.netscan` | Scans for network connections, sockets, and owning processes. Identifies C2 and exfiltration. |
| `windows.netstat` | Alternative plugin for active network connections with process context. |

## Persistence, Registry & Service Analysis

| Command | Description |
|---------|-------------|
| `windows.registry.hivelist` | Locates registry hives in memory (required before using other registry plugins). |
| `windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"` | Dumps specific registry keys for autostart persistence. |
| `windows.registry.scheduled_tasks` | Extracts scheduled tasks from memory. Common persistence mechanism. |
| `windows.registry.userassist` | Shows GUI program execution history with run counts and timestamps. |
| `windows.registry.amcache` | Parses Amcache for executed programs and file metadata. |
| `windows.svcscan` | Scans for Windows services. |
| `windows.malware.svcdiff` | Highlights hidden or anomalous services. |

## Kernel & Rootkit Detection

| Command | Description |
|---------|-------------|
| `windows.driverscan` | Scans for kernel drivers using pool tags. |
| `windows.modules` | Lists loaded kernel modules/drivers. |
| `windows.malware.drivermodule` | Helps detect hidden or manipulated kernel drivers. |
| `windows.malware.unhooked_system_calls` | Detects SSDT hooks and system call table tampering (rootkit behavior). |

## Advanced Scanning & Artifact Extraction

| Command | Description |
|---------|-------------|
| `windows.filescan` | Scans for open file objects in memory. |
| `windows.vadinfo --pid <PID>` | Detailed Virtual Address Descriptor information for deep memory analysis. |
| `yarascan --rules /path/to/rules.yar` | Scans memory using YARA rules for known malware signatures. |
| `windows.hashdump` | Extracts NTLM password hashes from SAM hive. |
| `windows.lsadump` | Dumps LSA secrets (service accounts, passwords). |
| `windows.malware.skeleton_key_check` | Checks for Skeleton Key (Mimikatz-style) LSASS backdoor. |

## Recommended Investigation Workflow

1. **Triage**:  
   `windows.info` → `pslist` → `pstree` → `cmdline`

2. **Hidden Processes**:  
   `psscan` → `malware.psxview`

3. **Injection Hunting**:  
   `malfind` → `hollowprocesses` → `processghosting` → `suspicious_threads`

4. **Network Analysis**:  
   `netscan`

5. **Persistence**:  
   Registry plugins + `scheduled_tasks` + `userassist`

6. **Kernel/Rootkit**:  
   `driverscan` → `modules` → `unhooked_system_calls`

7. **Confirmation**:  
   YARA scanning + artifact extraction (`dumpfiles`)

---

**Tool**: [Volatility 3 Framework](https://github.com/volatilityfoundation/volatility3)
