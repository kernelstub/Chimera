
#  CHIMERA


  > Advanced Linux Rootkit Framework</strong><br>
  > Kernel-space persistence, encrypted C2, hypervisor evasion, polymorphic code mutation

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Component Breakdown](#component-breakdown)
- [Build Pipeline](#build-pipeline)
- [Deployment Flow](#deployment-flow)
- [C2 Protocol](#c2-protocol)
- [Evasion Techniques](#evasion-techniques)
- [Build Instructions](#build-instructions)
- [Configuration Reference](#configuration-reference)
- [Threat Model](#threat-model)

---

## Overview

CHIMERA is a loadable kernel module (LKM) designed as a research artifact for studying advanced offensive rootkit techniques on Linux x86_64 systems. The project implements kernel-only C2 communications, multi-layer hypervisor detection, runtime polymorphic code mutation and automated persistence across five independent vectors.

Every component operates entirely in kernel space after initial load. No userspace daemon or binary remains resident post-exploitation.

> **Research Only.** This project exists to document and study offensive techniques for defensive purposes. Unauthorized deployment on systems you do not own is illegal.

---

## Architecture

```mermaid
graph TB
    subgraph Userland["Userland (Transient)"]
        LOADER["rk_loader"]
        MUTATOR["mutator.py"]
    end

    subgraph Kernel["Kernel Space (Resident)"]
        subgraph Core["rk_core"]
            INIT["Module Init"]
            SCHED["Scheduler"]
        end

        subgraph Comms["rk_beacon"]
            SOCK["Kernel TCP Socket"]
            FRAME["C2 Frame Builder"]
            JITTER["Jitter Engine"]
            KEYX["Key Exchange"]
        end

        subgraph Crypto["rk_crypto"]
            AES["AES-256-CBC"]
            RSA["RSA-2048"]
            PKCS["PKCS7 Padding"]
        end

        subgraph Stealth["rk_hide"]
            PROC["/proc Filter"]
            TCPF["tcp4_seq Hook"]
            VFSF["VFS File Filter"]
        end

        subgraph Evasion["rk_hv_evasion"]
            CPUID["CPUID Checks"]
            RDTSC["RDTSC Timing"]
            DMI["DMI/SMBIOS Scan"]
            MSR["MSR Analysis"]
        end

        subgraph Defense["rk_mem_guard"]
            PGD["Page Guarding"]
            NOTIF["Module Notifier"]
            WIPE["Self-Wipe Logic"]
        end

        subgraph Persist["rk_persist"]
            CRON["Cron Job"]
            SYSD["Systemd Unit"]
            LDPL["LD_PRELOAD"]
            MLOAD["modules-load.d"]
            RCLOC["rc.local"]
        end

        subgraph Polymorph["rk_polymorph"]
            XOR["XOR-Shift Cipher"]
            GEN["Generation Counter"]
            JIT["JIT Decrypt/Encrypt"]
        end
    end

    subgraph External["External"]
        C2["C2 Server<br>:443"]
        FORENSIC["Forensic Tools<br>LiME / Volatility"]
    end

    MUTATOR -->|"encrypted .ko"| LOADER
    LOADER -->|"memfd + init_module"| INIT
    INIT --> SCHED
    SCHED --> Comms
    Comms --> Crypto
    Comms --> SOCK
    SOCK -->|"encrypted channel"| C2
    SCHED --> Stealth
    SCHED --> Evasion
    SCHED --> Defense
    Defense -->|"detect"| FORENSIC
    Defense -->|"self-wipe"| WIPE
    INIT --> Persist
    INIT --> Polymorph
    Evasion -->|"paranoid mode"| JITTER
    Evasion -->|"skip disk IO"| Persist
```

---

## Component Breakdown

### Core Module

| File | Responsibility |
|------|---------------|
| `rk_core.c` | Module entry/exit, initialization orchestration, module list removal |
| `chimera.h` | Shared type definitions, constants, global state struct, function prototypes |

### Stealth Subsystem

| File | Responsibility |
|------|---------------|
| `rk_hide.c` | Process hiding via proc_ops replacement, TCP connection hiding via seq_ops hook, file path filtering |

Process hiding does **not** modify the syscall table. Instead it replaces function pointers inside the proc filesystem's internal `proc_ops` structures. EDR integrity monitors that watch `sys_call_table` for pointer modification see no changes.

```mermaid
sequenceDiagram
    participant Tool as /proc Reader
    participant Proc as procfs Layer
    participant Chimera as CHIMERA Hook
    participant Kernel as Real Kernel

    Tool->>Proc: readdir("/proc")
    Proc->>Chimera: iterate_shared()
    Chimera->>Chimera: is_hidden_pid(pid)?
    alt PID is hidden
        Chimera-->>Proc: skip entry (return 0)
    else PID is clean
        Chimera->>Kernel: original filldir()
        Kernel-->>Proc: directory entry
        Proc-->>Tool: entry returned
    end
```

### Cryptography

| File | Responsibility |
|------|---------------|
| `rk_crypto.c` | AES-256-CBC payload encryption via kernel crypto API, RSA-2048 session key exchange, PKCS7 padding, per-frame IV derivation |

Session keys are generated at connect time, encrypted with the server's RSA-2048 public key and transmitted once. All subsequent traffic uses AES-256-CBC with IVs derived by XORing the base IV with the frame sequence number. Keys exist only in kernel memory and are zeroed on teardown.

```mermaid
flowchart LR
    A["Generate Random<br>AES-256 Key"] --> B["RSA-2048 Encrypt<br>Session Key"]
    B --> C["Send to C2<br>(type 0xFF frame)"]
    C --> D["C2 Decrypts<br>with Private Key"]
    D --> E["All Further Frames<br>AES-256-CBC Encrypted"]
    E --> F["IV = base_iv XOR<br>seq_num[0:3]"]
```

### C2 Beacon

| File | Responsibility |
|------|---------------|
| `rk_beacon.c` | Kernel TCP socket management, beacon loop with jittered timing, heartbeat system info collection, task execution dispatcher, exponential backoff on failure |

### Hypervisor Evasion

| File | Responsibility |
|------|---------------|
| `rk_hv_evasion.c` | Six independent detection methods (CPUID leaf 0x1, CPUID hypervisor vendor, MSR VMX control, RDTSC timing variance, /proc/cpuinfo flag, DMI/SMBIOS strings) |

Detection requires confirmation from at least two methods to avoid false positives. When a hypervisor is confirmed the module enters paranoid mode: beacon intervals halve, disk-based persistence is skipped and all operations go memory-only.

```mermaid
graph TD
    subgraph Detection["Detection Methods"]
        M1["CPUID Leaf 0x1<br>ECX bit 31"]
        M2["CPUID 0x40000000<br>Vendor String"]
        M3["MSR 0x3A<br>VMX Control"]
        M4["RDTSC Timing<br>Variance Analysis"]
        M5["/proc/cpuinfo<br>'hypervisor' Flag"]
        M6["DMI/SMBIOS<br>Vendor Strings"]
    end

    M1 -->|pass/fail| AGG["Aggregator"]
    M2 -->|pass/fail| AGG
    M3 -->|pass/fail| AGG
    M4 -->|pass/fail| AGG
    M5 -->|pass/fail| AGG
    M6 -->|pass/fail| AGG

    AGG -->|>= 2 positives| PAR["Paranoid Mode"]
    AGG -->|< 2 positives| NOR["Normal Mode"]

    PAR --> P1["Halve beacon interval"]
    PAR --> P2["Skip disk persistence"]
    PAR --> P3["Memory-only operations"]
    PAR --> P4["Reduced footprint"]

    NOR --> N1["Full beacon interval"]
    NOR --> N2["All persistence vectors"]
    NOR --> N3["Standard operations"]
```

### Memory Protection

| File | Responsibility |
|------|---------------|
| `rk_mem_guard.c` | Module page reservation, kernel module load notifier for forensic tool detection, automatic self-wipe on forensic module detection |

The module registers a notifier on the kernel's module load chain. When a module with a name matching known forensic tools (LiME, Volatility memory dumpers, FTK, Rekall) loads, CHIMERA immediately zeroes all keys, restores original hooks and marks its own pages as reserved to prevent coherent memory reads.

### Polymorphic Engine

| File | Responsibility |
|------|---------------|
| `rk_polymorph.c` | Runtime XOR-shift cipher over the module's .text section, generation counter for unique mutations per deployment, JIT decrypt/encrypt wrappers for hooked functions |

The polymorphic engine operates at two levels:

1. **Build time**: `mutator.py` injects junk code, generates per-target encryption keys derived from hostname hashes and produces a unique encrypted artifact
2. **Runtime**: After module init, the .text section is XOR-shift encrypted in memory. Hooked functions decrypt their code region before execution and re-encrypt on return. The C2 server can push new keys to trigger re-polymorphism without reloading

### Persistence

| File | Responsibility |
|------|---------------|
| `rk_persist.c` | Five independent persistence vectors: cron job, systemd unit, LD_PRELOAD, modules-load.d, rc.local |

All writes go through kernel VFS. No userspace shell commands are spawned. Each vector is independent so removal of any single one does not kill the implant.

---

## Build Pipeline

```mermaid
flowchart TD
    SRC["Source Files<br>(C + Headers)"] --> GCC["gcc / Kernel Build System"]
    GCC --> KO["chimera.ko<br>(plaintext module)"]

    RSAKEY["Server RSA-2048<br>Public Key (DER)"] --> MUT["mutator.py"]
    KO --> MUT
    HOST["Target Hostname"] --> MUT

    MUT --> PATCH["Patch RSA pubkey<br>into rk_crypto.c"]
    PATCH --> JUNK["Inject junk code<br>(5% of binary size)"]
    JUNK --> ENC["AES-256-CBC encrypt<br>with hostname-derived key"]
    ENC --> ART["dist/.chimera_ko.enc<br>(per-target artifact)"]

    LDRSRC["loader/rk_loader.c"] --> LDRBUILD["gcc -static -O2 -s"]
    LDRBUILD --> STRIP["Strip all metadata<br>comments, symbols, build-id"]
    STRIP --> LDR["dist/.chimera_loader"]

    ART --> DEPLOY["Deploy to Target"]
    LDR --> DEPLOY
```

---

## Deployment Flow

```mermaid
sequenceDiagram
    participant Op as Operator
    participant Tgt as Target System
    participant K as Linux Kernel

    Op->>Tgt: Copy .chimera_ko.enc + .chimera_loader
    Op->>Tgt: Execute ./.chimera_loader

    Note over Tgt: Loader derives key from hostname
    Tgt->>Tgt: AES-256 decrypt .ko
    Tgt->>Tgt: XOR-shift polymorphic pass
    Tgt->>Tgt: Write to memfd (anonymous)
    Tgt->>Tgt: Zero plaintext from memory
    Tgt->>K: init_module(memfd)

    Note over K: Module loads into kernel space
    K->>K: Hide own PID from /proc
    K->>K: Run 6 hypervisor detection methods
    K->>K: Guard memory pages
    K->>K: Install proc + TCP hooks
    K->>K: Polymorph .text section
    K->>K: Remove self from module list
    K->>K: Start beacon thread
    K->>K: Install persistence vectors

    loop Every 30s ± 30% jitter
        K->>Op: TCP connect to C2:443
        K->>Op: RSA-encrypted session key (first time)
        K->>Op: AES-encrypted heartbeat
        Op->>K: Tasking (shell, exfil, update, wipe)
        K->>K: Execute task
        K->>Op: AES-encrypted response
    end
```

---

## C2 Protocol

All communication uses a custom framing protocol over raw TCP.

### Frame Structure

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 4 | `magic` | `0xCH1M3RA` in network byte order |
| 4 | 4 | `seq` | Monotonic sequence number |
| 8 | 2 | `type` | Task type identifier |
| 10 | 2 | `length` | Encrypted payload length |
| 12 | variable | `payload` | AES-256-CBC encrypted, PKCS7 padded |

The header is transmitted in plaintext for framing purposes. All sensitive data lives in the encrypted payload. The sequence number is incorporated into IV derivation so identical payloads produce different ciphertexts.

### Task Types

| Type | Hex | Direction | Description |
|------|-----|-----------|-------------|
| HEARTBEAT | `0x01` | Outbound | System fingerprint (hostname, uptime, PID, HV status) |
| SHELL | `0x02` | Inbound | Execute command via call_usermodehelper |
| EXFIL | `0x03` | Inbound | Read and exfiltrate file contents |
| PERSIST | `0x04` | Inbound | Reinstall all persistence vectors |
| UPDATE | `0x05` | Inbound | New polymorphic key + generation counter |
| WIPE | `0x06` | Inbound | Self-destruct: zero keys, unhook, unmap |
| KEY_EXCHANGE | `0xFF` | Outbound | RSA-encrypted AES session key (first frame) |

### Heartbeat TLV Format

```
[type:1][len:1][value:N] [type:1][len:1][value:N] ...
```

| Type ID | Content |
|---------|---------|
| `0x01` | Hostname (null-terminated string) |
| `0x02` | Uptime (4 bytes, little-endian seconds) |
| `0x03` | Module PID (4 bytes, little-endian) |
| `0x04` | Hypervisor detected (1 byte, 0 or 1) |

---

## Evasion Techniques

<details>
<summary><strong>Syscall Table Independence</strong></summary>

Most EDR products and kernel integrity modules monitor `sys_call_table` by hashing pointer values at load time and comparing periodically. CHIMERA never touches the syscall table. Process hiding replaces `proc_ops.iterate_shared` on the proc filesystem's internal structures. Network hiding replaces `seq_ops.show` on the tcp4 proc entry. Both modifications are invisible to syscall-table monitors.

</details>

<details>
<summary><strong>Module List Removal</strong></summary>

After initialization the module calls `list_del_init(&THIS_MODULE->list)` which unlinks the module struct from the kernel's loaded module list. Tools like `lsmod`, `cat /proc/modules` and `modinfo` enumerate this list and will not see CHIMERA. The module remains loaded and functional because the kernel holds its reference count.

</details>

<details>
<summary><strong>memfd Loading</strong></summary>

The userspace loader writes the decrypted module to an anonymous in-memory file descriptor created via `memfd_create()`. The kernel's `init_module()` syscall reads from this fd. The .ko plaintext never exists on disk. After loading the memfd is closed and all plaintext buffers are zeroed.

</details>

<details>
<summary><strong>Per-Target Binary Uniqueness</strong></summary>

Each build produces a cryptographically unique artifact. The deployment AES key is derived from a SHA-256 hash of the target hostname. Build-time junk code injection adds 5% random bytes. Runtime XOR-shift mutation ensures the in-memory .text section never matches the on-disk (encrypted) form or any other deployment's memory layout.

</details>

<details>
<summary><strong>Anti-Forensic Self-Wipe</strong></summary>

A notifier registered on the kernel's module load chain watches for forensic tool signatures. When detected the module zeroes all cryptographic keys, restores original hook pointers and marks its pages as reserved to block coherent physical memory access. This happens before the forensic module completes initialization.

</details>

---

## Build Instructions

### Prerequisites

| Requirement | Version |
|-------------|---------|
| Linux kernel headers | 5.x or 6.x (tested on 6.1) |
| GCC | 11+ |
| Python | 3.9+ |
| OpenSSL (for loader) | 3.0+ |
| cryptography (Python) | 41.0+ |

### Step 1: Generate RSA Keypair

```bash
mkdir -p keys
openssl genrsa -out keys/server_priv.pem 2048
openssl rsa -in keys/server_priv.pem -pubout -outform DER -out keys/server_pub.der
```

### Step 2: Build the Kernel Module

```bash
make all
```

### Step 3: Build Target Artifact

```bash
make mutate TARGET=webserver01 RSA_PUB=keys/server_pub.der
```

This produces two files in `dist/`:

| File | Purpose |
|------|---------|
| `.chimera_ko.enc` | AES-encrypted kernel module (unique to target) |
| `.chimera_loader` | Static userspace loader (stripped, no metadata) |

### Step 4: Deploy

```bash
scp dist/.chimera_ko.enc dist/.chimera_loader root@target:/tmp/
ssh root@target "cd /tmp && ./.chimera_loader"
```

### Clean Build

```bash
make clean
```

---

## Configuration Reference

All configuration lives in `include/chimera.h`.

| Constant | Default | Description |
|----------|---------|-------------|
| `C2_HOST` | `"192.168.1.100"` | C2 server IP address |
| `C2_PORT` | `443` | C2 server TCP port |
| `BEACON_BASE_MS` | `30000` | Base beacon interval in milliseconds |
| `BEACON_JITTER_PCT` | `0.30` | Random jitter as fraction of base (0.30 = 30%) |
| `AES_KEY_SIZE` | `32` | AES key length in bytes (256-bit) |
| `RSA_KEY_SIZE` | `256` | RSA key length in bytes (2048-bit) |
| `MAX_HIDDEN` | `256` | Maximum number of hidden PIDs |
| `RDTSC_SAMPLES` | `100` | Number of RDTSC timing samples |
| `RDTSC_THRESHOLD` | `500` | Cycle threshold for VM exit spike detection |

---

## Threat Model

### What CHIMERA Defends Against

| Defender | Technique CHIMERA Uses |
|----------|----------------------|
| Syscall table monitors | No syscall table modification |
| lsmod / modinfo | Module list unlinking |
| /proc scanning | proc_ops replacement |
| netstat / ss | tcp4 seq_ops hook |
| YARA memory scans | Runtime polymorphic .text encryption |
| Disk forensics | memfd loading, no plaintext on disk |
| LiME / Volatility | Module load notifier with automatic self-wipe |
| Timing-based beacon detection | Jittered sleep (30% randomization) |
| Hypervisor introspection | Six-method HV detection with paranoid mode |
| Integrity checkers | Page reservation, per-target unique binaries |

### What CHIMERA Does Not Defend Against

| Defender | Why |
|----------|-----|
| Kernel address space layout randomization (KASLR) bypass | Not implemented; assumes KASLR already bypassed at load time |
| eBPF-based monitoring | eBPF programs can observe socket creation and module loading events |
| Kernel runtime integrity (like kernel lockdown) | Kernel lockdown mode blocks unsigned module loading entirely |
| Hardware-based attestation (TPM, measured boot) | TPM PCRs would detect unsigned kernel modifications |
| Live response teams with custom kernel modules | A sufficiently novel forensic module would bypass the name-based notifier |

---

