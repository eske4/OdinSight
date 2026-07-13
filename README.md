# OdinSight — eBPF-Based Client-Side Anti-Cheat

OdinSight is an eBPF-based client-side anti-cheat prototype for Linux. It addresses the limitations of traditional runtime-only monitoring by establishing security policies before a game launches and maintaining them throughout the entire process lifecycle.

Developed as a 10th-semester Computer Science project at Aalborg University (Group CS-IT10), OdinSight leverages eBPF, LSM hooks, and CGroups to provide active policy enforcement and kernel integrity validation. It is a continuation of the TyrSecure project.

## Architecture

OdinSight utilizes a dual-component design to ensure protection:

* **Daemon**: A privileged system service responsible for validating kernel integrity, managing eBPF programs, and coordinating protected game execution.
* **Launcher**: An unprivileged interface used to request that the daemon spawn a protected game process.

## System Requirements & Integrity

OdinSight requires a secure host environment to function correctly. The daemon performs a Kernel Integrity Validation to ensure the following are enabled:

* Secure Boot
* Kernel Lockdown
* Kernel Module Signature Enforcement

> Note: If these integrity mechanisms are disabled, OdinSight will refuse to initialize, as the kernel environment cannot be considered sufficiently trusted.

## Supported Games & Compatibility

| Game | Version | Status |
| :--- | :--- | :--- |
| AssaultCube | 1.2.0.2 | ✅ Works |
| SuperTuxKart | 1.5 | ✅ Works |
| A Story About My Uncle | BUILD V. 5188 | ✅ Works |
| Baldur's Gate 3 | 4.1.1.7209685 | ⚠️ Partially Works |
| Valheim | 1.0.221.12 | ❌ Doesn't Work |
| Unturned | 3.26.3.2 | ❌ Doesn't Work |
| Unigine Superposition | 1.1 | 🧪 Testing |

## Installation & Usage

### Setup
```bash
make build
```

### Configuration
At your home folder (`~`), create a `.games` directory. Add the required games (such as those listed in the [Supported Games & Compatibility](#supported-games--compatibility) table). Other games should be installed via Steam with the specific version written in the [Supported Games & Compatibility](#supported-games--compatibility) table.

### Running the Anti-Cheat

1. **Start the Daemon**:
   ```bash
   sudo ./OdinSight_daemon
   ```
2. **Request Launch**:
   ```bash
   sudo ./OdinSight_launcher
   ```

## Features

OdinSight actively restricts several attack methods, including:

* **Debugger Attachment**: Blocks ptrace attempts by tools like GDB or Scanmem.
* **Memory Tampering**: Denies suspicious mmap and mprotect calls (e.g., writable-executable memory mappings).
* **Library Injection**: Blocks LD_PRELOAD injections at process execution time.
* **Process Inspection**: Restricts access to sensitive procfs entries and prevents namespace/mount manipulation.
* **Capability Misuse**: Limits privileged capabilities (e.g., CAP_SYS_ADMIN) within the protected game cgroup.

## Limitations

* **Experimental Prototype**: OdinSight is a research project and does not offer complete protection against all possible cheat strategies (e.g., input automation or network-level manipulation).
* **Compatibility**: Strict security policies may cause conflicts with certain game engines (e.g., Unity titles relying on writable-executable memory).
* **Trusted Foundation**: The system relies on the integrity of the host kernel; it is designed to be a client-side foundation and would require a server-side component for comprehensive session validation.
