# OdinSight — eBPF-Based Client-Side Anti-Cheat

OdinSight is an eBPF-based client-side anti-cheat prototype for Linux. It addresses the limitations of traditional runtime-only monitoring by establishing security policies before a game launches and maintaining them throughout the entire process lifecycle.

It is the final project for our Master’s in Computer Science at Aalborg University (Group CS-IT10). It’s the next iteration of the [TyrSecure project](https://github.com/eske4/TyrSecure). We took what we learned there and redesigned it into a much more specialized tool. The system leverages eBPF, LSM hooks, and CGroups to actively enforce security policies and validate kernel integrity throughout a game's lifecycle.

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

## Dependencies

To build and run OdinSight, your system must have the following dependencies installed. These versions were confirmed to work during development:

| Component | Dependency | Verified Version |
| :--- | :--- | :--- |
| **Compiler** | `Clang` | 22.1.8 |
| **Compiler** | `LLVM` | 22.1.8 |
| **Build System** | `GNU Make` | 4.4.1 |
| **Build System** | `CMake` | 4.4.0 |
| **Build Tools** | `pkg-config` | 2.5.1 |
| **Headers** | `linux-headers` | 7.1.3-arch1-2 |
| **Library** | `libbpf` | 1.7 |
| **Tooling** | `bpftool` | 7.7.0 |
| **Utility** | `git` | 2.55.0 |

## Installation & Usage

### Setup
```bash
make build
```

### Configuration
At your home folder (`~`), create a `.games` directory. Add the required games with the specific folder names (AssaultCube, SuperTuxKart, and optionally Unigine_Superposition if you want to perform benchmarks; they must follow the versions listed in the [Supported Games & Compatibility](#supported-games--compatibility) table). Other games should be installed via Steam with the specific version written in the [Supported Games & Compatibility](#supported-games--compatibility) table.

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
