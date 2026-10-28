# anchr

eBPF-based integrity monitoring system with container tracking, Merkle tree verification, TPM integration, and **policy-based configuration**.

## Overview

This system monitors file operations and container events using eBPF LSM and kprobe hooks. Measurements are organized per-container in a Merkle tree structure, with the root hash extended to a configurable TPM PCR (default: PCR 23) for hardware-backed attestation.

Policy-based configuration system allows fine-grained control over what gets measured, filtered, and how events are processed - configured via BPF maps and enforced at the kernel level.

## Directory Structure

```
anchr/
├── build/                 # Build output (auto-generated)
├── config/                # Policy configuration files
├── docs/                  # Architecture, policy management and kernel test docs
├── hooks/                 # eBPF hook implementations
│   └── lsm/               # LSM hooks
├── include/               # Header files
├── src/                   # Kernel module source (modular)
├── scripts/               # Test scripts
├── tests/                 # Validation tests
│   ├── kernel/            # Kernel module integration and unit tests
│   └── security/          # Bounded-input and security regression tests
├── tools/                 # Userspace management tool (anchr-tool)
├── utils/                 # Utility headers
├── verifier/              # Go verifier for measurement lists and attestation
│   ├── pkg/               # measurement, pcr, reader, securityfs, verifier packages
│   └── tests/             # Measurement list fixtures
├── Makefile               # Build system
└── go.mod                 # Go module of the verifier
```

## Components

### eBPF Hooks
- `lsm_bprm_check_security.c` - Process execution monitoring and container detection
- `lsm_file_post_open.c` - File access monitoring
- `lsm_inode_setattr.c` - File attribute change monitoring
- `lsm_mmap_file.c` - Memory-mapped file monitoring
- `lsm_socket_connect.c` - Network connection monitoring

All hooks are policy-enabled.

### Kernel Module
The module provides custom BPF kfuncs and manages:
- Container tracking with per-container measurement lists
- Merkle tree with SHA-256 hashing
- TPM PCR extensions (configurable index, default: 23)
- **Policy management and enforcement**
- SecurityFS interface at `/sys/kernel/security/anchr/`

### Verifier
Go library (`github.com/MonitOwl/anchr/verifier/pkg/...`) that replays the
measurement lists exposed in SecurityFS and attests them against the Merkle
leaf list and the TPM PCR value:
- `measurement` - measurement entries and lists
- `pcr` - software PCR used to replay extend sequences
- `reader` - line readers over files or in-memory lists
- `securityfs` - paths of the files exposed by the kernel module
- `verifier` - attestation of a measurement list against the leaf list and PCR

### Management Tool (anchr-tool)
Unified userspace tool that handles:
- Loading and attaching eBPF programs (LSM, kprobe, tracepoint, fentry/fexit)
- Policy initialization and management
- System status monitoring
- Daemon mode for background operation

## Build

Requirements:
- Linux kernel 6.13+ (the module imports the `BPF_INTERNAL` symbol namespace with the
  syntax introduced in 6.13; the hooks also rely on the `file_post_open` LSM hook (6.11)
  and the `bpf_get_task_exe_file` kfunc (6.12))
- Kernel configuration: `CONFIG_BPF_LSM=y` with `bpf` in the active LSM list (`lsm=` boot
  parameter), `CONFIG_IMA=y` for `bpf_ima_file_hash`, `CONFIG_DEBUG_INFO_BTF=y` and
  `CONFIG_DEBUG_INFO_BTF_MODULES=y`, `CONFIG_SECURITYFS=y`, and a TPM 2.0 for PCR extension
- clang, llvm, bpftool
- libbpf-devel, elfutils-libelf-devel, zlib-devel, libyaml-devel, openssl-devel
- kernel-devel, kernel-debuginfo (for BTF)

```bash
# Install dependencies (Fedora)
sudo dnf install kernel-devel libbpf-devel elfutils-libelf-devel zlib-devel libyaml-devel openssl-devel clang llvm bpftool
sudo dnf debuginfo-install kernel

# Build
make all
```

Output: `build/anchr.ko`, `build/anchr-tool`, `build/*.o`

### Verifier

```bash
go test ./verifier/...
```


## Usage

### Testing

```bash
# Script helper
./scripts/test.sh --help

# Verbose mode
sudo ./scripts/test.sh -v

# Test specific hook
sudo ./scripts/test.sh lsm_bprm_check_security -v
```

Run the bounded-input tests with AddressSanitizer and UndefinedBehaviorSanitizer:

```bash
make test-security CC=clang
```

For the kernel module integration suite, build the test fixtures and run on an
isolated host with BPF LSM and module BTF:

```bash
make modules kernel-tests
./scripts/test_kernel.sh --check --load-module
sudo ./scripts/test_kernel.sh --load-module

# Also exercise concurrent creation, measurements, and deduplication
sudo ./scripts/test_kernel.sh --load-module --stress
```

The suite checks kfunc contracts, measurements and hashes, namespace policy,
SecurityFS, TPM reads/extensions, all five hooks' denial propagation, retained
BPF pins and their cleanup, and kernel diagnostics. It unloads the module only
if it loaded it. Tests can extend TPM PCRs;
use a disposable test system. See [Kernel integration tests](docs/KERNEL_TESTS.md)
for requirements, coverage, cleanup behavior, and report locations.

### Kfunc interface

Every kfunc memory argument has an adjacent size argument checked by the BPF
verifier. String inputs must be NUL-terminated within the supplied extent. The
measurement API accepts a pointer-free `struct anchr_measurement_request` and
`sizeof(request)`. Its event name is required, an empty namespace selects
`default`, payloads are limited to 255 bytes, and dependency strings require
`ANCHR_MEASUREMENT_HAS_DEPENDENCIES`. Invalid inputs return `-EINVAL`; filter
functions return `false` for invalid inputs.

The shared request and policy layouts are declared in
`include/anchr_kfunc_types.h`. The module, BPF programs, and userspace tool
share these layouts, so build them together from the same revision; when
upgrading, reload the hooks and recreate their pinned maps.

### Manual

```bash
# 1. Load kernel module
sudo insmod build/anchr.ko

# Optional: Configure TPM PCR index (default: 23)
# sudo insmod build/anchr.ko tpm_pcr_index=10

# 2. Load eBPF program (daemon mode)
sudo ./build/anchr-tool load build/lsm_bprm_check_security.o -d

# 3. Initialize policy maps (REQUIRED!)
sudo ./build/anchr-tool policy-init

# 4. Check status
sudo ./build/anchr-tool status

# 5. View status and the namespace's measurements
sudo cat /sys/kernel/security/anchr/status
sudo cat /sys/kernel/security/anchr/namespaces/<namespace-id>/measurements

# Cleanup
sudo ./build/anchr-tool unload
sudo rmmod anchr
```

## Module Parameters

The anchr kernel module supports the following runtime parameters:

### TPM PCR Index

Configure which TPM PCR (Platform Configuration Register) to use for measurements:

```bash
# Load with custom PCR index
sudo insmod build/anchr.ko tpm_pcr_index=10

# View current PCR index
cat /sys/module/anchr/parameters/tpm_pcr_index

# Change at runtime (if module was loaded with writable permissions)
echo 15 | sudo tee /sys/module/anchr/parameters/tpm_pcr_index
```

**Default:** PCR 23 (commonly used for custom measurements)
**Valid range:** 0-23 (most TPMs)
**Note:** PCR 0-15 are typically reserved for BIOS/bootloader. PCR 16-23 are available for OS and application use.

## SecurityFS Interface
```
/sys/kernel/security/anchr/
├── merkle_root_history      # Current Merkle tree root hash
├── status                   # Module status and configuration
├── policy                   # Global policy
├── policy_apply             # Policy transaction endpoint
├── policy_changes           # Global policy change history
├── policy_map               # Policy-map binding endpoint
└── namespaces/
    └── <cgroup-derived-namespace>/
        ├── measurements     # This namespace's measurement list
        ├── policy           # Namespace policy extension, when created
        └── policy_changes   # Namespace policy audit history, when created
```

Read example:
```bash
cat /sys/kernel/security/anchr/merkle_root_history
cat /sys/kernel/security/anchr/status
cat /sys/kernel/security/anchr/namespaces/<cgroup-derived-namespace>/measurements
```

## Policy Configuration

anchr uses a policy system to control what gets measured and how:

### Architecture

- **BPF Maps**: Store policy configuration in pinned BPF maps at `/sys/fs/bpf/`
- **Kernel Enforcement**: Policies enforced in eBPF hooks (secure, fast, kernel-level)
- **Userspace Management**: `anchr-tool` manages policies (init defaults or load from YAML)
- **YAML Configuration**: Policies can be defined in `config/*.yaml` files

### Default Policy

**What Gets Measured:**
- Executable binaries
- Scripts and interpreted code
- Container workloads (Docker, Podman)
- User processes (user.slice)
- System services (system.slice)
- Files in /dev/, /tmp/
- Shared libraries (.so)
- **Everything except the minimal filters below**

**What Gets Filtered (minimal - only truly noisy system internals):**
- Root cgroup `/` (exact match only)
- init.scope processes

**Optional Filters (disabled by default, can be enabled via policy):**
- Files in /proc/ (enable with POLICY_FILTER_PROC_SYS)
- Files in /sys/ (enable with POLICY_FILTER_PROC_SYS)
- System cgroups (enable with POLICY_FILTER_SYSTEM_CGROUPS)
- /dev/ files (enable with POLICY_FILTER_DEV)
- Small files (enable with POLICY_FILTER_SMALL_FILES)
- Libraries (enable with POLICY_FILTER_LIBRARIES)
- /tmp/ files (enable with POLICY_FILTER_TMP_FILES)

**Actions Enabled:**
- TPM PCR 23 extension
- SecurityFS logging
- Kernel log output
- Per-container tracking
- Dependency chain building

### Policy Configuration Options

The policy system supports:

1. **Filter Flags** - Control what to skip/ignore:
   ```c
   POLICY_FILTER_SYSTEM_CGROUPS   // Skip /, init.scope (already minimal by default)
   POLICY_FILTER_PROC_SYS         // Skip /proc/, /sys/ (disabled by default)
   POLICY_FILTER_DEV              // Skip /dev/ (disabled by default)
   POLICY_FILTER_READONLY_FILES   // Skip readonly opens (disabled by default)
   POLICY_FILTER_SMALL_FILES      // Skip files below min size (disabled by default)
   POLICY_FILTER_NON_EXECUTABLE   // Skip non-executable files (disabled by default)
   POLICY_FILTER_LIBRARIES        // Skip .so files (disabled by default)
   POLICY_FILTER_TMP_FILES        // Skip /tmp/ files (disabled by default)
   ```

   **Default: ALL filters disabled (0x0) - tracks everything except / and init.scope**

2. **Action Flags** - Control what actions to take:
   ```c
   POLICY_ACTION_EXTEND_TPM       // Extend measurements to TPM
   POLICY_ACTION_LOG_SECURITYFS   // Log to securityfs
   POLICY_ACTION_LOG_KERNEL       // Log to kernel (printk)
   POLICY_ACTION_ALERT_SUSPICIOUS // Alert on suspicious activity
   POLICY_ACTION_BLOCK            // Block operations (future)
   POLICY_ACTION_TRACK_CONTAINER  // Track per-container
   POLICY_ACTION_BUILD_DEPS       // Build dependency chains
   ```

3. **Pattern Matching** - Ignore specific cgroups or paths:
   - Cgroup patterns: Exact match on cgroup names
   - Path patterns: Prefix match on file paths

4. **Per-Hook Configuration**:
   - Enable/disable individual hooks
   - Track containers per-hook
   - Enable/disable hash calculation

5. **Runtime Settings**:
   - Log level (0=none, 1=errors, 2=info, 3=debug)
   - Minimum file size threshold
   - Maximum path depth

### Customizing Policy

There are three ways to customize the policy:

#### 1. Use YAML Configuration Files (Recommended)

Edit `config/policy.yaml` or `config/policy-minimal.yaml`:

```yaml
policy:
  enabled: true
  log_level: 2
  measure_enabled: true
  appraise_enabled: false
  enforce_enabled: false
  container_tracking: true

filters:
  cgroup_patterns:
    - "/system.slice/"
    - "/docker/"
  path_patterns:
    - "/usr/bin/"
    - "/usr/sbin/"

hooks:
  - name: "lsm_bprm_check_security"
    enabled: true
    measure: true
```

Load the policy:
```bash
sudo ./build/anchr-tool policy-update config/policy.yaml
```

#### 2. Use SecurityFS Interface (Runtime)

Update policy through the securityfs interface:

```bash
# View current policy
cat /sys/kernel/security/anchr/policy

# Update individual settings
echo "log_level=3" | sudo tee /sys/kernel/security/anchr/policy
echo "filter_flags=0x7" | sudo tee /sys/kernel/security/anchr/policy
echo "action_flags=0x1F" | sudo tee /sys/kernel/security/anchr/policy
echo "min_file_size=4096" | sudo tee /sys/kernel/security/anchr/policy
```

#### 3. Use bpftool (Advanced)

Directly update BPF maps at runtime (advanced users):

```bash
# View current policy
sudo bpftool map dump pinned /sys/fs/bpf/anchr_policy_map

# Update with bpftool (requires knowledge of struct layout)
sudo bpftool map update pinned /sys/fs/bpf/anchr_policy_map \
    key 0 0 0 0 value 1 6 0 0 ...
```

### Verifying Policy

Check current policy status:

```bash
# View policy configuration
sudo bpftool map dump pinned /sys/fs/bpf/anchr_policy_map

# Check which hooks are enabled
sudo bpftool map dump pinned /sys/fs/bpf/anchr_hook_config_map

# View measurements (verify things are being recorded)
sudo cat /sys/kernel/security/anchr/status

# Check kernel logs for policy messages
sudo dmesg | grep -i anchr | grep -i policy
```

## Architecture

The system uses 6 communication channels between eBPF and kernel:

1. Kfunc: `bpf_container_create_or_get()` - Container registration
2. Kfunc: `bpf_container_add_measurement()` - Add measurement entry
3. Kfunc: `bpf_get_merkle_root()` - Read current root hash
4. BPF Map: Statistics counters
5. BPF Map: Active container LRU cache
6. Ring Buffer: Asynchronous event notifications

Merkle tree structure:
```
        Root Hash (PCR 23)
        /      |      \
   Leaf1    Leaf2    Leaf3
     /         |         \
[Container1][Container2][Container3]
```

Each leaf hash is computed from a container's measurement list. Root hash updates extend TPM PCR 23.

## Measurement Flow

When an event is detected by an eBPF hook:

1. **Get namespace** - Extract container ID from task's cgroup namespace
2. **Measure** - Compute hash of the event data (file path, process, etc.)
3. **Record in list** - Add measurement entry to container's measurement list
4. **Extend leaf** - Recompute container's leaf hash from updated measurement list
5. **Add to history** - Store measurement in global history list
6. **Extend root** - Recompute Merkle root hash from all leaf hashes
7. **Extend PCR** - Extend TPM PCR 23 with new root hash

This ensures each measurement is both container-specific and contributes to the global integrity state backed by hardware.

## Troubleshooting

**Missing BTF**: Install kernel-debuginfo and create vmlinux symlink
```bash
sudo dnf debuginfo-install kernel
sudo ln -sf $(find /usr/lib/debug -name vmlinux -type f | head -1) /lib/modules/$(uname -r)/build/vmlinux
```

**Module load fails**: Check dmesg for errors
```bash
sudo dmesg | tail -20
```

**No trace output**: Verify program attachment
```bash
sudo bpftool prog list
sudo cat /sys/kernel/debug/tracing/trace
```

# Acknowledgments

anchr originated from research carried out within TORSEC, the cybersecurity research group of Politecnico di Torino, by current and former members of the group who remain its authors.

# License

This project is open-source software distributed under the terms of the GNU General Public License version 2 (GPLv2). See [LICENSE](LICENSE) for the full text.
