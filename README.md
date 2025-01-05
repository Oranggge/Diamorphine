# Diamorphine Rootkit

Diamorphine is a simple LKM (Loadable Kernel Module) rootkit for Linux. It provides features for hiding processes, files, and sockets, as well as capabilities for privilege escalation. This fork includes additional modifications for research purposes, particularly in evading detection by Intrusion Detection Systems (IDS) such as Wazuh.

## Features

- Hide processes based on a given PID.
- Hide files and directories.
- Hide sockets.
- Bypass certain detection mechanisms of common IDS tools.
- Added support for syscall overrides for `getsid` and `getpgid` syscalls, designed to evade detection under specific configurations.

## Changes in This Fork

This fork was created by me, the following modifications were made:

### New Syscalls Overridden

- **`getsid` (System Call #124)**: Modified to include an evasion mechanism where invisible processes return an error code `-ESRCH` to mimic the behavior of non-existent processes.
- **`getpgid` (System Call #121)**: Similarly modified to return `-ESRCH` for invisible processes.

### Debugging Enhancements

- Added extensive `printk` logging to track calls to the overridden syscalls and the invisibility checks for processes.
- Logs include PID values and invisibility status for enhanced transparency and debugging during research.

### Code Structure Adjustments

- Updated syscall table interactions to include the newly overridden syscalls.
- Adjusted the initialization and cleanup routines to handle the additional syscalls without impacting other functionalities.

## Purpose of Changes

These updates aim to:

1. Investigate how these modifications affect the detection rates of the rootkit by IDS tools such as Wazuh.
2. Explore potential gaps in IDS configurations that allow evasion.
3. Provide a basis for improving IDS detection rules to counteract these evasion techniques.

## Usage

### Compilation

Ensure you have the Linux kernel headers installed for your target kernel. Then compile the rootkit using `make`:

```bash
make
```

### Loading the Rootkit

Use `insmod` to load the module into the kernel:

```bash
sudo insmod diamorphine.ko
```

### Unloading the Rootkit

Use `rmmod` to unload the module from the kernel:

```bash
sudo rmmod diamorphine
```

### Debugging

Logs are available in the kernel ring buffer. Use the following command to view them:

```bash
dmesg | grep ROOTKITS
```

## Disclaimer

This code is for educational and research purposes only. Using this rootkit on systems you do not own or without explicit authorization is illegal and unethical. Always ensure compliance with applicable laws and guidelines.

## Acknowledgments

This project is based on the original Diamorphine rootkit. Additional modifications were implemented as part of a bachelor thesis research project focusing on rootkit detection and evasion.
