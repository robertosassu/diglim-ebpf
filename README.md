# DIGLIM eBPF

## Introduction

Digest Lists Integrity Module (DIGLIM) is a pluggable Linux Security Module
(LSM) implemented as an eBPF program, primarily aiming at providing a basic
integrity appraisal functionality as a standalone component, without
requiring any change to the Linux kernel nor to Linux distributions. Thanks
to the eBPF portability feature, DIGLIM can be already used today on
currently available Linux distributions.

DIGLIM eBPF takes a set of reference values for file digests (called digest
lists) from the rpm package manager or from files generated by the user,
calculates the file digest when the file is going to be executed, and
allow/deny access if the digest is not found among the loaded reference
values. DIGLIM eBPF is currently not policy-based, it focuses only on
execution. More flexibility can be added in the future.

Although for file appraisal DIGLIM eBPF offers a functionality equivalent
to the kernel implementation, unfortunately it does not yet match the
security offered by the kernel-based implementation. Some of the reasons
are the pluggable nature of eBPF-based LSMs and the lack of support for PGP
keys and signatures. Arbitrary digest lists are accepted by DIGLIM eBPF and
the protection can be turned off by root, if he wishes.

Overall, DIGLIM eBPF offers a good preview of how the finished solution
will look like, letting people to evaluate the functionality to see if it
fulfills their requirements. In the meantime, development will continue to
fill the security gap.



## Architecture


                     6. lookup digest                     5. add/del digest
    +-------------+
    | DIGLIM eBPF |<---------( hash map )----------------------------
    |    (LSM)    |--------->( ring buffer )-----                   |
    +-------------+ push log                    |                   |
                                                |                   |
    kernel space                                |                   |
    ------------------------------------------------------------------------
    user space                                  |                   |
                                                |                   |
                                       pull log |                   |
                                                v                   |
               2. add/del digest list   +-------------+      +-------------+
      +-----+                           | DIGLIM eBPF |      | DIGLIM eBPF |
      | rpm |<-------( UNIX socket )--->|   (server)  |----->|  (parsers)  |
      +-----+    |                      +-------------+      +-------------+
         |       |                              ^
    +--------+   |                              |       4. parse digest list
    | client |<---                              |
    | (shell)|                                  |
    +--------+                                  |
         |                                      |
         ------------->(digest lists)------------

    1. write digest list            3. read digest list



The architecture depicted above shows the DIGLIM eBPF components, and how
they are split between user space and kernel space.

The DIGLIM eBPF server is responsible to load and attach the pluggable LSM
to the kernel. The pluggable LSM implements the following LSM hooks:

1. bprm_creds_for_exec: invoked when a file is being executed;
2. mmap_file: invoked when a file is being mmapped;
3. file_mprotect: invoked when the protection of a memory area is changed;
4. file_open: invoked when a file is opened;
5. kernel_read_file: invoked when a kernel reads a file.

When one of the hooks above (except file_open) is invoked, the eBPF
program invokes IMA to calculate the digest of the file being accessed. It
then performs a lookup in a hash map, to see if it finds the calculated file
digest among the reference values. If the file digest is found, access is
granted, otherwise it is denied.

A caching mechanism is used to unnecessarily recalculate the file digest
(e.g. when a file is only read multiple times). The cached result is
invalidated by the implemented file_open hook, if the file is opened for
writing.

On the user space side the server, as mentioned above, is responsible to
attach the eBPF program and to pin the hooks to the bpffs filesystem to
prevent the unplugging of the LSM. The server is run two times: the first
time as the init process, so that the reference values are loaded to the
eBPF program before other files are executed, and to load digest lists
that are not in the initial ram disk; the second time just listens to
connections by the rpm package manager, to update the hash map every time
a package is installed or removed, or by a client tool.

DIGLIM eBPF supports arbitrary digest list formats thanks to its modular
design: a dedicated library is used to parse the digest list and to add/del
the extracted digests to/from the hash map. Currently, two digest list
parsers are supported:

1. compact: the original digest list format defined together with the
kernel implementation;
2. rpm: the header of an RPM package with the signature appended.

DIGLIM eBPF has also a logging functionality, useful to detect and find the
reason why a permission was denied. It is implemented with a ring buffer,
that is written by the eBPF program, and read by the user space server.
Logs are then stored in system log.



## Configuration

### Automatic Setup

DIGLIM eBPF provides the script ``diglim_setup.sh`` to automatically
install and uninstall the configuration. See the manual for more details.


### Digest List Generation

Digest lists can be generated with the command line tools included in
DIGLIM eBPF. New digest list generators and parsers can be added at a later
time.

Examples:

1. Generate the digest lists for all packages from the RPM database:
```
# rpm_gen -d /etc/digest_lists
```

2. Generate a digest list for the kernel modules (for custom kernels):
```
# compact_gen -d /etc/digest_lists -i /lib/modules/`uname -r`
```

### Digest Lists Uploading at Run-time

Currently, DIGLIM eBPF allows unrestricted uploading of new digest lists.
The tool ``diglim_user_client`` can be used for this purpose. For example,
assuming that a digest list is generated for the script ``script.sh``:

```
# compact_gen -d /etc/digest_lists -i script.sh
```

It is possible to upload them to the eBPF program with the command:
```
# diglim_user_client -o add -p /etc/digest_lists/0-file_list-compact-script.sh
```


### Initial Ram Disk Generation

If DIGLIM eBPF is executed as the init process, DIGLIM eBPF itself and the
generated digest lists need to be copied to the initial ram disk. This task
can be accomplished by the diglim dracut module, which can be dynamically
selected at dracut run-time with the option ``-a diglim``, or statically,
by adding the line:

```
add_dracutmodules+=" diglim "
```

to a dracut configuration file.


### Kernel Command Line

To execute DIGLIM eBPF as the init process, the path of the new init must
specified in the kernel command line with:

```
rdinit=/sbin/diglim_user
```


### Systemd Service

A DIGLIM eBPF service can be automatically executed at boot time, so that
it can listen to connections by the rpm package manager and to the command
line tool. This can be achieved with the command:

```
# systemctl enable diglim_user.service
```


### rpm Plugin

DIGLIM eBPF includes also an rpm plugin to generate an rpm digest list with
an appended signature and to notify to the user space server the
availability of the new digest list (or to ask the removal of digests when
a package is removed). The plugin (not enabled by default) can be enabled
by adding the following line to the system-wide rpm macros file:

```
%__transaction_diglim           %{__plugindir}/diglim.so
```


### Troubleshooting

If an application is not executed correctly, or it terminates, it is
possible to do troubleshooting by looking in the system logs the lines with
``diglim_user``. They will contain the likely cause of the problem.

DIGLIM eBPF can be also turned off with the following command:

```
# systemctl stop diglim_user
```

If the problem happens at boot time, it is possible to run DIGLIM eBPF in
permissive mode by appending to the kernel command line:

```
-- -p
```
