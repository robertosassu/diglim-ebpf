# DIGLIM eBPF

## Introduction

Digest Lists Integrity Module (DIGLIM) is a pluggable security module
implemented as a set of eBPF programs, primarily aiming at providing a
basic integrity appraisal functionality as a standalone component. It does
so by building a pool of reference file digests from authenticated sources
(called digest lists), by querying the file digest calculated by IMA at the
time the file is being executed or read by the kernel, and by denying
access if the file digest is not found in the pool.

DIGLIM eBPF is based on the concept that the data necessary to make
security decisions does not necessarily need to be in the format expected
by the components making such decisions. Security components that don't
rely on this concept are prone to huge delays from the time the security
mechanism is implemented to when the data needed for the security decisions
are available.

One example is Integrity Measurement Architecture (IMA), which from the
beginning was developed around the concept of file signatures. However,
since Linux distributions don't provide this information in the desired
format (although they provide the same guarantee in a different way, not
supported by IMA), the appraisal functionality was long confined to ad-hoc
use cases, and didn't gain enough traction from the general user base.

While certainly this gap can be filled (and it likely will be, as a feature
was approved for Fedora 37 to include file signatures in the RPM headers),
this approach does not scale. Each software source needs to be modified to
accommodate the information in the format recognized by IMA. In addition,
the solution works for a single use case, i.e. verifying file content.
Verifying file metadata is not supported and would require adding another
signature to the RPM header.

DIGLIM eBPF works in a different way. Building a pool of reference digests
makes it possible being independent from a particular data format, and
being able to support existing ones, as long as a parser for the desired
data format is implemented. The pool can be then used by DIGLIM eBPF itself
or any other component (including IMA) to make security decisions.

Parsing already defined data formats does not necessarily increase the
complexity of the solution as whole, or diminish the security guarantees
that can be derived from it. The most complex parser included in DIGLIM
eBPF is the RPM header parser, which is less than 500 lines of code. In
addition, the safety (e.g. in terms of memory accesses) of each parser is
verified at run-time by the eBPF verifier. If a parser is unsafe, eBPF
refuses to load it.

Thanks to the new approach, DIGLIM eBPF is able to provide in a short time
appraisal functionality to virtually any Linux distribution without mass
rebuilding all packages. The only tasks Linux distribution vendors need to
do are to ensure that the keys they used to sign their package headers are
loaded in the kernel, and that the kernel is able to execute DIGLIM eBPF
code, when code is verified during the early stage of the boot process.

While the previous version of DIGLIM (fully in the kernel) provided good
numbers in terms of performance and memory occupation, currently eBPF is
slightly behind. To make sleepable security hooks work with eBPF, the
memory of the map where digests are stored need to be preallocated, causing
the occupation of more memory than necessary. This is just a technical
limitation, that can be solved in future by eBPF developers.

On the other hand, DIGLIM eBPF offers strong security guarantees. Assuming
that the kernel protects the environment before DIGLIM eBPF is loaded, once
activated DIGLIM eBPF ensures that only code coming from authenticated data
sources can be executed. This might allow to execute code exclusively
coming from the Linux distribution (leaving out malicious/unknown code), or
additional code which the user might have approved.

To summarize, DIGLIM eBPF makes it possible to make security decisions
depending on arbitrary sources of information, without being tied to a
particular data format. And, it also makes it possible to build upon it new
security components tailored to a specific use case, without the necessity
of modifying the kernel.


## Security Goals and Assumptions

DIGLIM eBPF aims at enforcing a Mandatory Access Control (MAC) integrity
policy on the code executed in the system, being it the main binary, or a
shared library, or generally code mapped in memory with execution
permission. In addition, the integrity of all files read by the kernel
(e.g. kernel modules and firmware) is evaluated.

Being a MAC policy, it is enforced system-wide, even against the willing of
the root user, which cannot turn off the enforcement at own discretion.
DIGLIM eBPF might allow this operation, upon evaluation of the system-wide
policy.

The decision of whether execution of code or reading of a file from the
kernel is granted is based on a query of the file digest calculated by IMA
to the pool of file digests populated by the digest list parsers.

The pool of digests can only be built from authenticated digest lists, i.e.
data with an appended digital signature that can be verified with a kernel
key in the primary or secondary keyring.

This is the set of components of the Trusted Computing Base (TCB) for
DIGLIM eBPF:

1. *kernel*: it is responsible to allow only execution of the same code
   DIGLIM eBPF would approve, and DIGLIM eBPF itself;

2. *eBPF subsystem*: must prevent interference with other eBPF programs
   and must prevent interruption of the DIGLIM eBPF services;

3. *kernel key retention/crypto services*: the first holds the public keys
   to be used to verify the digital signatures of the digest lists
   processed by DIGLIM eBPF; the second rejects non-approved data sources;

4. *DIGLIM eBPF*: protects its own assets from tampering by other
   components (this includes for example the eBPF map used to store file
   digests); processes the digest lists; makes the decision of granting
   execution or read of a file by the kernel based on the processed digest
   lists.

Any other component or actor in the system is considered untrusted. It is
assumed that it could misbehave or try to subvert the system-wide policy.

This include for example the component passing the digest lists from the
system storage to DIGLIM eBPF. If this component is malicious, tampering of
data will be detected by the *kernel key retention/crypto services*. User
space components shall not have the right to modify the data once they have
been passed to DIGLIM eBPF.


## Components

DIGLIM eBPF consists of the following components:


### Security Module

The security module is the component responsible to enforce the integrity
policy. It implements the following security hooks:

1. *bprm_creds_for_exec*: invoked when a file is being executed;

2. *mmap_file*: invoked when a file is being mmapped;

3. *file_mprotect*: invoked when the protection of a memory area is
    changed;

4. *file_open*: invoked when a file is opened;

5. *kernel_read_file*: invoked when a kernel reads a file;

6. *bpf*: invoked when there is an eBPF operation.


### Maps

DIGLIM eBPF introduced the following maps:

1. *digest_items*: hash map storing the file digests and their algorithm;

2. *data_input*: array map with one element used by user space to send a
   digest list to digest list parsers;

3. *inode_storage_map*: inode storage map used to cache the verification
   result for each inode; it also stores information about a digest from
   the digest list;

4. *dirnames_map*: internal map used by the RPM header parser to store a
   list of directories for which the digest should be taken regardless of
   whether the file has executable permission (otherwise it would be ignored)

5. *ringbuf*: ring buffer used to pass logs produced by the security module
   to user space.

With the exception of *data_input* and *ringbuf*, the other maps cannot be
modified by user space processes.


### Digest List Parsers

DIGLIM eBPF support an unbounded number of parsers. Currently, since the
address of the *digest_items* and *data_input* maps need to be known in
advance by each parser, all parsers and the security module are linked
together in the same object.

Currently, the following parsers are supported:

1. *compact parser*: parser of the original format defined by DIGLIM to
   efficiently store a large number of digests;

2. *rpm parser*: parser of the RPM header extracted from the
   RPMTAG_IMMUTABLE section;

3. *map parser*: parser of the raw value (digest algorithm + digest) to be
   added as it is to the *digest_items* map;

Each digest list parser attaches to the bpf() system call and looks for
updates of the first and only array element in the *data_input* map.


### User Space Run-time Components

As mentioned above, all the user space components are considered as
untrusted. These are:

1. *diglim_user_loader*: iterates over the digest lists stored in the
   /etc/digest_lists directory and pushes them to the *data_input* map;

2. *diglim_log*: waits for logs written by the security module to *ringbuf*
   and forwards them to the system log;

3. *diglim rpm plugin*: extracts the RPM header from packages being
   installed, and executes *diglim_user_loader* to request digests addition
   or deletion every time a package is installed or removed.


### Digest List Generators

Digest lists to be processed by the parsers can be generated with the
following tools:

1. *compact_gen*: generates digest lists in the compact format;

2. *rpm_gen*: extracts RPM headers and the associated signature from the RPM
   database (or from an individual package), and write them in a file ready
   to be verified by the kernel;

3. *map_gen*: writes the digest algorithm and digest to a file.

While *rpm_gen* produces a digest list with a module-style appended
signature, ready to be verified by the kernel, the others don't. An
external tool, such as *sign_file* from the Linux kernel, must be executed
to append a module-style signature.


## Architecture

The architecture depicted below shows the DIGLIM eBPF components, and how
they are split between user space and kernel space.

                                                 3. verify digest lists sig

              4. parse digest lists and push digests     (kernel keys)
                                       +--------------+        |
                                     +-| compact      |<-+     |
     5. lookup digests               | | parser eBPF  |  |     |
     ------------                    | +--------------+  |     |
     |          v                    |                   |     |
     |   +-------------+             | +--------------+  | +---------+
     |   | security    |<-(digest_)<-+-| rpm          |<-+-| kernel  |
     ----| module eBPF |  items map  | | parser eBPF  |  | | sig ver |
         +-------------+             | +--------------+  | +---------+
                |                    |                   |     ^
                | 6. write log       | +--------------+  |     |
            (ringbuf)                +-| map          |<-+     |
                |                      | parser eBPF  |        |
                |                      +--------------+ (data_input map)
    end-user system (kernel space)                             |
    -----------------------------------------------------------------------
    end-user system (user space)                               |
                |                                              |
                v                         2. push digest lists |
         +------------+                              +--------------------+
         | diglim_log |                              | diglim_user_loader |
         +------------+                              +--------------------+
                | 7. forward log                         ^         ^
                v                                        |         |
         +------------+                            +-------+ +------------+
         |   syslog   |                            | shell | | rpm plugin |
         +------------+                            +-------+ +------------+
                                                         ^         ^
                                                         |         |
    -----------------------------------------------------------------------
    vendor premises (different system, trusted by design)|         |
                                                         |         |
                       1. gen and sign digest lists/RPMs |         |
                       +-------------+                   |         |
                       | compact_gen |-+                 |         |
                       +-------------+ |                 |         |
                                       |                 |         |
                       +-------------+ |          (   signed   ) (RPMs)
                       | rpm_gen     |-+---------- digest lists
                       +-------------+ |
                                       |
                       +-------------+ |
                       | map_gen     |-+
                       +-------------+


Initially, digest lists are generated through one of the available
generators. This step can be done by a software vendor in its premises or
can be extracted at a later time by the diglim rpm plugin itself from RPMs.
If a user owns a key trusted by the kernel, it can generate and sign digest
lists at a later time, from a running system.

Currently, only a manual setup is supported. A tool named *diglim_setup.sh*
has been developed to guide the user through all the configuration steps
necessary to use DIGLIM eBPF.

All generated digest lists are written to the /etc/digest_lists directory,
so that *diglim_user_loader* can iterate over them, and push them to the
*data_input* map. *diglim_user_loader* can be invoked by the user from a
shell, or also by rpm through the diglim rpm plugin, after the plugin
extracted the RPM header.

Every loaded digest list parser is invoked every time there are data
available in the *data_input* map. As first step, they invoke the new
bpf_mod_verify_sig() helper, and provide to it the data from the
*data_input* map as it is. The helper tells if the signature appended to
the data (module-style signature) is successfully verified with a kernel
key in the primary or secondary keyring.

Once a digest list has been successfully verified, each parser attempts to
parse it. If it does not recognize the format, simply stops any further
processing. If it recognizes the format, the parser pushes extracted
digests to the protected *digest_items* map, so that they can be queried by
the security module.

When the *bprm_creds_for_exec*, *mmap_file* or *kernel_read_file* are
invoked, the security module invokes IMA to calculate the digest of the
file being accessed. It then performs a lookup in a *digest_items* map, to
see if it finds the calculated file digest among the reference values. If
the file digest is found, access is granted, otherwise it is denied.

The query result is cached in a structure associated to each inode (stored
in the *inode_storage_map* map) and it is invalidated if the file is opened
for writing (checked with the implemented *file_open* hook).

The *bpf* hook is used to prevent access to the hash map containing file
digests from user space. The only way to add/delete a digest is through one
of the implemented digest list parsers, which read data verified by the
kernel.

Errors produced by the hooks implemented in the security module are stored
in *ringbuf* and are delivered to the user space service *diglim_log*,
which then forwards them to the system log.


<a name="init"></a>
## Initialization

Currently, the initialization procedure of DIGLIM eBPF is not finalized yet
due to the need to synchronize with eBPF/other involved kernel developers.

One of the biggest challenges is how to ensure that the environment before
DIGLIM eBPF starts is adequately protected without adding significant
burden to Linux distribution vendor, which is one of the main DIGLIM eBPF
objectives.

DIGLIM eBPF can certainly take advantage of the mechanism to enforce signed
kernel modules (with the module.sig_enforce kernel option). However, it is
not enough as for example the kernel executes the modprobe binary 368 times
even before IMA is initialized.

Not restricting this type of operations means leaving the system in an
uncertain state, with living processes started from unverified code.
Although processes might be scanned later when DIGLIM eBPF starts, it is
not clear whether or not all the damage possibly caused by the unverified
processes can be assessed.

The safest approach is to deny anything that cannot be verified. However,
it has to be determined if this wouldn't break the behavior of existing
kernel drivers trying to probe the hardware and doing user space operations
when necessary. The earliest DIGLIM eBPF is loaded, the better are the
chances that something is not broken.

Clearly, the best chances can be obtained by embedding DIGLIM eBPF in the
kernel image, and by loading it with late_initcall(). However, although
DIGLIM eBPF might be running, other services DIGLIM eBPF relies on are not
available yet at that time: IMA and the kernel key retention service (is
still empty).

Alternatively, to avoid that every DIGLIM eBPF change needs to be pushed to
the kernel, DIGLIM eBPF could be embedded in a kernel module (similarly to
bpf_preload), and be loaded by eBPF at boot. The figure below depicts this
proposal:

          +---------------+
          | kernel/module |          +---------------------(data_input map)
          |---------------|          |                               ^
          | DIGLIM eBPF   |    +------------+                        |
          | light skel    |----| eBPF progs |---(digest_items map)   |
          |---------------|    +------------+              ^         |
          |               |          ^                     |         |
      +---| Init routine  |----------+ 1. load eBPF progs  |         |
      |   |               |                                |         |
      |   |               |--------------------------------+         |
      |   +---------------+ 3. push loader digest to digest_items map|
      |           ^                                                  |
      |           |                                                  |
      |           | 2. read and verify loader digest                 |
      |           |                                                  |
      |    (loader digest)                                           |
      |        signed                                                |
      |                                                              |
      | 4. execute diglim_user_loader                          kernel space
    -----------------------------------------------------------------------
      |                                                          user space
      v                                                              |
    +--------------------+                                           |
    | diglim_user_loader |-------------------------------------------+
    +--------------------+ 6. push digest lists to data_input map
             ^
             | 5. iterate over digest lists
             |
    (/etc/digest_lists)


The initialization logic is very simple. The kernel first loads the eBPF
programs and initializes the maps. Then, it adds the digest of
*diglim_user_loader* to the *digest_items* after the digest signature has
been verified. This step is necessary to ensure that the loader can run,
since the security module is already enforcing the integrity policy.
Otherwise, the loader execution would be denied.

Then, the kernel executes the loader, so that the latter can iterate over
the digest lists in /etc/digest_lists (previously added to the initial ram
disk) and push them to the *data_input* map. Finally, the process continues
as described above, with the invocation of the digest list parsers.

Since probably this solution won't be available soon, the fallback choice
is to start DIGLIM eBPF from user space. More specifically, the skeleton is
embedded in the *diglim_user* program and loaded by libbpf. The earliest
time it can be done is when the kernel executes the init program.
*diglim_user* has the ability to run as init (assuming that
*rdinit=/usr/sbin/diglim_user* is specified in the kernel command line) and
to start the real init after the DIGLIM eBPF initialization is complete.
The second proposal is depicted below:

          +---------------+
          |     kernel    |          +---------------------(data_input map)
          +---------------+          |                               ^
                  |           +------------+                         |
    1. execute    |           | eBPF progs |---(digest_items map)    |
       diglim_user|           +------------+                         |
                  |                  |                               |
                  |                  |                         kernel space
    -----------------------------------------------------------------------
                  |                  |                           user space
                  v                  |                               |
          +---------------+          |                               |
          |  diglim_user  |          |                               |
          |---------------|          | 2. load eBPF progs            |
          | DIGLIM eBPF   |          |                               |
          | skel          |          |                               |
          |---------------|          |                               |
     +----| Init routine  |----------+                               |
     |  +-|               |------------------------------------------+
     |  | |               | 4. push loader digest to data_input map  |
     |  | +---------------+                                          |
     |  |         ^                                                  |
     |  |         | 3. read loader digest                            |
     |  |         |                                                  |
     |  |  (loader digest)                                           |
     |  |      signed                                                |
     |  |                                                            |
     |  | 5. execute diglim_user_loader                              |
     |  v                                                            |
     | +--------------------+                                        |
     | | diglim_user_loader |----------------------------------------+
     | +--------------------+ 7. push digest lists to data_input map
     |           ^
     |           | 6. iterate over digest lists
     |           |
     |   (/etc/digest_lists)
     |
     | 8. execute real init
     v
    +------+
    | init |
    +------+

*diglim_user* behaves very similarly to the kernel counterpart. It first
loads the DIGLIM eBPF programs, then it reads the *diglim_user_loader*
digest from the disk and pushes it to the *data_input* map. Finally, it
executes *diglim_user_loader* to push the digest lists in /etc/digest_lists
(or the directory specified in the command line) to the *data_input* map.

One important distinction between the kernel space-based and the user
space-based solutions is that the latter currently does not prevent DIGLIM
eBPF programs from being stopped. Although there is a solution based on
denying removal of the files eBPF programs are pinned to, it will be
introduced at a later stage after a discussion with eBPF developers. The
kernel space-based solution does not have this problem, as the light
skeleton is never destroyed (keeping the link ref count greater than zero).

The remaining question is how to protect the system before *diglim_user*
starts. IMA for example could fill this gap, but this would introduce new
challenges. If IMA just denies execution or firmware reading for example,
it would do longer than if DIGLIM eBPF is loaded from the kernel. If IMA
needs to appraise files before *diglim_user* starts, the Linux distribution
vendor has to provide the file signatures necessary (included the file
signature of *diglim_user*), add support for xattrs in the initial ram disk
(currently not upstream), and find a secure way for IMA to handover
enforcement to DIGLIM eBPF.


## Effort for Linux Distribution Vendors

This section specifies more in detail what is required from Linux
distribution vendors to offer the DIGLIM eBPF service.

1. add distribution keys to the kernel primary keyring; this is not yet
   possible if the key type is PGP, although a patch set for supporting
   this type is available *[here](https://lore.kernel.org/linux-integrity/20181112102423.30415-1-roberto.sassu@huawei.com/)*;

2. integrate DIGLIM eBPF
    1. (a) take the kernel module code in
       kernel-mod/mod/diglim_kern_preload.c and compile it built-in in the
       kernel;
    2. (b) sign the built kernel module
       kernel-mod/mod/diglim_kern_preload.ko;

3. generate the digest of *diglim_user_loader* with the *map_gen* tool and
   sign it with a key whose public part will be loaded in the primary or
   the secondary keyring in the kernel.

Steps 1 and 2 need to be done only if the first integration alternative
mentioned in the [previous section](#init) is adopted. If DIGLIM
eBPF is initialized in user space, only step 3 is necessary.


## Configuration

### Automatic Setup

DIGLIM eBPF provides the script *diglim_setup.sh* to automatically
install and uninstall the configuration. See the manual for more details.


### Digest List Generation

Digest lists can be generated with the command line tools included in
DIGLIM eBPF. New digest list generators and parsers can be added at a later
time.

#### Examples

Generate the digest lists for all packages from the RPM database:

```
# rpm_gen -d /etc/digest_lists
```

Generate a digest list for the kernel modules (for custom kernels):
```
# compact_gen -d /etc/digest_lists -i /lib/modules/`uname -r`
```

Sign the digest list with the kernel private key (assuming that the kernel
is being built):
```
# scripts/sign-file sha256 certs/signing_key.pem certs/signing_key.pem \
                    /etc/digest_lists/0-file_list-compact-5.18.0-rc1+
```


### Digest Lists Uploading at Run-time

Digest lists can be pushed to DIGLIM eBPF by executing
*diglim_user_loader*. The requirement is that the digest list to be loaded
must be signed and verifiable with one of the kernel keys in the primary or
secondary keyring.

For example, to push one of the digest lists just generated the command is:

```
# diglim_user_loader -o add \
                     -d /etc/digest_lists/0-file_list-compact-5.18.0-rc1+
```


### Initial Ram Disk Generation

If DIGLIM eBPF is executed as the init process (in the initial ram disk),
DIGLIM eBPF itself and the generated digest lists need to be copied to the
initial ram disk. This task can be accomplished by the diglim dracut
module, which can be dynamically selected at dracut run-time with the
option *-a diglim*, or statically, by adding the line:

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


### Logging Service

The DIGLIM eBPF logging service can be automatically executed at boot time,
so that errors can be seen in the system journal. This can be achieved with
the command:

```
# systemctl enable diglim_log.service
```


### diglim rpm Plugin

DIGLIM eBPF includes also the *diglim* rpm plugin to generate an rpm digest
list with an appended signature and to execute *diglim_user_loader* to push
that digest list to the parsers (to request addition/deletion of digests).
The plugin (not enabled by default) can be enabled by adding the following
line to the system-wide rpm macros file:

```
%__transaction_diglim           %{__plugindir}/diglim.so
```


### Troubleshooting

If an application is not executed correctly, or it terminates, it is
possible to do troubleshooting by looking in the system logs the lines with
*diglim_log*. They will contain the likely cause of the problem.

DIGLIM eBPF can be also executed in permissive mode with the command:

```
# diglim_user -p -d /etc/digest_lists
```

If the problem happens at boot time, it is possible to run DIGLIM eBPF in
permissive mode by appending to the kernel command line:

```
-- -p
```
