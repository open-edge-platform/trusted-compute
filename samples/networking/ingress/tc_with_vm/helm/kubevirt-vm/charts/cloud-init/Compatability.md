## Operating Systems which Support Cloud-init

Cloud-init is supported across a wide-range of OS's though I do not and cannot test all of them.
I only test on Ubuntu Server and Debian cloud-images.

Below is a list of all distros Cloud-init says it supports:

- AlmaLinux, Alpine Linux, AOSC OS, Arch Linux
- CentOS, CloudLinux, Container-Optimized OS
- Debian, DragonFlyBSD
- EuroLinux
- Fedora, FreeBSD
- Gentoo
- MarinerOS, MIRACLE LINUX
- NetBSD
- OpenBSD, openEuler, OpenCloudOS, OpenMandriva
- PhotonOS
- Red Hat Enterprise Linux, Rocky
- SLES/openSUSE
- TencentOS
- Ubuntu
- Virtuozzo

## Module List

Cloud-Init is module-based and now has a very large ecosystem of supported sofware, please be aware of the following:
  1. I do not aim to support all of them and only add the ones I need as I encounter a need for them.
  2. Some modules are redundant as their functionality can be fully or mostly replaced by using the `write_files` or `runcmd` modules.
  3. PRs are welcome but you must provide proof of testing until such a time as automated tests can be written.


|Module|Support Status|
|:--|:--|
|Ansible| desired |
|APK Configure| desired |
|⭐️Apt Configure| use write_files |
|Apt Pipelining| Desired |
|⭐️Bootcmd| supported |
|Byobu| not planned |
|CA Certificates| desired |
|Chef| not planned |
|Disable EC2 Instance Metadata Service| not planned |
|⭐️Disk Setup| supported |
|Fan| not planned |
|Final Message| desired |
|Growpart| desired |
|GRUB dpkg| not planned |
|Install Hotplug| not planned |
|⭐️Keyboard| use write_files |
|Keys to Console| desired |
|Landscape| not planned |
|⭐️Locale| use write_files |
|LXD| not planned |
|MCollective| not planned |
|⭐️Mounts| supported |
|⭐️NTP| use write_files |
|⭐️Package Update Upgrade Install| supported |
|Phone Home| desired |
|Power State Change| not planned |
|Puppet| not planned |
|Resizefs| desired |
|⭐️Resolv Conf| use write_files |
|Red Hat Subscription| not planned |
|Rsyslog| desired |
|⭐️Runcmd| supported |
|Salt Minion| not planned |
|⭐️Scripts Per Boot| use write_files |
|⭐️Scripts Per Instance| use write_files |
|⭐️Scripts Per Once| use write_files |
|⭐️Scripts User| use write_files |
|⭐️Scripts Vendor| use write_files |
|Seed Random| desired |
|⭐️Set Hostname| support setting hostname only |
|⭐️Set Passwords| supported in user configuration |
|⭐️Snap| use Runcmd |
|Spacewalk| not planned |
|⭐️SSH| basic support in user configuration|
|SSH AuthKey Fingerprints| not planned |
|⭐️SSH Import ID| supported in user configuration |
|⭐️Timezone| use write_files |
|Ubuntu Drivers| not planned |
|Ubuntu Autoinstall| not planned |
|Ubuntu Pro| not planned |
|⭐️Update Etc Hosts| use write_files |
|Update Hostname| not planned |
|⭐️Users and Groups| supported |
|⭐️Wireguard| supported |
|⭐️Write Files| supported |
|Yum Add Repo| not planned |
|Zypper Add Repo| not planned |
