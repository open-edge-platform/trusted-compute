### Cloud-init no-cloud 

Holds your user-data file. Must be the first boot device

```yaml
- name: cloudinitvolume
  type: cdrom
  bus: sata
  readonly: true
  bootorder: 1
  pv-enable: false
```

### DataVolume disk with URL source example

```yaml
- name: harddrive
  type: disk
  bus: virtio
  bootorder: 2
  readonly: false
  pvsize: 32G
  pvstorageClass: local-path
  pvaccessMode: ReadWriteOnce
  source: url
  url: "https://cloud.debian.org/images/cloud/bookworm/daily/latest/debian-12-generic-amd64-daily.qcow2"
```

### DataVolume disk with existing PVC source example

```yaml
- name: harddrive
  type: disk
  bus: virtio
  bootorder: 2
  readonly: false
  pvsize: 32G
  pvstorageClassName: local-path
  nodePlacement: node0
  pvaccessMode: ReadWriteOnce
  source: pvc
  pvcnamespace: default
  pvcname: debian12
```

### ISO live-image example

```yaml
- name: iso
  type: cdrom
  bus: sata
  bootorder: 1
  readonly: true
  pvsize: 8G
  pvstorageClassName: local-path
  nodePlacement: node0
  pvaccessMode: ReadWriteOnce
  source: "https://www.itechtics.com/?dl_id=173"
```

### Empty PVC as disk example

```yaml
- name: harddrive
  type: disk
  bus: virtio
  bootorder: 2
  readonly: false
  pvsize: 32G
  pvstorageClassName: local-path
  nodePlacement: node0
  pvaccessMode: ReadWriteOnce
```

### Container Disk Example

```yaml
- name: virtio-drivers
  type: cdrom
  bus: sata
  bootorder: 3
  readonly: true
  image: "quay.io/kubevirt/virtio-container-disk:v1.0.0-rc.1-amd64"
```

### Ephemeral disk example

No persistance, these are deleted after the VM exists. Requires an existing PVC as a backing file

```yaml
- name: harddrive
  type: disk
  bus: virtio
  bootorder: 2
  readonly: false
  pvc: debian12
  ephemeral: true
```

#WW Local Disk example

Not working, will have to open a ticket about error: 
> disks need to be owned by 107:messagebus disks cannot be mounted, file systems unidentifiable

```yaml
- name: localfile
  type: hostDisk
  # -- Enter a capacity amount to create a new disk
  # otherwise expects an existing disk
  capacity: 500G
  path: /mnt/raid1/hdd2.img
```




