# Proxmox Migration Plan — thefarm

## Current State

| Component | Details |
|---|---|
| Host | thefarm |
| OS | Ubuntu 22.04 |
| CPU | Intel Xeon E5-2680 v4 (28 cores @ 2.40GHz) |
| RAM | 128GB |
| Storage | 1TB SSD (Crucial MX500), LVM |
| Hypervisor | VirtualBox |
| VMs | container, dhouse, mspro, ivmcon, engine1 (+ others) |

## Target State

| Component | Details |
|---|---|
| OS/Hypervisor | Proxmox VE 8.x (bare metal) |
| Storage | ZFS on /dev/sda3 (snapshots, compression, checksums) |
| VM format | qcow2 (converted from VirtualBox .vdi) |
| Management | Web UI at https://thefarm:8006 |

---

## Phase 1: Pre-Migration (while Ubuntu is still running)

### 1.1 Inventory VMs

```bash
VBoxManage list vms
```

Document each VM: name, disk size, RAM allocation, network config (bridged/NAT, MAC addresses, static IPs).

### 1.2 Export VMs

Option A — Export as OVA (preserves config):
```bash
VBoxManage export "container" -o /path/to/backup/container.ova
VBoxManage export "dhouse" -o /path/to/backup/dhouse.ova
VBoxManage export "mspro" -o /path/to/backup/mspro.ova
# repeat for each VM
```

Option B — Copy raw .vdi files (faster, convert later):
```bash
cp ~/VirtualBox\ VMs/*/\*.vdi /path/to/backup/
```

### 1.3 Backup location

You need somewhere to store ~500GB+ of VM images during migration:
- External USB drive
- NFS share on another machine
- stevesNuc over the network

### 1.4 Document network config

```bash
ip addr show
cat /etc/netplan/*.yaml
# Note: bridge interface name, IP, gateway, DNS
```

Record thefarm's IP and the bridge config so VMs keep their current IPs after migration.

### 1.5 Note LVM layout (for reference)

```
ubuntu--vg-ubuntu--lv: 100GB (root)
ubuntu--vg-lvol01: 100GB
ubuntu--vg-lvol02: 501GB (likely where VMs live)
```

---

## Phase 2: Install Proxmox

### 2.1 Download Proxmox VE ISO

https://www.proxmox.com/en/downloads

Write to USB:
```bash
# From your Mac:
dd if=proxmox-ve_8.x.iso of=/dev/diskN bs=4M status=progress
```

### 2.2 Install Proxmox on thefarm

1. Boot from USB
2. Select /dev/sda as install target
3. **Choose ZFS (RAID0 single disk)** — gives you snapshots + compression
4. Set hostname: `thefarm.local` (or your domain)
5. Configure network: same IP as current thefarm so your VMs' gateway doesn't change
6. Set root password
7. Install

### 2.3 Post-install access

- Web UI: `https://<thefarm-ip>:8006`
- SSH: `ssh root@<thefarm-ip>`

### 2.4 Remove enterprise repo (for free use)

```bash
# Disable paid repo
sed -i 's/^deb/# deb/' /etc/apt/sources.list.d/pve-enterprise.list

# Add no-subscription repo
echo "deb http://download.proxmox.com/debian/pve bookworm pve-no-subscription" > /etc/apt/sources.list.d/pve-no-subscription.list

apt update && apt dist-upgrade -y
```

---

## Phase 3: Import VMs

### 3.1 Copy backup files to Proxmox

From external drive or network:
```bash
# Mount external drive
mount /dev/sdX1 /mnt/backup

# Or SCP from another machine
scp user@stevesNuc:/backup/*.vdi /tmp/import/
```

### 3.2 Convert VDI to qcow2

```bash
# For each VM:
qemu-img convert -f vdi -O qcow2 /tmp/import/container.vdi /tmp/import/container.qcow2
qemu-img convert -f vdi -O qcow2 /tmp/import/dhouse.vdi /tmp/import/dhouse.qcow2
qemu-img convert -f vdi -O qcow2 /tmp/import/mspro.vdi /tmp/import/mspro.qcow2
```

### 3.3 Create VMs in Proxmox

Via web UI or CLI. Example for container:

```bash
# Create VM (ID 100)
qm create 100 --name container --memory 4096 --cores 2 --net0 virtio,bridge=vmbr0

# Import disk to ZFS storage
qm importdisk 100 /tmp/import/container.qcow2 local-zfs

# Attach the disk
qm set 100 --scsi0 local-zfs:vm-100-disk-0

# Set boot order
qm set 100 --boot order=scsi0

# Set OS type
qm set 100 --ostype l26
```

Repeat for each VM, adjusting ID, name, memory, cores.

### 3.4 If using OVA instead

```bash
# Extract OVA
tar -xvf container.ova

# Convert .vmdk to qcow2
qemu-img convert -f vmdk -O qcow2 container-disk001.vmdk /tmp/import/container.qcow2

# Then import as above
```

### 3.5 Network bridge setup

Proxmox creates `vmbr0` by default. Verify it's bridged to your physical NIC:

```bash
cat /etc/network/interfaces
```

Should look like:
```
auto vmbr0
iface vmbr0 inet static
    address <thefarm-ip>/24
    gateway <your-gateway>
    bridge-ports enp0s25
    bridge-stp off
    bridge-fd 0
```

VMs using `bridge=vmbr0` will be on the same L2 network as before — same IPs work.

---

## Phase 4: Verify

### 4.1 Start VMs and test

- Start each VM
- Verify network connectivity (ping, SSH)
- Verify IVM can scan them
- Verify scan engine can reach targets
- Run a test scan

### 4.2 Test snapshots

```bash
# Take a snapshot
qm snapshot 100 before-patching --description "Clean state before apt upgrade"

# Roll back if needed
qm rollback 100 before-patching
```

### 4.3 Set up scheduled backups

In Proxmox UI: Datacenter → Backup → Add:
- Schedule: Daily at 02:00
- Storage: local (or add a backup storage)
- Mode: Snapshot (no VM downtime)
- Retention: keep last 7

---

## Phase 5: Cleanup

- Delete backup files from /tmp/import
- Remove external drive
- Update any DNS/static IP references if thefarm's IP changed
- Update the asset exposure map in steering file if needed

---

## Estimated Timeline

| Step | Duration |
|---|---|
| Export VMs from VirtualBox | 1-2 hours (depends on disk sizes) |
| Install Proxmox | 15 minutes |
| Convert + import VMs | 1-2 hours |
| Network config + testing | 30 minutes |
| **Total downtime** | **3-5 hours** |

---

## Rollback Plan

If something goes wrong:
1. Boot thefarm from Ubuntu live USB
2. Reinstall Ubuntu 22.04
3. Restore VirtualBox + import OVA files
4. Back to original state

Keep the backup drive until you've verified everything works in Proxmox for at least a week.

---

## ZFS Benefits (why ZFS over LVM)

| Feature | LVM | ZFS |
|---|---|---|
| Snapshots | Basic, slow | Instant, no performance impact |
| Compression | Not built-in | Transparent LZ4 (saves 30-50% on VM disks) |
| Data integrity | None | Checksums on every block |
| Backup integration | Manual | Proxmox backup server integration |
| RAM usage | Minimal | Uses ARC cache (you have 128GB — plenty) |

With ZFS + 128GB RAM, your VMs will benefit from aggressive read caching (ARC) which makes disk I/O feel much faster than VirtualBox on LVM.
