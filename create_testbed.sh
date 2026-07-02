#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
BASE_DIR="$SCRIPT_DIR/vms"
DISK_SIZE="20G"
RAM="2048"
CORES="2"
QEMU_BIN="qemu-system-x86_64"
KVM_FLAG="-enable-kvm" 

echo "Initial Setup of the Testbed"

mkdir -p "$BASE_DIR"

echo "Searching for .iso files in current directory"
ISO_FILE=$(find "$BASE_DIR" -maxdepth 1 -name "*.iso" | head -n 1)

if [ -z "$ISO_FILE" ]; then
    echo "[ERROR] No ISO image found in $BASE_DIR."
    echo " -> Please download an Arch Linux ISO and move it to $BASE_DIR before running this script."
    echo " -> Example: wget https://mirrors.ic.unicamp.br/archlinux/iso/2026.07.01/archlinux-2026.07.01-x86_64.iso -P $BASE_DIR"
    exit 1
fi

echo "ISO found: $ISO_FILE"

setup_vm() {
    local VM_NAME=$1
    local DISK_FILE="$BASE_DIR/${VM_NAME}.qcow2"

    echo "Creating: $VM_NAME"
    
    if [ ! -f "$DISK_FILE" ]; then
        qemu-img create -f qcow2 "$DISK_FILE" $DISK_SIZE
    else
        echo "-> [WARN] Disk $DISK_FILE already exists. Skipping its creation."
    fi

    $QEMU_BIN $KVM_FLAG -m $RAM -smp $CORES \
      -drive file="$DISK_FILE",format=qcow2 \
      -cdrom "$ISO_FILE" \
      -boot d &
}

setup_vm "vm01_attacker"
setup_vm "vm02_victim"
setup_vm "vm03_ot_asset"

echo "[SUCCESS] All 3 VMs created."
echo "Install Arch for each VM to proceed" 
echo "Then run 'init_testbed.sh' to use the sandbox"
