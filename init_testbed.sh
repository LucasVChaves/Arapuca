#!/bin/bash
# Variaveis
QEMU_BIN="qemu-system-x86_64"
RAM="2048"
CORES="2"
IMAGE_DIR="./vms"

# VM-01 Atacante (Zona A)
$QEMU_BIN -m $RAM -smp $CORES -drive file=$IMAGE_DIR/vm01_attacker.qcow2,format=qcow2 \
  -netdev socket,id=it_net,mcast=230.0.0.1:1234 \
  -device e1000,netdev=it_net,mac=52:54:00:12:34:01 &

# VM-02 Vitima (Zona A) (Dual-Homed para atuar como Gateway ZTA)
# Possui duas placas: uma na rede IT (mcast 1) e uma na rede OT (mcast 2)
$QEMU_BIN -m $RAM -smp $CORES -drive file=$IMAGE_DIR/vm02_victim.qcow2,format=qcow2 \
  -netdev socket,id=it_net,mcast=230.0.0.1:1234 \
  -device e1000,netdev=it_net,mac=52:54:00:12:34:02 \
  -netdev socket,id=ot_net,mcast=230.0.0.2:5678 \
  -device e1000,netdev=ot_net,mac=52:54:00:56:78:02 &

# 3. VM-03 Chao de Fabrica (Zona B)
$QEMU_BIN -m $RAM -smp $CORES -drive file=$IMAGE_DIR/vm03_ot_asset.qcow2,format=qcow2 \
  -netdev socket,id=ot_net,mcast=230.0.0.2:5678 \
  -device e1000,netdev=ot_net,mac=52:54:00:56:78:03 &
