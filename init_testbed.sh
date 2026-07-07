#!/bin/bash
# Variaveis
QEMU_BIN="qemu-system-x86_64"
RAM="2048"
CORES="2"
BASE_DIR="./vms"

# VM-02 Vitima (Zona A, age como switch)
$QEMU_BIN $KVM_FLAG -m $RAM -smp $CORES -k pt-br \
  -drive file=$BASE_DIR/vm02_victim.qcow2,format=qcow2 \
  -netdev socket,id=it_net,listen=:1234 \
  -device e1000,netdev=it_net,mac=52:54:00:12:34:02 \
  -netdev socket,id=ot_net,listen=:5678 \
  -device e1000,netdev=ot_net,mac=52:54:00:56:78:02 &
echo "VM-02 Started. Hosting sockets on ports 1234 and 5678"

# Sem esse sleep nao da tempo de abrir as portas
sleep 2

# VM-01 Atacante (Zona A) 
$QEMU_BIN $KVM_FLAG -m $RAM -smp $CORES -k pt-br \
  -drive file=$BASE_DIR/vm01_attacker.qcow2,format=qcow2 \
  -netdev socket,id=it_net,connect=127.0.0.1:1234 \
  -device e1000,netdev=it_net,mac=52:54:00:12:34:01 &
echo "VM-01 connected to Zone A."

# 3. VM-03 Chao de Fabrica (Zona B)
$QEMU_BIN $KVM_FLAG -m $RAM -smp $CORES -k pt-br \
  -drive file=$BASE_DIR/vm03_ot_asset.qcow2,format=qcow2 \
  -netdev socket,id=ot_net,connect=127.0.0.1:5678 \
  -device e1000,netdev=ot_net,mac=52:54:00:56:78:03 &
echo "VM-03 connected to Zone B."

echo "Testbed Running"
