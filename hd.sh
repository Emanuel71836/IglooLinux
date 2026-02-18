# If you don't have a virtual hard drive, use...
# qemu-img create -f qcow2 igloo-hd.qcow2 1G

qemu-system-x86_64 \
    -drive file=igloo-hd.qcow2,format=qcow2 \
    -m 1G \
    -enable-kvm \
    -cpu host \
    -serial stdio