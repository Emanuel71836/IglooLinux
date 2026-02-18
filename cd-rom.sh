qemu-system-x86_64 \
    -boot d \
    -cdrom igloolinux.iso \
    -drive file=igloo-hd.qcow2,format=qcow2 \
    -m 1G \
    -enable-kvm \
    -cpu host \
    -serial stdio
    -net none \ # Remove this if you want network