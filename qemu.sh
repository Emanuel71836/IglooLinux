qemu-system-x86_64 \
    -kernel linux-6.12.13/arch/x86/boot/bzImage \
    -drive format=raw,file=igloo_disk.img \
    -append "root=/dev/sda rw console=ttyS0" \
    -nographic