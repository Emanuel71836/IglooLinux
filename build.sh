#!/bin/bash

DEST="./initramfs"
mkdir -p $DEST/bin $DEST/lib/x86_64-linux-gnu $DEST/lib64 $DEST/usr/sbin
mkdir -p ./iso/boot/grub

cp -L ./linux-6.19/arch/x86/boot/bzImage ./iso/boot/vmlinuz
cp /bin/{sh,cp,ls,mkdir} $DEST/bin/
cp /lib/x86_64-linux-gnu/{libc.so.6,libacl.so.1,libattr.so.1} $DEST/lib/x86_64-linux-gnu/
cp /lib64/ld-linux-x86-64.so.2 $DEST/lib64/

mkdir -p $DEST/usr/lib/grub/x86_64-efi
cp -r /usr/lib/grub/x86_64-efi/* $DEST/usr/lib/grub/x86_64-efi/

# 4. SIMPLE GRUB CONFIG
cat <<EOF > ./iso/boot/grub/grub.cfg
set timeout=0
menuentry "Igloo" {
    linux /boot/vmlinuz root=LABEL=IGLOO_ROOT rw console=tty0 console=ttyS0
    initrd /boot/initrd.img
}
EOF

echo "Packing initramfs..."
cd $DEST && find . -print0 | cpio --null -ov --format=newc | gzip -9 > ../iso/boot/initrd.img
cd ..

grub-mkrescue -o igloolinux.iso iso
echo "Done."