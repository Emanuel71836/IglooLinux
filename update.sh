sudo mount -o loop igloo_disk.img ./mnt_igloo

sudo cp ./init/target/x86_64-unknown-linux-musl/release/init ./mnt_igloo/sbin/init
sudo chmod +x ./mnt_igloo/sbin/init

sync
sudo umount ./mnt_igloo