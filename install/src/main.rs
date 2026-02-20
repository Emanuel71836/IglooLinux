#![deny(warnings)]

use dialoguer::{theme::ColorfulTheme, Confirm, Select};
use nix::sys::stat::{makedev, Mode, SFlag, mknod};
use nix::unistd::Uid;
use regex::Regex;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

const ROOT_LABEL: &str = "IGLOO_ROOT";
const ESP_LABEL: &str = "EFI";
// local path to the root filesystem tarball
const ROOTFS_TARBALL_PATH: &str = "/iso/igloo-rootfs.tar.gz";

#[derive(Debug, Clone, Copy)]
enum BootMode {
    Legacy,
    Uefi,
}

#[derive(Debug)]
struct Disk {
    path: String,
    size: String,
    model: Option<String>,
}

#[derive(Debug)]
struct Partition {
    path: String,
    size: String,
    fstype: Option<String>,
    label: Option<String>,
    mountpoint: Option<String>,
}

// handler to nvme disks
fn partition_path(disk: &str, part_num: u32) -> String {
    let disk_name = disk.trim_start_matches("/dev/");
    if disk_name.chars().last().map_or(false, |c| c.is_ascii_digit()) {
        format!("{}{}{}", disk, 'p', part_num)
    } else {
        format!("{}{}", disk, part_num)
    }
}

fn list_disks() -> Vec<Disk> {
    let output = Command::new("lsblk")
        .args(&["-o", "NAME,SIZE,MODEL,TYPE", "-d", "-n", "-l"])
        .output()
        .expect("failed to execute lsblk");
    let stdout = String::from_utf8_lossy(&output.stdout);

    let mut disks = Vec::new();
    let re = Regex::new(r"^(\S+)\s+(\S+)\s+(.*?)\s*(disk)?$").unwrap();
    for line in stdout.lines() {
        if let Some(caps) = re.captures(line) {
            let name = caps[1].to_string();
            let size = caps[2].to_string();
            let model = caps.get(3).map(|m| m.as_str().trim().to_string());
            let model = if model.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
                None
            } else {
                model
            };
            disks.push(Disk {
                path: format!("/dev/{}", name),
                size,
                model,
            });
        }
    }
    disks
}

fn list_all_partitions() -> Vec<Partition> {
    let output = Command::new("lsblk")
        .args(&["-o", "NAME,SIZE,FSTYPE,LABEL,MOUNTPOINT", "-n", "-l"])
        .output()
        .expect("failed to execute lsblk");
    let stdout = String::from_utf8_lossy(&output.stdout);

    let mut partitions = Vec::new();
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let name = parts[0];
        let size = parts[1].to_string();
        let fstype = if parts.len() > 2 { Some(parts[2].to_string()) } else { None };
        let label = if parts.len() > 3 { Some(parts[3].to_string()) } else { None };
        let mountpoint = if parts.len() > 4 { Some(parts[4].to_string()) } else { None };
        partitions.push(Partition {
            path: format!("/dev/{}", name),
            size,
            fstype,
            label,
            mountpoint,
        });
    }
    partitions
}

fn select_disk(disks: &[Disk]) -> &Disk {
    let selections: Vec<String> = disks
        .iter()
        .map(|d| {
            format!(
                "{} - {} {}",
                d.path,
                d.size,
                d.model.as_deref().unwrap_or("")
            )
        })
        .collect();
    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select a disk")
        .items(&selections)
        .default(0)
        .interact()
        .unwrap();
    &disks[selection]
}

fn select_partition<'a>(partitions: &'a [&Partition]) -> &'a Partition {
    let selections: Vec<String> = partitions
        .iter()
        .map(|p| {
            format!(
                "{} - {} [{}] label={} mount={}",
                p.path,
                p.size,
                p.fstype.as_deref().unwrap_or("unknown"),
                p.label.as_deref().unwrap_or("none"),
                p.mountpoint.as_deref().unwrap_or("none")
            )
        })
        .collect();
    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select a partition")
        .items(&selections)
        .default(0)
        .interact()
        .unwrap();
    partitions[selection]
}

fn create_partitions(disk: &Disk, mode: BootMode) -> (String, Option<String>) {
    match mode {
        BootMode::Legacy => {
            println!("Creating MBR partition table and one Linux partition on {}...", disk.path);

            run_command("parted", &["-s", &disk.path, "mklabel", "msdos"])
                .expect("Failed to create MBR label");
            run_command("parted", &["-s", &disk.path, "mkpart", "primary", "ext4", "0%", "100%"])
                .expect("Failed to create partition");
            let _ = Command::new("partprobe").arg(&disk.path).status();

            let root_part = partition_path(&disk.path, 1);
            (root_part, None)
        }
        BootMode::Uefi => {
            println!("Creating GPT partition table, ESP, and root partition on {}...", disk.path);

            run_command("sgdisk", &["--zap-all", &disk.path])
                .expect("Failed to wipe partition table");
            run_command("sgdisk", &["-n", "1:0:+512M", "-t", "1:EF00", &disk.path])
                .expect("Failed to create ESP");
            run_command("sgdisk", &["-n", "2:0:0", "-t", "2:8300", &disk.path])
                .expect("Failed to create root partition");
            let _ = Command::new("partprobe").arg(&disk.path).status();

            let esp_part = partition_path(&disk.path, 1);
            let root_part = partition_path(&disk.path, 2);
            (root_part, Some(esp_part))
        }
    }
}

fn format_ext4(partition: &str, label: &str) {
    println!("Formatting {} as ext4 with label '{}'...", partition, label);
    run_command("mkfs.ext4", &["-F", "-L", label, partition])
        .expect("Formatting failed");
}

fn set_label(partition: &str, label: &str) {
    println!("Setting label on {} to '{}'...", partition, label);
    run_command("e2label", &[partition, label])
        .expect("Setting label failed");
}

fn format_efi(partition: &str, label: &str) {
    println!("Formatting {} as FAT32 with label '{}'...", partition, label);
    run_command("mkfs.vfat", &["-F", "32", "-n", label, partition])
        .expect("Formatting ESP failed");
}

fn configure_network() {
    let network_dir = "/etc/systemd/network";
    fs::create_dir_all(network_dir).expect("failed to create /etc/systemd/network");

    let config = r#"[Match]
Name=en*

[Network]
DHCP=yes
"#;
    fs::write(format!("{}/20-wired.network", network_dir), config)
        .expect("failed to write network config");
    println!("Network configured for DHCP on all ethernet interfaces.");
}

fn populate_initramfs_from_live(initramfs_root: &Path) -> std::io::Result<()> {
    let dirs = ["/bin", "/boot", "/etc", "/lib", "/lib64", "/usr"];
    for dir in &dirs {
        let src = Path::new(dir);
        if !src.exists() {
            println!("Warning: source directory {} does not exist, skipping", dir);
            continue;
        }
        let dst = initramfs_root.join(dir.trim_start_matches('/'));
        println!("Copying {} to initramfs...", dir);
        run_command("cp", &["-a", dir, dst.to_str().unwrap()])?;
    }
    Ok(())
}

fn create_initramfs(target_root: &str) -> std::io::Result<()> {
    let init_src = "/init";
    let init_dst = format!("{}/boot/init", target_root);

    println!("Copying init binary to {}/boot/init...", target_root);
    fs::copy(init_src, &init_dst)?;

    let tmp_dir = tempdir()?;
    let initramfs_root = tmp_dir.path();

    populate_initramfs_from_live(initramfs_root)?;

    fs::copy(init_src, initramfs_root.join("init"))?;

    fs::create_dir_all(initramfs_root.join("dev"))?;

    let dev_console = initramfs_root.join("dev/console");
    mknod(
        &dev_console,
        SFlag::S_IFCHR,
        Mode::from_bits_truncate(0o622),
        makedev(5, 1),
    )
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("mknod console: {}", e)))?;

    let dev_null = initramfs_root.join("dev/null");
    mknod(
        &dev_null,
        SFlag::S_IFCHR,
        Mode::from_bits_truncate(0o666),
        makedev(1, 3),
    )
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("mknod null: {}", e)))?;

    let dev_zero = initramfs_root.join("dev/zero");
    mknod(
        &dev_zero,
        SFlag::S_IFCHR,
        Mode::from_bits_truncate(0o666),
        makedev(1, 5),
    )
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("mknod zero: {}", e)))?;

    let dev_random = initramfs_root.join("dev/random");
    mknod(
        &dev_random,
        SFlag::S_IFCHR,
        Mode::from_bits_truncate(0o666),
        makedev(1, 8),
    )
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("mknod random: {}", e)))?;

    let dev_urandom = initramfs_root.join("dev/urandom");
    mknod(
        &dev_urandom,
        SFlag::S_IFCHR,
        Mode::from_bits_truncate(0o666),
        makedev(1, 9),
    )
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("mknod urandom: {}", e)))?;

    let dev_tty = initramfs_root.join("dev/tty");
    mknod(
        &dev_tty,
        SFlag::S_IFCHR,
        Mode::from_bits_truncate(0o666),
        makedev(5, 0),
    )
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("mknod tty: {}", e)))?;

    let dev_tty0 = initramfs_root.join("dev/tty0");
    mknod(
        &dev_tty0,
        SFlag::S_IFCHR,
        Mode::from_bits_truncate(0o666),
        makedev(4, 0),
    )
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("mknod tty0: {}", e)))?;

    for i in 1..=6 {
        let dev_ttyn = initramfs_root.join(format!("dev/tty{}", i));
        mknod(
            &dev_ttyn,
            SFlag::S_IFCHR,
            Mode::from_bits_truncate(0o666),
            makedev(4, i),
        )
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("mknod tty{}: {}", i, e)))?;
    }

    println!("Creating initramfs image...");
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "cd {} && find . | cpio -o -H newc | gzip > {}/boot/initramfs-igloo.img",
            initramfs_root.display(),
            target_root
        ))
        .status()?;
    if !output.success() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Failed to create initramfs",
        ));
    }

    println!("Initramfs created at {}/boot/initramfs-igloo.img", target_root);
    Ok(())
}

fn install_grub(mode: BootMode, disk: &str, esp_mount: Option<&str>) -> std::io::Result<()> {
    match mode {
        BootMode::Legacy => {
            println!("Installing GRUB (i386-pc) to {}...", disk);
            run_command("grub-install", &["--target=i386-pc", "--boot-directory=/mnt/boot", disk])?;
        }
        BootMode::Uefi => {
            println!("Installing GRUB (x86_64-efi) to {}...", disk);
            let efi_dir = esp_mount.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "ESP mount point not provided for UEFI install",
                )
            })?;
            run_command(
                "grub-install",
                &[
                    "--target=x86_64-efi",
                    "--efi-directory",
                    efi_dir,
                    "--boot-directory=/mnt/boot",
                    "--removable",
                ],
            )?;
        }
    }

    println!("Writing /mnt/boot/grub/grub.cfg...");
    let grub_conf = r#"set timeout=5

menuentry "Igloo Linux" {
    search --label --set=root IGLOO_ROOT
    linux /boot/vmlinuz root=LABEL=IGLOO_ROOT rw console=tty0 console=ttyS0
    initrd /boot/initramfs-igloo.img
}
"#;
    fs::create_dir_all("/mnt/boot/grub")?;
    fs::write("/mnt/boot/grub/grub.cfg", grub_conf)?;

    Ok(())
}

/// retrieve the UUID of a partition using blkid.
fn get_uuid(partition: &str) -> std::io::Result<String> {
    let output = Command::new("blkid")
        .args(&["-s", "UUID", "-o", "value", partition])
        .output()?;
    if !output.status.success() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("blkid failed for {}", partition),
        ));
    }
    let uuid = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if uuid.is_empty() {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("no UUID found for {}", partition),
        ))
    } else {
        Ok(uuid)
    }
}

/// helper to run a command and convert non‑zero exit to an io::Error
fn run_command(cmd: &str, args: &[&str]) -> std::io::Result<()> {
    let status = Command::new(cmd)
        .args(args)
        .status()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("failed to execute {}: {}", cmd, e)))?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("{} exited with status {}", cmd, status),
        ))
    }
}

/// extract the root filesystem tarball from a local path into the target root
fn extract_rootfs_tarball(target_root: &str) -> std::io::Result<()> {
    println!("Extracting root filesystem from {} ...", ROOTFS_TARBALL_PATH);

    // check that the tarball exists
    if !Path::new(ROOTFS_TARBALL_PATH).exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Root filesystem tarball not found at {}", ROOTFS_TARBALL_PATH),
        ));
    }

    // extract the tarball directly into target_root
    run_command("tar", &["-xzf", ROOTFS_TARBALL_PATH, "-C", target_root])?;

    println!("Root filesystem extracted successfully.");
    Ok(())
}

fn install_system(
    mode: BootMode,
    root_part: &str,
    esp_part: Option<&str>,
) -> std::io::Result<()> {
    fs::create_dir_all("/mnt")?;

    // mount root partition
    println!("Mounting {} to /mnt...", root_part);
    run_command("mount", &[root_part, "/mnt"])?;

    // mount esp if present
    if let Some(esp) = esp_part {
        println!("Mounting {} to /mnt/boot/efi...", esp);
        fs::create_dir_all("/mnt/boot/efi")?;
        run_command("mount", &[esp, "/mnt/boot/efi"])?;
    }

    // extract root filesystem from local tarball
    extract_rootfs_tarball("/mnt")?;

    // obtain UUIDs for the partitions
    let root_uuid = get_uuid(root_part)?;
    let esp_uuid = if let Some(esp) = esp_part {
        Some(get_uuid(esp)?)
    } else {
        None
    };

    // write /etc/fstab with UUIDs
    println!("Creating /etc/fstab with UUIDs...");
    let mut fstab = String::new();
    fstab.push_str("# /etc/fstab: static file system information\n");
    fstab.push_str(&format!("UUID={} / ext4 rw,relatime 0 1\n", root_uuid));
    if let Some(uuid) = esp_uuid {
        fstab.push_str(&format!("UUID={} /boot/efi vfat defaults 0 2\n", uuid));
    }
    fs::write("/mnt/etc/fstab", fstab)?;

    create_initramfs("/mnt")?;

    // install grub
    let esp_mount = if matches!(mode, BootMode::Uefi) {
        Some("/mnt/boot/efi")
    } else {
        None
    };
    let disk = root_part
        .trim_end_matches(|c: char| c.is_ascii_digit())
        .trim_end_matches('p');
    install_grub(mode, disk, esp_mount)?;

    // unmount
    println!("Syncing and unmounting...");
    Command::new("sync").status().ok();

    if esp_part.is_some() {
        run_command("umount", &["/mnt/boot/efi"])?;
    }
    run_command("umount", &["/mnt"])?;

    println!("System installed successfully on {}", root_part);
    Ok(())
}

fn install() {
    let boot_modes = &["Legacy BIOS (MBR)", "UEFI (GPT)"];
    let mode_choice = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select boot mode")
        .items(boot_modes)
        .default(0)
        .interact()
        .unwrap();
    let mode = match mode_choice {
        0 => BootMode::Legacy,
        1 => BootMode::Uefi,
        _ => unreachable!(),
    };

    let install_options = &[
        "Create new partition (whole disk)",
        "Use existing EXT4 partition",
    ];
    let install_choice = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Installation type")
        .items(install_options)
        .default(0)
        .interact()
        .unwrap();

    match install_choice {
        0 => {
            let disks = list_disks();
            if disks.is_empty() {
                eprintln!("No disks found!");
                return;
            }
            let selected_disk = select_disk(&disks);
            println!("Selected disk: {}", selected_disk.path);

            let confirm = Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt("This will DESTROY ALL DATA on the selected disk. Continue?")
                .default(false)
                .interact()
                .unwrap();
            if !confirm {
                println!("Installation cancelled.");
                return;
            }

            let (root_part, esp_part) = create_partitions(selected_disk, mode);
            format_ext4(&root_part, ROOT_LABEL);
            if let Some(esp) = &esp_part {
                format_efi(esp, ESP_LABEL);
            }

            if let Err(e) = install_system(mode, &root_part, esp_part.as_deref()) {
                eprintln!("Installation failed: {}", e);
                return;
            }
        }
        1 => {
            let partitions = list_all_partitions();
            let ext4_partitions: Vec<&Partition> = partitions
                .iter()
                .filter(|p| p.fstype.as_deref() == Some("ext4"))
                .collect();
            if ext4_partitions.is_empty() {
                eprintln!("No EXT4 partitions found.");
                return;
            }
            let selected = select_partition(&ext4_partitions);
            println!("Selected partition: {}", selected.path);

            if selected.mountpoint.is_some() {
                eprintln!("Partition is already mounted. Please unmount it first.");
                return;
            }

            let should_set_label = if selected.label.as_deref() != Some(ROOT_LABEL) {
                Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt(format!(
                        "Partition label is {:?}. Set it to '{}'?",
                        selected.label.as_deref().unwrap_or("none"),
                        ROOT_LABEL
                    ))
                    .default(true)
                    .interact()
                    .unwrap()
            } else {
                false
            };

            if should_set_label {
                set_label(&selected.path, ROOT_LABEL);
            }

            let confirm = Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt("This will overwrite any existing data on the partition. Continue?")
                .default(false)
                .interact()
                .unwrap();
            if !confirm {
                println!("Installation cancelled.");
                return;
            }

            let esp_part = if matches!(mode, BootMode::Uefi) {
                println!("For UEFI, an ESP is required. Please select an existing EFI partition or create one manually.");
                println!("Skipping ESP for now – you'll need to set up boot manually.");
                None
            } else {
                None
            };

            if let Err(e) = install_system(mode, &selected.path, esp_part) {
                eprintln!("Installation failed: {}", e);
                return;
            }
        }
        _ => unreachable!(),
    }

    if Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Configure network for the installed system? (DHCP on all ethernet)")
        .default(true)
        .interact()
        .unwrap()
    {
        configure_network();
    }

    println!("\nInstallation complete.");
    if let Ok(exe_path) = std::env::current_exe() {
        if let Err(e) = std::fs::remove_file(&exe_path) {
            eprintln!("Warning: could not delete installer binary: {}", e);
        } else {
            println!("Installer binary removed.");
        }
    }

    if Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Reboot now?")
        .default(true)
        .interact()
        .unwrap()
    {
        println!("Rebooting via SysRq...");
        let _ = std::fs::write("/proc/sys/kernel/sysrq", "1");
        if let Err(e) = std::fs::write("/proc/sysrq-trigger", "b") {
            eprintln!("SysRq reboot failed: {}, falling back to normal reboot", e);
            Command::new("reboot").status().expect("reboot failed");
        }
    } else {
        println!("You can reboot later with the 'reboot' command.");
    }
}

fn main() {
    if !Uid::effective().is_root() {
        eprintln!("This installer must be run as root.");
        std::process::exit(1);
    }
    install();
}