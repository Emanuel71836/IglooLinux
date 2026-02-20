#![deny(warnings)]

extern crate libc;

use core::sync::atomic::{AtomicBool, Ordering};
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::ptr;
use std::path::Path;
use std::fs;
use std::process::Command;
use std::thread;
use std::time::Duration;

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);
static SIGCHLD_RECEIVED: AtomicBool = AtomicBool::new(false);

static mut CONSOLE_FD: libc::c_int = -1;

fn log_message(level: &str, msg: &str) {
    let formatted = format!("[{}] {}\n", level, msg);
    let bytes = formatted.as_bytes();
    let len = bytes.len() as libc::size_t;

    unsafe {
        libc::write(1, bytes.as_ptr() as *const _, len);
        if CONSOLE_FD != -1 {
            libc::write(CONSOLE_FD, bytes.as_ptr() as *const _, len);
        }
    }
}

macro_rules! log_info {
    ($($arg:tt)*) => { log_message("INFO", &format!($($arg)*)) };
}
macro_rules! log_warn {
    ($($arg:tt)*) => { log_message("WARN", &format!($($arg)*)) };
}
macro_rules! log_error {
    ($($arg:tt)*) => { log_message("ERROR", &format!($($arg)*)) };
}

fn fatal_error(msg: &str) -> ! {
    log_error!("FATAL: {}", msg);
    loop {
        unsafe { libc::pause() };
    }
}

fn mount_fs(source: &str, target: &str, fstype: &str, flags: libc::c_ulong, data: &str) -> bool {
    let c_source = CString::new(source).expect("CString::new failed for source");
    let c_target = CString::new(target).expect("CString::new failed for target");
    let c_fstype = CString::new(fstype).expect("CString::new failed for fstype");

    let c_data_storage: Option<CString> = if data.is_empty() {
        None
    } else {
        Some(CString::new(data).expect("CString::new failed for data"))
    };

    let c_data_ptr = match c_data_storage {
        Some(ref s) => s.as_ptr(),
        None => ptr::null(),
    };

    let ret = unsafe {
        libc::mount(
            c_source.as_ptr(),
            c_target.as_ptr(),
            c_fstype.as_ptr(),
            flags,
            c_data_ptr as *const libc::c_void,
        )
    };

    if ret == 0 {
        log_info!("Mounted {} on {} type {}", source, target, fstype);
        true
    } else {
        let err = std::io::Error::last_os_error();
        log_warn!("Failed to mount {} on {} ({}): {}", source, target, fstype, err);
        false
    }
}

fn mount_filesystems() {
    let _ = fs::create_dir_all("/proc");
    let _ = fs::create_dir_all("/sys");
    let _ = fs::create_dir_all("/dev");

    mount_fs("proc", "/proc", "proc", 0, "");
    mount_fs("sysfs", "/sys", "sysfs", 0, "");
    
    if !mount_fs("devtmpfs", "/dev", "devtmpfs", 0, "") {
        log_info!("/dev already mounted by kernel or failed, skipping fallback");
    }
}

// new function to ensure virtual filesystems are present in fallback mode
fn ensure_virtual_fs() {
    if Path::new("/proc").exists() && !Path::new("/proc/self").exists() {
        mount_fs("proc", "/proc", "proc", 0, "");
    }
    if Path::new("/sys").exists() && !Path::new("/sys/class").exists() {
        mount_fs("sysfs", "/sys", "sysfs", 0, "");
    }
    if Path::new("/dev").exists() && !Path::new("/dev/null").exists() {
        mount_fs("devtmpfs", "/dev", "devtmpfs", 0, "");
    }
}

fn parse_cmdline(content: &str) {
    for token in content.split_whitespace() {
        if token.is_empty() {
            continue;
        }
        if let Some(eq_pos) = token.find('=') {
            let (key, value) = token.split_at(eq_pos);
            let value = &value[1..];
            log_info!("cmdline: {} = {}", key, value);
        } else {
            log_info!("cmdline: {} (flag)", token);
        }
    }
}

fn read_cmdline() -> Option<String> {
    let mut cmdline = String::new();
    match File::open("/proc/cmdline").and_then(|mut f| f.read_to_string(&mut cmdline)) {
        Ok(_) => Some(cmdline),
        Err(e) => {
            log_warn!("Failed to read /proc/cmdline: {}", e);
            None
        }
    }
}

fn parse_cmdline_for_root(content: &str) -> Option<String> {
    for token in content.split_whitespace() {
        if let Some(eq_pos) = token.find('=') {
            let (key, value) = token.split_at(eq_pos);
            if key == "root" && value[1..].starts_with("PARTUUID=") {
                let partuuid = &value[1..]["PARTUUID=".len()..];
                return Some(partuuid.to_string());
            }
        }
    }
    None
}

fn find_device_by_partuuid(uuid: &str) -> Option<String> {
    let path = format!("/dev/disk/by-partuuid/{}", uuid.to_lowercase());
    if let Ok(canonical) = fs::canonicalize(&path) {
        canonical.to_str().map(|s| s.to_string())
    } else {
        None
    }
}

fn find_root_by_label(label: &str) -> Option<String> {
    let block_dir = Path::new("/sys/block");
    if !block_dir.exists() {
        return None;
    }

    for entry in fs::read_dir(block_dir).ok()? {
        let entry = entry.ok()?;
        let dev_name = entry.file_name();
        let dev_name = dev_name.to_string_lossy();

        let part_dir = entry.path();
        for part_entry in fs::read_dir(part_dir).ok()? {
            let part_entry = part_entry.ok()?;
            let part_name = part_entry.file_name();
            let part_name = part_name.to_string_lossy();
            if !part_name.starts_with(dev_name.as_ref()) {
                continue;
            }

            let part_path = format!("/dev/{}", part_name);
            let output = Command::new("blkid")
                .arg("-s")
                .arg("LABEL")
                .arg("-o")
                .arg("value")
                .arg(&part_path)
                .output()
                .ok()?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            let label_found = stdout.trim();
            if label_found == label {
                return Some(part_path);
            }
        }
    }
    None
}

// switch root logic
fn move_mount(oldpath: &str, newpath: &str) -> bool {
    let c_old = CString::new(oldpath).expect("CString::new failed");
    let c_new = CString::new(newpath).expect("CString::new failed");
    let ret = unsafe { libc::mount(c_old.as_ptr(), c_new.as_ptr(), ptr::null(), libc::MS_MOVE, ptr::null()) };
    if ret == 0 {
        true
    } else {
        let err = std::io::Error::last_os_error();
        log_warn!("Failed to move mount from {} to {}: {}", oldpath, newpath, err);
        false
    }
}

fn try_switch_root(device: &str) -> bool {
    log_info!("Attempting to switch root to device {}", device);

    if let Err(e) = fs::create_dir("/newroot") {
        log_warn!("Failed to create /newroot: {}", e);
        return false;
    }

    let fstypes = ["ext4", "ext3", "ext2", "btrfs", "xfs", "vfat"];
    let mut mounted = false;
    let mut used_fstype = "";
    for fstype in &fstypes {
        if mount_fs(device, "/newroot", fstype, libc::MS_RDONLY, "") {
            mounted = true;
            used_fstype = fstype;
            break;
        }
    }
    if !mounted {
        log_warn!("Could not mount {} with any known filesystem", device);
        return false;
    }

    if !mount_fs(device, "/newroot", used_fstype, libc::MS_REMOUNT | libc::MS_RELATIME, "") {
        log_warn!("Failed to remount {} read‑write", device);
        let _ = unsafe { libc::umount(CString::new("/newroot").unwrap().as_ptr()) };
        return false;
    }

    if let Err(e) = fs::create_dir("/newroot/oldroot") {
        log_warn!("Failed to create /newroot/oldroot: {}", e);
        let _ = unsafe { libc::umount(CString::new("/newroot").unwrap().as_ptr()) };
        return false;
    }

    if !move_mount("/proc", "/newroot/proc") {
        let _ = unsafe { libc::umount(CString::new("/newroot").unwrap().as_ptr()) };
        return false;
    }
    if !move_mount("/sys", "/newroot/sys") {
        let _ = unsafe { libc::umount(CString::new("/newroot").unwrap().as_ptr()) };
        return false;
    }
    if !move_mount("/dev", "/newroot/dev") {
        let _ = unsafe { libc::umount(CString::new("/newroot").unwrap().as_ptr()) };
        return false;
    }

    let ret = unsafe {
        libc::syscall(
            libc::SYS_pivot_root,
            CString::new("/newroot").unwrap().as_ptr(),
            CString::new("/newroot/oldroot").unwrap().as_ptr(),
        )
    };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        log_warn!("pivot_root failed: {}", err);
        return false;
    }

    if let Err(e) = std::env::set_current_dir("/") {
        log_warn!("chdir to / after pivot_root failed: {}", e);
        return false;
    }

    let c_oldroot = CString::new("/oldroot").unwrap();
    unsafe {
        libc::umount2(c_oldroot.as_ptr(), libc::MNT_DETACH);
    }

    log_info!("Switched root successfully, executing /sbin/init");
    let init_path = CString::new("/sbin/init").unwrap();
    let init_name = CString::new("init").unwrap();
    let args = [init_name.as_ptr(), ptr::null()];
    unsafe {
        libc::execvp(init_path.as_ptr(), args.as_ptr());
    }
    let err = std::io::Error::last_os_error();
    log_error!("execvp /sbin/init failed: {}", err);
    false
}

fn exec_init_from_initrd() -> ! {
    let init_path = CString::new("/sbin/init").unwrap();
    let init_name = CString::new("init").unwrap();
    let args = [init_name.as_ptr(), ptr::null()];
    unsafe {
        libc::execvp(init_path.as_ptr(), args.as_ptr());
    }
    let err = std::io::Error::last_os_error();
    log_error!("execvp /sbin/init from initrd failed: {}", err);
    fatal_error("Cannot start init from initrd");
}

// console handler
fn open_console() {
    let path = CString::new("/dev/console").expect("CString::new failed");
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        log_warn!("Failed to open /dev/console, logging to stdout only");
        return;
    }
    unsafe {
        CONSOLE_FD = fd;
    }
    log_info!("Opened /dev/console for logging");
}

// signal handling
extern "C" fn sigterm_handler(_signo: libc::c_int) {
    SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
}

extern "C" fn sigchld_handler(_signo: libc::c_int) {
    SIGCHLD_RECEIVED.store(true, Ordering::Relaxed);
}

fn setup_signals() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_flags = libc::SA_RESTART;
        sa.sa_sigaction = sigterm_handler as *const () as usize;
        if libc::sigaction(libc::SIGTERM, &sa, ptr::null_mut()) != 0 {
            log_warn!("Failed to set SIGTERM handler");
        }

        sa.sa_sigaction = sigchld_handler as *const () as usize;
        if libc::sigaction(libc::SIGCHLD, &sa, ptr::null_mut()) != 0 {
            log_warn!("Failed to set SIGCHLD handler");
        }
    }
}

// shell spawner
const SHELL_PATHS: &[&str] = &["/bin/bash", "/bin/sh"];

fn decode_status(status: i32) -> String {
    {
        if libc::WIFEXITED(status) {
            format!("exited with code {}", libc::WEXITSTATUS(status))
        } else if libc::WIFSIGNALED(status) {
            format!("terminated by signal {}", libc::WTERMSIG(status))
        } else if libc::WIFSTOPPED(status) {
            format!("stopped by signal {}", libc::WSTOPSIG(status))
        } else {
            format!("unknown status {}", status)
        }
    }
}

fn spawn_shell(tty_path: &str) -> Option<libc::pid_t> {
    for p in SHELL_PATHS {
        if Path::new(p).exists() {
            log_info!("Found shell: {}", p);
        } else {
            log_warn!("Shell not found: {}", p);
        }
    }

    let shell_path = SHELL_PATHS.iter().find(|&&p| Path::new(p).exists())?;
    let shell_path_str = *shell_path;

    std::env::set_var("PATH", "/sbin:/usr/sbin:/bin:/usr/bin");
    std::env::set_var("TERM", "linux");
    std::env::set_var("HOME", "/");
    std::env::set_var("USER", "root");
    std::env::set_var("LD_LIBRARY_PATH", "/lib/x86_64-linux-gnu:/lib64");

    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            libc::setsid();

            let path = CString::new(tty_path).expect("CString failed");
            let fd = libc::open(path.as_ptr(), libc::O_RDWR);
            
            if fd >= 0 {
                libc::ioctl(fd, libc::TIOCSCTTY as _, 1);
                libc::dup2(fd, 0);
                libc::dup2(fd, 1);
                libc::dup2(fd, 2);
                
                let msg = format!("Shell starting on {}...\n", tty_path);
                libc::write(fd, msg.as_ptr() as *const _, msg.len());
                
                if fd > 2 { libc::close(fd); }
            } else {
                let msg = format!("Failed to open {}!\n", tty_path);
                libc::write(1, msg.as_ptr() as *const _, msg.len());
                libc::_exit(1);
            }

            let pgrp = libc::getpid();
            libc::tcsetpgrp(0, pgrp);

            let shell_cstr = CString::new(shell_path_str).expect("CString failed");
            let shell_name = CString::new("sh").expect("CString failed");
            let args = [shell_name.as_ptr(), ptr::null()];

            libc::execvp(shell_cstr.as_ptr(), args.as_ptr());
            libc::_exit(127);
        } else if pid > 0 {
            log_info!("Spawned shell on {} (PID {})", tty_path, pid);
            Some(pid)
        } else {
            log_warn!("fork failed for {}", tty_path);
            None
        }
    }
}

// network
fn setup_dns() -> std::io::Result<()> {
    fs::create_dir_all("/etc")?;
    let mut file = File::create("/etc/resolv.conf")?;
    file.write_all(b"nameserver 8.8.8.8\nnameserver 1.1.1.1\n")?;
    Ok(())
}

fn init_network() {
    log_info!("Initializing network...");
    std::env::set_var("LD_LIBRARY_PATH", "/lib/x86_64-linux-gnu:/lib64");
    std::env::set_var("PATH", "/sbin:/usr/sbin:/bin:/usr/bin");

    match Command::new("ip").args(&["link", "set", "lo", "up"]).status() {
        Ok(status) if status.success() => log_info!("Loopback up"),
        Ok(status) => log_warn!("ip link set lo up failed with status: {}", status),
        Err(e) => log_warn!("Failed to execute ip for loopback: {}", e),
    }

    match Command::new("ip").args(&["link", "set", "eth0", "up"]).status() {
        Ok(status) if status.success() => log_info!("eth0 up"),
        Ok(status) => log_warn!("ip link set eth0 up failed with status: {}", status),
        Err(e) => log_warn!("Failed to execute ip for eth0: {}", e),
    }

    let dhcp_clients = [("udhcpc", &["-i", "eth0"][..]), ("dhcpcd", &["eth0"][..])];
    for (cmd, args) in &dhcp_clients {
        log_info!("Trying {}...", cmd);
        match Command::new(cmd).args(*args).spawn() {
            Ok(_child) => {
                log_info!("Spawned {}", cmd);
                break;
            }
            Err(e) => log_warn!("Failed to execute {}: {}", cmd, e),
        }
    }

    if let Err(e) = setup_dns() {
        log_warn!("Failed to write /etc/resolv.conf: {}", e);
    } else {
        log_info!("/etc/resolv.conf written with static DNS servers");
    }

    thread::sleep(Duration::from_secs(2));

    match Command::new("ip").arg("route").arg("show").output() {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                log_info!("Route: {}", line);
            }
            if stdout.is_empty() {
                log_warn!("No routes found – default gateway may be missing.");
            }
        }
        Ok(output) => log_warn!("ip route show failed with status: {}", output.status),
        Err(e) => log_warn!("Failed to execute ip route show: {}", e),
    }
}

fn main_loop(pid_tty0: &mut libc::pid_t, pid_tty_s0: &mut libc::pid_t) {
    loop {
        if SHUTDOWN_REQUESTED.load(Ordering::Relaxed) {
            log_info!("Shutdown requested, powering off");
            break;
        }

        if SIGCHLD_RECEIVED.load(Ordering::Relaxed) {
            SIGCHLD_RECEIVED.store(false, Ordering::Relaxed);

            loop {
                let mut status = 0;
                let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
                if pid == 0 {
                    break;
                } else if pid == -1 {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::ECHILD) {
                        break;
                    }
                    log_warn!("waitpid error while reaping: {}", err);
                    break;
                }

                if pid == *pid_tty0 {
                    let reason = decode_status(status);
                    log_info!("Shell on /dev/tty0 (PID {}) {} – respawning...", pid, reason);
                    if let Some(new_pid) = spawn_shell("/dev/tty0") {
                        *pid_tty0 = new_pid;
                    } else {
                        *pid_tty0 = -1;
                        log_error!("Failed to respawn shell on /dev/tty0");
                    }
                } else if pid == *pid_tty_s0 {
                    let reason = decode_status(status);
                    log_info!("Shell on /dev/ttyS0 (PID {}) {} – respawning...", pid, reason);
                    if let Some(new_pid) = spawn_shell("/dev/ttyS0") {
                        *pid_tty_s0 = new_pid;
                    } else {
                        *pid_tty_s0 = -1;
                        log_error!("Failed to respawn shell on /dev/ttyS0");
                    }
                } else {
                    let reason = decode_status(status);
                    log_info!("Reaped child process {}: {}", pid, reason);
                }
            }
        }

        if *pid_tty0 == -1 {
            if let Some(pid) = spawn_shell("/dev/tty0") {
                *pid_tty0 = pid;
            }
        }
        if *pid_tty_s0 == -1 {
            if let Some(pid) = spawn_shell("/dev/ttyS0") {
                *pid_tty_s0 = pid;
            }
        }

        unsafe { libc::usleep(100_000) };
    }
}

fn shutdown() -> ! {
    log_info!("Initiating system power-off");
    unsafe {
        libc::sync();
        if libc::reboot(libc::RB_POWER_OFF) == -1 {
            let err = std::io::Error::last_os_error();
            log_error!("reboot(RB_POWER_OFF) failed: {}", err);
        }
    }
    fatal_error("Shutdown failed – now sleeping forever");
}

fn main() {
    std::env::set_var("LD_LIBRARY_PATH", "/lib/x86_64-linux-gnu:/lib64");

    mount_filesystems();

    // give hardware time to settle
    thread::sleep(Duration::from_millis(500));

    let cmdline = read_cmdline().unwrap_or_default();
    parse_cmdline(&cmdline);

    if let Some(uuid) = parse_cmdline_for_root(&cmdline) {
        if let Some(device) = find_device_by_partuuid(&uuid) {
            if try_switch_root(&device) {
            }
        } else {
            log_warn!("No device found for PARTUUID {}", uuid);
        }
    }

    if let Some(device) = find_root_by_label("IGLOO_ROOT") {
        log_info!("Found root partition by label: {}", device);
        if try_switch_root(&device) {
        }
    } else {
        log_info!("No partition with label 'IGLOO_ROOT' found.");
    }

    if Path::new("/sbin/init").exists() {
        log_info!("No root partition switched, executing /sbin/init from initrd");
        exec_init_from_initrd();
    }

    // little fallback
    ensure_virtual_fs();

    unsafe {
        libc::signal(libc::SIGTTIN, libc::SIG_IGN);
        libc::signal(libc::SIGTTOU, libc::SIG_IGN);
    }
    open_console();
    init_network();
    setup_signals();

    let mut pid_tty0 = spawn_shell("/dev/tty0").unwrap_or(-1);
    let mut pid_tty_s0 = spawn_shell("/dev/ttyS0").unwrap_or(-1);

    if pid_tty0 == -1 && pid_tty_s0 == -1 {
        fatal_error("Cannot start any shell");
    }

    main_loop(&mut pid_tty0, &mut pid_tty_s0);
    shutdown();
}