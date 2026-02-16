#![deny(warnings)]

extern crate libc;

use core::sync::atomic::{AtomicBool, Ordering};
use std::ffi::CString;
use std::fs::File;
use std::io::Read;
use std::ptr;

// very cool signal handler
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
    mount_fs("proc", "/proc", "proc", 0, "");
    mount_fs("sysfs", "/sys", "sysfs", 0, "");
    
    if !mount_fs("devtmpfs", "/dev", "devtmpfs", 0, "") {
        log_info!("/dev already mounted by kernel or failed, skipping fallback");
    }
}

// kernel command line parser
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

fn process_cmdline() {
    let mut cmdline = String::new();
    match File::open("/proc/cmdline").and_then(|mut f| f.read_to_string(&mut cmdline)) {
        Ok(_) => parse_cmdline(&cmdline),
        Err(e) => log_warn!("Failed to read /proc/cmdline: {}", e),
    }
}

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

const SHELL_PATH: &str = "/bin/bash";

fn spawn_shell() -> Option<libc::pid_t> {
    std::env::set_var("PATH", "/sbin:/usr/sbin:/bin:/usr/bin");

    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            libc::setsid();

            let path = CString::new("/dev/console").expect("CString failed");
            let fd = libc::open(path.as_ptr(), libc::O_RDWR);
            
            if fd >= 0 {
                libc::ioctl(fd, libc::TIOCSCTTY as _, 1);
                
                libc::dup2(fd, 0);
                libc::dup2(fd, 1);
                libc::dup2(fd, 2);
                
                if fd > 2 { libc::close(fd); }
            }

            let pgrp = libc::getpid();
            libc::tcsetpgrp(0, pgrp);

            let shell_path = CString::new(SHELL_PATH).expect("CString failed");
            let shell_name = CString::new("bash").expect("CString failed");

            let args = [
                shell_name.as_ptr(),
                ptr::null()
            ];

            libc::execvp(shell_path.as_ptr(), args.as_ptr());
            libc::_exit(1);
        } else if pid > 0 {
            log_info!("Spawned shell (PID {})", pid);
            Some(pid)
        } else {
            None
        }
    }
}

fn main_loop() {
    let mut child_pid = match spawn_shell() {
        Some(pid) => pid,
        None => {
            fatal_error("Cannot start shell");
        }
    };

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

                if pid == child_pid {
                    log_info!("Shell (PID {}) exited with status {}, respawning...", child_pid, status);
                    match spawn_shell() {
                        Some(new_pid) => child_pid = new_pid,
                        None => fatal_error("Cannot respawn shell"),
                    }
                } else {
                    log_info!("Reaped child process {}", pid);
                }
            }
        }

        unsafe { libc::usleep(100_000) };
    }
}

// PC shutdown
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

// entry point
fn main() {
    mount_filesystems();
    
    unsafe {
        libc::signal(libc::SIGTTIN, libc::SIG_IGN);
        libc::signal(libc::SIGTTOU, libc::SIG_IGN);
    }

    open_console();
    process_cmdline();
    setup_signals();
    main_loop();
    shutdown();
}