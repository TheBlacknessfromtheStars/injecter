use libc::{iovec, pid_t};
use std::{
    fs::File,
    io::{BufRead, BufReader},
    os::raw::c_void,
};

use libc;

#[derive(Debug)]
pub struct MapInfo {
    start: usize,
    end: usize,
    perms: i32,
    is_private: bool,
    offset: usize,
    dev: libc::dev_t,
    ino: libc::ino_t,
    path: String,
}

impl MapInfo {
    fn parse_maps_line(line: &str) -> Option<MapInfo> {
        let parts: Vec<&str> = line.splitn(6, ' ').collect();
        let path = if parts[5].is_empty() {
            parts[5].trim_start().to_string()
        } else {
            String::new()
        };

        let perms_str = parts[1];
        let offset_str = parts[2];
        let ino_str = parts[4];

        let (start_str, end_str) = parts[0].split_once('-').unwrap();
        let start = usize::from_str_radix(start_str, 16).ok()?;
        let end = usize::from_str_radix(end_str, 16).ok()?;

        let perms_chars: Vec<char> = perms_str.chars().collect();
        if perms_chars.len() < 4 {
            return None;
        }
        let mut perms = 0;
        let is_private = perms_chars[3] == 'p';
        for ch in perms_chars.into_iter() {
            match ch {
                'r' => perms |= libc::PROT_READ,
                'w' => perms |= libc::PROT_WRITE,
                'x' => perms |= libc::PROT_EXEC,
                _ => continue,
            };
        }

        let offset = usize::from_str_radix(offset_str, 16).ok()?;

        let (major_str, minor_str) = parts[3].split_once(':').unwrap();
        let ma = u32::from_str_radix(major_str, 16).unwrap();
        let mi = u32::from_str_radix(minor_str, 16).unwrap();
        let dev = libc::makedev(ma, mi);
        let ino = libc::ino_t::from_str_radix(ino_str, 16).unwrap();

        Some(MapInfo {
            start,
            end,
            perms,
            is_private,
            offset,
            dev,
            ino,
            path,
        })
    }

    pub fn Scan(pid: &str) -> Vec<MapInfo> {
        let mut infos: Vec<MapInfo> = Vec::new();
        let path = format!("/proc/{}/maps", pid);

        let file = match File::open(&path) {
            Ok(f) => f,
            Err(e) => {
                eprint!("open {} failed: {}", path, e);
                return infos;
            }
        };

        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    eprint!("filed to read maps file: {}", e);
                    continue;
                }
            };

            if let Some(info) = Self::parse_maps_line(&line) {
                infos.push(info);
            }
        }

        infos
    }
}

pub fn write_proc(pid: pid_t, remote_addr: usize, buf: *mut c_void, len: usize) -> isize {
    let local = libc::iovec {
        iov_base: buf,
        iov_len: len,
    };

    let remote = libc::iovec {
        iov_base: remote_addr as *mut c_void,
        iov_len: len,
    };

    let l = unsafe {
        libc::process_vm_writev(
            pid,
            &local as *const libc::iovec,
            1,
            &remote as *const libc::iovec,
            1,
            0,
        )
    };

    if l == -1 {
        eprintln!("写入失败");
    } else if (l as usize) < len {
        eprintln!("");
    }

    l
}

pub fn read_proc(pid: pid_t, remote_addr: usize, buf: *mut c_void, len: usize) -> isize {
    let local = libc::iovec {
        iov_base: buf,
        iov_len: len,
    };

    let remote = libc::iovec {
        iov_base: remote_addr as *mut c_void,
        iov_len: len,
    };

    let l = unsafe {
        libc::process_vm_readv(
            pid,
            &local as *const libc::iovec,
            1,
            &remote as *const libc::iovec,
            1,
            0,
        )
    };

    if l == -1 {
        eprintln!("读取失败");
    } else if (l as usize) < len {
        eprintln!("");
    }

    l
}
