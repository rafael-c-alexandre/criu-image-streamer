//  Copyright 2020 Two Sigma Investments, LP.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

use prost::Message;
use std::{
    mem::size_of,
    os::unix::net::UnixStream,
    os::unix::io::{RawFd, AsRawFd, FromRawFd},
    io::{Read, Write},
    path::Path,
    fs,
};
use nix::{
    fcntl::{fcntl, FcntlArg, FdFlag, OFlag},
    sys::socket::{ControlMessageOwned, MsgFlags, recvmsg},
    sys::uio::IoVec,
    unistd::{sysconf, SysconfVar},
    unistd::pipe2,
};
use crate::{
    command::*,
};

use bytes::{BytesMut, Buf, BufMut};
use serde::Serialize;
use serde_json::Value;
use anyhow::{Result, Context};
use std::path::PathBuf;
use std::collections::HashSet;

pub const KB: usize = 1024;
pub const MB: usize = 1024*1024;
pub const EOF_ERR_MSG: &str = "EOF unexpectedly reached";

lazy_static::lazy_static! {
    pub static ref PAGE_SIZE: usize = sysconf(SysconfVar::PAGE_SIZE)
        .expect("Failed to determine PAGE_SIZE")
        .expect("Failed to determine PAGE_SIZE") as usize;

    static ref TAR_CMD: String = std::env::var("TAR_CMD")
        .unwrap_or_else(|_| "tar".to_string());
}

/// read_bytes_next() attempts to read exactly the number of bytes requested.
/// If we are at EOF, it returns Ok(None).
/// If it can read the number of bytes requested, it returns Ok(bytes_requested).
/// Otherwise, it returns Err("EOF error").
pub fn read_bytes_next<S: Read>(src: &mut S, len: usize) -> Result<Option<BytesMut>> {
    let mut buf = Vec::with_capacity(len);
    src.take(len as u64).read_to_end(&mut buf).context("Failed to read protobuf")?;
    Ok(match buf.len() {
        0 => None,
        l if l == len => Some(buf[..].into()),
        _ => bail!(EOF_ERR_MSG),
    })
}

/// pb_read_next() is useful to iterate through a stream of protobuf objects.
/// It returns Ok(obj) for each object to be read, and Ok(None) when EOF is reached.
/// It returns an error if an object is only partially read, or any deserialization error.
pub fn pb_read_next<S: Read, T: Message + Default>(src: &mut S) -> Result<Option<(T, usize)>> {
    Ok(match read_bytes_next(src, size_of::<u32>())? {
        None => None,
        Some(mut size_buf) => {
            let size = size_buf.get_u32_le() as usize;
            assert!(size < 10*KB, "Would read a protobuf of size >10KB. Something is wrong");
            let buf = read_bytes_next(src, size)?.ok_or_else(|| anyhow!(EOF_ERR_MSG))?;
            let bytes_read = size_of::<u32>() + size_buf.len() + buf.len();
            Some((T::decode(buf)?, bytes_read))
        }
    })
}

pub fn pb_read<S: Read, T: Message + Default>(src: &mut S) -> Result<T> {
    Ok(match pb_read_next(src)? {
        None => bail!(EOF_ERR_MSG),
        Some((obj, _size)) => obj,
    })
}

pub fn pb_write<S: Write, T: Message>(dst: &mut S, msg: &T) -> Result<usize> {
    let msg_size = msg.encoded_len();
    let mut buf = BytesMut::with_capacity(size_of::<u32>() + msg_size);
    assert!(msg_size < 10*KB, "Would serialize a protobuf of size >10KB. Something is wrong");
    buf.put_u32_le(msg_size as u32);

    msg.encode(&mut buf).context("Failed to encode protobuf")?;
    dst.write_all(&buf).context("Failed to write protobuf")?;

    Ok(buf.len())
}

pub fn recv_fd(socket: &mut UnixStream) -> Result<RawFd> {
    let mut cmsgspace = nix::cmsg_space!([RawFd; 1]);

    let msg = recvmsg(socket.as_raw_fd(),
                      &[IoVec::from_mut_slice(&mut [0])],
                      Some(&mut cmsgspace),
                      MsgFlags::empty())
        .context("Failed to read fd from socket")?;

    Ok(match msg.cmsgs().next() {
        Some(ControlMessageOwned::ScmRights(fds)) if fds.len() == 1 => fds[0],
        _ => bail!("No fd received"),
    })
}

pub fn emit_progress(progress_pipe: &mut fs::File, msg: &str) {
    // Writes to the progress pipe can fail. The parent may have closed that pipe, and we don't
    // need to get upset about failing reporting progress.
    let _ = writeln!(progress_pipe, "{}", msg);
}

pub fn create_dir_all(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir)
        .with_context(|| format!("Failed to create directory {}", dir.display()))
}

pub fn check_file_exists(file: &Path) -> bool {
    assert!(file.exists(),
        "The file {} is not accessible", file.display());
    true
}

pub fn tar_cmd(ext_files_paths: &Vec<PathBuf>, stdout: fs::File) -> Command {

    // Check if each file exists before advancing.
    ext_files_paths.into_iter().all(|path_buf| check_file_exists(&path_buf));

    // Remove duplicates from vec.
    let ext_files_paths_set : HashSet<_> = ext_files_paths.iter().cloned().collect();

    let mut cmd = Command::new(&[&*TAR_CMD]);

    // TODO We can't emit log lines during tarring, because we log them
    // And the log file is included in the tar archive. tar detects that the log file
    // is changing, and fails, ruining the fun. So we don't pass --verbose on tar for now
    // as it would emit output during tarring. We can come back to that issue later.
    /*
    if log_enabled!(log::Level::Trace) {
        cmd.arg("--verbose");
    }
    */

    cmd.args(&[
        "--directory", "/",
        "--create",
        "--preserve-permissions",
        "--ignore-failed-read", // Allows us to discard EPERM errors of files in /tmp
        "--sparse", // Support sparse files efficiently, libvirttime uses one
        "--file", "-",
    ])
        .args(&ext_files_paths_set)
        .stdout(Stdio::from(stdout));
    cmd
}

pub fn untar_cmd(stdin: fs::File) -> Command {
    let mut cmd = Command::new(&[&*TAR_CMD]);

    cmd.args(&[
        "--directory", "/",
        "--extract",
        "--preserve-permissions",
        "--no-overwrite-dir",
        "--file", "-",
    ])
        .stdin(Stdio::from(stdin));
    cmd
}

pub fn criu_dump_cmd(app_root_id: i32) -> Command {
    let mut cmd = Command::new(&[
        "criu", "dump",
        "--tree", &app_root_id.to_string(),
    ]);

    add_common_criu_opts(&mut cmd);

    cmd
}

pub fn criu_restore_cmd() -> Command {
    let mut cmd = Command::new(&[
        "criu", "restore",
        "--restore-sibling", "--restore-detached", // Become parent of the app (CLONE_PARENT)
    ]);

    add_common_criu_opts(&mut cmd);

    cmd
}

fn add_common_criu_opts(cmd: &mut Command) {
    cmd.arg("--images-dir").arg("/tmp");
    cmd.args(&[
        "--shell-job",  // Support attached TTYs
        "--stream",     // Use criu-image-streamer
    ]);
}


pub trait JsonMerge {
    fn merge(self, b: Value) -> Self;
}

impl JsonMerge for Value {
    fn merge(self, b: Value) -> Self {
        match (self, b) {
            (Value::Object(mut a), Value::Object(b)) => {
                a.extend(b);
                Value::Object(a)
            }
            _ => panic!()
        }
    }
}

pub struct Pipe {
    pub read: fs::File,
    pub write: fs::File,
}

impl Pipe {
    pub fn new(flags: OFlag) -> Result<Self> {
        let (fd_r, fd_w) = pipe2(flags).context("Failed to create a pipe")?;
        let read = unsafe { fs::File::from_raw_fd(fd_r) };
        let write = unsafe { fs::File::from_raw_fd(fd_w) };
        Ok(Self { read, write })
    }

    pub fn new_input() -> Result<Self> {
        let pipe = Self::new(OFlag::empty())?;
        fcntl(pipe.write.as_raw_fd(), FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
        Ok(pipe)
    }

    pub fn new_output() -> Result<Self> {
        let pipe = Self::new(OFlag::empty())?;
        fcntl(pipe.read.as_raw_fd(), FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
        Ok(pipe)
    }

}

#[derive(Serialize)]
pub struct IntermediateStats {
    pub shards: Vec<ShardStat>,
}

#[derive(Serialize)]
pub struct CheckpointStats {
    pub shards: Vec<ShardStat>,
    pub checkpoint_duration_seconds: f32,
}

#[derive(Serialize)]
pub struct RestoreStats {
    pub shards: Vec<ShardStat>,
    pub restore_duration_seconds: f32,
}

#[derive(Serialize)]
pub struct ShardStat {
    pub size: u64,
    pub transfer_duration_seconds: f32,
}
