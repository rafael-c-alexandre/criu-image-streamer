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

//! Executable entry point. Imports lib.rs via the criu_image_streamer crate.

// Unless we are in release mode, allow dead code, unused imports and variables,
// it makes development more enjoyable.
#![cfg_attr(debug_assertions, allow(dead_code, unused_imports, unused_variables))]

#[macro_use]
extern crate anyhow;

use std::{
    os::unix::io::FromRawFd,
    path::PathBuf,
    fs,
};
use structopt::{StructOpt, clap::AppSettings};
use criu_image_streamer::{
    capture::capture,
    extract::{serve, extract},
};
use nix::unistd::dup;
use anyhow::{Result, Context};
use criu_image_streamer::capture::dump;

fn parse_port_remap(s: &str) -> Result<(u16, u16)> {
    let mut parts = s.split(':');
    Ok(match (parts.next(), parts.next(), parts.next()) {
        (Some(old_port), Some(new_port), None) => {
            let old_port = old_port.parse().context("Provided old_port is not a u16 integer")?;
            let new_port = new_port.parse().context("Provided new_port is not a u16 integer")?;
            (old_port, new_port)
        },
        _ => bail!("Format is old_port:new_port")
    })
}

#[derive(StructOpt, PartialEq, Debug)]
#[structopt(about,
    // When showing --help, we want to keep the order of arguments defined
    // in the `Opts` struct, as opposed to the default alphabetical order.
    global_setting(AppSettings::DeriveDisplayOrder),
    // help subcommand is not useful, disable it.
    global_setting(AppSettings::DisableHelpSubcommand),
    // subcommand version is not useful, disable it.
    global_setting(AppSettings::VersionlessSubcommands),
)]
struct Opts {
    /// Images directory where the CRIU UNIX socket is created during streaming operations.
    // The short option -D mimics CRIU's short option for its --images-dir argument.
    #[structopt(short = "D", long)]
    images_dir: PathBuf,

    /// PID for the Application root PID needed when the operation
    /// is dump.
    #[structopt(short, long, require_delimiter = true)]
    app_pid: Option<i32>,

    /// External files to incorporate/extract in/from the image. Format is filename:fd
    /// where filename corresponds to the name of the file, fd corresponds to the pipe
    /// sending or receiving the file content. Multiple external files may be passed as
    /// a comma separated list.
    #[structopt(short, long, require_delimiter = true)]
    ext_files: Vec<PathBuf>,

    /// Option to be used in the extract/serve commands when the user wants ext-files
    /// that are incorporated in the checkpointed image to be retrieved as well.
    /// It is responsibility of the user to guarantee that those files were previously
    /// added to the tarball.
    #[structopt(short, long)]
    pick_ext_files: bool,

    /// Option to be used to define a pipe to where a the image is redirected to / retrieved
    /// from. If no pipe definition is given, it reverts back to the defaults.
    #[structopt(short = "P", long)]
    criu_pipe: Option<String>,

    /// File descriptor where to report progress. Defaults to 2.
    // The default being 2 is a bit of a lie. We dup(STDOUT_FILENO) due to ownership issues.
    #[structopt(short, long)]
    progress_fd: Option<i32>,

    /// When serving the image, remap on the fly the TCP listen socket ports.
    /// Format is old_port:new_port. May only be used with the serve operation.
    /// Multiple tcp port remaps may be passed as a comma separated list.
    #[structopt(long, parse(try_from_str=parse_port_remap), require_delimiter = true)]
    tcp_listen_remap: Vec<(u16, u16)>,

    #[structopt(subcommand)]
    operation: Operation,
}

#[derive(StructOpt, PartialEq, Debug)]
enum Operation {
    /// Capture a CRIU image
    Capture,

    /// Dump a CRIU images and captures it
    Dump,

    /// Serve a captured CRIU image to CRIU
    Serve,

    /// Serve a captured CRIU image to CRIU and restores the application
    Restore,

    /// Extract a captured CRIU image to the specified images_dir
    Extract,
}

fn do_main() -> Result<()> {
    use Operation::*;

    let opts: Opts = Opts::from_args();

    let progress_pipe = {
        let progress_fd = match opts.progress_fd {
            Some(fd) => fd,
            None => dup(libc::STDERR_FILENO)?
        };
        unsafe { fs::File::from_raw_fd(progress_fd) }
    };

    let criu_pipe = {
        match opts.operation {
            Dump | Capture => {
                match opts.criu_pipe {
                    // Criu pipe defaults to -> 'lz4 - - | aws s3 cp - s3://criu-bucket/img-test.lz4'
                    Some(pipe) => pipe,
                    None => String::from("lz4 - - | aws s3 cp - s3://criu-bucket/img-test.lz4")
                }
            }
            Restore | Serve | Extract => {
                match opts.criu_pipe {
                    // Criu pipe defaults to -> 'aws s3 cp s3://criu-bucket/img-test.lz4 - | lz4 -d - -'
                    Some(pipe) => pipe,
                    None => String::from("aws s3 cp s3://criu-bucket/img-test.lz4 - | lz4 -d - -")
                }
            }
        }
    };

    ensure!((opts.operation == Dump && opts.app_pid.is_some()) || (opts.operation != Dump && opts.app_pid.is_none()),
                "--app-pid is required and only supported when dumping the application");

    ensure!(opts.ext_files.is_empty() || (opts.operation == Capture || opts.operation == Dump),
                "--ext-files is only supported when capturing/dumping the image");

    ensure!(!opts.pick_ext_files || (opts.operation == Serve || opts.operation == Extract || opts.operation == Restore),
                "--pick-ext-files is only supported when serving/extracting/restoring the image");

    ensure!(opts.operation == Serve || opts.operation == Restore || opts.tcp_listen_remap.is_empty(),
            "--tcp-listen-remap is only supported when serving or restoring the image");

    match opts.operation {
        Capture => capture(&opts.images_dir, progress_pipe, opts.ext_files, criu_pipe),
        Dump => dump(&opts.images_dir, progress_pipe, opts.ext_files, opts.app_pid, criu_pipe),
        Extract => extract(&opts.images_dir, progress_pipe, opts.pick_ext_files, criu_pipe),
        Serve =>   serve(&opts.images_dir, progress_pipe, opts.pick_ext_files, opts.tcp_listen_remap, String::from("serve"), criu_pipe),
        Restore =>   serve(&opts.images_dir, progress_pipe, opts.pick_ext_files, opts.tcp_listen_remap, String::from("restore"), criu_pipe),
    }
}

fn main() {
    if let Err(e) = do_main() {
        eprintln!("criu-image-streamer Error: {:#}", e);
    }
}


#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn test_capture_basic() {
        assert_eq!(Opts::from_iter(&vec!["prog", "--images-dir", "imgdir", "capture"]),
            Opts {
                images_dir: PathBuf::from("imgdir"),
                app_pid: None,
                ext_files: vec![],
                tcp_listen_remap: vec![],
                progress_fd: None,
                operation: Operation::Capture,
                pick_ext_files: false,
                criu_pipe: None
            })
    }

    #[test]
    fn test_extract_basic() {
        assert_eq!(Opts::from_iter(&vec!["prog", "-D", "imgdir", "extract"]),
            Opts {
                images_dir: PathBuf::from("imgdir"),
                app_pid: None,
                ext_files: vec![],
                tcp_listen_remap: vec![],
                progress_fd: None,
                operation: Operation::Extract,
                pick_ext_files: false,
                criu_pipe: None
            })
    }

    #[test]
    fn test_extract_serve() {
        assert_eq!(Opts::from_iter(&vec!["prog", "-D", "imgdir", "serve"]),
            Opts {
                images_dir: PathBuf::from("imgdir"),
                app_pid: None,
                ext_files: vec![],
                tcp_listen_remap: vec![],
                progress_fd: None,
                operation: Operation::Serve,
                pick_ext_files: false,
                criu_pipe: None
            })
    }


    #[test]
    fn test_shards_fds() {
        assert_eq!(Opts::from_iter(&vec!["prog", "--images-dir", "imgdir", "--shard-fds", "1,2,3", "capture"]),
            Opts {
                images_dir: PathBuf::from("imgdir"),
                app_pid: None,
                ext_files: vec![],
                tcp_listen_remap: vec![],
                progress_fd: None,
                operation: Operation::Capture,
                pick_ext_files: false,
                criu_pipe: None
            })
    }

    #[test]
    fn test_ext_files() {
        assert_eq!(Opts::from_iter(&vec!["prog", "--images-dir", "imgdir", "--ext-files", "file1,file2", "capture"]),
            Opts {
                images_dir: PathBuf::from("imgdir"),
                app_pid: None,
                ext_files: vec![(PathBuf::from("file1")), (String::from("file2"))],
                tcp_listen_remap: vec![],
                progress_fd: None,
                operation: Operation::Capture,
                pick_ext_files: false,
                criu_pipe: None
            })
    }

    #[test]
    fn test_tcp_listen_remaps() {
        assert_eq!(Opts::from_iter(&vec!["prog", "--images-dir", "imgdir", "--tcp-listen-remap", "2000:3000,5000:6000", "serve"]),
            Opts {
                images_dir: PathBuf::from("imgdir"),
                app_pid: None,
                ext_files: vec![],
                tcp_listen_remap: vec![(2000,3000),(5000,6000)],
                progress_fd: None,
                operation: Operation::Serve,
                pick_ext_files: false,
                criu_pipe: None
            })
    }

    #[test]
    fn test_progess_fd() {
        assert_eq!(Opts::from_iter(&vec!["prog", "--images-dir", "imgdir", "--progress-fd", "3", "capture"]),
            Opts {
                images_dir: PathBuf::from("imgdir"),
                app_pid: None,
                ext_files: vec![],
                tcp_listen_remap: vec![],
                progress_fd: Some(3),
                operation: Operation::Capture,
                pick_ext_files: false,
                criu_pipe: None
            })
    }
}

