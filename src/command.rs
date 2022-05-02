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

use anyhow::{Result, Context};
use std::{
    borrow::Cow,
    io::Result as IoResult,
    os::unix::io::AsRawFd,
    ffi::{OsString, OsStr},
    collections::HashMap,
    process::Command as StdCommand,
    os::unix::process::CommandExt,
};
use nix::{
    fcntl::{fcntl, FcntlArg, FdFlag, OFlag},
};
use crate::util::Pipe;

// We re-export these, as they are part of our API
pub use std::process::{
    ExitStatus, Stdio, ChildStdin, ChildStdout, ChildStderr, Output
};
use crate::process::Process;

pub type EnvVars = HashMap<OsString, OsString>;

// We wrap the standard library `Command` to provide additional features:
// * Logging of the command executed, and failures
// * setpgrp()
// We have to delegate a few methods to the inner `StdCommand`, which makes it a bit verbose.
// We considered the subprocess crate, but it wasn't very useful, and it lacked
// the crucial feature of pre_exec() that the standard library has for doing setpgrp().

pub struct Command {
    inner: StdCommand,
    display_args: Vec<String>,
    show_cmd_on_spawn: bool,
    stderr_log_prefix: Option<Cow<'static, str>>,
}

impl Command {
    pub fn new<I: IntoIterator<Item = S>, S: AsRef<OsStr>>(args: I) -> Self {
        let mut args = args.into_iter();
        let program = args.next().unwrap(); // unwrap() is fine as we never pass empty args
        let mut cmd = Self {
            inner: StdCommand::new(&program),
            display_args: vec![Self::arg_for_display(&program)],
            show_cmd_on_spawn: true,
            stderr_log_prefix: None,
        };
        cmd.args(args);
        cmd
    }

    pub fn new_shell<S: AsRef<OsStr>>(script: S) -> Self {
        // We use bash for pipefail support
        let mut inner = StdCommand::new("/bin/bash");
        inner.arg("-o").arg("pipefail")
            .arg("-c").arg(&script)
            .arg("--");
        Self {
            inner,
            display_args: vec![Self::arg_for_display(&script)],
            show_cmd_on_spawn: true,
            stderr_log_prefix: None,
        }
    }

    pub fn arg<S: AsRef<OsStr>>(&mut self, arg: S) -> &mut Self {
        self.display_args.push(Self::arg_for_display(&arg));
        self.inner.arg(&arg);
        self
    }

    pub fn arg_for_display<S: AsRef<OsStr>>(arg: S) -> String {
        arg.as_ref().to_string_lossy().into_owned()
    }

    pub fn args<I: IntoIterator<Item = S>, S: AsRef<OsStr>>(&mut self, args: I) -> &mut Self {
        for arg in args { self.arg(arg); }
        self
    }

    pub fn set_child_subreaper(&mut self) -> &mut Self {
        let pre_exec_fn = || {
            let res = unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER) };
            if let Err(e) = nix::errno::Errno::result(res) {
                error!("Failed to set PR_SET_CHILD_SUBREAPER, proceeding anyways: {}", e);
            }
            Ok(())
        };
        unsafe { self.pre_exec(pre_exec_fn) }
    }

    pub fn show_cmd_on_spawn(&mut self, value: bool) -> &mut Self {
        self.show_cmd_on_spawn = value;
        self
    }

    pub fn spawn(&mut self) -> Result<Process> {
        let display_cmd = self.display_args.join(" ");
        let inner = self.inner.spawn()
            .with_context(|| format!("Failed to spawn `{}`", display_cmd))?;
        if self.show_cmd_on_spawn {
            debug!("+ {}", display_cmd);
        }
        Ok(Process::new(inner, display_cmd, self.stderr_log_prefix.clone()))
    }

    pub fn exec(&mut self) -> Result<()> {
        bail!(self.inner.exec())
    }

    /// `enable_stderr_logging` enables two things:
    /// 1) stderr is emitted via our logging facilities (info!()).
    ///    log lines are prefixed with `log_prefix`.
    /// 2) A fixed sized backlog is kept, and included in the error message.
    /// The process' stderr is drained when calling try_wait(), wait(), or drain_stderr_logger().
    pub fn enable_stderr_logging<S>(&mut self, log_prefix: S) -> &mut Command
        where S: Into<Cow<'static, str>>
    {
        self.stderr_log_prefix = Some(log_prefix.into());
        // We'd also like to redirect stdout to stderr in some cases.
        // But I can't find a way to do this in a simple way with the Rust std library.
        self.stderr(Stdio::piped());
        self
    }
}

// These are delegates to the inner `StdCommand`.
impl Command {
    pub fn env<K: AsRef<OsStr>, V: AsRef<OsStr>>(&mut self, key: K, val: V) -> &mut Command
    { self.inner.env(key, val); self }
    pub fn envs<I: IntoIterator<Item = (K, V)>, K: AsRef<OsStr>, V: AsRef<OsStr>>(&mut self, vars: I) -> &mut Command
    { self.inner.envs(vars); self }
    pub fn env_remove<K: AsRef<OsStr>>(&mut self, key: K) -> &mut Command
    { self.inner.env_remove(key); self }
    pub fn env_clear(&mut self) -> &mut Command
    { self.inner.env_clear(); self }
    pub fn stdin<T: Into<Stdio>>(&mut self, cfg: T) -> &mut Command
    { self.inner.stdin(cfg); self }
    pub fn stdout<T: Into<Stdio>>(&mut self, cfg: T) -> &mut Command
    { self.inner.stdout(cfg); self }
    pub fn stderr<T: Into<Stdio>>(&mut self, cfg: T) -> &mut Command
    { self.inner.stderr(cfg); self }
    #[allow(clippy::missing_safety_doc)]
    pub unsafe fn pre_exec<F>(&mut self, f: F) -> &mut Command
        where
            F: FnMut() -> IoResult<()> + Send + Sync + 'static
    { self.inner.pre_exec(f); self }
}
