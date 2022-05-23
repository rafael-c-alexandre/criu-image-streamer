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

//! We use a lib.rs file for building integration tests.

// Unless we are in release mode, allow dead code, unused imports and variables,
// it makes development more enjoyable.
#![cfg_attr(debug_assertions, allow(dead_code, unused_imports, unused_variables))]

#[macro_use]
extern crate anyhow;
#[macro_use]
extern crate serde_json;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;

pub mod util;
pub mod capture;
pub mod extract;
pub mod poller;
pub mod unix_pipe;
pub mod criu_connection;
pub mod ord_by;
pub mod image_patcher;
pub mod image_store;
pub mod mmap_buf;
pub mod command;
pub mod process;
pub mod error;
pub mod stderr_logger;
pub mod signal;
pub mod monitor;

// Protobufs definitions are defined in ../proto/
#[allow(clippy::all)]
pub mod criu {
    include!(concat!(env!("OUT_DIR"), "/criu.rs"));
}
#[allow(clippy::all)]
pub mod image {
    include!(concat!(env!("OUT_DIR"), "/image.rs"));
}

/// Exit code we return when encountering a fatal error.
/// We use 170 to distinguish from the application error codes.
pub const EXIT_CODE_FAILURE: u8 = 170;

#[derive(Debug)]
pub struct ExitCode(pub u8);
impl std::fmt::Display for ExitCode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Exiting with exit_code={}", self.0)
    }
}

impl ExitCode {
    pub fn from_error(e: &anyhow::Error) -> u8 {
        e.downcast_ref::<Self>()
            .map(|exit_code| exit_code.0)
            .unwrap_or(EXIT_CODE_FAILURE)
    }
}
