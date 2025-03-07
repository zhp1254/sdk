// Copyright (C) 2019-2023 Aleo Systems Inc.
// This file is part of the Aleo SDK library.

// The Aleo SDK library is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// The Aleo SDK library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with the Aleo SDK library. If not, see <https://www.gnu.org/licenses/>.

//!
//! [![Crates.io](https://img.shields.io/crates/v/aleo-wasm.svg?color=neon)](https://crates.io/crates/aleo-wasm)
//! [![Authors](https://img.shields.io/badge/authors-Aleo-orange.svg)](https://aleo.org)
//! [![License](https://img.shields.io/badge/License-GPLv3-blue.svg)](./LICENSE.md)
//!
//! [![github]](https://github.com/ProvableHQ/sdk)&ensp;[![crates-io]](https://crates.io/crates/aleo-wasm)&ensp;[![docs-rs]](https://docs.rs/aleo-wasm/latest/aleo-wasm/)
//!
//! [github]: https://img.shields.io/badge/github-8da0cb?style=for-the-badge&labelColor=555555&logo=github
//! [crates-io]: https://img.shields.io/badge/crates.io-fc8d62?style=for-the-badge&labelColor=555555&logo=rust
//! [docs-rs]: https://img.shields.io/badge/docs.rs-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs
//!
//! # Aleo Wasm
//!
//! Aleo JavaScript and WebAssembly bindings for building zero-knowledge web applications.
//!
//! `Rust` compiles easily to `WebAssembly` but creating the glue code necessary to use compiled WebAssembly binaries
//! from other languages such as JavaScript is a challenging task. `wasm-bindgen` is a tool that simplifies this process by
//! auto-generating JavaScript bindings to Rust code that has been compiled into WebAssembly.
//!
//! This crate uses `wasm-bindgen` to create JavaScript bindings to Aleo source code so that it can be used to create zero
//! knowledge proofs directly within `web browsers` and `NodeJS`.
//!
//! Functionality exposed by this crate includes:
//! * Aleo account management objects
//! * Aleo primitives such as `Records`, `Programs`, and `Transactions` and their associated helper methods
//! * A `ProgramManager` object that contains methods for authoring, deploying, and interacting with Aleo programs
//!
//! More information on these concepts can be found at the [Aleo Developer Hub](https://developer.aleo.org/concepts).
//!
//! ## Usage
//! The [wasm-pack](https://crates.io/crates/wasm-pack) tool is used to compile the Rust code in this crate into JavaScript
//! modules which can be imported into other JavaScript projects.
//!
//! #### Install Wasm-Pack
//! ```bash
//! curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
//! ```
//!
//! ### Build Instructions
//! The general syntax for compiling rust into WebAssembly based JavaScript modules with
//! [wasm-pack](https://crates.io/crates/wasm-pack) is as follows:
//! ```bash
//! wasm-pack build --target <target> --out-dir <out-dir> -- --features <crate-features>
//! ```
//!
//! Invoking this command will build a JavaScript module in the current directory with the default name `pkg` (which can
//! be changed as necessary using the `--out-dir` flag). This folder can then be imported directly as a JavaScript module
//! by other JavaScript modules.
//!
//! There are 3 possible JavaScript modules that [wasm-pack](https://crates.io/crates/wasm-pack) can be used to generate
//! when run within this crate:
//! 1. **NodeJS module:** Used to build NodeJS applications.
//! 2. **Single-Threaded browser module:** Used to build browser-based web applications.
//! 3. **Multi-Threaded browser module:** Used to build browser-based web applications which use web-worker based
//! multi-threading to achieve significant performance increases.
//!
//! These 3 modules and how to build them are explained in more detail below.
//!
//! ### 1. NodeJS Module
//!
//! This module has the features of the NodeJS environment built-in. It is single-threaded and unfortunately cannot yet be
//! used to generate Aleo program executions or deployments due to current Aleo protocol limitations. It can however still
//! be used to perform Aleo account, record, and program management tasks.
//!
//! #### Build Instructions
//! ```bash
//! wasm-pack build --release --target nodejs -- --features "serial" --no-default-features
//! ```
//!
//! ### 2. Single-Threaded browser module
//!
//! This module is very similar to the NodeJS module, however it is built to make use browser-based JavaScript environments
//! and can be used for program execution and deployment.
//!
//! If used for program execution or deployment, it suggested to do so on a web-worker as these operations are long-running
//! and will cause a browser window to hang if run in the main thread.
//!
//! #### Build Instructions
//! ```bash
//! wasm-pack build --release --target web
//! ```
//!
//! If you are intending to use this for program execution or deployment, it is recommended to build
//! with maximum or close to maximum memory allocation (which is 4 gigabytes for wasm).
//!
//! ```bash
//! RUSTFLAGS='-C link-arg=--max-memory=4294967296' wasm-pack build --release --target web
//! ````
//!
//! ### 3. Multi-Threaded browser module
//!
//! This module is also built for browser-based JavaScript environments, however it is built to make use of Rust-native
//! threading via web-workers (using the approach outlined in the `rayon-wasm-bindgen` crate). It is the most complex to use,
//! but it will run significantly faster when performing Aleo program executions and deployments and should be the choice for
//! performance-critical applications.
//!
//! To build with threading enabled, it is necessary to use `nightly Rust` and set certain `RUSTFLAGS` to enable the
//! necessary threading features. The `wasm-pack` build command is shown below.
//! ```bash
//! # Set rustflags to enable atomics,
//! # bulk-memory, and mutable-globals.
//! # Also, set the maximum memory to
//! # 4294967296 bytes (4GB).
//! export RUSTFLAGS='-C target-feature=+atomics,+bulk-memory,+mutable-globals -C link-arg=--max-memory=4294967296'
//!
//! # Use rustup to run the following commands
//! # with the nightly version of Rust.
//! rustup run nightly \
//!
//! # Use wasm-pack to build the project.
//! # Specify the 'parallel' feature for
//! # multi-threading and the 'browser'
//! # feature to enable program execution
//! # and include necessary unstable options
//! # using -Z
//! wasm-pack build --release --target web --out-dir pkg-parallel \
//! -- --features "parallel, browser" -Z build-std=panic_abort,std
//! ```
//!
//! ## Testing
//!
//! Run tests in NodeJS
//! ```bash
//! wasm-pack test --node
//! ```
//!
//! Run tests in a browser
//! ```bash
//! wasm-pack test --[firefox/chrome/safari]
//! ```
//!
//! ## Building Web Apps
//!
//! Further documentation and tutorials as to how to use the modules built from this crate to build web apps  will be built
//! in the future. However - in the meantime, the [provable.tools](https://provable.tools) website is a good
//! example of how to use these modules to build a web app. Its source code can be found in the
//!

use std::ffi::CStr;
use std::ffi::c_char;
use std::ffi::CString;

use serde_json;
use serde::{Deserialize, Serialize};

pub mod account;
pub use account::*;

pub mod programs;
pub use programs::*;

pub mod record;
pub use record::*;

pub mod types;
pub use types::Field;

#[cfg(not(test))]
mod thread_pool;

#[cfg(test)]
mod thread_pool {
    use std::future::Future;

    #[allow(dead_code)]
    #[allow(clippy::manual_async_fn)]
    pub fn spawn<A, F>(f: F) -> impl Future<Output = A>
    where
        A: Send + 'static,
        F: FnOnce() -> A + Send + 'static,
    {
        async move { f() }
    }
}

use wasm_bindgen::prelude::*;

use std::str::FromStr;

use types::native::RecordPlaintextNative;
use rand::{rngs::StdRng};
use rand::SeedableRng;

use crate::native::IdentifierNative;
use crate::native::ProvingKeyNative;
use crate::native::VerifyingKeyNative;

use crate::types::native::{
    CurrentAleo,
    ProcessNative,
    TransactionNative
};

// Facilities for cross-platform logging in both web browsers and nodeJS
#[wasm_bindgen]
extern "C" {
    // Log a &str the console in the browser or console.log in nodejs
    #[wasm_bindgen(js_namespace = console)]
    pub fn log(s: &str);
}

#[derive(Serialize, Deserialize)]
struct TransferInfo {
    private_key: String,
    receiver: String,
    amount: u64,
    fee: u64,
    state_root: String,
    transfer_proving_key: String,
    transfer_verifying_key: String,
    fee_proving_key: String,
    fee_verifying_key: String,
}

/// A trait providing convenient methods for accessing the amount of Aleo present in a record
pub trait Credits {
    /// Get the amount of credits in the record if the record possesses Aleo credits
    fn credits(&self) -> Result<f64, String> {
        Ok(self.microcredits()? as f64 / 1_000_000.0)
    }

    /// Get the amount of microcredits in the record if the record possesses Aleo credits
    fn microcredits(&self) -> Result<u64, String>;
}

impl Credits for RecordPlaintextNative {
    fn microcredits(&self) -> Result<u64, String> {
        match self
            .find(&[native::IdentifierNative::from_str("microcredits").map_err(|e| e.to_string())?])
            .map_err(|e| e.to_string())?
        {
            native::Entry::Private(native::PlaintextNative::Literal(native::LiteralNative::U64(amount), _)) => {
                Ok(*amount)
            }
            _ => Err("The record provided does not contain a microcredits field".to_string()),
        }
    }
}

#[cfg(not(test))]
#[doc(hidden)]
pub use thread_pool::run_rayon_thread;
use types::native;

#[cfg(not(test))]
#[wasm_bindgen(js_name = "initThreadPool")]
pub async fn init_thread_pool(url: web_sys::Url, num_threads: usize) -> Result<(), JsValue> {
    console_error_panic_hook::set_once();

    thread_pool::ThreadPool::builder().url(url).num_threads(num_threads).build_global().await?;

    Ok(())
}

#[no_mangle]
pub extern "C" fn new_private() -> *const c_char {
       let key = PrivateKey::new();
       let key_str = key.to_string();
       let c_key = CString::new(key_str).unwrap();
       c_key.into_raw()
}

#[no_mangle]
pub extern "C" fn free_c_char(ptr: *mut c_char) {
    unsafe { drop(CString::from_raw(ptr)) };
}

#[no_mangle]
pub extern "C" fn private_to_address(key: *const c_char) -> *const c_char {
       let key_tmp = unsafe { CStr::from_ptr(key) };
       let key_str = match key_tmp.to_str() {
              Ok(v) => v,
              Err(e) => {
                  panic!("key to_str err: {:?}", e);
              }
          };

       let key_n = match PrivateKey::from_string(key_str) {
             Ok(v) => v,
             Err(e) => {
                 panic!("parse key err: {:?}", e);
             }
         };
       let addr = key_n.to_address().to_string();
       let ret = CString::new(addr).unwrap();
       ret.into_raw()
}

#[no_mangle]
pub extern "C" fn transfer(key: *const c_char) -> *const c_char {
    let key_json = unsafe {
            assert!(!key.is_null());
            CStr::from_ptr(key)
        };

    let json_str = match key_json.to_str() {
        Ok(v) => v,
        Err(e) => {
            panic!("parse json err: {:?}", e);
        }
    };

    let data: TransferInfo = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(e) => {
            panic!("json to struct err: {:?}", e)
        }
    };

    let transaction = match create_transfer(data) {
        Ok(v) => v,
        Err(e) => {
            panic!("create transfer err: {:?}", e)
        }
    };

    let tx = transaction.to_string();
     let ret = CString::new(tx).unwrap();
     ret.into_raw()
}

fn create_transfer(data: TransferInfo) -> Result<Transaction, String>{
     let private_key = PrivateKey::from_string(&data.private_key).map_err(|e| e.to_string())?;

     let fee_verifying_key = VerifyingKey::from_string(&data.fee_verifying_key).map_err(|e| e.to_string())?;
      let fee_proving_key = ProvingKey::from_string(&data.fee_proving_key).map_err(|e| e.to_string())?;

      let verifying_key = VerifyingKey::from_string(&data.transfer_verifying_key).map_err(|e| e.to_string())?;
      let proving_key = ProvingKey::from_string(&data.transfer_proving_key).map_err(|e| e.to_string())?;

    let program_string = ProgramNative::credits().unwrap().to_string();
    let program =
                ProgramNative::from_str(program_string).map_err(|_| "The program ID provided was invalid".to_string())?;
    println!("begin ProgramNative credits: {}, id: {}", program_string, program.id().to_string());

    let amount = data.amount;
    let inputs = [data.receiver, format!("{amount}_u64")];
    let rng = &mut StdRng::from_entropy();
     // Initialize the process.
    let mut process_native = ProcessNative::load().unwrap();
    let process = &mut process_native;
    let stack = process.get_stack(program.id()).map_err(|e| e.to_string())?;

    let fee_identifier = IdentifierNative::from_str("fee_public").map_err(|e| e.to_string())?;

    println!("begin insert_proving_key fee");
    if !stack.contains_proving_key(&fee_identifier) {
        stack
            .insert_proving_key(&fee_identifier, ProvingKeyNative::from(fee_proving_key))
            .map_err(|e| e.to_string())?;
        stack
            .insert_verifying_key(&fee_identifier, VerifyingKeyNative::from(fee_verifying_key))
            .map_err(|e| e.to_string())?;
    }

    println!("begin insert_proving_key transfer");
    let transfer_identifier = IdentifierNative::from_str("transfer_public").map_err(|e| e.to_string())?;
    if !stack.contains_proving_key(&transfer_identifier) {
            stack
                .insert_proving_key(&transfer_identifier, ProvingKeyNative::from(proving_key))
                .map_err(|e| e.to_string())?;
            stack
                .insert_verifying_key(&transfer_identifier, VerifyingKeyNative::from(verifying_key))
                .map_err(|e| e.to_string())?;
    }

    println!("begin authorize transfer");
    // Authorize .
    let authorization = process
        .authorize::<CurrentAleo, _>(
            &private_key,
            // program.id
            program.id(),
            // func name
            transfer_identifier,
            // input
            inputs.iter(),
            rng,
        )
        .unwrap();
    // Construct the fee trace.
    println!("begin execute transfer");
    let (_, mut trace) = process.execute::<CurrentAleo, _>(authorization, rng).unwrap();
    // Prepare the assignments.
    println!("begin prepare offline_query");
    let offline_query = OfflineQuery::new(&data.state_root).unwrap();
    let _ = trace.prepare(offline_query.clone());

    println!("begin prove_execution");
     let execution =
                trace.prove_execution::<CurrentAleo, _>("credits.aleo/transfer", rng).map_err(|e| e.to_string())?;
     let execution_id = execution.to_execution_id().map_err(|e| e.to_string())?;

     //attach fee
     println!("begin authorize fee");
     let fee_authorization = process.authorize_fee_public::<CurrentAleo, _>(
         &private_key,
         // base fee
         data.fee,
         //priority fee
         0u64,
         execution_id,
         rng,
     ).map_err(|e| e.to_string())?;

     let (_, mut fee_trace) = process
                 .execute::<CurrentAleo, _>(fee_authorization, rng)
                 .map_err(|err| err.to_string())?;
     let _ = fee_trace.prepare(offline_query.clone());
     let fee = fee_trace.prove_fee::<CurrentAleo, _>(&mut StdRng::from_entropy()).map_err(|e|e.to_string())?;

     let transaction = TransactionNative::from_execution(execution, Some(fee)).map_err(|err| err.to_string())?;
     Ok(Transaction::from(transaction))
}


