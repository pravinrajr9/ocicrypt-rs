// Copyright The ocicrypt Authors.
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "utils-runner")]
pub mod runner;

#[cfg(feature = "utils-keyprovider")]
pub mod keyprovider;

/// first argument is the command, like cat or echo,
/// the second is the list of args to pass to it
#[allow(unused_variables)]
pub trait CommandExecuter {
    fn exec(&self, cmd: String, args: &Vec<String>, input: Vec<u8>) -> std::io::Result<Vec<u8>>;
}
