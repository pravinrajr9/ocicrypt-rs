use crate::utils::{runner, CommandExecuter};
use bincode::Error;
use std::process::{Command, Stdio};

#[derive(Debug)]
pub struct Runner {}

impl CommandExecuter for Runner {
    /// ExecuteCommand is used to execute a linux command line command and return the output of the command with an error if it exists.
    fn exec(&self, cmd: String, args: Vec<String>, input: &[u8]) -> Result<Vec<u8>, Error> {
        let output = match Command::new(cmd)
            .stdin(input)
            .args(args)
            .stdout(Stdio::piped())
            .output()
        {
            Ok(x) => x.stdout,
            Err(x) => return Err(anyhow!("error while running command: {:?} ", cmd)),
        };

        Ok(output)
    }
}
