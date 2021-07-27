use crate::keywrap::KeyWrapper;
use crate::utils::runner;
use std::collections::hash_map::RandomState;
use crate::config::{DecryptConfig, EncryptConfig, KeyProviderAttrs, Command};
use std::collections::HashMap;
use std::ptr::null;
use std::fmt::Error;

/// A KeyProvider keywrapper
#[derive(Debug)]
pub struct KeyProviderKeyWrapper {
    provider: String,
    attrs: KeyProviderAttrs,
}

pub const OP_KEY_WRAP: &str = "keywrap";
pub const OP_KEY_UNWRAP: &str = "keyunwrap";

#[derive(Serialize, Deserialize, Debug)]
/// KeyProviderKeyWrapProtocolInput defines the input to the key provider binary or grpc method.
pub struct KeyProviderKeyWrapProtocolInput {
    // op is either "keywrap" or "keyunwrap"
    op: String,
    // keywrapparams encodes the arguments to key wrap if operation is set to wrap
    keywrapparams: KeyWrapParams,
    // keyunwrapparams encodes the arguments to key unwrap if operation is set to unwrap
    keyunwrapparams: KeyUnwrapParams,
}

#[derive(Serialize, Deserialize)]
// KeyProviderKeyWrapProtocolOutput defines the output of the key provider binary or grpc method.
pub struct KeyProviderKeyWrapProtocolOutput {
    // keywrapresults encodes the results to key wrap if operation is to wrap
    keywrapresults: KeyWrapResults,
    // keyunwrapresults encodes the result to key unwrap if operation is to unwrap
    keyunwrapresults: KeyUnwrapResults,
}

#[derive(Serialize, Deserialize)]
pub struct KeyWrapParams {
    pub ec: *EncryptConfig,
    optsdata: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct KeyUnwrapParams {
    pub dc: *DecryptConfig,
    annotation: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct KeyUnwrapResults {
    optsdata: Vec<u8>
}

#[derive(Serialize, Deserialize)]
pub struct KeyWrapResults {
    annotation: Vec<u8>
}


impl KeyWrapper for KeyProviderKeyWrapper {
    fn wrap_keys(&self, enc_config: &EncryptConfig, opts_data: &[u8]) -> Result<Vec<u8>, Error> {
        let protocol_output;
        let input = KeyProviderKeyWrapProtocolInput {
            op: OP_KEY_WRAP.to_string(),
            keywrapparams: KeyWrapParams { ec: enc_config, optsdata: Vec::from(opts_data) },
            keyunwrapparams: KeyUnwrapParams { dc: Default::default(), annotation: vec![] },
        };
        let serialized_input = match bincode::serialize(&input) {
            Ok(x) => x,
            Err(x) => return Err(anyhow!("Error while marshalling json"))
        };

        if enc_config.param.contains_key(kw.provider) {
            if &self.attrs.cmd != "" {
                protocol_output = match get_provider_command_output(serialized_input, *self.attrs.cmd) {
                    Ok(x) => x,
                    Err(x) => return Err(anyhow!("Error while retrieving keyprovider protocol command output"))
                };
                Ok(protocol_output.keywrapresults.annotation)
            } else if &self.attrs.grpc != "" {
                protocol_output = match get_provider_grpc_output(serialized_input, *self.attrs.grpc, OP_KEY_WRAP) {
                    Ok(x) => x,
                    Err(x) => return Err(anyhow!("Error while retrieving keyprovider protocol command output"))
                };
                Ok(protocol_output.keywrapresults.annotation)
            } else {
                Err(anyhow!("Unsupported keyprovider invocation. Supported invocation methods are grpc and cmd"))
            }
        }
    }

    fn unwrap_keys(&self, dc_config: &DecryptConfig, json_string: &[u8]) -> Result<Vec<u8>, Error> {
        let protocol_output;
        let input = KeyProviderKeyWrapProtocolInput {
            op: "keyunwrap".to_string(),
            keywrapparams: KeyWrapParams { ec: (), optsdata: vec![] },
            keyunwrapparams: KeyUnwrapParams { dc: dc_config, annotation: Vec::from(json_string) },
        };
        let serialized_input = match bincode::serialize(&input) {
            Ok(x) => x,
            Err(x) => return Err(anyhow!("Error while marshalling json"))
        };

        if &self.attrs.cmd != "" {
            protocol_output = match get_provider_command_output(serialized_input, *self.attrs.cmd) {
                Ok(x) => x,
                Err(x) => return Err(anyhow!("Error while retrieving keyprovider protocol command output"))
            };
            Ok(protocol_output.keyunwrapresults.optsdata)
        } else if &self.attrs.grpc != "" {
            protocol_output = match get_provider_grpc_output(serialized_input, *self.attrs.grpc, OP_KEY_UNWRAP) {
                Ok(x) => x,
                Err(x) => return Err(anyhow!("Error while retrieving keyprovider protocol command output"))
            };
            Ok(protocol_output.keyunwrapresults.optsdata)
        } else {
            Err(anyhow!("Unsupported keyprovider invocation. Supported invocation methods are grpc and cmd"))
        }
    }


    fn no_possible_keys(&self, dc_param: &HashMap<String, Vec<Vec<u8>>, RandomState>) -> bool {
        unimplemented!()
    }

    fn annotation_id(&self) -> &str {
        "org.opencontainers.image.enc.keys.provider." + kw.provider
    }
}

fn get_provider_grpc_output(p0: Result<Vec<u8>, E>, p1: Box<str>, p2: &str) {
    unimplemented!()
}

fn get_provider_command_output(input: Vec<u8>, cmd: Command) -> Result<KeyProviderKeyWrapProtocolOutput, E> {
    let protocol_output = KeyProviderKeyWrapProtocolOutput;
    // Convert interface to command structure
    let respBytes = match runner.exec(command.Path, command.Args, input) {
        Ok(x) => x,
        Err(x) => x,
    };

    let protocolOuput = match bincode::deserialize(&respBytes) {
        Ok(x) => x,
        Err(x) => return Err(anyhow!("Error while unmarshalling binary executable command output",))
    };

    return protocol_output;
}