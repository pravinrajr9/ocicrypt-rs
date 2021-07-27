use crate::keywrap::KeyWrapper;
use crate::utils::runner;
use crate::utils::keyprovider as keyproviderpb;
use tonic::{transport::Server, Request, Response, Status};
use std::collections::hash_map::RandomState;
use crate::config::{DecryptConfig, EncryptConfig, KeyProviderAttrs, Command};
use std::collections::HashMap;
use std::ptr::null;
use std::fmt::Error;
use crate::utils;
extern crate init;
use init::init;

pub mod keyprovider {
    tonic::include_proto!("keyprovider");
}


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
    pub ec: * EncryptConfig,
    optsdata: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct KeyUnwrapParams {
    pub dc: * DecryptConfig,
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
                protocol_output = match get_provider_grpc_output(serialized_input, self.attrs.grpc.to_string(), OP_KEY_WRAP) {
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
            protocol_output = match get_provider_grpc_output(serialized_input, self.attrs.grpc.to_string(), OP_KEY_UNWRAP) {
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

async fn get_provider_grpc_output(input: Vec<u8>, connection_string: String, operation: &str) -> Result<(), Box<dyn std::error::Error>> {
    let protocol_output = KeyProviderKeyWrapProtocolOutput;

    // create a channel ie connection to server
    let channel = tonic::transport::Channel::from_static(&connection_string)
        .connect()
        .await?;

    let mut client = keyproviderpb::key_provider_service_client::KeyProviderServiceClient::new(channel);
    let request = tonic::Request::new(keyproviderpb::KeyProviderKeyWrapProtocolInput { key_provider_key_wrap_protocol_input: input });
    if operation == OP_KEY_WRAP {
        let grpc_output = client.wrap_key(request).await?.into_inner();
        let protocol_ouput = match bincode::deserialize(&grpc_output.key_provider_key_wrap_protocol_output) {
            Ok(x) => x,
            Err(x) => return Err(anyhow!("Error while unmarshalling binary executable command output",))
        };
        protocol_ouput
    } else if operation == OP_KEY_UNWRAP {
        grpc_output = client.un_wrap_key(request);
        let protocol_output = match bincode::deserialize(&grpc_output.key_provider_key_wrap_protocol_output) {
            Ok(x) => x,
            Err(x) => return Err(anyhow!("Error while unmarshalling binary executable command output",))
        };
        protocol_output
    }
    return Err(anyhow!("Protocol not supported"));
}

fn get_provider_command_output(input: Vec<u8>, cmd: Command) -> Result<KeyProviderKeyWrapProtocolOutput, E> {
    let protocol_output = KeyProviderKeyWrapProtocolOutput;
    // Convert interface to command structure
    let resp_bytes = match runner.exec(command.Path, command.Args, input) {
        Ok(x) => x,
        Err(x) => x,
    };

    let protocol_output:KeyProviderKeyWrapProtocolOutput  = match bincode::deserialize(&resp_bytes) {
        Ok(x) => x,
        Err(x) => return Err(anyhow!("Error while unmarshalling binary executable command output",))
    };
    return Ok(protocol_output);
}

#[cfg(test)]
mod tests {
    use crate::utils::keyprovider::{KeyProviderKeyWrapProtocolInput as grpc_input, KeyProviderKeyWrapProtocolOutput as grpc_output};
    use crate::utils::keyprovider::{key_provider_service_server::{KeyProviderServiceServer}};
    use crate::keywrap::keyprovider;
    use std::net::SocketAddr;
    use tonic::{transport::Server, Request, Response, Status};

    ///Test runner which mocks binary executable for key wrapping and unwrapping
    struct TestRunner {}

    //Mock annotation packet, which goes into container image manifest
    #[derive(Serialize, Deserialize, Debug)]
    pub struct AnnotationPacket {
        pub key_url: String,
        pub wrapped_key: Vec<u8>,
        pub wrap_type: String,
    }

    //grpc server with mock api implementation for serving the clients with mock WrapKey and Unwrapkey grpc method implementations
    #[derive(Default)]
    struct test_server {}

    fn init() {
        #[tonic::async_trait]
        impl server for test_server {
            async fn wrap_key(
                &self,
                req: Request<grpc_input>,
            ) -> Result<tonic::Response<grpc_output>, tonic::Status> {

                let keyp :keyprovider::KeyProviderKeyWrapProtocolInput = match bincode::deserialize(&*req.into_inner().key_provider_key_wrap_protocol_input) {
                    Ok(x) => x,
                    Err(x) => return Err(anyhow!("Error while unmarshalling binary executable command output",))
                };

                c, _ := aes.NewCipher(encryptingKey)
                gcm, _ := cipher.NewGCM(c)
                nonce := make([]byte, gcm.NonceSize())
                _, err = io.ReadFull(rand.Reader, nonce)
                if err != nil{
                    return nil, err
                }

                wrappedKey := gcm.Seal(nonce, nonce, keyP.KeyWrapParams.OptsData, nil)

                jsonString, _ := json.Marshal(annotationPacket{
                    KeyUrl:     "https://key-provider/key-uuid",
                    WrappedKey: wrappedKey,
                    WrapType:   "AES",
                })

                protocolOuputSerialized, _ := json.Marshal(KeyProviderKeyWrapProtocolOutput{
                    KeyWrapResults: KeyWrapResults{Annotation: jsonString},
                })

                return &keyproviderpb.KeyProviderKeyWrapProtocolOutput{
                    KeyProviderKeyWrapProtocolOutput: protocolOuputSerialized,
                }, nil

                Ok(tonic::Response::new(reply))
            }

            async fn unwrap_key(
                self,
                request: tonic::Request<KeyProviderKeyWrapProtocolInput>,
            ) -> Result<tonic::Response<KeyProviderKeyWrapProtocolOutput>, tonic::Status> {
                let reply = HelloReply {
                    message: format!("Hello {}!", request.into_inner().name),
                };

                Ok(tonic::Response::new(reply))
            }

    }
        let addr: SocketAddr = "127.0.0.1:8000".parse()?;
        let server = test_server::default();

        Server::builder()
            .add_service(KeyProviderServiceServer::new(server))
            .serve(addr)
            .await?;
}