use anyhow::{anyhow, Result};
use crate::keywrap::KeyWrapper;
use crate::utils::keyprovider as keyproviderpb;
use tonic;
use std::collections::hash_map::RandomState;
use crate::config::{DecryptConfig, EncryptConfig, KeyProviderAttrs, Command};
use std::collections::HashMap;
use crate::{utils};
use tokio;
use crate::utils::{CommandExecuter};
use tokio::runtime::Runtime;
use core::option::Option;

use core::fmt::Debug;
use tonic::codegen::http::Uri;


impl Debug for dyn CommandExecuter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "CommandExecuter")
    }
}


/// A KeyProvider keywrapper
#[derive(Debug)]
pub struct KeyProviderKeyWrapper {
    pub provider: String,
    pub attrs: KeyProviderAttrs,
    pub runner: Option<Box<dyn CommandExecuter>>,
}

pub const OP_KEY_WRAP: &str = "keywrap";
pub const OP_KEY_UNWRAP: &str = "keyunwrap";

/// KeyProviderKeyWrapProtocolInput defines the input to the key provider binary or grpc method.
#[derive(Serialize, Deserialize, Debug)]
pub struct KeyProviderKeyWrapProtocolInput {
    // op is either "keywrap" or "keyunwrap"
    op: String,
    // keywrapparams encodes the arguments to key wrap if operation is set to wrap
    keywrapparams: Option<KeyWrapParams>,
    // keyunwrapparams encodes the arguments to key unwrap if operation is set to unwrap
    keyunwrapparams: Option<KeyUnwrapParams>,
}


// KeyProviderKeyWrapProtocolOutput defines the output of the key provider binary or grpc method.
#[derive(Serialize, Deserialize)]
pub struct KeyProviderKeyWrapProtocolOutput {
    // keywrapresults encodes the results to key wrap if operation is to wrap
    keywrapresults: Option<KeyWrapResults>,
    // keyunwrapresults encodes the result to key unwrap if operation is to unwrap
    keyunwrapresults: Option<KeyUnwrapResults>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyWrapParams {
    pub ec: Option<EncryptConfig>,
    optsdata: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyUnwrapParams {
    pub dc: Option<DecryptConfig>,
    annotation: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyUnwrapResults {
    optsdata: Vec<u8>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyWrapResults {
    annotation: Vec<u8>
}

pub fn new_key_wrapper(p: String, kp_conf: KeyProviderAttrs, runner: Option<Box<dyn utils::CommandExecuter>>) -> KeyProviderKeyWrapper {
    let kp = KeyProviderKeyWrapper {
        provider: p,
        attrs: kp_conf,
        runner: runner,
    };
    kp
}

impl KeyWrapper for KeyProviderKeyWrapper {
    // NewKeyWrapper returns a new key wrapping interface using keyprovider
    fn wrap_keys(&self, enc_config: &EncryptConfig, opts_data: &[u8]) -> Result<Vec<u8>> {
        let mut protocol_output = KeyProviderKeyWrapProtocolOutput { keywrapresults: None, keyunwrapresults: None };
        let key_wrap_params = KeyWrapParams { ec: Some(enc_config.clone()), optsdata: Vec::from(opts_data) };
        let input = KeyProviderKeyWrapProtocolInput {
            op: OP_KEY_WRAP.to_string(),
            keywrapparams: Option::from(key_wrap_params),
            keyunwrapparams: None,
        };
        let serialized_input = bincode::serialize(&input).unwrap();

        if enc_config.param.contains_key(&self.provider.to_string()) {
            if self.attrs.cmd.as_ref().is_some() {
                protocol_output = get_provider_command_output(serialized_input, &self.attrs.cmd, self.runner.as_ref().unwrap()).unwrap()
            } else if self.attrs.grpc.as_ref().is_some() {
                let rt = Runtime::new().unwrap().block_on(get_provider_grpc_output(serialized_input, self.attrs.grpc.as_ref().unwrap(), OP_KEY_WRAP.to_string()));
                protocol_output = rt.unwrap()
            }
        }
        let key_wrap_results = match protocol_output.keywrapresults {
            Some(x) => x,
            None => return Err(anyhow!("protocol output is empty"))
        };
        Ok(key_wrap_results.annotation)
    }

    fn unwrap_keys(&self, dc_config: &DecryptConfig, json_string: &[u8]) -> Result<Vec<u8>> {
        let mut protocol_output = KeyProviderKeyWrapProtocolOutput { keywrapresults: None, keyunwrapresults: None };
        let key_unwrap_params = KeyUnwrapParams { dc: Some(dc_config.clone()), annotation: Vec::from(json_string) };
        let input = KeyProviderKeyWrapProtocolInput {
            op: "keyunwrap".to_string(),
            keywrapparams: None,
            keyunwrapparams: Option::from(key_unwrap_params),
        };
        let serialized_input = bincode::serialize(&input).unwrap();

        if self.attrs.cmd.as_ref().is_some() {
            protocol_output = get_provider_command_output(serialized_input, &self.attrs.cmd, self.runner.as_ref().unwrap()).unwrap();
        } else if self.attrs.grpc.as_ref().is_some() {
            let rt = Runtime::new().unwrap().block_on(get_provider_grpc_output(serialized_input, self.attrs.grpc.as_ref().unwrap(), OP_KEY_UNWRAP.to_string()));
            protocol_output = rt.unwrap();
        }
        Ok(protocol_output.keyunwrapresults.unwrap().optsdata)
    }


    fn annotation_id(&self) -> String {
        format!("{}{}", "org.opencontainers.image.enc.keys.provider.", "anirgj")
    }

    fn no_possible_keys(&self, _dc_param: &HashMap<String, Vec<Vec<u8>>, RandomState>) -> bool {
        unimplemented!()
    }
}

async fn get_provider_grpc_output(input: Vec<u8>, conn: &str, operation: String) -> Result<KeyProviderKeyWrapProtocolOutput> {
    let mut protocol_output = KeyProviderKeyWrapProtocolOutput { keywrapresults: None, keyunwrapresults: None };
    let uri = conn.parse::<Uri>().unwrap();
    // create a channel ie connection to server
    let channel = tonic::transport::Channel::builder(uri)
        .connect()
        .await.unwrap();

    let mut client = keyproviderpb::key_provider_service_client::KeyProviderServiceClient::new(channel);
    let request = tonic::Request::new(keyproviderpb::KeyProviderKeyWrapProtocolInput { key_provider_key_wrap_protocol_input: input });
    if operation == OP_KEY_WRAP {
        let grpc_output = client.wrap_key(request).await?;
        protocol_output = bincode::deserialize(&grpc_output.into_inner().key_provider_key_wrap_protocol_output).unwrap();
    } else if operation == OP_KEY_UNWRAP {
        let grpc_output = client.un_wrap_key(request).await?;
        protocol_output = bincode::deserialize(&grpc_output.into_inner().key_provider_key_wrap_protocol_output).unwrap();
    }
    Ok(protocol_output)
}

fn get_provider_command_output(input: Vec<u8>, cmd: &Option<Command>, runner: &Box<dyn utils::CommandExecuter>) -> Result<KeyProviderKeyWrapProtocolOutput> {
    let resp_bytes: Vec<u8>;
    // Convert interface to command structure
    resp_bytes = runner.exec(cmd.as_ref().unwrap().path.to_string(), cmd.as_ref().unwrap().args.as_ref().unwrap(), input).unwrap();

    let protocol_output = bincode::deserialize(&resp_bytes).unwrap();
    Ok(protocol_output)
}

#[cfg(test)]
mod tests {
    use crate::utils::keyprovider::{KeyProviderKeyWrapProtocolInput as grpc_input, KeyProviderKeyWrapProtocolOutput as grpc_output};
    use crate::utils::keyprovider::{key_provider_service_server::{KeyProviderServiceServer}};
    use crate::utils::{CommandExecuter};
    use crate::keywrap::{keyprovider, KeyWrapper};
    use crate::{config};
    use std::net::SocketAddr;
    use tonic;
    use tonic::{transport::Server, Request, Status, transport};
    use aes_gcm::aead::{Aead, NewAead};
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use crate::keywrap::keyprovider::{KeyProviderKeyWrapProtocolOutput, KeyWrapResults, KeyUnwrapResults, KeyProviderKeyWrapProtocolInput, new_key_wrapper};
    use std::{env, fs};
    use crate::config::{EncryptConfig, DecryptConfig};
    use crate::utils::keyprovider::key_provider_service_server::KeyProviderService;
    use tokio::sync::mpsc;
    use tokio::runtime::Runtime;
    use std::time::Duration;
    use std::thread::sleep;

    ///Test runner which mocks binary executable for key wrapping and unwrapping
    #[derive(Clone, Copy)]
    pub struct TestRunner {}

    static mut ENC_KEY: &[u8; 32] = b"passphrasewhichneedstobe32bytes!";
    static mut DEC_KEY: &[u8; 32] = b"passphrasewhichneedstobe32bytes!";

    //Mock annotation packet, which goes into container image manifest
    #[derive(Serialize, Deserialize, Debug)]
    pub struct AnnotationPacket {
        pub key_url: String,
        pub wrapped_key: Vec<u8>,
        pub wrap_type: String,
    }


    //grpc server with mock api implementation for serving the clients with mock WrapKey and Unwrapkey grpc method implementations
    #[derive(Default)]
    struct TestServer {}

    /*
    async fn start_server() -> Result<(), transport::Error> {

        println!("server started");
        let addr: SocketAddr = "127.0.0.1:8990".parse().unwrap();
        let server = TestServer::default();
        Server::builder()
            .add_service(KeyProviderServiceServer::new(server))
            .serve(addr)
            .await?;
        Ok(())
    }
*/
 //   #[tokio::test]
    async fn start_server(){
        let (tx, mut rx) = mpsc::unbounded_channel();

        println!("server started");
        let addr: SocketAddr = "127.0.0.1:8990".parse().unwrap();
        let server = TestServer::default();
        let serve = Server::builder()
            .add_service(KeyProviderServiceServer::new(server))
            .serve(addr);

        tokio::spawn(async move {
            if let Err(e) = serve.await {
                eprintln!("Error = {:?}", e);
            }

            tx.send(()).unwrap();
        });

        rx.recv().await;
   }

    #[tonic::async_trait]
    impl KeyProviderService for TestServer {
        async fn wrap_key(
            &self,
            request: Request<grpc_input>,
        ) -> Result<tonic::Response<grpc_output>, tonic::Status> {
            let keyp: keyprovider::KeyProviderKeyWrapProtocolInput = bincode::deserialize(&request.into_inner().key_provider_key_wrap_protocol_input).unwrap();

            let cipher = Aes256Gcm::new(Key::from_slice(unsafe { ENC_KEY }));
            let nonce = Nonce::from_slice(b"unique nonce");
            let sym_key: &[u8] = &keyp.keywrapparams.unwrap().optsdata;
            let wrapped_key = cipher.encrypt(nonce, sym_key).unwrap();

            let ap = AnnotationPacket {
                key_url: "https://key-provider/key-uuid".to_string(),
                wrapped_key: wrapped_key,
                wrap_type: "AES".to_string(),
            };

            let ap_serialized = match bincode::serialize(&ap) {
                Ok(x) => x,
                Err(e) => return Err(Status::unknown(format!(
                    "There was an error while getting a pl: {}", e)))
            };

            let key_wrap_output = KeyProviderKeyWrapProtocolOutput { keywrapresults: Option::from(KeyWrapResults { annotation: ap_serialized }), keyunwrapresults: None };
            let protocol_ouput_serialized = match bincode::serialize(&key_wrap_output) {
                Ok(x) => x,
                Err(e) => return Err(Status::unknown(format!(
                    "There was an error while getting a pl: {}", e)))
            };

            Ok(tonic::Response::new(grpc_output { key_provider_key_wrap_protocol_output: protocol_ouput_serialized }))
        }

        async fn un_wrap_key(&self, request: Request<grpc_input>) -> Result<tonic::Response<grpc_output>, tonic::Status> {
            let keyp: keyprovider::KeyProviderKeyWrapProtocolInput = match bincode::deserialize(&request.into_inner().key_provider_key_wrap_protocol_input) {
                Ok(x) => x,
                Err(e) => return Err(Status::unknown(format!(
                    "There was an error while getting a pl: {}", e)))
            };
            let a: &[u8] = &keyp.keyunwrapparams.unwrap().annotation;
            let ap: AnnotationPacket = bincode::deserialize(a).unwrap();

            let cipher = Aes256Gcm::new(Key::from_slice(unsafe { DEC_KEY }));
            let nonce = Nonce::from_slice(b"unique nonce");
            let wrapped_key = ap.wrapped_key;
            let unwrapped_key = cipher
                .decrypt(nonce, wrapped_key.as_ref())
                .expect("decryption failure!");

            let key_wrap_output = KeyProviderKeyWrapProtocolOutput { keywrapresults: None, keyunwrapresults: Option::from(KeyUnwrapResults { optsdata: unwrapped_key }) };
            let protocol_ouput_serialized = bincode::serialize(&key_wrap_output).unwrap();

            Ok(tonic::Response::new(grpc_output { key_provider_key_wrap_protocol_output: protocol_ouput_serialized }))
        }
    }


    impl CommandExecuter for TestRunner {
        /// ExecuteCommand is used to execute a linux command line command and return the output of the command with an error if it exists.
        fn exec(&self, cmd: String, _args: &Vec<String>, input: Vec<u8>) -> std::io::Result<Vec<u8>> {
            let mut key_wrap_output = KeyProviderKeyWrapProtocolOutput { keywrapresults: None, keyunwrapresults: None };
            if cmd == "/usr/lib/keyprovider-wrapkey" {
                let keyp: KeyProviderKeyWrapProtocolInput = bincode::deserialize(input.as_ref()).unwrap();

                let cipher = Aes256Gcm::new(Key::from_slice(unsafe { ENC_KEY }));
                let nonce = Nonce::from_slice(b"unique nonce");
                let sym_key: &[u8] = &keyp.keywrapparams.unwrap().optsdata;
                let wrapped_key = cipher.encrypt(nonce, sym_key).unwrap();

                let ap = AnnotationPacket {
                    key_url: "https://key-provider/key-uuid".to_string(),
                    wrapped_key: wrapped_key,
                    wrap_type: "AES".to_string(),
                };

                let ap_serialized = bincode::serialize(&ap).unwrap();

                key_wrap_output = KeyProviderKeyWrapProtocolOutput { keywrapresults: Option::from(KeyWrapResults { annotation: ap_serialized }), keyunwrapresults: None };
            } else if cmd == "/usr/lib/keyprovider-unwrapkey" {
                let keyp: KeyProviderKeyWrapProtocolInput = bincode::deserialize(input.as_ref()).unwrap();
                let ap_bytes: &[u8] = &keyp.keyunwrapparams.unwrap().annotation;
                let ap: AnnotationPacket = bincode::deserialize(ap_bytes).unwrap();

                let cipher_text = ap.wrapped_key;
                let cipher = Aes256Gcm::new(Key::from_slice(unsafe { DEC_KEY }));
                let nonce = Nonce::from_slice(b"unique nonce");
                let unwrapped_key = cipher
                    .decrypt(nonce, cipher_text.as_ref())
                    .expect("decryption failure!");

                key_wrap_output = KeyProviderKeyWrapProtocolOutput { keywrapresults: None, keyunwrapresults: Option::from(KeyUnwrapResults { optsdata: unwrapped_key }) };
            }
            let keywrap_output_serialized = bincode::serialize(&key_wrap_output).unwrap();
            Ok(keywrap_output_serialized)
        }
    }

    #[test]
    fn test_key_provider_command_success() {
        let test_runner = TestRunner {};
        let test_conf_path = "config.json";
        env::set_var("OCICRYPT_KEYPROVIDER_CONFIG", test_conf_path);

        //Config File with executable for key wrap
        let config_file1_data = "{\"key-providers\": \
                               {\"keyprovider\": {
                                    \"cmd\": { \
                                       \"path\": \"/usr/lib/keyprovider-wrapkey\", \
                                       \"args\": [] \
                                     }\
                                 }\
                              }\
                          }";

        //Config File with executable for key unwrap
        let config_file2_data = "{\"key-providers\": \
                               {\"keyprovider\": {
                                    \"cmd\": { \
                                       \"path\": \"/usr/lib/keyprovider-unwrapkey\", \
                                       \"args\": [] \
                                     }\
                                 }\
                              }\
                          }";


        fs::write(test_conf_path, config_file1_data).expect("Unable to write file");

        let opts_data = b"symmetric_key";

        let kp = config::get_configuration().unwrap();
        let kp_attrs = kp.key_providers.get("keyprovider").unwrap();
        let key_wrapper = new_key_wrapper("keyprovider".to_string(), kp_attrs.clone(), Some(Box::new(test_runner)));

        let mut ec = EncryptConfig::default();
        let mut dc = DecryptConfig::default();
        let mut ec_params = vec![];
        let param = "keyprovider".to_string().into_bytes();
        ec_params.push(param.clone());

        assert!(ec.encrypt_with_key_provider(ec_params).is_ok());

        assert!(key_wrapper.wrap_keys(&ec, opts_data).is_ok());

        let key_wrap_output_result = key_wrapper.wrap_keys(&ec, opts_data);

        fs::write(test_conf_path, config_file2_data).expect("Unable to write file");

        let kp = config::get_configuration().unwrap();
        let kp_attrs = kp.key_providers.get("keyprovider").unwrap();
        let key_wrapper = new_key_wrapper("keyprovider".to_string(), kp_attrs.clone(), Some(Box::new(test_runner)));

        let mut dc_params = vec![];
        dc_params.push(param);

        assert!(dc.decrypt_with_key_provider(dc_params).is_ok());

        let key_wrap_output_result = key_wrapper.unwrap_keys(&dc, key_wrap_output_result.unwrap().as_ref());
        let unwrapped_key: &[u8] = &key_wrap_output_result.unwrap();
        assert_eq!(opts_data, unwrapped_key);
        fs::remove_file(test_conf_path).expect("unable to remove config test file ");
    }


    fn function_that_spawns() {
        // Had we not used `rt.enter` below, this would panic.
        tokio::spawn(async move {
            let (tx, mut rx) = mpsc::unbounded_channel();

            println!("server started");
            let addr: SocketAddr = "127.0.0.1:8990".parse().unwrap();
            let server = TestServer::default();
            let serve = Server::builder()
                .add_service(KeyProviderServiceServer::new(server))
                .serve(addr);

            tokio::spawn(async move {
                if let Err(e) = serve.await {
                    eprintln!("Error = {:?}", e);
                }

                tx.send(()).unwrap();
            });

            rx.recv().await;
        });
    }

    #[test]
    fn test_key_provider_grpc_success() {

       let rt1 = Runtime::new().unwrap();
        let _guard = rt1.enter();
        function_that_spawns();

        sleep(Duration::from_secs(5));
        let test_conf_path = "config.json";
        env::set_var("OCICRYPT_KEYPROVIDER_CONFIG", test_conf_path);

        let config_file1_data = "{\"key-providers\": \
                                           {\"keyprovider\": {
                                                \"grpc\": \"tcp://127.0.0.1:8990\"
                                             },\
                                            \"keyprovider1\": {
                                                \"grpc\": \"tcp://localhost:32223\"
                                             }\
                                          }\
                                     }";
        fs::write(test_conf_path, config_file1_data).expect("Unable to write file");


        let opts_data = b"symmetric_key";
        let mut ec = EncryptConfig::default();
        let mut dc = DecryptConfig::default();

        let mut ec_params = vec![];
        let param = "keyprovider".to_string().into_bytes();
        ec_params.push(param.clone());

        let oc_config = config::get_configuration().unwrap();
        let kp_attrs = oc_config.key_providers.get("keyprovider").unwrap();
        let key_wrapper = new_key_wrapper("keyprovider".to_string(), kp_attrs.clone(), None);
        assert!(ec.encrypt_with_key_provider(ec_params).is_ok());

        assert!(key_wrapper.wrap_keys(&ec, opts_data).is_ok());
        let key_wrap_output_result = key_wrapper.wrap_keys(&ec, opts_data);

        let mut dc_params = vec![];
        dc_params.push(param);

        assert!(dc.decrypt_with_key_provider(dc_params).is_ok());

        let json_string: &[u8] = &key_wrap_output_result.unwrap();

        let key_wrap_output_result = key_wrapper.unwrap_keys(&dc, json_string);
        let unwrapped_key: &[u8] = &key_wrap_output_result.unwrap();
        assert_eq!(opts_data, unwrapped_key);
        fs::remove_file(test_conf_path).expect("unable to remove config test file ");

       rt1.shutdown_background();

    }
}