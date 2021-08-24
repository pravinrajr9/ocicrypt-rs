// Copyright The ocicrypt Authors.
// SPDX-License-Identifier: Apache-2.0

extern crate tonic_build;


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protos = vec![
        "src/utils/proto/keyprovider.proto",
    ];

    tonic_build::configure().build_server(true).out_dir("src/utils/grpc")
        .compile(&protos,&["src/utils"])?;

    ttrpc_codegen::Codegen::new()
        .out_dir("src/utils/ttrpc")
        .inputs(&protos)
        .include("src/utils")
        .rust_protobuf()
      .run().expect("Gen code failed.");

    Ok(())
}