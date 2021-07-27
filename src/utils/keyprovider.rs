#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KeyProviderKeyWrapProtocolInput {
    #[prost(bytes = "vec", tag = "1")]
    pub key_provider_key_wrap_protocol_input: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KeyProviderKeyWrapProtocolOutput {
    #[prost(bytes = "vec", tag = "1")]
    pub key_provider_key_wrap_protocol_output: ::prost::alloc::vec::Vec<u8>,
}
#[doc = r" Generated client implementations."]
pub mod key_provider_service_client {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    #[derive(Debug, Clone)]
    pub struct KeyProviderServiceClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl KeyProviderServiceClient<tonic::transport::Channel> {
        #[doc = r" Attempt to create a new client by connecting to a given endpoint."]
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: std::convert::TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }
    impl<T> KeyProviderServiceClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::ResponseBody: Body + Send + Sync + 'static,
        T::Error: Into<StdError>,
        <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> KeyProviderServiceClient<InterceptedService<T, F>>
        where
            F: FnMut(tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status>,
            T: tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
                Response = http::Response<
                    <T as tonic::client::GrpcService<tonic::body::BoxBody>>::ResponseBody,
                >,
            >,
            <T as tonic::codegen::Service<http::Request<tonic::body::BoxBody>>>::Error:
                Into<StdError> + Send + Sync,
        {
            KeyProviderServiceClient::new(InterceptedService::new(inner, interceptor))
        }
        #[doc = r" Compress requests with `gzip`."]
        #[doc = r""]
        #[doc = r" This requires the server to support it otherwise it might respond with an"]
        #[doc = r" error."]
        pub fn send_gzip(mut self) -> Self {
            self.inner = self.inner.send_gzip();
            self
        }
        #[doc = r" Enable decompressing responses with `gzip`."]
        pub fn accept_gzip(mut self) -> Self {
            self.inner = self.inner.accept_gzip();
            self
        }
        pub async fn wrap_key(
            &mut self,
            request: impl tonic::IntoRequest<super::KeyProviderKeyWrapProtocolInput>,
        ) -> Result<tonic::Response<super::KeyProviderKeyWrapProtocolOutput>, tonic::Status>
        {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/keyprovider.KeyProviderService/WrapKey");
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn un_wrap_key(
            &mut self,
            request: impl tonic::IntoRequest<super::KeyProviderKeyWrapProtocolInput>,
        ) -> Result<tonic::Response<super::KeyProviderKeyWrapProtocolOutput>, tonic::Status>
        {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/keyprovider.KeyProviderService/UnWrapKey");
            self.inner.unary(request.into_request(), path, codec).await
        }
    }
}
