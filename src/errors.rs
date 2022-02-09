// using `displaydoc` instead of `thiserror`, see
// https://github.com/dtolnay/thiserror/pull/64#issuecomment-735805334
// `thiserror` does not support #![no_std]
//! Error types related to transaction API

use ark_serialize::SerializationError as ArkSerializationError;
use ark_std::string::String;
use displaydoc::Display;
use jf_primitives::errors::PrimitivesError;

/// All possible categories of error from Transaction API
#[derive(Display, Debug)]
pub enum TxnApiError {
    /// Crypto primitives failed: {0}
    FailedPrimitives(String),
    /// Plonk SNARK failed: {0}
    FailedSnark(String),
    /// AssetCode verification failed: {0}
    FailedAssetCodeVerification(String),
    /// Credential creation failed: {0}
    FailedCredentialCreation(String),
    /// Credential verification failed: {0}
    FailedCredentialVerification(String),
    /// Failed Transaction Verification: {0}
    FailedTransactionVerification(String),
    /// Failed Serialization: {0}
    FailedSerialization(String),
    /// Failed ReceiverMemo Signature: {0}
    FailedReceiverMemoSignature(PrimitivesError),
    /// Failed Transaction Memo Signature: {0}"
    FailedTxMemoSignature(PrimitivesError),
    /// Failed AuditMemo Decryption: {0}
    FailedAuditMemoDecryption(String),
    /// I/O failure: {0}
    IoError(String),
    /// Invalid parameters: {0}
    InvalidParameter(String),
    /// Failed to deserialize: {0}
    DeserializationError(DeserializationError),
    /// Incorrect fee collection: {0}
    IncorrectFee(String),
    /// Parameters generation error:{0}
    ParametersGenerationError(String),
    #[rustfmt::skip]
    /// ‼ ️Internal error! Please report to Crypto Team immediately!\nMessage: {0}"
    InternalError(String),
    /// Invalid Attribute code
    InvalidAttribute,
}

/// Errors from deserialization.
#[derive(Display, Debug)]
pub enum DeserializationError {
    /// Failed to deserialize with Arkworks: {0}
    ArkSerializationError(ArkSerializationError),
    /// Failed to deserialize with Serde: {0}
    SerdeError(String),
}

#[cfg(not(feature = "std"))]
impl From<TxnApiError> for anyhow::Error {
    fn from(e: TxnApiError) -> Self {
        Self::msg(e)
    }
}

impl From<ArkSerializationError> for TxnApiError {
    fn from(e: ArkSerializationError) -> Self {
        Self::DeserializationError(DeserializationError::ArkSerializationError(e))
    }
}

impl From<DeserializationError> for TxnApiError {
    fn from(e: DeserializationError) -> Self {
        Self::DeserializationError(e)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TxnApiError {}
