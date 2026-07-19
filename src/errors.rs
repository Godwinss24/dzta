// src/errors.rs
use thiserror::Error;

#[derive(Error, Debug)]
pub enum WalletError {
    #[error("Fabric client error: {0}")]
    FabricError(String),

    #[error("VCX error: {0}")]
    VcxError(String),

    #[error("Askar error: {0}")]
    AskarError(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Chaincode invocation failed: {0}")]
    ChaincodeFailed(String),

    #[error("Invalid response from peer")]
    InvalidResponse,

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Endorse error: {0}")]
    EndorseError(String),

    #[error("Commit error: {0}")]
    CommitError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Credential not found: {0}")]
    CredentialNotFound(String),

    #[error("DID not found: {0}")]
    DIDNotFound(String),

    #[error("Invalid witness: {0}")]
    InvalidWitness(String),

    #[error("Signing error: {0}")]
    SigningError(String),

    #[error("Transaction failed: {0}")]
    TransactionFailed(String),

    #[error("gRPC error: {0}")]
    GrpcError(String),

    #[error("Revocation check failed: {0}")]
    RevocationError(String),

    #[error("Timeout waiting for transaction confirmation")]
    TransactionTimeout,

    #[error("Unknown error: {0}")]
    Unknown(String),
}

pub type WalletResult<T> = Result<T, WalletError>;
