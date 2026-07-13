# Decentralized Zero Trust Architecture (DZTA) Docs

Current Zero Trust (ZT) security architectures rely on a centralized Policy Decision Point (PDP). This project implements a Decentralized Zero Trust Architecture (dZTA) optimized specifically for Mobile Edge Computing (MEC), using Hyperledger Fabric for blockchain-backed Verifiable Credential management, DID registration, and ZK proof witness generation.

---

## Table of Contents

1. [Build & Run](#build--run)
2. [Testing](#testing)
3. [Config](#config)
4. [Credential Manager](#credential-manager)
5. [Fabric Client](#fabric-client)
6. [Schema Engine](#schema-engine)
7. [ZKP Witness Generator](#zkp-witness-generator)
8. [ChainCode](#chaincode)
9. [Models](#models)
10. [Error Handling](#error-handling)

---

## Build & Run

### Prerequisites

- Rust toolchain (edition 2024)
- A running Hyperledger Fabric network with the `dztac` chaincode deployed
- A valid connection profile in `config/connection-profile.yaml`

### Build

```bash
cargo build
```

### Run

```bash
cargo run
```

This executes the demo workflow in `src/main.rs`, which initializes a Fabric client, creates a credential, generates a ZKP witness, and exports it as Circom-compatible JSON input.

### Configuration

Copy and edit the connection profile to match your Fabric network:

```bash
cp config/connection-profile.yaml config/my-network.yaml
```

Update the peer URLs, orderer URLs, and certificate paths in the YAML file before running.

---

## Testing

### Running Tests

```bash
cargo test
```

### Mock Mode

`FabricClient` supports a **mock mode** for testing without a live Fabric network. When `is_mock` is set to `true`, all chaincode queries return realistic mock responses. This allows you to test credential creation, witness generation, and schema validation locally.

To enable mock mode:

```rust
let mut client = FabricClient::new(/* ... */).await?;
client.set_mock(true);
```

---

## Config

The config module holds the different `ConnectionConfig` for different nodes (peers, orderers) in the fabric network.

```rust
pub struct ConnectionConfig {
    pub version: String,
    pub peers: HashMap<String, PeerConfig>,
    pub orderers: HashMap<String, OrdererConfig>,
    pub organizations: HashMap<String, OrgConfig>,
    pub channels: HashMap<String, ChannelConfig>,
    pub client: ClientConfig,
}
```

Implementations of this struct help you get peers, channels, orderers.

```rust
pub struct UserContext {
    cert_pem: String,
    key_pem: String,
    msp_id: String,
}
```

An important implementation of this struct is the `sign_bytes` function, which enables a user in that org to sign a transaction in order for him/her to perform different admin configs on a node in the network. It uses the private key to sign a message (bytes), so a node can verify that the instructions are from the right identity on the network.

---

## Credential Manager

```rust
pub struct CredentialManager {
    pub fabric_client: FabricClient,
    pub askar_store_path: String,
    pub askar_store: Arc<tokio::sync::RwLock<Option<Store>>>,
}
```

A credential manager manages the different Verifiable Credentials (VC) in the user's wallet. `askar_store_path` is the path on the mobile device which the VC's will be stored at.

### Creating a Credential

```rust
pub async fn create_credential(
    &self,
    schema_id: &str,
    issuer_did: &str,
    subject_did: &str,
    credential_attributes: &CredentialAttributes,
    expires_at_unix: i64,
)
```

- A **schema** is a structure which an org uses for its VC's. It is stored on the blockchain's ledger, so it has an id.
- A **Decentralized Identity (DID)** is a unique identity given to each org, user, etc. The `generate_did` function generates a new DID: it hashes the msp id and the peer's url and takes the first 16 bytes, giving something like `did:dzta:<16 bytes>`.
- **Subject DID** is the DID which the credential is being created for.
- **Credential attributes** will be the different fields in the credential, which will be validated against the schema fetched from the blockchain.

After all these steps, the credential is stored in the askar wallet, and a log will be stored on the blockchain to mark that this event happened. 
Note: `credential_id` is a unique UUID generated for each credential in the store.

### Initializing the Store

```rust
pub async fn initialize_askar_store(
    &self,
    pass_key: &str,
) -> WalletResult<()>
```

This initializes a store on the user's device, which will be used for storing the different credentials. It uses **RwLock**, which will ensure only one writer to the store but multiple readers.

### Checking Revocation Status

```rust
pub async fn is_credential_revoked(&self, credential_id: &str) -> WalletResult<bool>
```

This calls the blockchain to check if a credential has been revoked or not.

### Extracting Proofable Fields

```rust
pub async fn extract_proofable_fields(
    &self,
    credential_id: &str,
) -> WalletResult<CredentialAttributes>
```

Extract fields from a credential so it can be fed into the ZK circuit.

### Revoking a Credential

```rust
pub async fn revoke_credential(&self, credential_id: &str) -> WalletResult<()>
```

Revokes a credential both on the Fabric blockchain and in the local Askar wallet.

### Storing a Credential

```rust
async fn store_credential_in_askar(
    &self,
    credential_id: &str,
    credential_data: &Value,
) -> WalletResult<()>
```

This inserts a credential into the store.

---

## Fabric Client

```rust
pub struct FabricClient {
    #[serde(skip)]
    pub config: Arc<RwLock<ConnectionConfig>>,
    pub channel_name: String,
    pub chaincode_name: String,
    pub org_mspid: String,
    pub peer_url: String,
    pub is_mock: bool, // Flag to toggle between mock mode and the production network
}
```

This is a client that allows us to communicate with the blockchain. It's a very important struct.

### Building an Identity

```rust
fn build_sdk_identity(&self, user_context: &UserContext) -> WalletResult<Identity>
```

A user is one who is allowed to configure different nodes. They have admin privileges. This function uses the certificate & key certificate to build an identity using the fabric_sdk. This allows you to have an `Identity` struct from the fabric_sdk.

### Connecting to the Gateway

```rust
async fn connect_gateway_client(&self, identity: Identity, config: &ConnectionConfig, peer_name: &str) -> WalletResult<Client>
```

After building an identity, you can connect to the gateway.

### Registering a DID

```rust
pub async fn register_did(
    &self,
    did: &str,
    issuer_did: &str,
    public_key: &str,
) -> WalletResult<String>
```

This registers a DID on the blockchain.

### Resolving a DID

```rust
pub async fn resolve_did(&self, did: &str) -> WalletResult<DIDDocument>
```

Resolves a DID from the blockchain and returns its document.

### Querying DIDs by Issuer

```rust
pub async fn query_dids_by_issuer(&self, issuer_did: &str) -> WalletResult<Vec<DIDDocument>>
```

Returns all DIDs issued by a given issuer.

### Registering a Schema

```rust
pub async fn register_schema(
    &self,
    schema_id: &str,
    issuer_did: &str,
    name: &str,
    version: &str,
    attributes: Vec<SchemaAttribute>,
) -> WalletResult<String>
```

Registers a credential schema on the blockchain.

### Getting a Schema

```rust
pub async fn get_schema(&self, schema_id: &str) -> WalletResult<CredentialSchema>
```

Fetches a credential schema from the blockchain.

### Recording Credential Metadata

```rust
pub async fn record_credential_metadata(
    &self,
    credential_id: &str,
    schema_id: &str,
    issuer_did: &str,
    subject_did: &str,
    proofable_fields: Vec<String>,
    expires_at: i64,
) -> WalletResult<String>
```

Records credential metadata on the blockchain after creation.

### Getting Credential Metadata

```rust
pub async fn get_credential_metadata(&self, credential_id: &str) -> WalletResult<CredentialMetadata>
```

Fetches credential metadata from the blockchain.

---

## Schema Engine

```rust
pub struct SchemaEngine;
```

A stateless engine that validates credential fields against a schema definition fetched from the blockchain. This ensures that credentials conform to their declared structure before they are stored or used in ZK proofs.

### Validating Fields

```rust
pub fn validate_fields(
    schema: &CredentialSchema,
    credential_subject: &Value,
) -> WalletResult<()>
```

Validates that a credential subject's fields match the schema's attribute definitions. Checks:

- **string** fields: must be JSON strings
- **integer** fields: must be JSON integers
- **timestamp** fields: must be a positive Unix timestamp (i64) or a valid RFC3339 string

Returns an error if any field is missing, has the wrong type, or uses an unrecognized type.

---

## ZKP Witness Generator

```rust
pub struct ZKPWitnessGenerator {
    credential_manager: Arc<CredentialManager>,
}
```

Generates ZKP witness data from stored credentials for use with Circom circuits. The witness contains the credential's proofable fields and is serialized to a Circom-compatible JSON format.

### Generating a Witness

```rust
pub async fn generate_witness(&self, credential_id: &str) -> WalletResult<ZKPWitness>
```

Generates a witness for a single credential. Verifies the credential is active (not revoked, not expired), retrieves metadata from Fabric, extracts proofable fields, and constructs a `ZKPWitness`.

### Generating Circom Input

```rust
pub async fn generate_circom_input(&self, credential_id: &str) -> WalletResult<Value>
```

Generates a witness and returns it as a Circom-compatible JSON `Value`. Uses camelCase field names (e.g., `credentialId`, `clearanceLevel`).

### Generating Witness with Constraints

```rust
pub async fn generate_witness_with_constraints(
    &self,
    credential_id: &str,
    constraints: WitnessConstraints,
) -> WalletResult<Value>
```

Generates a witness enriched with constraint flags for range proofs and access control checks. The `WitnessConstraints` struct:

```rust
pub struct WitnessConstraints {
    pub min_clearance_level: u32,
    pub max_clearance_level: u32,
    pub allowed_orgs: Vec<String>,
    pub time_window_start: i64,
    pub time_window_end: i64,
}
```

### Batch Generating Witnesses

```rust
pub async fn generate_batch_witnesses(
    &self,
    credential_ids: &[&str],
) -> WalletResult<Vec<ZKPWitness>>
```

Generates witnesses for multiple credentials. Credentials that fail are silently skipped (logged at debug level).

### Exporting Witness to File

```rust
pub async fn export_witness_to_file(
    &self,
    credential_id: &str,
    output_path: &str,
) -> WalletResult<()>
```

Generates a witness and writes the Circom-compatible JSON to a file.

### Validating a Witness

```rust
pub fn validate_witness(&self, witness: &ZKPWitness) -> WalletResult<()>
```

Validates that a witness has all required non-empty fields and a positive timestamp.

---

## ChainCode

```rust
pub struct ChaincodeInvocation {
    pub function: String,
    pub args: Vec<String>,
}
```

The chaincode is written using GO and deployed on the nodes in the network. Rust calls them by specifying the name of the function and the args to it.

Some of the functions include:
- `RegisterDID`
- `ResolveDID`
- `RecordCredentialMetadata`
- `GetCredentialMetadata`
- `IsCredentialRevoked`
- `RevokeCredential`
- `RegisterSchema`

### Invoking Chaincode

```rust
async fn invoke_chaincode(&self, invocation: &ChaincodeInvocation) -> WalletResult<String>
```

This builds an identity, connects to the gateway, endorses a transaction, and — depending on the result from the endorsing peers — sends the transaction to the rest of the network.

---

## Models

All model types derive `Debug`, `Clone`, `Serialize`, and `Deserialize`.

### DIDDocument

```rust
pub struct DIDDocument {
    pub did: String,
    pub issuer_did: String,
    pub public_key: String,
    pub created: i64,
    pub updated: i64,
    pub active: bool,
}
```

Represents a Decentralized Identity document stored on the Fabric ledger.

### CredentialMetadata

```rust
pub struct CredentialMetadata {
    pub credential_id: String,
    pub schema_id: String,
    pub issuer_did: String,
    pub subject_did: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub revoked: bool,
    pub revoked_at: Option<i64>,
    pub zkp_supported: bool,
    pub proofable_fields: Vec<String>,
}
```

On-chain metadata for a credential. The full VC JSON-LD is stored locally in Askar; only non-sensitive metadata lives on the blockchain.

### CredentialSchema

```rust
pub struct CredentialSchema {
    pub schema_id: String,
    pub issuer_did: String,
    pub name: String,
    pub version: String,
    pub attributes: Vec<SchemaAttribute>,
    pub created: i64,
}
```

Defines the structure that Verifiable Credentials must conform to.

### SchemaAttribute

```rust
pub struct SchemaAttribute {
    pub name: String,
    pub attr_type: String, // "string", "integer", "timestamp"
    pub predicate: bool,   // Can be used in ZKP predicate
}
```

An individual attribute definition within a schema.

### StoredCredential

```rust
pub struct StoredCredential {
    pub credential_id: String,
    pub schema_id: String,
    pub issuer_did: String,
    pub subject_did: String,
    pub credential_data: serde_json::Value, // Raw VC JSON-LD
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub stored_in_askar: bool,
}
```

A credential as stored in the local Askar wallet.

### CredentialAttributes

```rust
pub struct CredentialAttributes {
    pub user_role_id: String,
    pub org_id: String,
    pub clearance_level: u32,
    pub timestamp: i64,
}
```

The proofable fields extracted from a credential for ZK circuit input.

### ZKPWitness

```rust
pub struct ZKPWitness {
    pub credential_id: String,
    pub schema_id: String,
    pub issuer_did: String,
    pub subject_did: String,
    pub user_role_id: String,
    pub org_id: String,
    pub clearance_level: u32,
    pub timestamp: i64,
    pub issued_at: i64,
    pub expires_at: i64,
}
```

Input data for a Circom ZK circuit. Includes `to_circom_input()` which serializes to camelCase JSON.

### ChaincodeInvocation

```rust
pub struct ChaincodeInvocation {
    pub function: String,
    pub args: Vec<String>,
}
```

Payload sent to the Fabric chaincode.

### ChaincodeResponse

```rust
pub struct ChaincodeResponse {
    pub status: u32,
    pub payload: Vec<u8>,
    pub message: String,
}
```

Response received from the Fabric chaincode.

---

## Error Handling

All fallible operations return `WalletResult<T>`, which is a type alias for `Result<T, WalletError>`.

```rust
pub type WalletResult<T> = Result<T, WalletError>;
```

The `WalletError` enum covers all failure modes

```rust 
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
```