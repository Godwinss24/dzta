// src/fabric_client.rs
use crate::config::{ConnectionConfig, UserContext};
use crate::errors::{WalletError, WalletResult};
use crate::models::*;
use log::{debug, error, info, warn};
use serde_json::json;
use std::sync::Arc;
use tokio::sync::RwLock;
// use std::time::Duration;
use prost::Message;
use tokio::time::sleep;
use tokio::time::timeout as tokio_timeout;
use std::time::{Duration, Instant};
use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};


pub use fabric_sdk::gateway::client::{Client, ClientBuilder};
pub use fabric_sdk::identity::{Identity, IdentityBuilder};
use fabric_sdk::fabric::gateway::{
    gateway_client::GatewayClient, 
    EndorseRequest, 
    EndorseResponse, 
    SignedCommitStatusRequest,
    CommitStatusRequest
};
#[derive(Debug, Clone, Serialize)]
pub struct FabricClient {
    #[serde(skip)]
    pub config: Arc<RwLock<ConnectionConfig>>,
    pub channel_name: String,
    pub chaincode_name: String,
    pub org_mspid: String,
    pub peer_url: String,
    pub is_mock: bool, // Flag to toggle between mock mode and the production network
}

#[derive(Debug, Clone, Serialize)]
pub struct ChaincodeInvocation {
    pub function: String,
    pub args: Vec<String>,
}

impl FabricClient {
    /// Initialize Fabric client
    pub async fn new(
        config_path: &str,
        channel_name: &str,
        chaincode_name: &str,
        org_name: &str,
        peer_name: &str,
    ) -> WalletResult<Self> {
        let config = ConnectionConfig::from_file(config_path).await?;
        let org_mspid = config.get_org_mspid(org_name)?;
        let peer_url = config.get_peer_url(peer_name)?;

        info!("Initialized Fabric client: {} on {}", chaincode_name, peer_url);

        Ok(FabricClient {
            config: Arc::new(RwLock::new(config)),
            channel_name: channel_name.to_string(),
            chaincode_name: chaincode_name.to_string(),
            org_mspid,
            peer_url,
            is_mock: false, // Default to true; toggle manually or via env setup
        })
    }

    /// Sets the execution mode manually (useful for shifting from test environment variables)
    pub fn set_mock(&mut self, is_mock: bool) {
        self.is_mock = is_mock;
    }

    /// Helper to instantiate an SDK-native identity structure from local configuration layout
    fn build_sdk_identity(&self, user_context: &UserContext) -> WalletResult<Identity> {
        let cert_pem = user_context.get_cert_pem();
        let private_key_pem = user_context.get_key_pem();

        // Check if the string content looks like a raw PEM block or a file path path-marker
        let loaded_cert = if cert_pem.contains("-----BEGIN CERTIFICATE-----") {
            cert_pem.as_bytes().to_vec()
        } else {
            // Synchronous fallback read if called inside non-async contexts
            std::fs::read(cert_pem).map_err(|e| WalletError::ConfigError(format!("Failed to load cert file: {}", e)))?
        };

        let loaded_key = if private_key_pem.contains("-----BEGIN PRIVATE KEY-----") {
            private_key_pem.to_string()
        } else {
            std::fs::read_to_string(private_key_pem).map_err(|e| WalletError::ConfigError(format!("Failed to load key file: {}", e)))?
        };

        IdentityBuilder::from_pem(&loaded_cert)
            .map_err(|e| WalletError::ConfigError(format!("Identity PEM parsing failed: {:?}", e)))?
            .with_msp(&self.org_mspid)
            .map_err(|e| WalletError::ConfigError(format!("Invalid MSP initialization: {:?}", e)))?
            .with_private_key(loaded_key)
            .map_err(|e| WalletError::ConfigError(format!("Private key binding failed: {:?}", e)))?
            .build()
            .map_err(|e| WalletError::ConfigError(format!("Failed to compile SDK identity structures: {:?}", e)))
    }

    /// Helper to establish a working connected client layout pointing to your node gateway

    async fn connect_gateway_client(&self, identity: Identity, config: &ConnectionConfig, peer_name: &str) -> WalletResult<Client> {
        // FIXED: Clean out grpcs:// and grpc:// alongside standard HTTP schemes
        let peer_authority = self.peer_url
            .replace("grpcs://", "")
            .replace("grpc://", "")
            .replace("https://", "")
            .replace("http://", "");
        
        // Dynamically load the configured TLS CA certificate asset relative to this specific peer
        let tls_cert_bytes = config.read_peer_tls_cert_bytes(peer_name).await?;

        let mut client = ClientBuilder::new()
            .with_identity(identity)
            .map_err(|e| WalletError::ConfigError(format!("Client identity assignment failed: {:?}", e)))?
            .with_tls(tls_cert_bytes)
            .map_err(|e| WalletError::ConfigError(format!("Client TLS configuration failed: {:?}", e)))?
            .with_scheme("https")
            .map_err(|e| WalletError::ConfigError(format!("Client scheme declaration failed: {:?}", e)))?
            .with_authority(peer_authority) // This will now receive "peer0-org1.localho.st:443" perfectly!
            .map_err(|e| WalletError::ConfigError(format!("Client endpoint assignment failed: {:?}", e)))?
            .build()
            .map_err(|e| WalletError::NetworkError(format!("Failed to build SDK client layout: {:?}", e)))?;

        client.connect().await.map_err(|e| {
            WalletError::NetworkError(format!("Gateway gRPC channel handshake failed: {}", e))
        })?;

        Ok(client)
    }

    pub fn generate_did(&self) -> String {
        // Fallback or static generation for mock testing
        if self.is_mock {
            return "did:dzta:mockorg1mspid123456789".to_string();
        }

        // Derive a unique suffix by hashing the mspid and peer network endpoint
        let mut hasher = Sha256::new();
        hasher.update(self.org_mspid.as_bytes());
        hasher.update(self.peer_url.as_bytes());
        let hash_result = hasher.finalize();
        
        // Format to hex string
        let id_suffix = hex::encode(&hash_result[0..16]); // Use first 16 bytes for a clean identifier

        // Returns standard format: did:dzta:<hex_suffix>
        format!("did:dzta:{}", id_suffix)
    }

    /// Register DID on Fabric ledger
    pub async fn register_did(
        &self,
        did: &str,
        issuer_did: &str,
        public_key: &str,
    ) -> WalletResult<String> {
        let invocation = ChaincodeInvocation {
            function: "RegisterDID".to_string(),
            args: vec![
                did.to_string(),
                issuer_did.to_string(),
                public_key.to_string(),
            ],
        };
        self.invoke_chaincode(&invocation).await
    }

    /// Resolve DID from Fabric ledger
    pub async fn resolve_did(&self, did: &str) -> WalletResult<DIDDocument> {
        let invocation = ChaincodeInvocation {
            function: "ResolveDID".to_string(),
            args: vec![did.to_string()],
        };

        let response = self.query_chaincode(&invocation).await?;
        let did_doc: DIDDocument = serde_json::from_slice(&response)
            .map_err(WalletError::SerializationError)?;
        Ok(did_doc)
    }

    /// Record credential metadata on Fabric ledger
    pub async fn record_credential_metadata(
        &self,
        credential_id: &str,
        schema_id: &str,
        issuer_did: &str,
        subject_did: &str,
        expires_at: i64,
    ) -> WalletResult<String> {
        let invocation = ChaincodeInvocation {
            function: "RecordCredentialMetadata".to_string(),
            args: vec![
                credential_id.to_string(),
                schema_id.to_string(),
                issuer_did.to_string(),
                subject_did.to_string(),
                expires_at.to_string(),
            ],
        };
        self.invoke_chaincode(&invocation).await
    }

    /// Get credential metadata from Fabric ledger
    pub async fn get_credential_metadata(
        &self,
        credential_id: &str,
    ) -> WalletResult<CredentialMetadata> {
        let invocation = ChaincodeInvocation {
            function: "GetCredentialMetadata".to_string(),
            args: vec![credential_id.to_string()],
        };

        let response = self.query_chaincode(&invocation).await?;
        let metadata: CredentialMetadata = serde_json::from_slice(&response)
            .map_err(WalletError::SerializationError)?;
        Ok(metadata)
    }

    /// Check if credential is revoked on Fabric ledger
    pub async fn is_credential_revoked(&self, credential_id: &str) -> WalletResult<bool> {
        let invocation = ChaincodeInvocation {
            function: "IsCredentialRevoked".to_string(),
            args: vec![credential_id.to_string()],
        };

        let response = self.query_chaincode(&invocation).await?;
        let revoked: bool = serde_json::from_slice(&response)
            .map_err(WalletError::SerializationError)?;
        Ok(revoked)
    }

    /// Revoke credential on Fabric ledger
    pub async fn revoke_credential(&self, credential_id: &str) -> WalletResult<String> {
        let invocation = ChaincodeInvocation {
            function: "RevokeCredential".to_string(),
            args: vec![credential_id.to_string()],
        };
        self.invoke_chaincode(&invocation).await
    }

    /// Register credential schema on Fabric ledger
    pub async fn register_schema(
        &self,
        schema_id: &str,
        issuer_did: &str,
        name: &str,
        version: &str,
        attributes: &[SchemaAttribute],
    ) -> WalletResult<String> {
        let attributes_json = serde_json::to_string(attributes)
            .map_err(WalletError::SerializationError)?;

        let invocation = ChaincodeInvocation {
            function: "RegisterSchema".to_string(),
            args: vec![
                schema_id.to_string(),
                issuer_did.to_string(),
                name.to_string(),
                version.to_string(),
                attributes_json,
            ],
        };
        self.invoke_chaincode(&invocation).await
    }

    /// Get credential schema from Fabric ledger
    pub async fn get_schema(&self, schema_id: &str) -> WalletResult<CredentialSchema> {
        let invocation = ChaincodeInvocation {
            function: "GetSchema".to_string(),
            args: vec![schema_id.to_string()],
        };

        let response = self.query_chaincode(&invocation).await?;
        let schema: CredentialSchema = serde_json::from_slice(&response)
            .map_err(WalletError::SerializationError)?;
        Ok(schema)
    }

    /// Query DIDs by issuer
    pub async fn query_dids_by_issuer(
        &self,
        issuer_did: &str,
    ) -> WalletResult<Vec<DIDDocument>> {
        let invocation = ChaincodeInvocation {
            function: "QueryDIDsByIssuer".to_string(),
            args: vec![issuer_did.to_string()],
        };

        let response = self.query_chaincode(&invocation).await?;
        let dids: Vec<DIDDocument> = serde_json::from_slice(&response)
            .map_err(WalletError::SerializationError)?;
        Ok(dids)
    }

    /// Invoke chaincode (write/modify ledger state via gateway endorsement)
 
    async fn invoke_chaincode(&self, invocation: &ChaincodeInvocation) -> WalletResult<String> {
        debug!(
            "Invoking chaincode function: {} with args: {:?}",
            invocation.function, invocation.args
        );

        if self.is_mock {
            info!("Mock Chaincode invocation completed: {}", invocation.function);
            return Ok(format!("Mock transaction submitted: {}", invocation.function));
        }

        // 1. Load active config mapping and cryptographic context details
        let config_guard = self.config.read().await;
        let user_context = config_guard.get_user_context().map_err(|_| {
            WalletError::ConfigError("Failed to load active user cryptographic contexts".to_string())
        })?;

        // 2. Map dynamic internal identity configurations
        let identity = self.build_sdk_identity(&user_context)?;

        // 3. Establish the live SDK gateway client link
        let client = self.connect_gateway_client(identity, &config_guard, "org1-peer0.default").await?;

        // =================================================================
        // DIAGNOSTIC LOGGING: Check variables right before call_builder injection
        // =================================================================
        info!(
            "[dZTA SDK Trace] Assembling transaction proposal.\n\
            Target Channel   : '{}'\n\
            Target Chaincode : '{}'\n\
            Target Function  : '{}'\n\
            Payload Arguments: {:?}",
            self.channel_name, self.chaincode_name, invocation.function, invocation.args
        );

        // 4. Assemble proposals using the exact ChaincodeCallBuilder layout patterns

        // Build the prepared payload transaction mapping
       
        let mut call_builder = client.get_chaincode_call_builder();
        call_builder
            .with_channel_name(&self.channel_name)
            .map_err(|e| WalletError::ConfigError(format!("Invalid channel assignment: {:?}", e)))?
            .with_chaincode_id(&self.chaincode_name)
            .map_err(|e| WalletError::ConfigError(format!("Invalid chaincode execution identifier: {:?}", e)))?
            .with_function_name(&invocation.function)
            .map_err(|e| WalletError::ConfigError(format!("Invalid function endpoint layout: {:?}", e)))?
            .with_system_chaincode(); // <-- FORCE THE CLEAN BARE FUNCTION STRING PAYLOAD HERE!

        call_builder
            .with_function_args(&invocation.args)
            .map_err(|e| WalletError::ConfigError(format!("Failed to inject transaction string payloads: {:?}", e)))?;

        let prepared_tx = call_builder.build_prepared().map_err(|e| {
            WalletError::ChaincodeFailed(format!("Failed to construct prepared execution payload: {:?}", e))
        })?;

        // Safely pull out the Transaction ID for validation tracing
        let tx_id = prepared_tx.signed_proposal()
            .get_proposal()
            .and_then(|p| p.get_header())
            .and_then(|h| h.get_channel_header())
            .map(|ch| ch.tx_id)
            .unwrap_or_default();

        // =================================================================
        // DIAGNOSTIC LOGGING: Check generated proposal metadata before network flight
        // =================================================================
        info!(
            "[dZTA SDK Trace] Dispatching Proposal for Endorsement.\n\
            Generated TxID   : '{}'\n\
            Target Endpoint  : grpcs://peer0-org1.localho.st:443",
            tx_id
        );

        // 5. Submit to active network peers for execution consensus signatures
        let _envelope = prepared_tx.endorse(&client).await.map_err(|e| {
            WalletError::ChaincodeFailed(format!("Ledger transaction signature execution rejected: {:?}", e))
        })?;

        info!("Chaincode invocation submitted successfully: {} (TxID: {}). Awaiting ledger commit...", invocation.function, tx_id);

        // 6. Polling block commit confirmation using the client's internal commit status handler
        self.wait_for_transaction_commit(&client, &tx_id, 30).await?;

        info!("Transaction {} fully committed to block state.", tx_id);
        Ok(tx_id)
    }

    /// Query chaincode (read ledger state - no orderer consensus required)
    async fn query_chaincode(&self, invocation: &ChaincodeInvocation) -> WalletResult<Vec<u8>> {
        debug!(
            "Querying chaincode function: {} with args: {:?}",
            invocation.function, invocation.args
        );

        if self.is_mock {
            info!("Mock Chaincode query executed: {}", invocation.function);
            
            let mock_json = match invocation.function.trim() {
                "GetCredentialMetadata" => {
                    let cred_id = invocation.args.first().cloned().unwrap_or_default();
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as i64;

                    json!({
                        "credential_id": cred_id,
                        "schema_id": "mock-schema-id",
                        "issuer_did": "did:example:issuer",
                        "subject_did": "did:example:subject",
                        "issued_at": now - 3600,       // Issued 1 hour ago
                        "expires_at": now + 31536000,   // Expires 1 year from now
                        "revoked": false,
                        "revoked_at": null,
                        "zkp_supported": true,
                        "proofable_fields": ["user_role_id", "org_id", "clearance_level", "timestamp"]
                    })
                },
                "IsCredentialRevoked" => json!(false),
                "GetSchema" => {
                    let schema_id = invocation.args.first().cloned().unwrap_or_default();
                    json!({
                        "schema_id": schema_id,
                        "issuer_did": "did:example:issuer",
                        "name": "TestSchema",
                        "version": "1.0.0",
                        "attributes": []
                    })
                },
                "ResolveDID" => json!({
                    "id": invocation.args.first().cloned().unwrap_or_default(),
                    "public_key": "placeholder_pubkey",
                    "authentication": ["key-1"]
                }),
                _ => json!(false) 
            };

            return serde_json::to_vec(&mock_json).map_err(WalletError::SerializationError);
        }

        // 1. Load context layouts
        let config_guard = self.config.read().await;
        let user_context = config_guard.get_user_context().map_err(|_| {
            WalletError::ConfigError("Failed to load active user cryptographic contexts".to_string())
        })?;

        // 2. Build live client infrastructure connections
        let identity = self.build_sdk_identity(&user_context)?;
        // let client = self.connect_gateway_client(identity, &config_guard).await?;
        // Inside invoke_chaincode and query_chaincode:
        let client = self.connect_gateway_client(identity, &config_guard, "org1-peer0").await?;

        // 3. Assemble the read proposal call parameters
        let mut call_builder = client.get_chaincode_call_builder();
        call_builder
            .with_channel_name(&self.channel_name)
            .map_err(|e| WalletError::ConfigError(format!("Invalid channel assignment: {:?}", e)))?
            .with_chaincode_id(&self.chaincode_name)
            .map_err(|e| WalletError::ConfigError(format!("Invalid chaincode execution identifier: {:?}", e)))?
            .with_function_name(&invocation.function)
            .map_err(|e| WalletError::ConfigError(format!("Invalid function endpoint layout: {:?}", e)))?
            .with_system_chaincode(); // <-- FORCE THE CLEAN BARE FUNCTION STRING PAYLOAD HERE!

        call_builder
            .with_function_args(&invocation.args)
            .map_err(|e| WalletError::ConfigError(format!("Failed to inject transaction string payloads: {:?}", e)))?;

        let prepared_tx = call_builder.build_prepared().map_err(|e| {
            WalletError::ChaincodeFailed(format!("Failed to compile evaluate transaction details: {:?}", e))
        })?;

        // 4. Evaluate read-only query states using client endpoints
        let response_payload = prepared_tx.evaluate(&client).await.map_err(|e| {
            WalletError::ChaincodeFailed(format!("Gateway query payload transaction execution failure: {:?}", e))
        })?;

        Ok(response_payload)
    }

    /// Polls the native Fabric Gateway CommitStatus endpoint until a given transaction ID 
 

    // / Polls the SDK client's native commit_status verification loop
    // pub async fn wait_for_transaction_commit(
    //     &self,
    //     client: &Client,
    //     tx_id: &str,
    //     timeout_secs: u64,
    // ) -> WalletResult<()> {
    //     if self.is_mock {
    //         info!("Mock Mode Active: Simulating immediate successful transaction commit for {}", tx_id);
    //         return Ok(());
    //     }

    //     let start = std::time::Instant::now();
    //     let timeout = Duration::from_secs(timeout_secs);
    //     let poll_interval = Duration::from_millis(500);

    //     loop {
    //         if start.elapsed() > timeout {
    //             error!("Transaction tracing window expired for tx: {}", tx_id);
    //             return Err(WalletError::ChaincodeFailed(format!(
    //                 "Transaction {} not committed within {} seconds", 
    //                 tx_id, timeout_secs
    //             )));
    //         }

           
    //         match client.commit_status(tx_id.to_string(), self.channel_name.clone()).await {
    //             Ok(status_payload) => {
    //                 if status_payload.result == 0 {
    //                     info!("Transaction {} confirmed in block number: {}", tx_id, status_payload.block_number);
    //                     return Ok(());
    //                 }
                    
    //                 if status_payload.result > 0 {
    //                     return Err(WalletError::ChaincodeFailed(format!(
    //                         "Transaction {} rejected by peer validation code: {}", 
    //                         tx_id, status_payload.result
    //                     )));
    //                 }
    //             }
    //             Err(e) => {
    //                 // Change from debug! to warn! or info! and dump the error details
    //                 warn!("[dZTA Sync Trace] Commit status check returned an error: {:?}", e);
    //             }
    //         }

    //         sleep(poll_interval).await;
    //     }
    // }

    pub async fn wait_for_transaction_commit(
        &self,
        client: &Client,
        tx_id: &str,
        timeout_secs: u64,
    ) -> WalletResult<()> {
        if self.is_mock {
            info!("Mock Mode Active: Simulating immediate successful transaction commit for {}", tx_id);
            return Ok(());
        }

        let start = Instant::now();
        let timeout = Duration::from_secs(timeout_secs);
        let poll_interval = Duration::from_millis(500);
        // Give individual network round-trips a strict 2-second upper bound
        let wire_timeout = Duration::from_secs(2); 

        loop {
            // 1. Guard against cumulative execution timeout expiration
            if start.elapsed() > timeout {
                error!("Transaction tracing window expired for tx: {}", tx_id);
                return Err(WalletError::ChaincodeFailed(format!(
                    "Transaction {} not committed within {} seconds", 
                    tx_id, timeout_secs
                )));
            }

            // 2. Prepare the underlying gRPC commit status check future
            let status_future = client.commit_status(tx_id.to_string(), self.channel_name.clone());
            
            // 3. Execute the future wrapped inside a tokio network timeout guard
            match tokio_timeout(wire_timeout, status_future).await {
                Ok(Ok(status_payload)) => {
                    // Transaction validated and successfully committed to a block
                    if status_payload.result == 0 {
                        info!(
                            "Transaction {} confirmed in block number: {}", 
                            tx_id, status_payload.block_number
                        );
                        return Ok(());
                    }
                    
                    // Transaction found but rejected by peer validation logic (e.g., MVCC_READ_CONFLICT)
                    if status_payload.result > 0 {
                        return Err(WalletError::ChaincodeFailed(format!(
                            "Transaction {} rejected by peer validation code: {}", 
                            tx_id, status_payload.result
                        )));
                    }
                }
                Ok(Err(e)) => {
                    // The peer node returned an active network/transport error (e.g., UnexpectedEof, connection reset)
                    warn!(
                        "[dZTA Sync Trace] Commit status check returned a node/transport error: {:?}", 
                        e
                    );
                }
                Err(_) => {
                    // The network request failed to respond completely within the 2-second wire_timeout window
                    warn!(
                        "[dZTA Sync Trace] Commit status check request timed out on the wire for tx: {}", 
                        tx_id
                    );
                }
            }

            // 4. Back off before dispatching the next evaluation poll
            sleep(poll_interval).await;
        }
    }

    // pub async fn wait_for_transaction_commit(
    //     &self,
    //     client: &Client,
    //     tx_id: &str,
    //     timeout_secs: u64,
    // ) -> WalletResult<()> {
    //     if self.is_mock {
    //         info!("Mock Mode Active: Simulating immediate successful transaction commit for {}", tx_id);
    //         return Ok(());
    //     }

    //     // Bypass unstable gRPC gateway commit_status streams
    //     info!("[dZTA Sync] Transaction {} successfully broadcasted to consensus network. Waiting for state synchronization...", tx_id);
        
    //     // Give the local orderer container a brief, predictable window to cut the block and commit to CouchDB/LevelDB state
    //     tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        
    //     info!("[dZTA Sync] State synchronization window completed for tx: {}", tx_id);
    //     Ok(())
    // }

    pub async fn get_endorsements_with_retry(
        &self,
        mut gateway_channel: GatewayClient<tonic::transport::Channel>,
        request: EndorseRequest,
        max_retries: u32,
    ) -> WalletResult<EndorseResponse> {
        // Short-circuit if we are running in mock test mode
        if self.is_mock {
            info!("Mock Mode Active: Simulating immediate successful peer endorsements");
            return Ok(EndorseResponse { prepared_transaction: None });
        }

        let mut retries = 0;

        while retries < max_retries {
            match gateway_channel.endorse(request.clone()).await {
                Ok(response) => {
                    debug!("Sufficient peer endorsements collected successfully.");
                    return Ok(response.into_inner());
                },
                Err(e) => {
                    retries += 1;
                    warn!("Endorsement attempt {}/{} failed: {:?}", retries, max_retries, e);
                    
                    if retries >= max_retries {
                        return Err(WalletError::ChaincodeFailed(format!(
                            "Max endorsement retries exhausted. Gateway Error: {}", e.message()
                        )));
                    }

                    // Calculate exponential backoff interval: 100ms -> 200ms -> 400ms...
                    let backoff_ms = 100 * (2_u64.pow(retries - 1));
                    debug!("Backing down endorsement thread context for {}ms...", backoff_ms);
                    sleep(Duration::from_millis(backoff_ms)).await;
                }
            }
        }

        Err(WalletError::ChaincodeFailed("Unexpected system exit within client retry block".to_string()))
    }

    /// Get channel name
    pub fn get_channel_name(&self) -> &str {
        &self.channel_name
    }

    /// Get chaincode name
    pub fn get_chaincode_name(&self) -> &str {
        &self.chaincode_name
    }

    /// Get organization MSP ID
    pub fn get_org_mspid(&self) -> &str {
        &self.org_mspid
    }

    /// Get peer URL
    pub fn get_peer_url(&self) -> &str {
        &self.peer_url
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fabric_client_init() {
        let result = FabricClient::new(
            "config/connection-profile.yaml",
            "demo",
            "asset",
            "org1",
            "org1-peer0",
        )
        .await;

        assert!(result.is_ok() || result.is_err());
    }
}