// src/credential_manager.rs
use crate::errors::{WalletError, WalletResult};
use crate::models::*;
use crate::fabric_client::FabricClient;
use serde_json::{json, Value};
use uuid::Uuid;
use log::{info, debug, error};
use std::sync::Arc;
use aries_askar::{Store, StoreKeyMethod};
use aries_askar::entry::EntryTag;

pub struct CredentialManager {
    pub fabric_client: FabricClient,
    pub askar_store_path: String,
    pub askar_store: Arc<tokio::sync::RwLock<Option<Store>>>,
}

impl CredentialManager {
    /// Initialize credential manager with Fabric client and Askar store
    pub fn new(fabric_client: FabricClient, askar_store_path: &str) -> Self {
        info!("Initializing credential manager with Askar at: {}", askar_store_path);

        CredentialManager {
            fabric_client,
            askar_store_path: askar_store_path.to_string(),
            askar_store: Arc::new(tokio::sync::RwLock::new(None)),
        }
    }

    /// Create and store a new credential (issuer side)
    pub async fn create_credential(
        &self,
        schema_id: &str,
        issuer_did: &str,
        subject_did: &str,
        credential_attributes: &CredentialAttributes,
        expires_at_unix: i64,
    ) -> WalletResult<StoredCredential> {
        let credential_id = Uuid::new_v4().to_string();

        // 1. Live Fetch the target schema structure from Fabric/Mock layer
        let schema = self.get_schema(schema_id).await?;

        // 2. Draft the raw Subject data mapping
        let subject_payload = json!({
            "id": subject_did,
            "userRoleId": credential_attributes.user_role_id,
            "orgId": credential_attributes.org_id,
            "clearanceLevel": credential_attributes.clearance_level,
            "timestamp": credential_attributes.timestamp,
        });

        // 3. ENFORCE structural integrity dynamically against the active schema definition
        crate::schema_engine::SchemaEngine::validate_fields(&schema, &subject_payload)?;

        // 4. Build W3C Verifiable Credential if validation succeeds
        let vc = json!({
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
            ],
            "type": ["VerifiableCredential"],
            "issuer": issuer_did,
            "issuanceDate": chrono::Utc::now().to_rfc3339(),
            "expirationDate": chrono::DateTime::<chrono::Utc>::from_timestamp(expires_at_unix, 0)
                .unwrap()
                .to_rfc3339(),
            "credentialSubject": subject_payload,
            "proof": {
                "type": "Ed25519Signature2018",
                "verificationMethod": format!("{}#key-1", issuer_did),
                "signatureValue": "placeholder_signature"
            }
        });

        // Store in Askar (encrypted)
        self.store_credential_in_askar(&credential_id, &vc).await?;

        // Record metadata on Fabric (public)
        self.fabric_client
            .record_credential_metadata(
                &credential_id,
                schema_id,
                issuer_did,
                subject_did,
                expires_at_unix,
            )
            .await?;

        let now = chrono::Utc::now();
        let expires_at = chrono::DateTime::<chrono::Utc>::from_timestamp(expires_at_unix, 0);

        let credential = StoredCredential {
            credential_id: credential_id.clone(),
            schema_id: schema_id.to_string(),
            issuer_did: issuer_did.to_string(),
            subject_did: subject_did.to_string(),
            credential_data: vc,
            issued_at: now,
            expires_at,
            stored_in_askar: true,
        };

        info!("Credential created and stored post-validation: {}", credential_id);
        Ok(credential)
    }

    pub async fn initialize_askar_store(
        &self,
        pass_key: &str,
    ) -> WalletResult<()> {
        info!("Initializing Askar store at: {}", self.askar_store_path);

        // 1. Ensure target directory path exists
        if let Some(parent) = std::path::Path::new(&self.askar_store_path).parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                error!("Failed to create Askar database directory tree: {:?}", e);
                WalletError::StorageError(format!("Directory provisioning failed: {}", e))
            })?;
        }

        use aries_askar::storage::KdfMethod;
        let key_method = StoreKeyMethod::DeriveKey(KdfMethod::Argon2i(Default::default()));

        // Format raw sqlite URI without extra connection query modifications
        let db_uri = if self.askar_store_path.starts_with("file:") || self.askar_store_path.contains("://") {
            self.askar_store_path.clone()
        } else {
            format!("sqlite://{}", self.askar_store_path)
        };

        // 2. Check if the database path already exists as a file
        let path = std::path::Path::new(&self.askar_store_path);
        
        let store = if path.exists() {
            debug!("Askar database file exists. Opening store session...");
            Store::open(
                &db_uri,
                Some(key_method),
                pass_key.to_string().into(),
                None,
            )
            .await
        } else {
            info!("Askar database file not found. Provisioning brand new secure store...");
            Store::provision(
                &db_uri,
                key_method,
                pass_key.to_string().into(),
                None,
                false, // recreate flag set to false so it doesn't blast away data unexpectedly
            )
            .await
        }
        .map_err(|e| {
            error!("Failed to open/provision Askar store: {:?}", e);
            WalletError::StorageError(format!("Askar store initialization failed: {}", e))
        })?;

        let mut store_lock = self.askar_store.write().await;
        *store_lock = Some(store);

        info!("Askar store initialized successfully");
        Ok(())
    }

    /// Retrieve credential from Askar by ID
    pub async fn get_credential(&self, credential_id: &str) -> WalletResult<StoredCredential> {
        debug!("Retrieving credential from Askar: {}", credential_id);

        // Retrieve from Askar
        let vc_data = self.retrieve_credential_from_askar(credential_id).await?;

        // Retrieve metadata from Fabric
        let metadata = self
            .fabric_client
            .get_credential_metadata(credential_id)
            .await?;

        let credential = StoredCredential {
            credential_id: metadata.credential_id.clone(),
            schema_id: metadata.schema_id.clone(),
            issuer_did: metadata.issuer_did.clone(),
            subject_did: metadata.subject_did.clone(),
            credential_data: vc_data,
            issued_at: chrono::DateTime::<chrono::Utc>::from_timestamp(metadata.issued_at, 0)
                .unwrap(),
            expires_at: chrono::DateTime::<chrono::Utc>::from_timestamp(metadata.expires_at, 0),
            stored_in_askar: true,
        };

        Ok(credential)
    }


    pub async fn get_credential_metadata_from_askar(
        &self,
        credential_id: &str,
    ) -> WalletResult<Value> {
        debug!("Retrieving credential metadata from Askar: {}", credential_id);

        let store_lock = self.askar_store.read().await;
        let store = store_lock.as_ref()
            .ok_or_else(|| WalletError::StorageError("Askar store not initialized".to_string()))?;

        let mut session = store.session(None)
            .await
            .map_err(|e| {
                WalletError::StorageError(format!("Session creation failed: {}", e))
            })?;

        let entry = session.fetch(
            "credentials",
            credential_id,
            false,
        )
        .await
        .map_err(|e| {
            WalletError::StorageError(format!("Metadata retrieval failed: {}", e))
        })?
        .ok_or_else(|| {
            WalletError::StorageError(format!("Credential not found: {}", credential_id))
        })?;

        // Search through the EntryTag vector for the "revoked" tag
        let is_revoked = entry.tags
            .iter()
            .find(|tag| tag.name() == "revoked")
            .map(|tag| tag.value() == "true")
            .unwrap_or(false);

        // Map it back into the JSON value schema expected by the rest of your application
        let metadata = json!({
            "revoked": is_revoked
        });

        Ok(metadata)
    }

    /// Verify credential is not revoked
    pub async fn verify_credential_active(&self, credential_id: &str) -> WalletResult<bool> {
        debug!("Verifying credential is active: {}", credential_id);

        let is_revoked = self
            .fabric_client
            .is_credential_revoked(credential_id)
            .await?;

        if is_revoked {
            return Err(WalletError::RevocationError(format!(
                "Credential revoked: {}",
                credential_id
            )));
        }

        // Check expiration
        let metadata = self
            .fabric_client
            .get_credential_metadata(credential_id)
            .await?;

        let now = chrono::Utc::now().timestamp();
        if now > metadata.expires_at {
            return Err(WalletError::RevocationError(format!(
                "Credential expired: {}",
                credential_id
            )));
        }

        Ok(true)
    }

    /// Extract proofable fields from credential for ZKP
    pub async fn extract_proofable_fields(
        &self,
        credential_id: &str,
    ) -> WalletResult<CredentialAttributes> {
        let credential = self.get_credential(credential_id).await?;

        // Extract fields from credential_data
        let subject = credential
            .credential_data
            .get("credentialSubject")
            .ok_or_else(|| WalletError::InvalidWitness("Missing credentialSubject".to_string()))?;

        let user_role_id = subject
            .get("userRoleId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| WalletError::InvalidWitness("Missing userRoleId".to_string()))?
            .to_string();

        let org_id = subject
            .get("orgId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| WalletError::InvalidWitness("Missing orgId".to_string()))?
            .to_string();

        let clearance_level = subject
            .get("clearanceLevel")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| WalletError::InvalidWitness("Missing clearanceLevel".to_string()))?
            as u32;

        let timestamp = subject
            .get("timestamp")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| WalletError::InvalidWitness("Missing timestamp".to_string()))?;

        Ok(CredentialAttributes {
            user_role_id,
            org_id,
            clearance_level,
            timestamp,
        })
    }

    /// Revoke credential (issuer side)
    pub async fn revoke_credential(&self, credential_id: &str) -> WalletResult<()> {
        info!("Revoking credential: {}", credential_id);

        // Mark as revoked on Fabric
        self.fabric_client.revoke_credential(credential_id).await?;

        // Mark as revoked in Askar
        self.mark_credential_revoked_in_askar(credential_id)
            .await?;

        Ok(())
    }

    /// Register a new credential schema
    pub async fn register_schema(
        &self,
        issuer_did: &str,
        name: &str,
        version: &str,
        attributes: &[SchemaAttribute],
    ) -> WalletResult<String> {
        let schema_id = Uuid::new_v4().to_string();

        self.fabric_client
            .register_schema(&schema_id, issuer_did, name, version, attributes)
            .await?;

        info!("Schema registered: {} ({})", schema_id, name);
        Ok(schema_id)
    }

    /// Get credential schema
    pub async fn get_schema(&self, schema_id: &str) -> WalletResult<CredentialSchema> {
        debug!("Retrieving schema: {}", schema_id);
        self.fabric_client.get_schema(schema_id).await
    }

    // ============ Private Askar Methods ============


    async fn store_credential_in_askar(
        &self,
        credential_id: &str,
        credential_data: &Value,
    ) -> WalletResult<()> {
        debug!("Storing credential in Askar: {}", credential_id);

        let store_lock = self.askar_store.read().await;
        let store = store_lock.as_ref()
            .ok_or_else(|| WalletError::StorageError("Askar store not initialized".to_string()))?;

        // Serialize credential to string
        let credential_json = credential_data.to_string();

        // Create a session for the transaction
        let mut session = store.session(None)
            .await
            .map_err(|e| {
                error!("Failed to create Askar session: {:?}", e);
                WalletError::StorageError(format!("Session creation failed: {}", e))
            })?;

        let tags = vec![
            EntryTag::Plaintext("stored_at".to_string(), chrono::Utc::now().to_rfc3339()),
            EntryTag::Plaintext("revoked".to_string(), "false".to_string()),
        ];

        // Store the credential with metadata
        // Format: category/name pairs for organization
        session.insert(
            "credentials",  // category
            credential_id,  // name/key
            &credential_json.as_bytes(),  // value
            Some(&tags),  // tags/metadata
            None,  // no secret
        )
        .await
        .map_err(|e| {
            error!("Failed to store credential in Askar: {:?}", e);
            WalletError::StorageError(format!("Credential storage failed: {}", e))
        })?;

        // Commit the session
        session.commit()
            .await
            .map_err(|e| {
                error!("Failed to commit Askar session: {:?}", e);
                WalletError::StorageError(format!("Session commit failed: {}", e))
            })?;

        debug!("Credential stored successfully in Askar: {}", credential_id);
        Ok(())
    }



    async fn retrieve_credential_from_askar(
        &self,
        credential_id: &str,
    ) -> WalletResult<Value> {
        debug!("Retrieving credential from Askar: {}", credential_id);

        let store_lock = self.askar_store.read().await;
        let store = store_lock.as_ref()
            .ok_or_else(|| WalletError::StorageError("Askar store not initialized".to_string()))?;

        // Create a read-only session
        let mut session = store.session(None)
            .await
            .map_err(|e| {
                error!("Failed to create Askar session: {:?}", e);
                WalletError::StorageError(format!("Session creation failed: {}", e))
            })?;

        // Retrieve the credential entry
        let entry = session.fetch(
            "credentials",  // category
            credential_id,  // name/key
            false,  // not_secret
        )
        .await
        .map_err(|e| {
            error!("Failed to retrieve credential from Askar: {:?}", e);
            WalletError::StorageError(format!("Credential retrieval failed: {}", e))
        })?
        .ok_or_else(|| {
            error!("Credential not found in Askar: {}", credential_id);
            WalletError::StorageError(format!("Credential not found: {}", credential_id))
        })?;

        let credential_data: Value = serde_json::from_slice(&entry.value)
            .map_err(|e| WalletError::StorageError(format!("Deserialization failed: {}", e)))?;

        debug!("Credential retrieved successfully from Askar: {}", credential_id);
        Ok(credential_data)
    }


    async fn mark_credential_revoked_in_askar(
        &self,
        credential_id: &str,
    ) -> WalletResult<()> {
        debug!("Marking credential as revoked in Askar: {}", credential_id);

        let store_lock = self.askar_store.read().await;
        let store = store_lock.as_ref()
            .ok_or_else(|| WalletError::StorageError("Askar store not initialized".to_string()))?;

        let mut session = store.session(None)
            .await
            .map_err(|e| {
                error!("Failed to create Askar session: {:?}", e);
                WalletError::StorageError(format!("Session creation failed: {}", e))
            })?;

        let entry = session.fetch(
            "credentials",
            credential_id,
            false,
        )
        .await
        .map_err(|e| {
            error!("Failed to fetch credential for revocation: {:?}", e);
            WalletError::StorageError(format!("Fetch failed: {}", e))
        })?
        .ok_or_else(|| {
            error!("Credential not found for revocation: {}", credential_id);
            WalletError::StorageError(format!("Credential not found: {}", credential_id))
        })?;

        
        let updated_tags = vec![
            EntryTag::Plaintext("revoked".to_string(), "true".to_string()),
            EntryTag::Plaintext("revoked_at".to_string(), chrono::Utc::now().to_rfc3339()),
        ];

        // Fixed: Use entry.value() to get the underlying byte slice
        session.replace(
            "credentials",
            credential_id,
            &entry.value,  // Correct way to access payload bytes
            Some(&updated_tags),
            None,
        )
        .await
        .map_err(|e| {
            error!("Failed to update revocation status in Askar: {:?}", e);
            WalletError::StorageError(format!("Revocation update failed: {}", e))
        })?;

        session.commit()
            .await
            .map_err(|e| {
                error!("Failed to commit revocation session: {:?}", e);
                WalletError::StorageError(format!("Session commit failed: {}", e))
            })?;

        debug!("Credential marked as revoked in Askar: {}", credential_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_extract_proofable_fields() {
        let attrs = CredentialAttributes {
            user_role_id: "admin".to_string(),
            org_id: "org123".to_string(),
            clearance_level: 5,
            timestamp: 1688000000,
        };

        assert_eq!(attrs.user_role_id, "admin");
        assert_eq!(attrs.clearance_level, 5);
    }
}
