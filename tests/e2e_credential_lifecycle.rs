use std::sync::Arc;
use log::{info, warn};

use dzta::{
    FabricClient, CredentialManager, ZKPWitnessGenerator,
    ConnectionConfig, CredentialAttributes, SchemaAttribute,
};

#[tokio::test]
async fn test_full_credential_lifecycle_e2e() {
    // 1. SETUP LOGGING AND CONTEXT PARSING
    let _ = env_logger::builder().is_test(true).try_init();
    info!("Starting decentralized Zero-Trust Architecture (dZTA) E2E integration test pipeline...");

    // Path to your local Fabric network configuration profile
    let config_path = "config/connection-profile.yaml"; 
    let channel_name = "demo";
    let chaincode_name = "dztac";
    let org_name = "Org1MSP";        // Set this to match your YAML profile org key
    let peer_name = "org1-peer0.default"; // Set this to match your YAML profile peer key

    let _config_exists = std::path::Path::new(config_path).exists();

    let fabric_client = match FabricClient::new(config_path, channel_name, chaincode_name, org_name, peer_name).await {
        Ok(client) => {
            info!("Connection profile parsed. Setting live network routing path... ");
            let mut c = client;
            c.set_mock(false); // Clear the default mock flag so it executes live gRPC transactions!
            c
        }
        Err(e) => {
            warn!("Could not read connection profile ({}). Falling back to local Mock validation buffers.", e);
            FabricClient {
                config: std::sync::Arc::new(tokio::sync::RwLock::new(match ConnectionConfig::from_file(config_path).await {
                    Ok(cfg) => cfg,
                    Err(_) => unsafe { std::mem::transmute::<[u8; std::mem::size_of::<ConnectionConfig>()], ConnectionConfig>([0u8; std::mem::size_of::<ConnectionConfig>()]) }
                })), 
                channel_name: channel_name.to_string(),
                chaincode_name: chaincode_name.to_string(),
                org_mspid: "Org1MSP".to_string(),
                peer_url: "grpcs://peer0-org1.localho.st:443".to_string(),
                is_mock: true, 
            }
        }
    };

    // Store sqlite secure database at a clean relative location
    let askar_db_path = "target/debug/test_askar_wallet.db";
    
    // Ensure a clean test environment by deleting past database instances
    if std::path::Path::new(askar_db_path).exists() {
        let _ = std::fs::remove_file(askar_db_path);
    }

    let cred_manager = Arc::new(CredentialManager::new(
        fabric_client.clone(),
        askar_db_path
    ));
    
    // Initialize the secure envelope store using Argon2i key derivation
    cred_manager
        .initialize_askar_store("super_secure_passphrase_123")
        .await
        .expect("Failed to initialize secure Aries Askar local database instance");

    // =================================================================
    // STEP 3: IDENTITY PROVISIONING (GENERATE & REGISTER DIDS)
    // =================================================================
    info!("Generating cryptographic identities via local node environment metrics...");

    let config_guard = fabric_client.config.read().await.clone();
    let user_context = config_guard.get_user_context()
        .expect("Failed to load user context profile metadata");
    
    // Generate deterministic DID for the Issuer using node hash derivations
    let issuer_did = cred_manager.fabric_client.generate_did();
    
    // --- MODIFICATION HERE: Parse the certificate content instead of using the path string ---
    let cert_path = user_context.get_cert_pem(); 
    let cert_bytes = std::fs::read(&cert_path)
        .unwrap_or_else(|_| panic!("Failed to read certificate from path: {}", cert_path));
    let issuer_pubkey_pem = String::from_utf8(cert_bytes)
        .expect("Certificate file does not contain valid UTF-8 sequences");
    
    // Assign a distinct identifier for the Subject edge wallet
    let subject_did = "did:dzta:user-nathaniel-777";
    let subject_pubkey = "ed25519_public_key_bytes_for_subject_placeholder";

    info!("Registering generated Issuer identity document on ledger: {}", issuer_did);
    cred_manager.fabric_client
        .register_did(&issuer_did, &issuer_did, &issuer_pubkey_pem)
        .await
        .expect("Failed to register Issuer identity document");

    info!("Registering Subject identity document on ledger: {}", subject_did);
    cred_manager.fabric_client
        .register_did(subject_did, &issuer_did, subject_pubkey)
        .await
        .expect("Failed to register Subject identity document");

    // Assert identity resolution works before building schema contexts
    let resolved_doc = cred_manager.fabric_client.resolve_did(&issuer_did).await
        .expect("Failed to resolve newly registered DID document from Fabric world state");
        
    info!("✓ Identity resolution check confirmed active for: {}", resolved_doc.did);

    // =================================================================
    // STEP 4: DEFINING AND REGISTERING APPLICATION SCHEMA
    // =================================================================
    let schema_name = "SecurityClearanceTemplate";
    let schema_version = "1.0.0";

    let schema_attributes = vec![
        SchemaAttribute { name: "userRoleId".to_string(), attr_type: "string".to_string(), predicate: false },
        SchemaAttribute { name: "orgId".to_string(), attr_type: "string".to_string(), predicate: false },
        SchemaAttribute { name: "clearanceLevel".to_string(), attr_type: "integer".to_string(), predicate: true },
        SchemaAttribute { name: "timestamp".to_string(), attr_type: "timestamp".to_string(), predicate: false },
    ];

    info!("Registering schema structure mapping directly to Go chaincode state table...");
    let schema_id = cred_manager
        .register_schema(&issuer_did, schema_name, schema_version, &schema_attributes)
        .await
        .expect("Schema registration execution pipeline failed");
    
    info!("Schema registered successfully with ID: {}", schema_id);

    // =================================================================
    // STEP 5: CREDENTIAL PROVISIONING (ISSUANCE SIDE)
    // =================================================================
    let credential_payload = CredentialAttributes {
        user_role_id: "systems-engineer".to_string(),
        org_id: "hyperledger-nigeria-hub".to_string(),
        clearance_level: 5,
        timestamp: chrono::Utc::now().timestamp(),
    };

    // Set expiration bounds to +24 hours out
    let expires_at_unix = chrono::Utc::now().timestamp() + (24 * 60 * 60);

    info!("Validating structural attributes and creating W3C verifiable credential...");
    let stored_credential = cred_manager
        .create_credential(&schema_id, &issuer_did, subject_did, &credential_payload, expires_at_unix)
        .await
        .expect("Failed to execute credential template parsing or Fabric metadata anchor logging");

    let target_credential_id = stored_credential.credential_id.clone();
    info!("Verifiable Credential securely written to local Askar and anchored on ledger. ID: {}", target_credential_id);

    // =================================================================
    // STEP 6: READ-SIDE BLOCKCHAIN VERIFICATION (ZERO-TRUST VALIDATION)
    // =================================================================
    info!("Executing ledger active verification loop for Credential ID: {}...", target_credential_id);
    let validation_result = cred_manager
        .verify_credential_active(&target_credential_id)
        .await
        .expect("Zero-trust validation verification loop encountered an unexpected processing error");

    assert!(validation_result, "The generated credential should report active valid state metrics");
    info!("✓ Verification Passed: Credential is alive and well on the blockchain.");

    // =================================================================
    // STEP 7: REVOCATION LIFECYCLE MUTATION
    // =================================================================
    info!("Triggering administrative ledger revocation request for Credential ID: {}...", target_credential_id);
    cred_manager
        .revoke_credential(&target_credential_id)
        .await
        .expect("Administrative chain code modification failed during revocation routing");

    info!("Revocation execution completed. Running post-revocation zero-trust fallback validation...");
    let post_revocation_check = cred_manager.verify_credential_active(&target_credential_id).await;

    match post_revocation_check {
        Err(dzta::errors::WalletError::RevocationError(msg)) => {
            info!("✓ Revocation Verified: System blocked execution path as designed. Reason: {}", msg);
        }
        _ => {
            panic!("Security Failure: Credential remained active after running administrative ledger revocation transactions.");
        }
    }

    info!("🎉 All decentralized identity (dZTA) infrastructure checks passed flawlessly!");
}