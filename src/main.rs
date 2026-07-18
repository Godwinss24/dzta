use dzta::{
    FabricClient, CredentialManager, ZKPWitnessGenerator,
    ConnectionConfig, CredentialAttributes, SchemaAttribute,
};
use std::sync::Arc;
use log::{info};
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    info!("=== VCX Fabric Wallet (Layer 2) ===");
    info!("Initializing wallet server...");

    // Load connection profile
    let config = ConnectionConfig::from_file("config/connection-profile.yaml").await?;
    info!("✓ Connection profile loaded");

    // Initialize Fabric client
    let fabric_client = FabricClient::new(
        "/home/godwins/Github/Rust-Projects/dzta/config/connection-profile2.yaml",
        "demo",
        "asset",
        "Org1MSP",
        "org1-peer0.default",
    )
    .await?;
    info!("✓ Fabric client initialized");

    // Initialize credential manager
    let credential_manager = Arc::new(CredentialManager::new(
        fabric_client,
        "/tmp/vcx_askar_store",
    ));
    info!("✓ Credential manager initialized");

    // Initialize witness generator
    let witness_generator = ZKPWitnessGenerator::new(credential_manager.clone());
    info!("✓ ZKP witness generator initialized");

    // === EXAMPLE WORKFLOW ===

    // 1. Register a schema
    info!("\n--- Step 1: Register Credential Schema ---");
    let attributes = vec![
        SchemaAttribute {
            name: "userRoleId".to_string(),
            attr_type: "string".to_string(),
            predicate: true,
        },
        SchemaAttribute {
            name: "orgId".to_string(),
            attr_type: "string".to_string(),
            predicate: true,
        },
        SchemaAttribute {
            name: "clearanceLevel".to_string(),
            attr_type: "integer".to_string(),
            predicate: true,
        },
        SchemaAttribute {
            name: "timestamp".to_string(),
            attr_type: "timestamp".to_string(),
            predicate: false,
        },
    ];

    let schema_id = credential_manager
        .register_schema(
            "did:example:issuer",
            "ClearanceCredential",
            "1.0",
            &attributes,
        )
        .await?;
    info!("✓ Schema registered: {}", schema_id);

    // --- Step 1: Register Credential Schema ---
    
    // --- Step 1.5: Unlock the Secure Askar Vault ---
    info!("Unlocking Askar secure store...");
    let pass_key = "your_secret_passphrase_here"; // In production, load this from an env var or vault
    credential_manager.initialize_askar_store(pass_key).await?;
    info!("✓ Askar secure store unlocked");


    // 2. Create a credential
    info!("\n--- Step 2: Create Credential ---");
    let credential_attrs = CredentialAttributes {
        user_role_id: "security_officer".to_string(),
        org_id: "org_dod".to_string(),
        clearance_level: 5,
        timestamp: chrono::Utc::now().timestamp(),
    };

    let expires_at = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::days(365))
        .unwrap()
        .timestamp();

    let credential = credential_manager
        .create_credential(
            &schema_id,
            "did:example:issuer",
            "did:example:holder",
            &credential_attrs,
            expires_at,
        )
        .await?;
    info!("✓ Credential created: {}", credential.credential_id);

    let credential_id = credential.credential_id.clone();

    // 3. Generate ZKP witness
    info!("\n--- Step 3: Generate ZKP Witness ---");
    let witness = witness_generator.generate_witness(&credential_id).await?;
    info!("✓ Witness generated:");
    info!("  - Credential ID: {}", witness.credential_id);
    info!("  - User Role: {}", witness.user_role_id);
    info!("  - Org: {}", witness.org_id);
    info!("  - Clearance Level: {}", witness.clearance_level);
    info!("  - Timestamp: {}", witness.timestamp);

    // 4. Export to Circom JSON
    info!("\n--- Step 4: Export to Circom ---");
    witness_generator
        .export_witness_to_file(&credential_id, "witness_input.json")
        .await?;
    info!("✓ Witness exported to witness_input.json");

    let circom_input = witness_generator
        .generate_circom_input(&credential_id)
        .await?;
    info!("✓ Circom input: {}", serde_json::to_string_pretty(&circom_input)?);

    // 5. Verify credential is active
    info!("\n--- Step 5: Verify Credential ---");
    let is_active = credential_manager
        .verify_credential_active(&credential_id)
        .await?;
    info!("✓ Credential is active: {}", is_active);

    // 6. Revoke credential (demonstration)
    info!("\n--- Step 6: Revoke Credential ---");
    credential_manager
        .revoke_credential(&credential_id)
        .await?;
    info!("✓ Credential revoked: {}", credential_id);

    // 7. Verify revocation
    info!("\n--- Step 7: Verify Revocation ---");
    let is_revoked = credential_manager
        .fabric_client
        .is_credential_revoked(&credential_id)
        .await?;
    info!("✓ Credential is revoked: {}", is_revoked);

    info!("\n=== Wallet workflow completed successfully ===");

    Ok(())
}