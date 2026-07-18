use std::fs;

use anyhow::Context;
use dzta::{
    ConnectionConfig, FabricClient,
    fabric_client::{ClientBuilder, Identity, IdentityBuilder},
};
use fabric_sdk::gateway::chaincode::ChaincodeCallBuilder;
use log::{error, info, warn};

#[tokio::test]
async fn mock_tesssst() {
    let _ = env_logger::builder().is_test(true).try_init();

    let config_path = "/home/godwins/Github/Rust-Projects/dzta/config/connection-profile3.yaml";
    let channel_name = "dzta-france";
    let chaincode_name = "asset_chaincode";
    let org_name = "Org1MSP"; // Set this to match your YAML profile org key
    let peer_name = "org1-peer0"; // Set this to match your YAML profile peer key

    let raw_config = match fs::read_to_string(&config_path) {
        Ok(x) => x,
        Err(e) => {
            error!("Unable to read file at {}. Err: {}", &config_path, e);
            return;
        }
    };

    let network_config: ConnectionConfig = match serde_yaml::from_str(&raw_config) {
        Ok(x) => x,
        Err(e) => {
            error!("Unable to deserialize. Err: {}", e);
            return;
        }
    };

    let org1admin = match &network_config.organizations.get("Org1MSP") {
        Some(x) => match x.users.get("admin") {
            Some(x) => x,
            None => {
                return;
            }
        },
        None => {
            error!("Unable to get organization",);
            return;
        }
    };

    let cert = match fs::read(&org1admin.cert.path) {
        Ok(x) => x,
        Err(e) => {
            error!("Unable to read {}: {}", &org1admin.cert.path, e);
            return;
        }
    };

    let pkey = match fs::read_to_string(&org1admin.key.path) {
        Ok(x) => x,
        Err(e) => {
            error!("Unable to read {}: {}", &org1admin.cert.path, e);
            return;
        }
    };

    // println!("{:?}",);

    let peer_tls_path = &network_config
        .get_peer_config("org1-peer0")
        .expect("Peer config not found")
        .clone()
        .tls_ca_certs
        .expect("tlsCACerts for peer not found")
        .path;

    let org_tls_ca = match fs::read_to_string(peer_tls_path) {
        Ok(x) => x,
        Err(e) => {
            error!("Unable to read {}: {}", &org1admin.cert.path, e);
            return;
        }
    };

    let identity = match IdentityBuilder::from_pem(cert) {
        Ok(x) => match x
            .with_private_key(pkey)
            .expect("Unable to get private key")
            .with_msp("Org1MSP")
            .expect("UNABLE to get ORG1 MSP")
            .build()
        {
            Ok(x) => x,
            Err(e) => {
                error!("Unable to build identity. Err: {}", e);
                return;
            }
        },
        Err(e) => {
            error!("Unable to build identity. Err: {}", e);
            return;
        }
    };

    let mut client = match ClientBuilder::new()
        .with_identity(identity)
        .expect("Unable to create builder with identity")
        .with_tls(org_tls_ca)
    {
        Ok(x) => match x.build() {
            Ok(x) => x,
            Err(e) => {
                error!("Unable to build client. Err: {}", e);
                return;
            }
        },
        Err(e) => {
            error!("Unable to build client builder. Err: {}", e);
            return;
        }
    };

    match client.connect().await {
        Ok(_) => {
            info!("Connection successful")
        }
        Err(e) => {
            error!("Unable to build connect. Err: {}", e);
            return;
        }
    }

    let prepared_transaction = client
        .get_chaincode_call_builder()
        .with_channel_name("dzta-france")
        .expect("Unable to set channel name")
        .with_chaincode_id("asset_chaincode")
        .expect("Unable to set chaincode id")
        .with_function_name("PutValue")
        .expect("Unable to set function name")
        .with_function_args(["name", "orange"])
        .expect("Unable to set function arguments")
        .build()
        .expect("Unable to build chaincode call");

    let envelope = match prepared_transaction.endorse(&client).await {
        Ok(x) => x,
        Err(e) => {
            error!("Unable to get envelope. Err: {}", e);
            return;
        }
    };

    // let fabric_client = match FabricClient::new(
    //     config_path,
    //     channel_name,
    //     chaincode_name,
    //     org_name,
    //     peer_name,
    // )
    // .await
    // {
    //     Ok(client) => {
    //         info!("Connection profile parsed. Setting live network routing path... ");
    //         let mut c = client;
    //         c.set_mock(false); // Clear the default mock flag so it executes live gRPC transactions!
    //         c
    //     }
    //     Err(e) => {
    //         warn!(
    //             "Could not read connection profile ({}). Falling back to local Mock validation buffers.",
    //             e
    //         );
    //         // FabricClient {
    //         //     config: std::sync::Arc::new(tokio::sync::RwLock::new(match ConnectionConfig::from_file(config_path).await {
    //         //         Ok(cfg) => cfg,
    //         //         Err(_) => unsafe { std::mem::transmute::<[u8; std::mem::size_of::<ConnectionConfig>()], ConnectionConfig>([0u8; std::mem::size_of::<ConnectionConfig>()]) }
    //         //     })),
    //         //     channel_name: channel_name.to_string(),
    //         //     chaincode_name: chaincode_name.to_string(),
    //         //     org_mspid: "Org1MSP".to_string(),
    //         //     peer_url: "grpcs://peer0-org1.localho.st:443".to_string(),
    //         //     is_mock: true,
    //         // }
    //         return;
    //     }
    // };

    // let result = fabric_client
    //     .mock_fn("did", "issuer_did", "public_key")
    //     .await;
    // info!("{:?}", result);

    // let get_result = fabric_client
    //     .mock_fn("did", "issuer_did", "public_key")
    //     .await;
    // info!("{:?}", get_result);
}
