use std::fs;

use anyhow::Context;
use dzta::{
    ConnectionConfig, FabricClient,
    fabric_client::{ClientBuilder, Identity, IdentityBuilder},
};
use fabric_sdk::{gateway::chaincode::ChaincodeCallBuilder, gateway::client};
use log::{error, info, warn};

async fn try_submit(
    client: &client::Client,
    channel_name: &str,
    chaincode_name: &str,
    function_name: &str,
    args: &[&str],
) -> Result<(), String> {
    let mut builder = client.get_chaincode_call_builder();
    let b = builder
        .with_channel_name(channel_name)
        .unwrap()
        .with_chaincode_id(chaincode_name)
        .unwrap()
        .with_contract_id("DztaContract")
        .expect("Unable to set contract")
        .with_function_name(function_name)
        .unwrap();
    if !args.is_empty() {
        b.with_function_args(args).unwrap();
    }
    let sp = b.build().unwrap();

    match sp.endorse(client).await {
        Ok(mut envelope) => {
            envelope
                .submit(client)
                .await
                .map_err(|err| err.to_string())?;
            envelope
                .wait_for_commit(client)
                .await
                .map_err(|err| err.to_string())?;
        }
        Err(e) => return Err(e.to_string()),
    }

    Ok(())
}

#[tokio::test]
async fn mock_tesssst() {
    let _ = env_logger::builder().is_test(true).try_init();

    let config_path = "/home/godwins/Github/Rust-Projects/dzta/config/connection-profile3.yaml";
    let channel_name = "dzta-france";
    let chaincode_name = "go_chaincode";
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

    let peer_endpoint = &network_config
        .get_peer_config("org1-peer0")
        .expect("Peer config not found")
        .url
        .replace("grpcs://", "")
        .replace("grpc://", "")
        .replace("https://", "")
        .replace("http://", "");

    // Dynamically load the configured TLS CA certi;
    println!("{}", peer_endpoint);

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
        .with_scheme("https")
        .expect("UNABLE TO SET SCHEME")
        .with_authority(peer_endpoint)
        .expect("UNABLE TO SET AUTHORITY")
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

    //  "ResolveDID",
    // "did:example:123456",
    //     "did:example:123456",        // did
    // "did:example:issuer001",     // issuerDID
    // "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE..." // publicKey
    // let builder = client.get_chaincode_call_builder();

    // println!("{}", builder.endorsing_organizations);
    // println!("{}", builder.chaincode_name);

    let signed_proposal = client
        .get_chaincode_call_builder()
        .with_channel_name("dzta-france")
        .expect("Unable to set channel name")
        .with_chaincode_id("go_chaincode")
        .expect("Unable to set chaincode id")
        .with_contract_id("DztaContract")
        .expect("Unable to set contract")
        .with_function_name("RegisterDID")
        .expect("Unable to set function name")
        .with_function_args([
            "did:example:mail.cooom.goofle.",
            "did:example:issuer001",
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE",
        ])
        .expect("Unable to set function arguments")
        .build()
        .expect("Unable to build chaincode call");

    // let response = client.process_proposal(signed_proposal).await.expect("UNABLE TO PROCESS PROPOSAL");
    // let result = response
    //     .response
    //     .as_ref()
    //     .map(|r| r.payload.clone())
    //     .unwrap_or_default();

    //  info!("Query result: {}", String::from_utf8_lossy(&result));

    let mut envelope = match signed_proposal.endorse(&client).await {
        Ok(x) => x,
        Err(e) => {
            error!("Unable to get envelope. Err: {}", e);
            return;
        }
    };

    match envelope.submit(&client).await {
        Ok(x) => {
            match x.wait_for_commit(&client).await {
                Ok(x) => {
                    info!("Commit Status Response: {:?}", &x);
                }
                Err(e) => {
                    error!("Unable to get get commit . Err: {}", e);
                    return;
                }
            };
        }
        Err(e) => {
            error!("Unable to submit transaction to orderer. Err: {}", e);
            return;
        }
    }

    let prepared_transaction = client
        .get_chaincode_call_builder()
        .with_channel_name("dzta-france")
        .expect("Unable to set channel name")
        .with_chaincode_id("go_chaincode")
        .expect("Unable to set chaincode id")
        .with_contract_id("DztaContract")
        .expect("Unable to set contract")
        .with_function_name("ResolveDID")
        .expect("Unable to set function name")
        .with_function_args([
            "did:example:mail.cooom.goofle.",
            // "did:example:issuer001",
            // "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE",
        ])
        .expect("Unable to set function arguments")
        .build()
        .expect("Unable to build chaincode call");

    let result = match client
        .evaluate(
            prepared_transaction,
            String::new(),
            channel_name.to_string(),
        )
        .await
    {
        Ok(x) => {
            let result = String::from_utf8_lossy(&x);
            info!("Query result: {}", result)
        }
        Err(e) => {
            error!("Unable to build connect. Err: {}", e);
            return;
        }
    };
}
