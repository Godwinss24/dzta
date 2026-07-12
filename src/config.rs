// src/config.rs
use serde::{Deserialize, Serialize};
use crate::errors::{WalletError, WalletResult};
use std::collections::HashMap;
use std::path::Path;
use log::{info, debug, warn};

/// A helper struct to capture nested YAML properties formatted as `{ path: "..." }`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathWrapper {
    pub path: String,
}

// #[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConnectionConfig {
    pub version: String,
    pub peers: HashMap<String, PeerConfig>,
    pub orderers: HashMap<String, OrdererConfig>,
    pub organizations: HashMap<String, OrgConfig>,
    pub channels: HashMap<String, ChannelConfig>,
    pub client: ClientConfig,
}

// #[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PeerConfig {
    pub url: String,
    #[serde(default)]
    pub grpc_options: GrpcOptions,
    #[serde(rename = "tlsCACerts")]
    pub tls_ca_certs: Option<PathWrapper>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]

#[serde(rename_all = "camelCase")]
pub struct OrdererConfig {
    pub url: String,
    #[serde(default)]
    pub grpc_options: GrpcOptions,
    #[serde(rename = "tlsCACerts")]
    pub tls_ca_certs: Option<PathWrapper>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgConfig {
    pub mspid: String,
    #[serde(default)] 
    pub users: HashMap<String, UserConfig>,
    #[serde(default)]
    pub peers: Vec<String>,
    #[serde(default, rename = "certificateAuthorities")]
    pub certificate_authorities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelConfig {
    pub peers: HashMap<String, PeerInChannelConfig>,
    pub orderers: Vec<String>,
    pub endorsement_policy: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserConfig {
    pub cert: PathWrapper,
    pub key: PathWrapper,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientConfig {
    pub organization: String,
    #[serde(default = "default_logging")]
    pub logging: LoggingConfig,
}

fn default_logging() -> LoggingConfig {
    LoggingConfig {
        level: "info".to_string(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct GrpcOptions {
    pub ssl_target_name_override: Option<String>,
    pub keep_alive_time_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LoggingConfig {
    pub level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PeerInChannelConfig {
    pub endorsing_peer: bool,
    pub chaincode_query: bool,
    pub ledger_query: bool,
    pub event_source: bool,
}

impl ConnectionConfig {
    /// Load configuration from YAML file
    pub async fn from_file(path: &str) -> WalletResult<Self> {
        debug!("Loading configuration from: {}", path);
        
        if !Path::new(path).exists() {
            return Err(WalletError::ConfigError(format!(
                "Configuration file not found: {}",
                path
            )));
        }

        let content = tokio::fs::read_to_string(path)
            .await
            .map_err(|e| WalletError::ConfigError(format!(
                "Failed to read config file {}: {}",
                path, e
            )))?;

        let config: ConnectionConfig = serde_yaml::from_str(&content)
            .map_err(|e| WalletError::ConfigError(format!(
                "Failed to parse YAML config: {}",
                e
            )))?;

        config.validate()?;
        info!("Configuration loaded successfully");
        Ok(config)
    }

    /// Validate configuration integrity
    pub fn validate(&self) -> WalletResult<()> {
        debug!("Validating configuration");

        // Validate client organization exists
        if !self.organizations.contains_key(&self.client.organization) {
            return Err(WalletError::ConfigError(format!(
                "Client organization '{}' not found in configuration",
                self.client.organization
            )));
        }

        // Validate at least one peer exists
        if self.peers.is_empty() {
            return Err(WalletError::ConfigError(
                "No peers configured".to_string(),
            ));
        }

        // Validate at least one orderer exists
        if self.orderers.is_empty() {
            return Err(WalletError::ConfigError(
                "No orderers configured".to_string(),
            ));
        }

        // Validate at least one channel exists
        if self.channels.is_empty() {
            return Err(WalletError::ConfigError(
                "No channels configured".to_string(),
            ));
        }

        // Validate all organizations have users
        for (org_name, org) in &self.organizations {
            if org.peers.is_empty() {
                warn!("Organization '{}' has no users configured", org_name);
            }

            // Validate peer references
            for peer_name in &org.peers {
                if !self.peers.contains_key(peer_name) {
                    return Err(WalletError::ConfigError(format!(
                        "Peer '{}' referenced in org '{}' not found",
                        peer_name, org_name
                    )));
                }
            }
        }

        // Validate channel configurations
        for (channel_name, channel) in &self.channels {
            for orderer_name in &channel.orderers {
                if !self.orderers.contains_key(orderer_name) {
                    return Err(WalletError::ConfigError(format!(
                        "Orderer '{}' referenced in channel '{}' not found",
                        orderer_name, channel_name
                    )));
                }
            }

            for peer_name in channel.peers.keys() {
                if !self.peers.contains_key(peer_name) {
                    return Err(WalletError::ConfigError(format!(
                        "Peer '{}' referenced in channel '{}' not found",
                        peer_name, channel_name
                    )));
                }
            }
        }

        debug!("Configuration validation passed");
        Ok(())
    }

    /// Get user context for the configured organization
    pub fn get_user_context(&self) -> WalletResult<UserContext> {
        debug!(
            "Getting user context for organization: {}",
            self.client.organization
        );

        let org = self.organizations.get(&self.client.organization).ok_or_else(|| {
            WalletError::ConfigError("Organization not found".to_string())
        })?;

        let user = org.users.values().next().ok_or_else(|| {
            WalletError::ConfigError("No users configured for organization".to_string())
        })?;

        UserContext::new(&user.cert.path, &user.key.path, &org.mspid)
    }

    /// Get user context for a specific organization
    pub fn get_user_context_for_org(&self, org_name: &str) -> WalletResult<UserContext> {
        debug!("Getting user context for organization: {}", org_name);

        let org = self.organizations.get(org_name).ok_or_else(|| {
            WalletError::ConfigError(format!("Organization '{}' not found", org_name))
        })?;

        let user = org.users.values().next().ok_or_else(|| {
            WalletError::ConfigError(format!(
                "No users configured for organization '{}'",
                org_name
            ))
        })?;

        UserContext::new(&user.cert.path, &user.key.path, &org.mspid)
    }

    /// Get a specific user context by organization and username
    pub fn get_user_context_by_name(
        &self,
        org_name: &str,
        user_name: &str,
    ) -> WalletResult<UserContext> {
        debug!(
            "Getting user context for org: {}, user: {}",
            org_name, user_name
        );

        let org = self.organizations.get(org_name).ok_or_else(|| {
            WalletError::ConfigError(format!("Organization '{}' not found", org_name))
        })?;

        let user = org.users.get(user_name).ok_or_else(|| {
            WalletError::ConfigError(format!(
                "User '{}' not found in organization '{}'",
                user_name, org_name
            ))
        })?;

        UserContext::new(&user.cert.path, &user.key.path, &org.mspid)
    }

    /// Get the first available orderer URL
    pub fn get_orderer_url(&self) -> WalletResult<String> {
        self.orderers
            .values()
            .next()
            .map(|o| o.url.clone())
            .ok_or_else(|| WalletError::ConfigError("No orderers configured".to_string()))
    }

    /// Get a specific orderer by name
    pub fn get_orderer_url_by_name(&self, orderer_name: &str) -> WalletResult<String> {
        self.orderers
            .get(orderer_name)
            .map(|o| o.url.clone())
            .ok_or_else(|| {
                WalletError::ConfigError(format!("Orderer '{}' not found", orderer_name))
            })
    }

    /// Get all orderer URLs
    pub fn get_all_orderer_urls(&self) -> Vec<String> {
        self.orderers
            .values()
            .map(|o| o.url.clone())
            .collect()
    }

    /// Get orderer config by name
    pub fn get_orderer_config(&self, orderer_name: &str) -> WalletResult<&OrdererConfig> {
        self.orderers.get(orderer_name).ok_or_else(|| {
            WalletError::ConfigError(format!("Orderer '{}' not found", orderer_name))
        })
    }

    /// Get a specific peer URL by name
    pub fn get_peer_url(&self, peer_name: &str) -> WalletResult<String> {
        self.peers
            .get(peer_name)
            .map(|p| p.url.clone())
            .ok_or_else(|| WalletError::ConfigError(format!("Peer '{}' not found", peer_name)))
    }

    /// Get peer config by name
    pub fn get_peer_config(&self, peer_name: &str) -> WalletResult<&PeerConfig> {
        self.peers
            .get(peer_name)
            .ok_or_else(|| WalletError::ConfigError(format!("Peer '{}' not found", peer_name)))
    }

    /// Get all peer URLs
    pub fn get_all_peer_urls(&self) -> Vec<String> {
        self.peers.values().map(|p| p.url.clone()).collect()
    }

    /// Get peers for a specific channel
    pub fn get_channel_peers(&self, channel_name: &str) -> WalletResult<Vec<String>> {
        self.channels
            .get(channel_name)
            .map(|c| c.peers.keys().cloned().collect())
            .ok_or_else(|| {
                WalletError::ConfigError(format!("Channel '{}' not found", channel_name))
            })
    }

    /// Get orderers for a specific channel
    pub fn get_channel_orderers(&self, channel_name: &str) -> WalletResult<Vec<String>> {
        self.channels
            .get(channel_name)
            .map(|c| c.orderers.clone())
            .ok_or_else(|| {
                WalletError::ConfigError(format!("Channel '{}' not found", channel_name))
            })
    }

    /// Get endorsing peers for a specific channel
    pub fn get_endorsing_peers(&self, channel_name: &str) -> WalletResult<Vec<String>> {
        self.channels
            .get(channel_name)
            .map(|c| {
                c.peers
                    .iter()
                    .filter(|(_, config)| config.endorsing_peer)
                    .map(|(name, _)| name.clone())
                    .collect()
            })
            .ok_or_else(|| {
                WalletError::ConfigError(format!("Channel '{}' not found", channel_name))
            })
    }

    /// Get organization MSP ID
    pub fn get_org_mspid(&self, org_name: &str) -> WalletResult<String> {
        self.organizations
            .get(org_name)
            .map(|o| o.mspid.clone())
            .ok_or_else(|| {
                WalletError::ConfigError(format!("Organization '{}' not found", org_name))
            })
    }

    /// Get channel config
    pub fn get_channel_config(&self, channel_name: &str) -> WalletResult<&ChannelConfig> {
        self.channels.get(channel_name).ok_or_else(|| {
            WalletError::ConfigError(format!("Channel '{}' not found", channel_name))
        })
    }

    /// Get organization config
    pub fn get_org_config(&self, org_name: &str) -> WalletResult<&OrgConfig> {
        self.organizations.get(org_name).ok_or_else(|| {
            WalletError::ConfigError(format!("Organization '{}' not found", org_name))
        })
    }

    /// Reads and returns the raw TLS CA certificate bytes for a specific peer node name
    // pub async fn read_peer_tls_cert_bytes(&self, peer_name: &str) -> WalletResult<Vec<u8>> {
    //     let peer = self.peers.get(peer_name).ok_or_else(|| {
    //         WalletError::ConfigError(format!("Peer '{}' not found for TLS loading", peer_name))
    //     })?;

    //     if let Some(ref wrapper) = peer.tls_ca_certs {
    //         tokio::fs::read(&wrapper.path)
    //             .await
    //             .map_err(|e| WalletError::ConfigError(format!("Failed to read TLS CA file {}: {}", wrapper.path, e)))
    //     } else {
    //         Ok(Vec::new()) // Fallback gracefully if TLS is unconfigured or disabled
    //     }
    // }
    pub async fn read_peer_tls_cert_bytes(&self, peer_name: &str) -> WalletResult<Vec<u8>> {
        // Try exact match first
        let peer_opt = self.peers.get(peer_name)
            // Fallback 1: If it's looking for "org1-peer0", match against "org1-peer0.default"
            .or_else(|| self.peers.get(&format!("{}.default", peer_name)))
            // Fallback 2: If it has ".default", strip it and check
            .or_else(|| self.peers.get(&peer_name.replace(".default", "")));

        let peer = peer_opt.ok_or_else(|| {
            WalletError::ConfigError(format!("Peer '{}' not found for TLS loading", peer_name))
        })?;

        if let Some(ref wrapper) = peer.tls_ca_certs {
            tokio::fs::read(&wrapper.path)
                .await
                .map_err(|e| WalletError::ConfigError(format!("Failed to read TLS CA file {}: {}", wrapper.path, e)))
        } else {
            Ok(Vec::new()) // Fallback gracefully if TLS is unconfigured or disabled
        }
    }
    /// Check if peer supports chaincode queries
    pub fn peer_supports_chaincode_query(
        &self,
        channel_name: &str,
        peer_name: &str,
    ) -> WalletResult<bool> {
        self.channels
            .get(channel_name)
            .and_then(|c| c.peers.get(peer_name))
            .map(|p| p.chaincode_query)
            .ok_or_else(|| {
                WalletError::ConfigError(format!(
                    "Peer '{}' not found in channel '{}'",
                    peer_name, channel_name
                ))
            })
    }

    /// Check if peer supports ledger queries
    pub fn peer_supports_ledger_query(
        &self,
        channel_name: &str,
        peer_name: &str,
    ) -> WalletResult<bool> {
        self.channels
            .get(channel_name)
            .and_then(|c| c.peers.get(peer_name))
            .map(|p| p.ledger_query)
            .ok_or_else(|| {
                WalletError::ConfigError(format!(
                    "Peer '{}' not found in channel '{}'",
                    peer_name, channel_name
                ))
            })
    }

    /// Get TLS CA certificate path for a peer
    pub fn get_peer_tls_ca_cert_path(&self, peer_name: &str) -> WalletResult<Option<String>> {
        self.peers
            .get(peer_name)
            .map(|p| p.tls_ca_certs.as_ref().map(|tc| tc.path.clone()))
            .ok_or_else(|| WalletError::ConfigError(format!("Peer '{}' not found", peer_name)))
    }

    /// Get TLS CA certificate path for an orderer
    pub fn get_orderer_tls_ca_cert_path(&self, orderer_name: &str) -> WalletResult<Option<String>> {
        self.orderers
            .get(orderer_name)
            .map(|o| o.tls_ca_certs.as_ref().map(|tc| tc.path.clone()))
            .ok_or_else(|| {
                WalletError::ConfigError(format!("Orderer '{}' not found", orderer_name))
            })
    }
}

/// User context holding credentials for signing proposals
#[derive(Debug, Clone)]
pub struct UserContext {
    cert_pem: String,
    key_pem: String,
    msp_id: String,
}

impl UserContext {
    /// Create new user context
    pub fn new(cert_pem: &str, key_pem: &str, msp_id: &str) -> WalletResult<Self> {
        if cert_pem.is_empty() {
            return Err(WalletError::ConfigError(
                "Certificate cannot be empty".to_string(),
            ));
        }

        if key_pem.is_empty() {
            return Err(WalletError::ConfigError(
                "Private key cannot be empty".to_string(),
            ));
        }

        if msp_id.is_empty() {
            return Err(WalletError::ConfigError(
                "MSP ID cannot be empty".to_string(),
            ));
        }
        Ok(UserContext {
            cert_pem: cert_pem.to_string(),
            key_pem: key_pem.to_string(),
            msp_id: msp_id.to_string(),
        })
    }

    pub fn get_cert_pem(&self) -> &str {
        &self.cert_pem
    }
    
    pub fn get_key_pem(&self) -> &str {
        &self.key_pem
    }

    pub fn get_msp_id(&self) -> &str {
        &self.msp_id
    }

    pub fn sign_bytes(&self, bytes: &[u8]) -> WalletResult<Vec<u8>> {
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::sign::Signer;

        let private_key = PKey::private_key_from_pem(self.key_pem.as_bytes())
            .map_err(|e| WalletError::SigningError(e.to_string()))?;

        let mut signer = Signer::new(MessageDigest::sha256(), &private_key)
            .map_err(|e| WalletError::SigningError(e.to_string()))?;

        signer
            .update(bytes)
            .map_err(|e| WalletError::SigningError(e.to_string()))?;

        let signature = signer
            .sign_to_vec()
            .map_err(|e| WalletError::SigningError(e.to_string()))?;

        Ok(signature)
    }
}