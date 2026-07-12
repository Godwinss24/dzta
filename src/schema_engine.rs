// src/schema_engine.rs
use crate::errors::{WalletError, WalletResult};
use crate::models::CredentialSchema;
use serde_json::Value;
use log::{debug, error};

pub struct SchemaEngine;

impl SchemaEngine {
    /// Validates a credentialSubject's fields against your live raw schema attributes
    pub fn validate_fields(schema: &CredentialSchema, credential_subject: &Value) -> WalletResult<()> {
        debug!("Running live validation for schema: {} v{}", schema.name, schema.version);

        for attr in &schema.attributes {
            let field_value = credential_subject.get(&attr.name).ok_or_else(|| {
                WalletError::InvalidWitness(format!("Missing required schema field: '{}'", attr.name))
            })?;

            match attr.attr_type.as_str() {
                "string" => {
                    if !field_value.is_string() {
                        return Err(WalletError::InvalidWitness(format!(
                            "Type mismatch for '{}'. Expected string, found value: {}", attr.name, field_value
                        )));
                    }
                }
                "integer" => {
                    if !field_value.is_i64() && !field_value.is_u64() {
                        return Err(WalletError::InvalidWitness(format!(
                            "Type mismatch for '{}'. Expected integer, found value: {}", attr.name, field_value
                        )));
                    }
                }
                "timestamp" => {
                    // Accepts numeric Unix timestamp values or standardized RFC3339 string strings
                    if let Some(ts) = field_value.as_i64() {
                        if ts <= 0 {
                            return Err(WalletError::InvalidWitness(format!("Invalid negative timestamp range for '{}'", attr.name)));
                        }
                    } else if let Some(ts_str) = field_value.as_str() {
                        if chrono::DateTime::parse_from_rfc3339(ts_str).is_err() {
                            return Err(WalletError::InvalidWitness(format!(
                                "Field '{}' is not a valid RFC3339 timestamp string", attr.name
                            )));
                        }
                    } else {
                        return Err(WalletError::InvalidWitness(format!(
                            "Type mismatch for '{}'. Expected Unix timestamp integer or RFC3339 string format.", attr.name
                        )));
                    }
                }
                unknown => {
                    return Err(WalletError::ConfigError(format!(
                        "Unrecognized schema type constraint '{}' on field '{}'", unknown, attr.name
                    )));
                }
            }
        }

        debug!("✓ Live schema structural verification passed");
        Ok(())
    }
}