package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// --- LEDGER DATA STRUCTURES (Matching Rust Models) ---

type SchemaAttribute struct {
	Name      string `json:"name"`
	AttrType  string `json:"type"` // "string", "integer", "timestamp"
	Predicate bool   `json:"predicate"`
}

type CredentialSchema struct {
	SchemaID   string            `json:"schema_id"`
	IssuerDID  string            `json:"issuer_did"`
	Name       string            `json:"name"`
	Version    string            `json:"version"`
	Attributes []SchemaAttribute `json:"attributes"`
	Created    int64             `json:"created"`
}

type CredentialMetadata struct {
	CredentialID string `json:"credential_id"`
	SchemaID     string `json:"schema_id"`
	IssuerDID    string `json:"issuer_did"`
	SubjectDID   string `json:"subject_did"`
	IssuedAt     int64  `json:"issued_at"`
	ExpiresAt    int64  `json:"expires_at"`
	Revoked      bool   `json:"revoked"`
}

type DIDDocument struct {
	DID            string   `json:"did"`
	PublicKey      string   `json:"public_key"`
	Authentication []string `json:"authentication"`
	IssuerDID      string   `json:"issuer_did"`
	Created        int64    `json:"created"`
	Updated        int64    `json:"updated"`
	Active         bool     `json:"active"`
}

type VerificationReceipt struct {
	CredentialID string `json:"credential_id"`
	VerifierMEC  string `json:"verifier_mec"`
	VerifiedAt   int64  `json:"verified_at"`
	TeeQuote     string `json:"tee_quote"` // Hardware attestation signature
}

// --- SMART CONTRACT DEFINITION ---

type DztaContract struct {
	contractapi.Contract
}

// ==========================================
// 1. SCHEMA MANAGEMENT LIFECYCLE
// ==========================================

// RegisterSchema handles template creation
func (c *DztaContract) RegisterSchema(ctx contractapi.TransactionContextInterface, schemaID string, issuerDID string, name string, version string, attributesJSON string) error {
	key := fmt.Sprintf("SCHEMA_%s", schemaID)

	var attributes []SchemaAttribute
	err := json.Unmarshal([]byte(attributesJSON), &attributes)
	if err != nil {
		return fmt.Errorf("failed to parse schema attributes payload: %v", err)
	}

	// Use tx timestamp for deterministic 'created' field tracking
	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	var createdTime int64 = 0
	if err == nil {
		createdTime = txTimestamp.Seconds
	}

	schema := CredentialSchema{
		SchemaID:   schemaID,
		IssuerDID:  issuerDID,
		Name:       name,
		Version:    version,
		Attributes: attributes,
		Created:    createdTime,
	}

	schemaBytes, err := json.Marshal(schema)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(key, schemaBytes)
}

// GetSchema fetches a schema template by ID
func (c *DztaContract) GetSchema(ctx contractapi.TransactionContextInterface, schemaID string) (*CredentialSchema, error) {
	key := fmt.Sprintf("SCHEMA_%s", schemaID)
	schemaBytes, err := ctx.GetStub().GetState(key)
	if err != nil {
		return nil, fmt.Errorf("failed reading world state: %v", err)
	}
	if schemaBytes == nil {
		return nil, fmt.Errorf("schema %s does not exist", schemaID)
	}

	var schema CredentialSchema
	err = json.Unmarshal(schemaBytes, &schema)
	if err != nil {
		return nil, err
	}
	return &schema, nil
}

// ==========================================
// 2. CREDENTIAL META & REVOCATION LIFECYCLE
// ==========================================

// RecordCredentialMetadata runs during step 4 of create_credential
func (c *DztaContract) RecordCredentialMetadata(ctx contractapi.TransactionContextInterface, credentialID string, schemaID string, issuerDID string, subjectDID string, expiresAt int64) error {
	key := fmt.Sprintf("CRED_%s", credentialID)

	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	var issuedAt int64 = 0
	if err == nil {
		issuedAt = txTimestamp.Seconds
	}

	meta := CredentialMetadata{
		CredentialID: credentialID,
		SchemaID:     schemaID,
		IssuerDID:    issuerDID,
		SubjectDID:   subjectDID,
		IssuedAt:     issuedAt,
		ExpiresAt:    expiresAt,
		Revoked:      false,
	}

	metaBytes, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(key, metaBytes)
}

// GetCredentialMetadata maps to your Rust gateway metadata verification
func (c *DztaContract) GetCredentialMetadata(ctx contractapi.TransactionContextInterface, credentialID string) (*CredentialMetadata, error) {
	key := fmt.Sprintf("CRED_%s", credentialID)
	metaBytes, err := ctx.GetStub().GetState(key)
	if err != nil {
		return nil, fmt.Errorf("failed reading world state: %v", err)
	}
	if metaBytes == nil {
		return nil, fmt.Errorf("credential %s metadata does not exist", credentialID)
	}

	var meta CredentialMetadata
	err = json.Unmarshal(metaBytes, &meta)
	if err != nil {
		return nil, err
	}
	return &meta, nil
}

// IsCredentialRevoked checks the explicit boolean status flag
func (c *DztaContract) IsCredentialRevoked(ctx contractapi.TransactionContextInterface, credentialID string) (bool, error) {
	meta, err := c.GetCredentialMetadata(ctx, credentialID)
	if err != nil {
		return false, err
	}
	return meta.Revoked, nil
}

// RevokeCredential handles administrative lifecycle mutations
func (c *DztaContract) RevokeCredential(ctx contractapi.TransactionContextInterface, credentialID string) error {
	key := fmt.Sprintf("CRED_%s", credentialID)
	meta, err := c.GetCredentialMetadata(ctx, credentialID)
	if err != nil {
		return err
	}

	meta.Revoked = true

	metaBytes, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(key, metaBytes)
}

// ==========================================
// 3. DECENTRALIZED IDENTIFIER (DID) REGISTRY
// ==========================================

// RegisterDID saves DID document links to the chain state
func (c *DztaContract) RegisterDID(ctx contractapi.TransactionContextInterface, did string, issuerDID string, publicKey string) error {
	key := fmt.Sprintf("DID_%s", did)

	// Reject duplicate registration rather than silently overwriting
	existing, err := ctx.GetStub().GetState(key)
	if err != nil {
		return fmt.Errorf("failed reading world state: %v", err)
	}
	if existing != nil {
		return fmt.Errorf("did document %s already exists", did)
	}

	txTime, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("failed to get tx timestamp: %v", err)
	}
	now := txTime.AsTime().Unix()

	doc := DIDDocument{
		DID:            did,
		PublicKey:      publicKey,
		Authentication: []string{"key-1"},
		IssuerDID:      issuerDID,
		Created:        now,
		Updated:        now,
		Active:         true,
	}

	docBytes, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(key, docBytes)
}

// ResolveDID recovers public identifier anchors
func (c *DztaContract) ResolveDID(ctx contractapi.TransactionContextInterface, did string) (*DIDDocument, error) {
	key := fmt.Sprintf("DID_%s", did)
	docBytes, err := ctx.GetStub().GetState(key)
	if err != nil {
		return nil, fmt.Errorf("failed reading world state: %v", err)
	}
	if docBytes == nil {
		return nil, fmt.Errorf("did document %s does not exist", did)
	}

	var doc DIDDocument
	err = json.Unmarshal(docBytes, &doc)
	if err != nil {
		return nil, err
	}
	return &doc, nil
}

// QueryDIDsByIssuer searches indexed assets using a rich JSON CouchDB execution block
func (c *DztaContract) QueryDIDsByIssuer(ctx contractapi.TransactionContextInterface, issuerDID string) ([]*DIDDocument, error) {
	queryString := fmt.Sprintf(`{"selector":{"issuer_did":"%s"}}`, issuerDID)

	resultsIterator, err := ctx.GetStub().GetQueryResult(queryString)
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var documents []*DIDDocument
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		var doc DIDDocument
		err = json.Unmarshal(queryResponse.Value, &doc)
		if err != nil {
			return nil, err
		}
		documents = append(documents, &doc)
	}

	return documents, nil
}

// --- ENGINE STARTUP ---

func main() {
	dztaContract := new(DztaContract)
	cc, err := contractapi.NewChaincode(dztaContract)
	if err != nil {
		log.Panicf("Error creating dzta chaincode: %v", err)
	}

	ccServer := shim.ChaincodeServer{
		CCID:    os.Getenv("CHAINCODE_ID"),
		Address: os.Getenv("CHAINCODE_SERVER_ADDRESS"),
		CC:      cc,
		TLSProps: shim.TLSProperties{
			Disabled: true,
		},
	}

	log.Printf("Starting Production Dzta Gateway CCAAS Server at %s", ccServer.Address)
	if err := ccServer.Start(); err != nil {
		log.Panicf("Error starting dzta chaincode server: %v", err)
	}
}
