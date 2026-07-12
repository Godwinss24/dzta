#!/bin/bash
set -e

export CHAINCODE_NAME=dzta
export CHAINCODE_LABEL=dzta
export SEQUENCE=1
export VERSION="1.2"
export ENDORSEMENT_POLICY="OR('Org1MSP.member', 'Org2MSP.member')"

echo "=== 1. Enrolling Admin Identities ==="
kubectl hlf identity create --name org1-admin --namespace default \
    --ca-name org1-ca --ca-namespace default \
    --ca ca --mspid Org1MSP --enroll-id explorer-admin --enroll-secret explorer-adminpw \
    --ca-enroll-id=enroll --ca-enroll-secret=enrollpw --ca-type=admin || true

kubectl hlf identity create --name org2-admin --namespace default \
    --ca-name org2-ca --ca-namespace default \
    --ca ca --mspid Org2MSP --enroll-id explorer-admin --enroll-secret explorer-adminpw \
    --ca-enroll-id=enroll --ca-enroll-secret=enrollpw --ca-type=admin || true

echo "=== 2. Creating Network Config Profiles ==="
kubectl hlf networkconfig create --name=org1-cp -o Org1MSP -o OrdererMSP -c demo --identities=org1-admin.default --secret=org1-cp || true
kubectl hlf networkconfig create --name=org2-cp -o Org2MSP -o OrdererMSP -c demo --identities=org2-admin.default --secret=org2-cp || true

echo "=== 3. Exporting Connection Profile Profiles ==="
kubectl get secret org1-cp -o jsonpath="{.data.config\.yaml}" | base64 --decode > org1.yaml
kubectl get secret org2-cp -o jsonpath="{.data.config\.yaml}" | base64 --decode > org2.yaml

echo "=== 4. Computing Contract Content Hash ID ==="
export PACKAGE_ID=$(kubectl hlf chaincode calculatepackageid --path=./chaincode.tgz --language=golang --label=$CHAINCODE_LABEL)
echo "Generated Target PACKAGE_ID: $PACKAGE_ID"

echo "=== 5. Injecting Routing Map onto Peer Targets ==="
# Org 1 Peers
kubectl hlf chaincode install --path=./chaincode.tgz --config=org1.yaml --language=golang --label=$CHAINCODE_LABEL --user=org1-admin-default --peer=org1-peer0.default
kubectl hlf chaincode install --path=./chaincode.tgz --config=org1.yaml --language=golang --label=$CHAINCODE_LABEL --user=org1-admin-default --peer=org1-peer1.default

# Org 2 Peers
kubectl hlf chaincode install --path=./chaincode.tgz --config=org2.yaml --language=golang --label=$CHAINCODE_LABEL --user=org2-admin-default --peer=org2-peer0.default
# kubectl hlf chaincode install --path=./chaincode.tgz --config=org2.yaml --language=golang --label=$CHAINCODE_LABEL --user=org2-admin-default --peer=org2-peer1.default

echo "=== 6. Syncing Standing Chaincode Pod Service ==="
kubectl hlf externalchaincode sync --image=dzta-cc:1.7 \
    --name=$CHAINCODE_NAME \
    --namespace=default \
    --package-id=$PACKAGE_ID \
    --tls-required=false \
    --replicas=1

echo "=== 7. Approving Chaincode Definitions ==="
kubectl hlf chaincode approveformyorg --config=org1.yaml --user=org1-admin-default --peer=org1-peer0.default \
    --package-id=$PACKAGE_ID --version "$VERSION" --sequence "$SEQUENCE" --name=$CHAINCODE_NAME \
    --policy="${ENDORSEMENT_POLICY}" --channel=demo

kubectl hlf chaincode approveformyorg --config=org2.yaml --user=org2-admin-default --peer=org2-peer0.default \
    --package-id=$PACKAGE_ID --version "$VERSION" --sequence "$SEQUENCE" --name=$CHAINCODE_NAME \
    --policy="${ENDORSEMENT_POLICY}" --channel=demo

echo "=== 8. Committing Consensus to Channel 'demo' ==="
kubectl hlf chaincode commit --config=org1.yaml --user=org1-admin-default --mspid=Org1MSP \
    --version "$VERSION" --sequence "$SEQUENCE" --name=$CHAINCODE_NAME \
    --policy="${ENDORSEMENT_POLICY}" --channel=demo

echo "--------------------------------------------------------"
echo "✓ Success! '$CHAINCODE_NAME' is live and ready via CCAAS!"
echo "--------------------------------------------------------"