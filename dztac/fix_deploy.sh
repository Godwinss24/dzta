# 1. Set your environment variables to the correct hyphenated name
export CHAINCODE_NAME=dzta-contract
export CHAINCODE_LABEL=dzta-contract
export VERSION="1.3"
export SEQUENCE=2
export ENDORSEMENT_POLICY="OR('Org1MSP.member', 'Org2MSP.member')"

# 2. Recalculate the correct package ID using the hyphenated label
export PACKAGE_ID=$(kubectl hlf chaincode calculatepackageid --path=./chaincode.tgz --language=golang --label=$CHAINCODE_LABEL)

# 3. Approve the updated definition for both organizations
kubectl hlf chaincode approveformyorg --config=org1.yaml --user=org1-admin-default --peer=org1-peer0.default \
    --package-id=$PACKAGE_ID --version "$VERSION" --sequence "$SEQUENCE" --name=$CHAINCODE_NAME \
    --policy="${ENDORSEMENT_POLICY}" --channel=demo

kubectl hlf chaincode approveformyorg --config=org2.yaml --user=org2-admin-default --peer=org2-peer0.default \
    --package-id=$PACKAGE_ID --version "$VERSION" --sequence "$SEQUENCE" --name=$CHAINCODE_NAME \
    --policy="${ENDORSEMENT_POLICY}" --channel=demo

# 4. Commit the new sequence to the channel ledger
kubectl hlf chaincode commit --config=org1.yaml --user=org1-admin-default --mspid=Org1MSP \
    --version "$VERSION" --sequence "$SEQUENCE" --name=$CHAINCODE_NAME \
    --policy="${ENDORSEMENT_POLICY}" --channel=demo