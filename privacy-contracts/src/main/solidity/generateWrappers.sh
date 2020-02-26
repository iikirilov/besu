#!/usr/bin/env bash

targets="
PrivacyGroup
PrivacyInterface
PrivacyProxy
"

for target in ${targets}; do

  solc --overwrite --bin --abi \
        -o build  \
        ${target}.sol

done

for target in ${targets}; do

    web3j solidity generate \
        -b build/${target}.bin \
        -a build/${target}.abi \
        -o ../java \
        -p org.hyperledger.besu.privacy.contracts.generated

done