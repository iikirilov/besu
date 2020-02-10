/*
 * Copyright ConsenSys AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package org.hyperledger.besu.ethereum.mainnet.precompiles.privacy;

import static org.hyperledger.besu.crypto.Hash.keccak256;
import static org.hyperledger.besu.ethereum.privacy.PrivateStateRootResolver.EMPTY_ROOT_HASH;

import org.hyperledger.besu.crypto.SECP256K1;
import org.hyperledger.besu.enclave.Enclave;
import org.hyperledger.besu.enclave.EnclaveClientException;
import org.hyperledger.besu.enclave.EnclaveIOException;
import org.hyperledger.besu.enclave.EnclaveServerException;
import org.hyperledger.besu.enclave.types.ReceiveResponse;
import org.hyperledger.besu.ethereum.chain.Blockchain;
import org.hyperledger.besu.ethereum.chain.TransactionLocation;
import org.hyperledger.besu.ethereum.core.Address;
import org.hyperledger.besu.ethereum.core.BlockHeader;
import org.hyperledger.besu.ethereum.core.DefaultEvmAccount;
import org.hyperledger.besu.ethereum.core.Gas;
import org.hyperledger.besu.ethereum.core.Hash;
import org.hyperledger.besu.ethereum.core.MutableAccount;
import org.hyperledger.besu.ethereum.core.MutableWorldState;
import org.hyperledger.besu.ethereum.core.PrivacyParameters;
import org.hyperledger.besu.ethereum.core.ProcessableBlockHeader;
import org.hyperledger.besu.ethereum.core.Wei;
import org.hyperledger.besu.ethereum.core.WorldUpdater;
import org.hyperledger.besu.ethereum.debug.TraceOptions;
import org.hyperledger.besu.ethereum.mainnet.AbstractPrecompiledContract;
import org.hyperledger.besu.ethereum.privacy.PrivateStateRootResolver;
import org.hyperledger.besu.ethereum.privacy.PrivateTransaction;
import org.hyperledger.besu.ethereum.privacy.PrivateTransactionProcessor;
import org.hyperledger.besu.ethereum.privacy.PrivateTransactionReceipt;
import org.hyperledger.besu.ethereum.privacy.PrivateTransactionWithMetadata;
import org.hyperledger.besu.ethereum.privacy.Restriction;
import org.hyperledger.besu.ethereum.privacy.group.OnChainGroupManagement;
import org.hyperledger.besu.ethereum.privacy.storage.PrivacyGroupHeadBlockMap;
import org.hyperledger.besu.ethereum.privacy.storage.PrivateBlockMetadata;
import org.hyperledger.besu.ethereum.privacy.storage.PrivateStateStorage;
import org.hyperledger.besu.ethereum.privacy.storage.PrivateTransactionMetadata;
import org.hyperledger.besu.ethereum.rlp.BytesValueRLPInput;
import org.hyperledger.besu.ethereum.rlp.RLP;
import org.hyperledger.besu.ethereum.vm.DebugOperationTracer;
import org.hyperledger.besu.ethereum.vm.GasCalculator;
import org.hyperledger.besu.ethereum.vm.MessageFrame;
import org.hyperledger.besu.ethereum.worldstate.WorldStateArchive;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.units.bigints.UInt256;

public class OnChainPrivacyPrecompiledContract extends AbstractPrecompiledContract {

  // Dummy signature for transactions to not fail being processed.
  private static final SECP256K1.Signature FAKE_SIGNATURE =
      SECP256K1.Signature.create(SECP256K1.HALF_CURVE_ORDER, SECP256K1.HALF_CURVE_ORDER, (byte) 0);

  private final Enclave enclave;
  private final WorldStateArchive privateWorldStateArchive;
  private final PrivateStateStorage privateStateStorage;
  private final PrivateStateRootResolver privateStateRootResolver;
  private PrivateTransactionProcessor privateTransactionProcessor;

  private static final Logger LOG = LogManager.getLogger();

  public OnChainPrivacyPrecompiledContract(
      final GasCalculator gasCalculator, final PrivacyParameters privacyParameters) {
    this(
        gasCalculator,
        privacyParameters.getEnclave(),
        privacyParameters.getPrivateWorldStateArchive(),
        privacyParameters.getPrivateStateStorage());
  }

  OnChainPrivacyPrecompiledContract(
      final GasCalculator gasCalculator,
      final Enclave enclave,
      final WorldStateArchive worldStateArchive,
      final PrivateStateStorage privateStateStorage) {
    super("OnChainPrivacy", gasCalculator);
    this.enclave = enclave;
    this.privateWorldStateArchive = worldStateArchive;
    this.privateStateStorage = privateStateStorage;
    this.privateStateRootResolver = new PrivateStateRootResolver(privateStateStorage);
  }

  public void setPrivateTransactionProcessor(
      final PrivateTransactionProcessor privateTransactionProcessor) {
    this.privateTransactionProcessor = privateTransactionProcessor;
  }

  @Override
  public Gas gasRequirement(final Bytes input) {
    return Gas.of(0L);
  }

  @Override
  public Bytes compute(final Bytes input, final MessageFrame messageFrame) {
    final ProcessableBlockHeader currentBlockHeader = messageFrame.getBlockHeader();
    if (!BlockHeader.class.isAssignableFrom(currentBlockHeader.getClass())) {
      if (!messageFrame.isPersistingState()) {
        // We get in here from block mining.
        return Bytes.EMPTY;
      } else {
        throw new IllegalArgumentException(
            "The MessageFrame contains an illegal block header type. Cannot persist private block metadata without current block hash.");
      }
    }
    final Hash currentBlockHash = ((BlockHeader) currentBlockHeader).getHash();

    final String key;
    final String addKey;
    if (input.size() == 32) {
      key = input.toBase64String();
      addKey = null;
    } else if (input.size() == 64) {
      key = input.slice(0, 32).toBase64String();
      addKey = input.slice(32, 32).toBase64String();
    } else {
      throw new RuntimeException();
    }

    final ReceiveResponse receiveResponse;
    try {
      receiveResponse = enclave.receive(key);
    } catch (final EnclaveClientException e) {
      LOG.debug("Can not fetch private transaction payload with key {}", key, e);
      return Bytes.EMPTY;
    } catch (final EnclaveServerException e) {
      LOG.error("Enclave is responding but errored perhaps it has a misconfiguration?", e);
      throw e;
    } catch (final EnclaveIOException e) {
      LOG.error("Can not communicate with enclave is it up?", e);
      throw e;
    }

    final BytesValueRLPInput bytesValueRLPInput =
        new BytesValueRLPInput(
            Bytes.wrap(Base64.getDecoder().decode(receiveResponse.getPayload())), false);
    bytesValueRLPInput.enterList();
    final PrivateTransaction privateTransaction = PrivateTransaction.readFrom(bytesValueRLPInput);
    final Optional<Bytes32> versionOptional;
    if (!bytesValueRLPInput.isEndOfCurrentList()) {
      versionOptional = Optional.of(bytesValueRLPInput.readBytes32());
    } else {
      versionOptional = Optional.empty();
    }
    bytesValueRLPInput.leaveList();

    final WorldUpdater publicWorldState = messageFrame.getWorldState();

    // TODO sort out the exception being thrown here
    final Bytes32 privacyGroupId =
        Bytes32.wrap(privateTransaction.getPrivacyGroupId().orElseThrow(RuntimeException::new));

    LOG.trace(
        "Processing private transaction {} in privacy group {}",
        privateTransaction.getHash(),
        privacyGroupId);

    final PrivacyGroupHeadBlockMap privacyGroupHeadBlockMap =
        privateStateStorage.getPrivacyGroupHeadBlockMap(currentBlockHash).orElseThrow();

    final Blockchain currentBlockchain = messageFrame.getBlockchain();

    final Hash lastRootHash =
        privateStateRootResolver.resolveLastStateRoot(privacyGroupId, currentBlockHash);

    final MutableWorldState disposablePrivateState =
        privateWorldStateArchive.getMutable(lastRootHash).get();

    final WorldUpdater privateWorldStateUpdater = disposablePrivateState.updater();

    if (lastRootHash.equals(EMPTY_ROOT_HASH)) {
      // inject management
      final DefaultEvmAccount managementPrecompile =
          privateWorldStateUpdater.createAccount(Address.DEFAULT_PRIVACY_MANAGEMENT);
      final MutableAccount mutableManagementPrecompiled = managementPrecompile.getMutable();
      // this is the code for the simple management contract
      mutableManagementPrecompiled.setCode(OnChainGroupManagement.DEFAULT_GROUP_MANAGEMENT_CODE);

      // inject proxy
      final DefaultEvmAccount proxyPrecompile =
          privateWorldStateUpdater.createAccount(Address.PRIVACY_PROXY);
      final MutableAccount mutableProxyPrecompiled = proxyPrecompile.getMutable();
      // this is the code for the proxy contract
      mutableProxyPrecompiled.setCode(OnChainGroupManagement.DEFAULT_PROXY_PRECOMPILED_CODE);
      // manually set the management contract address so the proxy can trust it
      mutableProxyPrecompiled.setStorageValue(
          UInt256.ZERO, UInt256.fromBytes(Bytes32.leftPad(Address.DEFAULT_PRIVACY_MANAGEMENT)));

      privateWorldStateUpdater.commit();
      disposablePrivateState.persist();
    }

    if (addKey != null && privacyGroupHeadBlockMap.get(privacyGroupId) == null) {
      final ReceiveResponse addReceiveResponse;
      try {
        addReceiveResponse = enclave.receive(addKey);
        final List<PrivateTransactionWithMetadata> privateTransactionWithMetadataList =
            deserializeAddToGroupPayload(
                Bytes.wrap(Base64.getDecoder().decode(addReceiveResponse.getPayload())));

        long lastBlockNumber = -1;
        for (int i = 0; i < privateTransactionWithMetadataList.size(); i++) {
          final PrivateTransactionWithMetadata privateTransactionWithMetadata =
              privateTransactionWithMetadataList.get(i);
          final PrivateTransactionProcessor.Result result =
              privateTransactionProcessor.processTransaction(
                  currentBlockchain,
                  publicWorldState,
                  privateWorldStateUpdater,
                  currentBlockHeader,
                  privateTransactionWithMetadata.getPrivateTransaction(),
                  messageFrame.getMiningBeneficiary(),
                  new DebugOperationTracer(TraceOptions.DEFAULT),
                  messageFrame.getBlockHashLookup(),
                  privacyGroupId);

          if (result.isInvalid()
              || !result.isSuccessful()
              || !disposablePrivateState
                  .rootHash()
                  .equals(
                      privateTransactionWithMetadata
                          .getPrivateTransactionMetadata()
                          .getStateRoot())) {
            LOG.error(
                "Failed to rehydrate private transaction {} - Expecting root hash {}, but got {}",
                privateTransactionWithMetadata.getPrivateTransaction().toString(),
                disposablePrivateState.rootHash().toHexString(),
                privateTransactionWithMetadata.getPrivateTransactionMetadata().getStateRoot());
          }
          // We need to commit here so we can verify that the last payload locks the group
          // further down

          if (messageFrame.isPersistingState()) {
            final TransactionLocation markerTransactionLocation =
                currentBlockchain
                    .getTransactionLocation(
                        privateTransactionWithMetadata
                            .getPrivateTransactionMetadata()
                            .getPrivacyMarkerTransactionHash())
                    .orElseThrow();
            final PrivacyGroupHeadBlockMap temp =
                privateStateStorage
                    .getPrivacyGroupHeadBlockMap(markerTransactionLocation.getBlockHash())
                    .orElse(PrivacyGroupHeadBlockMap.EMPTY);
            persistePrivateState(
                privateTransactionWithMetadata
                    .getPrivateTransactionMetadata()
                    .getPrivacyMarkerTransactionHash(),
                markerTransactionLocation.getBlockHash(),
                privateTransactionWithMetadata.getPrivateTransaction(),
                privacyGroupId,
                temp,
                disposablePrivateState,
                privateWorldStateUpdater,
                result);

            final BlockHeader blockHeader =
                currentBlockchain
                    .getBlockHeader(markerTransactionLocation.getBlockHash())
                    .orElseThrow();
            final long blockNumber = blockHeader.getNumber();

            if (lastBlockNumber == -1) {
              lastBlockNumber = blockNumber;
            }

            if (blockNumber - lastBlockNumber > 1) {
              rehydratePrivacyGroupHeadBlockMap(
                  privacyGroupId, currentBlockchain, lastBlockNumber, blockNumber);
            }

            lastBlockNumber = blockNumber;
          }
        }

        if (messageFrame.isPersistingState()) {
          final PrivateStateStorage.Updater privateStateUpdater = privateStateStorage.updater();
          privateStateUpdater.putAddDataKey(
              privacyGroupId, Bytes32.wrap(Bytes.fromBase64String(addKey)));
          privateStateUpdater.commit();
          long blockNumber = currentBlockchain.getChainHeadBlockNumber();
          if (blockNumber - lastBlockNumber > 1) {
            rehydratePrivacyGroupHeadBlockMap(
                privacyGroupId, currentBlockchain, lastBlockNumber, blockNumber);
          }
        }

      } catch (final EnclaveClientException e) {
        LOG.debug("Can not fetch private transaction payload with key {}", key, e);
        return Bytes.EMPTY;
      } catch (final EnclaveServerException e) {
        LOG.error("Enclave is responding but errored perhaps it has a misconfiguration?", e);
        throw e;
      } catch (final EnclaveIOException e) {
        LOG.error("Can not communicate with enclave is it up?", e);
        throw e;
      }
    }

    // We need the "lock status" of the group for every single transaction but we don't want this
    // call to affect the state
    // privateTransactionProcessor.processTransaction(...) commits the state if the process was
    // successful before it returns
    final MutableWorldState canExecutePrivateState =
        privateWorldStateArchive.getMutable(disposablePrivateState.rootHash()).get();
    final WorldUpdater canExecuteUpdater = canExecutePrivateState.updater();

    final PrivateTransactionProcessor.Result canExecuteResult =
        privateTransactionProcessor.processTransaction(
            currentBlockchain,
            publicWorldState,
            canExecuteUpdater,
            currentBlockHeader,
            buildSimulationTransaction(
                privacyGroupId,
                privateWorldStateUpdater,
                OnChainGroupManagement.CAN_EXECUTE_METHOD_SIGNATURE),
            messageFrame.getMiningBeneficiary(),
            new DebugOperationTracer(TraceOptions.DEFAULT),
            messageFrame.getBlockHashLookup(),
            privacyGroupId);

    if (privateTransaction.getPayload().toHexString().startsWith("0xf744b089")
        && !canExecuteResult.getOutput().toHexString().endsWith("0")) {
      LOG.info(
          "Privacy Group {} is not locked while trying to add to group with commitment {}",
          privacyGroupId.toHexString(),
          messageFrame.getTransactionHash());
      return Bytes.EMPTY;
    }

    if (!privateTransaction.getPayload().toHexString().startsWith("0xf744b089")
        && canExecuteResult.getOutput().toHexString().endsWith("0")) {
      LOG.info(
          "Privacy Group {} is locked while trying to execute transaction with commitment {}",
          privacyGroupId.toHexString(),
          messageFrame.getTransactionHash());
      return Bytes.EMPTY;
    }

    // We need the "version" of the group for every single transaction but we don't want this
    // call to affect the state
    // privateTransactionProcessor.processTransaction(...) commits the state if the process was
    // successful before it returns
    final MutableWorldState getVersionState =
        privateWorldStateArchive.getMutable(disposablePrivateState.rootHash()).get();
    final WorldUpdater getVersionUpdater = getVersionState.updater();

    final PrivateTransactionProcessor.Result getVersionResult =
        privateTransactionProcessor.processTransaction(
            currentBlockchain,
            publicWorldState,
            getVersionUpdater,
            currentBlockHeader,
            buildSimulationTransaction(
                privacyGroupId,
                privateWorldStateUpdater,
                OnChainGroupManagement.GET_VERSION_METHOD_SIGNATURE),
            messageFrame.getMiningBeneficiary(),
            new DebugOperationTracer(TraceOptions.DEFAULT),
            messageFrame.getBlockHashLookup(),
            privacyGroupId);

    if (versionOptional.isPresent()) {
      if (!versionOptional.get().equals(getVersionResult.getOutput())) {
        LOG.info(
            "Privacy Group {} version mismatch for commitment {}: expecting {} but got {}",
            privacyGroupId.toBase64String(),
            messageFrame.getTransactionHash(),
            getVersionResult.getOutput(),
            versionOptional.get());
        return Bytes.EMPTY;
      }
    }

    final PrivateTransactionProcessor.Result result =
        privateTransactionProcessor.processTransaction(
            currentBlockchain,
            publicWorldState,
            privateWorldStateUpdater,
            currentBlockHeader,
            privateTransaction,
            messageFrame.getMiningBeneficiary(),
            new DebugOperationTracer(TraceOptions.DEFAULT),
            messageFrame.getBlockHashLookup(),
            privacyGroupId);

    if (result.isInvalid() || !result.isSuccessful()) {
      LOG.error(
          "Failed to process private transaction {}: {}",
          privateTransaction.getHash(),
          result.getValidationResult().getErrorMessage());
      return Bytes.EMPTY;
    }

    if (messageFrame.isPersistingState()) {
      persistePrivateState(
          messageFrame.getTransactionHash(),
          currentBlockHash,
          privateTransaction,
          privacyGroupId,
          privacyGroupHeadBlockMap,
          disposablePrivateState,
          privateWorldStateUpdater,
          result);
    }

    return result.getOutput();
  }

  protected void rehydratePrivacyGroupHeadBlockMap(
      final Bytes32 privacyGroupId,
      final Blockchain currentBlockchain,
      final long from,
      final long to) {
    for (long j = from + 1; j < to; j++) {
      final BlockHeader theBlockHeader = currentBlockchain.getBlockHeader(j).orElseThrow();
      final PrivacyGroupHeadBlockMap thePrivacyGroupHeadBlockMap =
          privateStateStorage
              .getPrivacyGroupHeadBlockMap(theBlockHeader.getHash())
              .orElse(PrivacyGroupHeadBlockMap.EMPTY);
      final PrivateStateStorage.Updater privateStateUpdater = privateStateStorage.updater();
      thePrivacyGroupHeadBlockMap.put(
          Bytes32.wrap(privacyGroupId), currentBlockchain.getBlockHeader(from).get().getHash());
      privateStateUpdater.putPrivacyGroupHeadBlockMap(
          theBlockHeader.getHash(), new PrivacyGroupHeadBlockMap(thePrivacyGroupHeadBlockMap));
      privateStateUpdater.commit();
    }
  }

  protected void persistePrivateState(
      final Hash commitmentHash,
      final Hash currentBlockHash,
      final PrivateTransaction privateTransaction,
      final Bytes32 privacyGroupId,
      final PrivacyGroupHeadBlockMap privacyGroupHeadBlockMap,
      final MutableWorldState disposablePrivateState,
      final WorldUpdater privateWorldStateUpdater,
      final PrivateTransactionProcessor.Result result) {

    LOG.trace(
        "Persisting private state {} for privacyGroup {}",
        disposablePrivateState.rootHash(),
        privacyGroupId);
    privateWorldStateUpdater.commit();
    disposablePrivateState.persist();

    final PrivateStateStorage.Updater privateStateUpdater = privateStateStorage.updater();

    updatePrivateBlockMetadata(
        commitmentHash,
        currentBlockHash,
        privacyGroupId,
        disposablePrivateState.rootHash(),
        privateStateUpdater);

    final Bytes32 txHash = keccak256(RLP.encode(privateTransaction::writeTo));

    final int txStatus =
        result.getStatus() == PrivateTransactionProcessor.Result.Status.SUCCESSFUL ? 1 : 0;

    final PrivateTransactionReceipt privateTransactionReceipt =
        new PrivateTransactionReceipt(
            txStatus, result.getLogs(), result.getOutput(), result.getRevertReason());

    privateStateUpdater.putTransactionReceipt(currentBlockHash, txHash, privateTransactionReceipt);

    if (!privacyGroupHeadBlockMap.contains(Bytes32.wrap(privacyGroupId), currentBlockHash)) {
      privacyGroupHeadBlockMap.put(Bytes32.wrap(privacyGroupId), currentBlockHash);
      privateStateUpdater.putPrivacyGroupHeadBlockMap(
          currentBlockHash, new PrivacyGroupHeadBlockMap(privacyGroupHeadBlockMap));
    }
    privateStateUpdater.commit();
  }

  private PrivateTransaction buildSimulationTransaction(
      final Bytes privacyGroupId,
      final WorldUpdater privateWorldStateUpdater,
      final Bytes payload) {
    return PrivateTransaction.builder()
        .privateFrom(Bytes.EMPTY)
        .privacyGroupId(privacyGroupId)
        .restriction(Restriction.RESTRICTED)
        .nonce(
            privateWorldStateUpdater.getAccount(Address.ZERO) != null
                ? privateWorldStateUpdater.getAccount(Address.ZERO).getNonce()
                : 0)
        .gasPrice(Wei.of(1000))
        .gasLimit(3000000)
        .to(Address.PRIVACY_PROXY)
        .sender(Address.ZERO)
        .value(Wei.ZERO)
        .payload(payload)
        .signature(FAKE_SIGNATURE)
        .build();
  }

  private void updatePrivateBlockMetadata(
      final Hash markerTransactionHash,
      final Hash currentBlockHash,
      final Bytes32 privacyGroupId,
      final Hash rootHash,
      final PrivateStateStorage.Updater privateStateUpdater) {
    final PrivateBlockMetadata privateBlockMetadata =
        privateStateStorage
            .getPrivateBlockMetadata(currentBlockHash, Bytes32.wrap(privacyGroupId))
            .orElseGet(PrivateBlockMetadata::empty);
    privateBlockMetadata.addPrivateTransactionMetadata(
        new PrivateTransactionMetadata(markerTransactionHash, rootHash));
    privateStateUpdater.putPrivateBlockMetadata(
        Bytes32.wrap(currentBlockHash), Bytes32.wrap(privacyGroupId), privateBlockMetadata);
  }

  private List<PrivateTransactionWithMetadata> deserializeAddToGroupPayload(
      final Bytes encodedAddToGroupPayload) {
    final ArrayList<PrivateTransactionWithMetadata> deserializedResponse = new ArrayList<>();
    final BytesValueRLPInput bytesValueRLPInput =
        new BytesValueRLPInput(encodedAddToGroupPayload, false);
    final int noOfEntries = bytesValueRLPInput.enterList();
    for (int i = 0; i < noOfEntries; i++) {
      deserializedResponse.add(PrivateTransactionWithMetadata.readFrom(bytesValueRLPInput));
    }
    bytesValueRLPInput.leaveList();
    return deserializedResponse;
  }
}
