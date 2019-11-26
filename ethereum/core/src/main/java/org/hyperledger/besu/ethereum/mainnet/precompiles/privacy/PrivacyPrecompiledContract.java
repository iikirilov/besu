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

import org.hyperledger.besu.enclave.Enclave;
import org.hyperledger.besu.enclave.EnclaveClientException;
import org.hyperledger.besu.enclave.EnclaveIOException;
import org.hyperledger.besu.enclave.EnclaveServerException;
import org.hyperledger.besu.enclave.types.ReceiveResponse;
import org.hyperledger.besu.ethereum.chain.Blockchain;
import org.hyperledger.besu.ethereum.core.BlockHeader;
import org.hyperledger.besu.ethereum.core.Gas;
import org.hyperledger.besu.ethereum.core.Hash;
import org.hyperledger.besu.ethereum.core.Log;
import org.hyperledger.besu.ethereum.core.MutableWorldState;
import org.hyperledger.besu.ethereum.core.PrivacyParameters;
import org.hyperledger.besu.ethereum.core.ProcessableBlockHeader;
import org.hyperledger.besu.ethereum.core.WorldUpdater;
import org.hyperledger.besu.ethereum.debug.TraceOptions;
import org.hyperledger.besu.ethereum.mainnet.AbstractPrecompiledContract;
import org.hyperledger.besu.ethereum.privacy.PrivateTransaction;
import org.hyperledger.besu.ethereum.privacy.PrivateTransactionProcessor;
import org.hyperledger.besu.ethereum.privacy.storage.PrivateBlockMetadata;
import org.hyperledger.besu.ethereum.privacy.storage.PrivateGroupIdToLatestBlockWithTransactionMap;
import org.hyperledger.besu.ethereum.privacy.storage.PrivateStateStorage;
import org.hyperledger.besu.ethereum.privacy.storage.PrivateTransactionMetadata;
import org.hyperledger.besu.ethereum.rlp.BytesValueRLPInput;
import org.hyperledger.besu.ethereum.rlp.RLP;
import org.hyperledger.besu.ethereum.trie.MerklePatriciaTrie;
import org.hyperledger.besu.ethereum.vm.DebugOperationTracer;
import org.hyperledger.besu.ethereum.vm.GasCalculator;
import org.hyperledger.besu.ethereum.vm.MessageFrame;
import org.hyperledger.besu.ethereum.worldstate.WorldStateArchive;

import java.util.Base64;
import java.util.List;

import java.util.Collections;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

public class PrivacyPrecompiledContract extends AbstractPrecompiledContract {
  private static final Hash EMPTY_ROOT_HASH = Hash.wrap(MerklePatriciaTrie.EMPTY_TRIE_NODE_HASH);

  private final Enclave enclave;
  private final WorldStateArchive privateWorldStateArchive;
  private final PrivateStateStorage privateStateStorage;
  private PrivateTransactionProcessor privateTransactionProcessor;

  private static final Logger LOG = LogManager.getLogger();

  public PrivacyPrecompiledContract(
      final GasCalculator gasCalculator, final PrivacyParameters privacyParameters) {
    this(
        gasCalculator,
        privacyParameters.getEnclave(),
        privacyParameters.getPrivateWorldStateArchive(),
        privacyParameters.getPrivateStateStorage());
  }

  PrivacyPrecompiledContract(
      final GasCalculator gasCalculator,
      final Enclave enclave,
      final WorldStateArchive worldStateArchive,
      final PrivateStateStorage privateStateStorage) {
    super("Privacy", gasCalculator);
    this.enclave = enclave;
    this.privateWorldStateArchive = worldStateArchive;
    this.privateStateStorage = privateStateStorage;
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
    final String key = input.toBase64String();

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
    final PrivateTransaction privateTransaction = PrivateTransaction.readFrom(bytesValueRLPInput);
    final WorldUpdater publicWorldState = messageFrame.getWorldState();
    final Bytes privacyGroupId = Bytes.fromBase64String(receiveResponse.getPrivacyGroupId());

  LOG.trace(
          "Processing private transaction {} in privacy group {}",
          privateTransaction.getHash(),
          privacyGroupId);

    final ProcessableBlockHeader currentBlockHeader = messageFrame.getBlockHeader();
    final Map<Bytes32, Hash> privacyGroupToLatestBlockWithTransactionMap =
        privateStateStorage
            .getPrivacyGroupToLatestBlockWithTransactionMap(currentBlockHeader.getParentHash())
            .map(PrivateGroupIdToLatestBlockWithTransactionMap::getMap)
            .orElse(Collections.emptyMap());

    final Blockchain currentBlockchain = messageFrame.getBlockchain();
    final Hash currentBlockHash = ((BlockHeader) currentBlockHeader).getHash();

    final Hash lastRootHash =
        getLastRootHash(
            privacyGroupId,
            currentBlockHeader,
            privacyGroupToLatestBlockWithTransactionMap,
            currentBlockHash);

    final MutableWorldState disposablePrivateState =
        privateWorldStateArchive.getMutable(lastRootHash).get();

    final WorldUpdater privateWorldStateUpdater = disposablePrivateState.updater();
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
      LOG.trace(
          "Persisting private state {} for privacyGroup {}",
          disposablePrivateState.rootHash(),
          privacyGroupId);
      privateWorldStateUpdater.commit();
      disposablePrivateState.persist();

      final PrivateStateStorage.Updater privateStateUpdater = privateStateStorage.updater();
      final PrivateBlockMetadata privateBlockMetadata =
          privateStateStorage
              .getPrivateBlockMetadata(currentBlockHash, Bytes32.wrap(privacyGroupId))
              .orElseGet(PrivateBlockMetadata::empty);
      privateBlockMetadata.addPrivateTransactionMetadata(
          new PrivateTransactionMetadata(
              messageFrame.getTransactionHash(), disposablePrivateState.rootHash()));
      privateStateUpdater.putPrivateBlockMetadata(
          Bytes32.wrap(currentBlockHash.getByteArray()),
          Bytes32.wrap(privacyGroupId),
          privateBlockMetadata);

      final Bytes32 txHash = keccak256(RLP.encode(privateTransaction::writeTo));
      final List<Log> logs = result.getLogs();
      if (!logs.isEmpty()) {
        privateStateUpdater.putTransactionLogs(txHash, result.getLogs());
      }
      if (result.getRevertReason().isPresent()) {
        privateStateUpdater.putTransactionRevertReason(txHash, result.getRevertReason().get());
      }

      privateStateUpdater.putTransactionStatus(
          txHash,
          Bytes.of(result.getStatus() == PrivateTransactionProcessor.Result.Status.SUCCESSFUL ? 1 : 0));
      privateStateUpdater.putTransactionResult(txHash, result.getOutput());

      // TODO: could check whether the map already contains the right block hash
      privacyGroupToLatestBlockWithTransactionMap.put(
          Bytes32.wrap(privacyGroupId), currentBlockHash);
      privateStateUpdater.putPrivacyGroupToLatestBlockWithTransactionMap(
          currentBlockHash,
          new PrivateGroupIdToLatestBlockWithTransactionMap(
              privacyGroupToLatestBlockWithTransactionMap));

      privateStateUpdater.commit();
    }

    return result.getOutput();
  }

  private Hash getLastRootHash(
      final BytesValue privacyGroupId,
      final ProcessableBlockHeader currentBlockHeader,
      final Map<Bytes32, Hash> privacyGroupToLatestBlockWithTransactionMap,
      final Hash currentBlockHash) {
    final Hash lastRootHash;
    if (BlockHeader.class.isAssignableFrom(currentBlockHeader.getClass())
        && privateStateStorage
            .getPrivateBlockMetadata(currentBlockHash, Bytes32.wrap(privacyGroupId))
            .isPresent()) {
      // Check if block already has meta data for the privacy group
      lastRootHash =
          privateStateStorage
              .getPrivateBlockMetadata(currentBlockHash, Bytes32.wrap(privacyGroupId))
              .get()
              .getLatestStateRoot();
    } else if (privacyGroupToLatestBlockWithTransactionMap.containsKey(
        Bytes32.wrap(privacyGroupId))) {
      // Check this PG head block is being tracked
      final Hash blockHashForLastBlockWithTx =
          privacyGroupToLatestBlockWithTransactionMap.get(Bytes32.wrap(privacyGroupId));
      lastRootHash =
          privateStateStorage
              .getPrivateBlockMetadata(blockHashForLastBlockWithTx, Bytes32.wrap(privacyGroupId))
              .get()
              .getLatestStateRoot();
    } else {
      // First transaction for this PG
      lastRootHash = EMPTY_ROOT_HASH;
    }
    return lastRootHash;
  }
}
