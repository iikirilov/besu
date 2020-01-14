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

import org.apache.tuweni.units.bigints.UInt256;
import org.hyperledger.besu.enclave.Enclave;
import org.hyperledger.besu.enclave.EnclaveClientException;
import org.hyperledger.besu.enclave.EnclaveIOException;
import org.hyperledger.besu.enclave.EnclaveServerException;
import org.hyperledger.besu.enclave.types.ReceiveResponse;
import org.hyperledger.besu.ethereum.chain.Blockchain;
import org.hyperledger.besu.ethereum.core.Address;
import org.hyperledger.besu.ethereum.core.BlockHeader;
import org.hyperledger.besu.ethereum.core.DefaultEvmAccount;
import org.hyperledger.besu.ethereum.core.Gas;
import org.hyperledger.besu.ethereum.core.Hash;
import org.hyperledger.besu.ethereum.core.Log;
import org.hyperledger.besu.ethereum.core.MutableAccount;
import org.hyperledger.besu.ethereum.core.MutableWorldState;
import org.hyperledger.besu.ethereum.core.PrivacyParameters;
import org.hyperledger.besu.ethereum.core.ProcessableBlockHeader;
import org.hyperledger.besu.ethereum.core.WorldUpdater;
import org.hyperledger.besu.ethereum.debug.TraceOptions;
import org.hyperledger.besu.ethereum.mainnet.AbstractPrecompiledContract;
import org.hyperledger.besu.ethereum.privacy.PrivateStateRootResolver;
import org.hyperledger.besu.ethereum.privacy.PrivateTransaction;
import org.hyperledger.besu.ethereum.privacy.PrivateTransactionProcessor;
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

import java.util.Base64;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

public class OnChainPrivacyPrecompiledContract extends AbstractPrecompiledContract {
  private static final Bytes PROXY_PRECOMPILED_CODE =
          Bytes.fromHexString(
                  "0x608060405234801561001057600080fd5b50600436106100575760003560e01c80630b0235be1461005c5780633659cfe6146100df5780635c60da1b1461012357806361544c911461016d578063f744b089146101bd575b600080fd5b6100886004803603602081101561007257600080fd5b8101908080359060200190929190505050610297565b6040518080602001828103825283818151815260200191508051906020019060200280838360005b838110156100cb5780820151818401526020810190506100b0565b505050509050019250505060405180910390f35b610121600480360360208110156100f557600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291905050506103ed565b005b61012b610453565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b6101a36004803603604081101561018357600080fd5b810190808035906020019092919080359060200190929190505050610478565b604051808215151515815260200191505060405180910390f35b61027d600480360360408110156101d357600080fd5b8101908080359060200190929190803590602001906401000000008111156101fa57600080fd5b82018360208201111561020c57600080fd5b8035906020019184602083028401116401000000008311171561022e57600080fd5b919080806020026020016040519081016040528093929190818152602001838360200280828437600081840152601f19601f82011690508083019250505050505050919291929050505061053e565b604051808215151515815260200191505060405180910390f35b606060008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1690508073ffffffffffffffffffffffffffffffffffffffff16630b0235be846040518263ffffffff1660e01b81526004018082815260200191505060006040518083038186803b15801561031057600080fd5b505afa158015610324573d6000803e3d6000fd5b505050506040513d6000823e3d601f19601f82011682018060405250602081101561034e57600080fd5b810190808051604051939291908464010000000082111561036e57600080fd5b8382019150602082018581111561038457600080fd5b82518660208202830111640100000000821117156103a157600080fd5b8083526020830192505050908051906020019060200280838360005b838110156103d85780820151818401526020810190506103bd565b50505050905001604052505050915050919050565b8073ffffffffffffffffffffffffffffffffffffffff166000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16141561044757600080fd5b61045081610645565b50565b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b6000806000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1690508073ffffffffffffffffffffffffffffffffffffffff166361544c9185856040518363ffffffff1660e01b81526004018083815260200182815260200192505050602060405180830381600087803b1580156104fa57600080fd5b505af115801561050e573d6000803e3d6000fd5b505050506040513d602081101561052457600080fd5b810190808051906020019092919050505091505092915050565b6000806000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1690508073ffffffffffffffffffffffffffffffffffffffff1663f744b08985856040518363ffffffff1660e01b81526004018083815260200180602001828103825283818151815260200191508051906020019060200280838360005b838110156105db5780820151818401526020810190506105c0565b505050509050019350505050602060405180830381600087803b15801561060157600080fd5b505af1158015610615573d6000803e3d6000fd5b505050506040513d602081101561062b57600080fd5b810190808051906020019092919050505091505092915050565b806000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505056fea265627a7a723158201a4ce973c48fac53e12b2885293aadcefb528b025fa49259e116bdb69e3bee5f64736f6c634300050c0032");

  private static final Bytes SIMPLE_GROUP_MANAGEMENT_CODE =
          Bytes.fromHexString(
                  "0x608060405234801561001057600080fd5b50600436106100415760003560e01c80630b0235be1461004657806361544c91146100c9578063f744b08914610119575b600080fd5b6100726004803603602081101561005c57600080fd5b81019080803590602001909291905050506101f3565b6040518080602001828103825283818151815260200191508051906020019060200280838360005b838110156100b557808201518184015260208101905061009a565b505050509050019250505060405180910390f35b6100ff600480360360408110156100df57600080fd5b81019080803590602001909291908035906020019092919050505061025f565b604051808215151515815260200191505060405180910390f35b6101d96004803603604081101561012f57600080fd5b81019080803590602001909291908035906020019064010000000081111561015657600080fd5b82018360208201111561016857600080fd5b8035906020019184602083028401116401000000008311171561018a57600080fd5b919080806020026020016040519081016040528093929190818152602001838360200280828437600081840152601f19601f820116905080830192505050505050509192919290505050610284565b604051808215151515815260200191505060405180910390f35b60606101fe826102aa565b61020757600080fd5b600080548060200260200160405190810160405280929190818152602001828054801561025357602002820191906000526020600020905b81548152602001906001019080831161023f575b50505050509050919050565b600061026a836102aa565b61027357600080fd5b61027c826102ca565b905092915050565b600061028f836102aa565b61029857600080fd5b6102a283836103ac565b905092915050565b600080600160008481526020019081526020016000205414159050919050565b600080600160008481526020019081526020016000205490506000811180156102f857506000805490508111155b156103a1576000805490508114610365576000806001600080549050038154811061031f57fe5b90600052602060002001549050806000600184038154811061033d57fe5b9060005260206000200181905550816001600083815260200190815260200160002081905550505b600160008181805490500391508161037d9190610700565b506000600160008581526020019081526020016000208190555060019150506103a7565b60009150505b919050565b6000806001905060008090505b8351811015610683578381815181106103ce57fe5b6020026020010151851415610462577fcc7365305ae5f16c463d1383713d699f43c5548bbda5537ee61373ceb9aaf213600085838151811061040c57fe5b60200260200101516040518083151515158152602001828152602001806020018281038252602f815260200180610773602f9139604001935050505060405180910390a181801561045b575060005b9150610676565b61047e84828151811061047157fe5b60200260200101516102aa565b15610525577fcc7365305ae5f16c463d1383713d699f43c5548bbda5537ee61373ceb9aaf21360008583815181106104b257fe5b60200260200101516040518083151515158152602001828152602001806020018281038252601b8152602001807f4163636f756e7420697320616c72656164792061204d656d6265720000000000815250602001935050505060405180910390a181801561051e575060005b9150610675565b600061054385838151811061053657fe5b602002602001015161068e565b9050606081610587576040518060400160405280601b81526020017f4163636f756e7420697320616c72656164792061204d656d62657200000000008152506105a1565b604051806060016040528060218152602001610752602191395b90507fcc7365305ae5f16c463d1383713d699f43c5548bbda5537ee61373ceb9aaf213828785815181106105d157fe5b602002602001015183604051808415151515815260200183815260200180602001828103825283818151815260200191508051906020019080838360005b8381101561062a57808201518184015260208101905061060f565b50505050905090810190601f1680156106575780820380516001836020036101000a031916815260200191505b5094505050505060405180910390a18380156106705750815b935050505b5b80806001019150506103b9565b508091505092915050565b600080600160008481526020019081526020016000205414156106f657600082908060018154018082558091505090600182039060005260206000200160009091929091909150556001600084815260200190815260200160002081905550600190506106fb565b600090505b919050565b81548183558181111561072757818360005260206000209182019101610726919061072c565b5b505050565b61074e91905b8082111561074a576000816000905550600101610732565b5090565b9056fe4d656d626572206163636f756e74206164646564207375636365737366756c6c79416464696e67206f776e206163636f756e742061732061204d656d626572206973206e6f74207065726d6974746564a265627a7a72315820a107512b70ab542d281dec98f617a21ec804e782f03f9f55043e8135e99372e864736f6c634300050c0032"
          );

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

    if (lastRootHash == EMPTY_ROOT_HASH) {
      // inject proxy
      final DefaultEvmAccount proxyPrecompile =
              privateWorldStateUpdater.createAccount(Address.PRIVACY_PROXY);
      final MutableAccount mutableProxyPrecompiled = proxyPrecompile.getMutable();
      // this is the code for the proxy which has no constructor
      mutableProxyPrecompiled.setCode(PROXY_PRECOMPILED_CODE);
      // manually set the management contract address so the proxy can trust it
      mutableProxyPrecompiled.setStorageValue(
              UInt256.ZERO, UInt256.fromBytes(Bytes32.leftPad(Address.ZERO)));
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
      LOG.trace(
          "Persisting private state {} for privacyGroup {}",
          disposablePrivateState.rootHash(),
          privacyGroupId);
      privateWorldStateUpdater.commit();
      disposablePrivateState.persist();

      final PrivateStateStorage.Updater privateStateUpdater = privateStateStorage.updater();

      updatePrivateBlockMetadata(
          messageFrame.getTransactionHash(),
          currentBlockHash,
          privacyGroupId,
          disposablePrivateState.rootHash(),
          privateStateUpdater);

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
          Bytes.of(
              result.getStatus() == PrivateTransactionProcessor.Result.Status.SUCCESSFUL ? 1 : 0));
      privateStateUpdater.putTransactionResult(txHash, result.getOutput());

      // TODO: this map could be passed through from @PrivacyBlockProcessor and saved once at the
      // end of block processing
      if (!privacyGroupHeadBlockMap.contains(Bytes32.wrap(privacyGroupId), currentBlockHash)) {
        privacyGroupHeadBlockMap.put(Bytes32.wrap(privacyGroupId), currentBlockHash);
        privateStateUpdater.putPrivacyGroupHeadBlockMap(
            currentBlockHash, new PrivacyGroupHeadBlockMap(privacyGroupHeadBlockMap));
      }
      privateStateUpdater.commit();
    }

    return result.getOutput();
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
        Bytes32.wrap(currentBlockHash.getByteArray()),
        Bytes32.wrap(privacyGroupId),
        privateBlockMetadata);
  }
}
