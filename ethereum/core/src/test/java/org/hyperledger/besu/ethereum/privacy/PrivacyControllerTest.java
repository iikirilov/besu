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
package org.hyperledger.besu.ethereum.privacy;

import static com.google.common.collect.Lists.newArrayList;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static java.util.Collections.singletonMap;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.hyperledger.besu.ethereum.mainnet.TransactionValidator.TransactionInvalidReason.INCORRECT_PRIVATE_NONCE;
import static org.hyperledger.besu.ethereum.mainnet.TransactionValidator.TransactionInvalidReason.PRIVATE_NONCE_TOO_LOW;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.hyperledger.besu.crypto.SECP256K1;
import org.hyperledger.besu.crypto.SECP256K1.KeyPair;
import org.hyperledger.besu.enclave.Enclave;
import org.hyperledger.besu.enclave.EnclaveServerException;
import org.hyperledger.besu.enclave.types.PrivacyGroup;
import org.hyperledger.besu.enclave.types.PrivacyGroup.Type;
import org.hyperledger.besu.enclave.types.ReceiveResponse;
import org.hyperledger.besu.enclave.types.SendResponse;
import org.hyperledger.besu.ethereum.chain.Blockchain;
import org.hyperledger.besu.ethereum.core.Address;
import org.hyperledger.besu.ethereum.core.BlockHeader;
import org.hyperledger.besu.ethereum.core.Hash;
import org.hyperledger.besu.ethereum.core.Transaction;
import org.hyperledger.besu.ethereum.core.Wei;
import org.hyperledger.besu.ethereum.mainnet.TransactionProcessor;
import org.hyperledger.besu.ethereum.mainnet.TransactionValidator.TransactionInvalidReason;
import org.hyperledger.besu.ethereum.mainnet.ValidationResult;
import org.hyperledger.besu.ethereum.privacy.markertransaction.FixedKeySigningPrivateMarkerTransactionFactory;
import org.hyperledger.besu.ethereum.privacy.storage.PrivacyGroupHeadBlockMap;
import org.hyperledger.besu.ethereum.privacy.storage.PrivateBlockMetadata;
import org.hyperledger.besu.ethereum.privacy.storage.PrivateStateStorage;
import org.hyperledger.besu.ethereum.privacy.storage.PrivateTransactionMetadata;
import org.hyperledger.orion.testutil.OrionKeyUtils;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.io.Base64;
import org.jetbrains.annotations.NotNull;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class PrivacyControllerTest {

  private static final String TRANSACTION_KEY = "93Ky7lXwFkMc7+ckoFgUMku5bpr9tz4zhmWmk9RlNng=";
  private static final KeyPair KEY_PAIR =
      KeyPair.create(
          SECP256K1.PrivateKey.create(
              new BigInteger(
                  "8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63", 16)));
  private static final byte[] PAYLOAD = new byte[0];
  private static final List<String> PRIVACY_GROUP_ADDRESSES = newArrayList("8f2a", "fb23");
  private static final String PRIVACY_GROUP_NAME = "pg_name";
  private static final String PRIVACY_GROUP_DESCRIPTION = "pg_desc";
  private static final String ENCLAVE_PUBLIC_KEY = "A1aVtMxLCUHmBVHXoZzzBgPbW/wj5axDpW9X8l91SGo=";
  private static final String ENCLAVE_KEY2 = "Ko2bVqD+nNlNYL5EE7y3IdOnviftjiizpjRt+HTuFBs=";
  private static final String PRIVACY_GROUP_ID = "DyAOiF/ynpc+JXa2YAGB0bCitSlOMNm+ShmB/7M6C4w=";

  private PrivacyController privacyController;
  private PrivacyController brokenPrivacyController;
  private PrivateTransactionValidator privateTransactionValidator;
  private Enclave enclave;
  private String enclavePublicKey;
  private PrivateNonceProvider privateNonceProvider;
  private PrivateTransactionSimulator privateTransactionSimulator;
  private Blockchain blockchain;
  private PrivateStateStorage privateStateStorage;

  private static final Transaction PUBLIC_TRANSACTION =
      Transaction.builder()
          .nonce(0)
          .gasPrice(Wei.of(1000))
          .gasLimit(3000000)
          .to(Address.fromHexString("0x627306090abab3a6e1400e9345bc60c78a8bef57"))
          .value(Wei.ZERO)
          .payload(Base64.decode(TRANSACTION_KEY))
          .sender(Address.fromHexString("0xfe3b557e8fb62b89f4916b721be55ceb828dbd73"))
          .chainId(BigInteger.valueOf(2018))
          .signAndBuild(KEY_PAIR);

  private Enclave mockEnclave() {
    Enclave mockEnclave = mock(Enclave.class);
    SendResponse response = new SendResponse(TRANSACTION_KEY);
    ReceiveResponse receiveResponse = new ReceiveResponse(new byte[0], PRIVACY_GROUP_ID, null);
    when(mockEnclave.send(anyString(), anyString(), anyList())).thenReturn(response);
    when(mockEnclave.send(anyString(), anyString(), anyString())).thenReturn(response);
    when(mockEnclave.receive(any(), any())).thenReturn(receiveResponse);
    return mockEnclave;
  }

  private Enclave brokenMockEnclave() {
    Enclave mockEnclave = mock(Enclave.class);
    when(mockEnclave.send(anyString(), anyString(), anyList()))
        .thenThrow(EnclaveServerException.class);
    return mockEnclave;
  }

  private PrivateTransactionValidator mockPrivateTransactionValidator() {
    PrivateTransactionValidator validator = mock(PrivateTransactionValidator.class);
    when(validator.validate(any(), any())).thenReturn(ValidationResult.valid());
    return validator;
  }

  @Before
  public void setUp() throws Exception {
    blockchain = mock(Blockchain.class);
    privateTransactionSimulator = mock(PrivateTransactionSimulator.class);
    privateStateStorage = mock(PrivateStateStorage.class);
    privateNonceProvider = mock(ChainHeadPrivateNonceProvider.class);

    enclavePublicKey = OrionKeyUtils.loadKey("orion_key_0.pub");
    privateTransactionValidator = mockPrivateTransactionValidator();
    enclave = mockEnclave();

    privacyController =
        new PrivacyController(
            blockchain,
            enclave,
            privateTransactionValidator,
            new FixedKeySigningPrivateMarkerTransactionFactory(
                Address.DEFAULT_PRIVACY, (address) -> 0, KEY_PAIR),
            privateNonceProvider,
            privateTransactionSimulator,
            privateStateStorage);
    brokenPrivacyController =
        new PrivacyController(
            blockchain,
            brokenMockEnclave(),
            privateTransactionValidator,
            new FixedKeySigningPrivateMarkerTransactionFactory(
                Address.DEFAULT_PRIVACY, (address) -> 0, KEY_PAIR),
            privateNonceProvider,
            privateTransactionSimulator,
            privateStateStorage);
  }

  @Test
  public void sendsValidLegacyTransaction() {

    final PrivateTransaction transaction = buildLegacyPrivateTransaction(1);

    final SendTransactionResponse sendTransactionResponse =
        privacyController.sendTransaction(transaction, ENCLAVE_PUBLIC_KEY);

    final ValidationResult<TransactionInvalidReason> validationResult =
        privacyController.validatePrivateTransaction(
            transaction, sendTransactionResponse.getPrivacyGroupId(), ENCLAVE_PUBLIC_KEY);

    final Transaction markerTransaction =
        privacyController.createPrivacyMarkerTransaction(
            sendTransactionResponse.getEnclaveKey(), transaction);

    assertThat(validationResult).isEqualTo(ValidationResult.valid());
    assertThat(markerTransaction.contractAddress()).isEqualTo(PUBLIC_TRANSACTION.contractAddress());
    assertThat(markerTransaction.getPayload()).isEqualTo(PUBLIC_TRANSACTION.getPayload());
    assertThat(markerTransaction.getNonce()).isEqualTo(PUBLIC_TRANSACTION.getNonce());
    assertThat(markerTransaction.getSender()).isEqualTo(PUBLIC_TRANSACTION.getSender());
    assertThat(markerTransaction.getValue()).isEqualTo(PUBLIC_TRANSACTION.getValue());
    verify(enclave)
        .send(anyString(), eq(ENCLAVE_PUBLIC_KEY), eq(List.of(ENCLAVE_PUBLIC_KEY, ENCLAVE_KEY2)));
  }

  @Test
  public void sendValidBesuTransaction() {

    final PrivateTransaction transaction = buildBesuPrivateTransaction(1);

    when(enclave.retrievePrivacyGroup(any(String.class)))
        .thenReturn(new PrivacyGroup("", Type.PANTHEON, "", "", emptyList()));

    final SendTransactionResponse sendTransactionResponse =
        privacyController.sendTransaction(transaction, ENCLAVE_PUBLIC_KEY);

    final ValidationResult<TransactionInvalidReason> validationResult =
        privacyController.validatePrivateTransaction(
            transaction,
            transaction.getPrivacyGroupId().get().toBase64String(),
            ENCLAVE_PUBLIC_KEY);

    final Transaction markerTransaction =
        privacyController.createPrivacyMarkerTransaction(
            sendTransactionResponse.getEnclaveKey(), transaction);

    assertThat(validationResult).isEqualTo(ValidationResult.valid());
    assertThat(markerTransaction.contractAddress()).isEqualTo(PUBLIC_TRANSACTION.contractAddress());
    assertThat(markerTransaction.getPayload()).isEqualTo(PUBLIC_TRANSACTION.getPayload());
    assertThat(markerTransaction.getNonce()).isEqualTo(PUBLIC_TRANSACTION.getNonce());
    assertThat(markerTransaction.getSender()).isEqualTo(PUBLIC_TRANSACTION.getSender());
    assertThat(markerTransaction.getValue()).isEqualTo(PUBLIC_TRANSACTION.getValue());
    verify(enclave).send(anyString(), eq(ENCLAVE_PUBLIC_KEY), eq(PRIVACY_GROUP_ID));
  }

  @Test
  public void findOnChainPrivacyGroups() {
    final List<String> privacyGroupAddresses = newArrayList(ENCLAVE_PUBLIC_KEY, ENCLAVE_KEY2);

    final PrivacyGroup privacyGroup =
        new PrivacyGroup(PRIVACY_GROUP_ID, Type.PANTHEON, "", "", privacyGroupAddresses);

    final PrivacyGroupHeadBlockMap privacyGroupHeadBlockMap =
        new PrivacyGroupHeadBlockMap(
            Map.of(Bytes32.wrap(Bytes.fromBase64String(PRIVACY_GROUP_ID)), Hash.ZERO));
    when(privateStateStorage.getPrivacyGroupHeadBlockMap(any()))
        .thenReturn(Optional.of(privacyGroupHeadBlockMap));
    when(privateTransactionSimulator.process(any(), any(), any()))
        .thenReturn(
            Optional.of(
                new PrivateTransactionProcessor.Result(
                    TransactionProcessor.Result.Status.SUCCESSFUL,
                    emptyList(),
                    0,
                    Bytes.fromHexString(
                        "0x0000000000000000000000000000000000000000000000000000000000000020"
                            + "0000000000000000000000000000000000000000000000000000000000000002"
                            + Bytes.fromBase64String(ENCLAVE_PUBLIC_KEY).toUnprefixedHexString()
                            + Bytes.fromBase64String(ENCLAVE_KEY2).toUnprefixedHexString()),
                    ValidationResult.valid(),
                    Optional.empty())));

    final List<PrivacyGroup> privacyGroups =
        privacyController.findOnChainPrivacyGroup(privacyGroupAddresses, ENCLAVE_PUBLIC_KEY);
    assertThat(privacyGroups).hasSize(1);
    assertThat(privacyGroups.get(0)).isEqualToComparingFieldByField(privacyGroup);
    verify(privateStateStorage).getPrivacyGroupHeadBlockMap(any());
    verify(privateTransactionSimulator).process(any(), any(), any());
  }

  @Test
  public void sendTransactionWhenEnclaveFailsThrowsEnclaveError() {
    assertThatExceptionOfType(EnclaveServerException.class)
        .isThrownBy(
            () ->
                brokenPrivacyController.sendTransaction(
                    buildLegacyPrivateTransaction(), ENCLAVE_PUBLIC_KEY));
  }

  @Test
  public void validateTransactionWithTooLowNonceReturnsError() {
    when(privateTransactionValidator.validate(any(), any()))
        .thenReturn(ValidationResult.invalid(PRIVATE_NONCE_TOO_LOW));

    final PrivateTransaction transaction = buildLegacyPrivateTransaction(0);
    final SendTransactionResponse sendTransactionResponse =
        privacyController.sendTransaction(transaction, ENCLAVE_PUBLIC_KEY);
    final ValidationResult<TransactionInvalidReason> validationResult =
        privacyController.validatePrivateTransaction(
            transaction, sendTransactionResponse.getPrivacyGroupId(), ENCLAVE_PUBLIC_KEY);
    assertThat(validationResult).isEqualTo(ValidationResult.invalid(PRIVATE_NONCE_TOO_LOW));
  }

  @Test
  public void validateTransactionWithIncorrectNonceReturnsError() {
    when(privateTransactionValidator.validate(any(), any()))
        .thenReturn(ValidationResult.invalid(INCORRECT_PRIVATE_NONCE));

    final PrivateTransaction transaction = buildLegacyPrivateTransaction(2);

    final SendTransactionResponse sendTransactionResponse =
        privacyController.sendTransaction(transaction, ENCLAVE_PUBLIC_KEY);
    final ValidationResult<TransactionInvalidReason> validationResult =
        privacyController.validatePrivateTransaction(
            transaction, sendTransactionResponse.getPrivacyGroupId(), ENCLAVE_PUBLIC_KEY);
    assertThat(validationResult).isEqualTo(ValidationResult.invalid(INCORRECT_PRIVATE_NONCE));
  }

  @Test
  public void retrievesTransaction() {
    when(enclave.receive(anyString(), anyString()))
        .thenReturn(new ReceiveResponse(PAYLOAD, PRIVACY_GROUP_ID, null));

    final ReceiveResponse receiveResponse =
        privacyController.retrieveTransaction(TRANSACTION_KEY, ENCLAVE_PUBLIC_KEY);

    assertThat(receiveResponse.getPayload()).isEqualTo(PAYLOAD);
    assertThat(receiveResponse.getPrivacyGroupId()).isEqualTo(PRIVACY_GROUP_ID);
    verify(enclave).receive(TRANSACTION_KEY, enclavePublicKey);
  }

  @Test
  public void buildsEmptyTransactionListWhenNoGroupIsTracked() {
    when(blockchain.getChainHeadHash()).thenReturn(Hash.ZERO);
    when(privateStateStorage.getPrivacyGroupHeadBlockMap(any(Hash.class)))
        .thenReturn(Optional.empty());
    final List<Hash> privacyGroupMarkerTransactions =
        privacyController.buildTransactionList(
            Bytes32.wrap(Bytes.fromBase64String(PRIVACY_GROUP_ID)));

    assertThat(privacyGroupMarkerTransactions.size()).isEqualTo(0);
  }

  @Test
  public void buildsEmptyTransactionListWhenRequestedGroupIsNotTracked() {
    when(blockchain.getChainHeadHash()).thenReturn(Hash.ZERO);
    when(privateStateStorage.getPrivacyGroupHeadBlockMap(any(Hash.class)))
        .thenReturn(
            Optional.of(
                new PrivacyGroupHeadBlockMap(
                    singletonMap(
                        Bytes32.wrap(Bytes.fromBase64String(ENCLAVE_PUBLIC_KEY)), Hash.ZERO))));
    final List<Hash> privacyGroupMarkerTransactions =
        privacyController.buildTransactionList(
            Bytes32.wrap(Bytes.fromBase64String(PRIVACY_GROUP_ID)));

    assertThat(privacyGroupMarkerTransactions.size()).isEqualTo(0);
    verify(privateStateStorage).getPrivacyGroupHeadBlockMap(Hash.ZERO);
  }

  @Test
  public void buildsTransactionListWhenRequestedGroupHasTransaction() {
    when(blockchain.getChainHeadHash()).thenReturn(Hash.ZERO);
    when(privateStateStorage.getPrivacyGroupHeadBlockMap(any(Hash.class)))
        .thenReturn(
            Optional.of(
                new PrivacyGroupHeadBlockMap(
                    singletonMap(
                        Bytes32.wrap(Bytes.fromBase64String(PRIVACY_GROUP_ID)), Hash.ZERO))));
    when(privateStateStorage.getPrivateBlockMetadata(any(Bytes32.class), any(Bytes32.class)))
        .thenReturn(
            Optional.of(
                new PrivateBlockMetadata(
                    singletonList(new PrivateTransactionMetadata(Hash.ZERO, Hash.ZERO)))));
    when(blockchain.getBlockHeader(any(Hash.class)))
        .thenReturn(buildBlockHeaderWithParentHash(null));
    final List<Hash> privacyGroupMarkerTransactions =
        privacyController.buildTransactionList(
            Bytes32.wrap(Bytes.fromBase64String(PRIVACY_GROUP_ID)));

    assertThat(privacyGroupMarkerTransactions.size()).isEqualTo(1);
    assertThat(privacyGroupMarkerTransactions.get(0)).isEqualTo(Hash.ZERO);
    verify(privateStateStorage).getPrivacyGroupHeadBlockMap(Hash.ZERO);
    verify(privateStateStorage)
        .getPrivateBlockMetadata(
            any(Bytes32.class), eq(Bytes32.wrap(Bytes.fromBase64String(PRIVACY_GROUP_ID))));
  }

  @SuppressWarnings("unchecked")
  @Test
  public void buildsTransactionListWhenRequestedGroupHasTransactions() {
    when(blockchain.getChainHeadHash()).thenReturn(Hash.ZERO);
    final Optional<PrivacyGroupHeadBlockMap> privacyGroupHeadBlockMap =
        Optional.of(
            new PrivacyGroupHeadBlockMap(
                singletonMap(Bytes32.wrap(Bytes.fromBase64String(PRIVACY_GROUP_ID)), Hash.ZERO)));
    final Optional<PrivateBlockMetadata> privateBlockMetadata =
        Optional.of(
            new PrivateBlockMetadata(
                singletonList(new PrivateTransactionMetadata(Hash.ZERO, Hash.ZERO))));
    when(privateStateStorage.getPrivacyGroupHeadBlockMap(any(Hash.class)))
        .thenReturn(privacyGroupHeadBlockMap, privacyGroupHeadBlockMap, Optional.empty());
    when(privateStateStorage.getPrivateBlockMetadata(any(Bytes32.class), any(Bytes32.class)))
        .thenReturn(privateBlockMetadata, privateBlockMetadata);
    when(blockchain.getBlockHeader(any(Hash.class)))
        .thenReturn(buildBlockHeaderWithParentHash(Hash.ZERO));

    final List<Hash> privacyGroupMarkerTransactions =
        privacyController.buildTransactionList(
            Bytes32.wrap(Bytes.fromBase64String(PRIVACY_GROUP_ID)));

    assertThat(privacyGroupMarkerTransactions.size()).isEqualTo(2);
    assertThat(privacyGroupMarkerTransactions.get(0)).isEqualTo(Hash.ZERO);
    assertThat(privacyGroupMarkerTransactions.get(1)).isEqualTo(Hash.ZERO);
    verify(privateStateStorage, times(3)).getPrivacyGroupHeadBlockMap(Hash.ZERO);
    verify(privateStateStorage, times(2))
        .getPrivateBlockMetadata(
            any(Bytes32.class), eq(Bytes32.wrap(Bytes.fromBase64String(PRIVACY_GROUP_ID))));
  }

  @NotNull
  private Optional<BlockHeader> buildBlockHeaderWithParentHash(final Hash parentHash) {
    return Optional.of(
        new BlockHeader(
            parentHash, null, null, null, null, null, null, null, 0, 0, 0, 0, null, null, 0, null));
  }

  @Test
  public void createsPrivacyGroup() {
    final PrivacyGroup enclavePrivacyGroupResponse =
        new PrivacyGroup(
            PRIVACY_GROUP_ID,
            Type.PANTHEON,
            PRIVACY_GROUP_NAME,
            PRIVACY_GROUP_DESCRIPTION,
            PRIVACY_GROUP_ADDRESSES);
    when(enclave.createPrivacyGroup(any(), any(), any(), any()))
        .thenReturn(enclavePrivacyGroupResponse);

    final PrivacyGroup privacyGroup =
        privacyController.createPrivacyGroup(
            PRIVACY_GROUP_ADDRESSES,
            PRIVACY_GROUP_NAME,
            PRIVACY_GROUP_DESCRIPTION,
            ENCLAVE_PUBLIC_KEY);

    assertThat(privacyGroup).isEqualToComparingFieldByField(enclavePrivacyGroupResponse);
    verify(enclave)
        .createPrivacyGroup(
            PRIVACY_GROUP_ADDRESSES,
            enclavePublicKey,
            PRIVACY_GROUP_NAME,
            PRIVACY_GROUP_DESCRIPTION);
  }

  @Test
  public void deletesPrivacyGroup() {
    when(enclave.deletePrivacyGroup(anyString(), anyString())).thenReturn(PRIVACY_GROUP_ID);

    final String deletedPrivacyGroupId =
        privacyController.deletePrivacyGroup(PRIVACY_GROUP_ID, ENCLAVE_PUBLIC_KEY);

    assertThat(deletedPrivacyGroupId).isEqualTo(PRIVACY_GROUP_ID);
    verify(enclave).deletePrivacyGroup(PRIVACY_GROUP_ID, enclavePublicKey);
  }

  @Test
  public void findsPrivacyGroup() {
    final PrivacyGroup privacyGroup =
        new PrivacyGroup(
            PRIVACY_GROUP_ID,
            Type.PANTHEON,
            PRIVACY_GROUP_NAME,
            PRIVACY_GROUP_DESCRIPTION,
            PRIVACY_GROUP_ADDRESSES);
    when(enclave.findPrivacyGroup(any())).thenReturn(new PrivacyGroup[] {privacyGroup});

    final PrivacyGroup[] privacyGroups =
        privacyController.findPrivacyGroup(PRIVACY_GROUP_ADDRESSES, ENCLAVE_PUBLIC_KEY);
    assertThat(privacyGroups).hasSize(1);
    assertThat(privacyGroups[0]).isEqualToComparingFieldByField(privacyGroup);
    verify(enclave).findPrivacyGroup(PRIVACY_GROUP_ADDRESSES);
  }

  @Test
  public void determinesNonceForEeaRequest() {
    final Address address = Address.fromHexString("55");
    final long reportedNonce = 8L;
    final PrivacyGroup[] returnedGroups =
        new PrivacyGroup[] {
          new PrivacyGroup(
              PRIVACY_GROUP_ID, Type.LEGACY, "Group1_Name", "Group1_Desc", emptyList()),
        };

    when(enclave.findPrivacyGroup(any())).thenReturn(returnedGroups);
    when(privateNonceProvider.getNonce(any(Address.class), any(Bytes32.class))).thenReturn(8L);

    final long nonce =
        privacyController.determineNonce(
            ENCLAVE_PUBLIC_KEY, new String[] {ENCLAVE_KEY2}, address, ENCLAVE_PUBLIC_KEY);

    assertThat(nonce).isEqualTo(reportedNonce);
    verify(enclave)
        .findPrivacyGroup(
            argThat((m) -> m.containsAll(newArrayList(ENCLAVE_PUBLIC_KEY, ENCLAVE_KEY2))));
  }

  @Test
  public void determineNonceForEeaRequestWithNoMatchingGroupReturnsZero() {
    final long reportedNonce = 0L;
    final Address address = Address.fromHexString("55");
    final PrivacyGroup[] returnedGroups = new PrivacyGroup[0];

    when(enclave.findPrivacyGroup(any())).thenReturn(returnedGroups);

    final long nonce =
        privacyController.determineNonce(
            "privateFrom", new String[] {"first", "second"}, address, ENCLAVE_PUBLIC_KEY);

    assertThat(nonce).isEqualTo(reportedNonce);
    verify(enclave)
        .findPrivacyGroup(
            argThat((m) -> m.containsAll(newArrayList("first", "second", "privateFrom"))));
  }

  @Test
  public void determineNonceForEeaRequestWithMoreThanOneMatchingGroupThrowsException() {
    final Address address = Address.fromHexString("55");
    final PrivacyGroup[] returnedGroups =
        new PrivacyGroup[] {
          new PrivacyGroup("Group1", Type.LEGACY, "Group1_Name", "Group1_Desc", emptyList()),
          new PrivacyGroup("Group2", Type.LEGACY, "Group2_Name", "Group2_Desc", emptyList()),
        };

    when(enclave.findPrivacyGroup(any())).thenReturn(returnedGroups);

    assertThatExceptionOfType(RuntimeException.class)
        .isThrownBy(
            () ->
                privacyController.determineNonce(
                    "privateFrom", new String[] {"first", "second"}, address, ENCLAVE_PUBLIC_KEY));
  }

  private static PrivateTransaction buildLegacyPrivateTransaction() {
    return buildLegacyPrivateTransaction(0);
  }

  private static PrivateTransaction buildLegacyPrivateTransaction(final long nonce) {
    return buildPrivateTransaction(nonce)
        .privateFrom(Base64.decode(ENCLAVE_PUBLIC_KEY))
        .privateFor(newArrayList(Base64.decode(ENCLAVE_PUBLIC_KEY), Base64.decode(ENCLAVE_KEY2)))
        .signAndBuild(KEY_PAIR);
  }

  private static PrivateTransaction buildBesuPrivateTransaction(final long nonce) {

    return buildPrivateTransaction(nonce)
        .privateFrom(Bytes.fromBase64String(ENCLAVE_PUBLIC_KEY))
        .privacyGroupId(Bytes.fromBase64String(PRIVACY_GROUP_ID))
        .signAndBuild(KEY_PAIR);
  }

  private static PrivateTransaction.Builder buildPrivateTransaction(final long nonce) {
    return PrivateTransaction.builder()
        .nonce(nonce)
        .gasPrice(Wei.of(1000))
        .gasLimit(3000000)
        .to(Address.fromHexString("0x627306090abab3a6e1400e9345bc60c78a8bef57"))
        .value(Wei.ZERO)
        .payload(Bytes.fromHexString("0x"))
        .sender(Address.fromHexString("0xfe3b557e8fb62b89f4916b721be55ceb828dbd73"))
        .chainId(BigInteger.valueOf(2018))
        .restriction(Restriction.RESTRICTED);
  }
}
