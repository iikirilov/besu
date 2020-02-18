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

import static java.util.Collections.singletonList;
import static java.util.Collections.singletonMap;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.hyperledger.besu.crypto.SECP256K1;
import org.hyperledger.besu.enclave.types.ReceiveResponse;
import org.hyperledger.besu.ethereum.chain.Blockchain;
import org.hyperledger.besu.ethereum.core.Address;
import org.hyperledger.besu.ethereum.core.BlockHeader;
import org.hyperledger.besu.ethereum.core.Hash;
import org.hyperledger.besu.ethereum.core.Transaction;
import org.hyperledger.besu.ethereum.core.Wei;
import org.hyperledger.besu.ethereum.privacy.storage.PrivacyGroupHeadBlockMap;
import org.hyperledger.besu.ethereum.privacy.storage.PrivateBlockMetadata;
import org.hyperledger.besu.ethereum.privacy.storage.PrivateStateStorage;
import org.hyperledger.besu.ethereum.privacy.storage.PrivateTransactionMetadata;
import org.hyperledger.besu.ethereum.rlp.RLP;

import java.math.BigInteger;
import java.util.List;
import java.util.Optional;

import com.google.common.collect.Lists;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.io.Base64;
import org.jetbrains.annotations.NotNull;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class OnChainPrivacyControllerTest {

  private static final String TRANSACTION_KEY = "93Ky7lXwFkMc7+ckoFgUMku5bpr9tz4zhmWmk9RlNng=";
  private static final SECP256K1.KeyPair KEY_PAIR =
      SECP256K1.KeyPair.create(
          SECP256K1.PrivateKey.create(
              new BigInteger(
                  "8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63", 16)));

  private static final String ENCLAVE_PUBLIC_KEY = "A1aVtMxLCUHmBVHXoZzzBgPbW/wj5axDpW9X8l91SGo=";
  private static final String PRIVACY_GROUP_ID = "DyAOiF/ynpc+JXa2YAGB0bCitSlOMNm+ShmB/7M6C4w=";

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

  private static final PrivateTransaction VALID_PRIVATE_TRANSACTION =
      new PrivateTransaction(
          0L,
          Wei.of(1),
          21000L,
          Optional.of(
              Address.wrap(Bytes.fromHexString("0x095e7baea6a6c7c4c2dfeb977efac326af552d87"))),
          Wei.of(
              new BigInteger(
                  "115792089237316195423570985008687907853269984665640564039457584007913129639935")),
          SECP256K1.Signature.create(
              new BigInteger(
                  "32886959230931919120748662916110619501838190146643992583529828535682419954515"),
              new BigInteger(
                  "14473701025599600909210599917245952381483216609124029382871721729679842002948"),
              Byte.valueOf("0")),
          Bytes.fromHexString("0x"),
          Address.wrap(Bytes.fromHexString("0x83db8f1f96dbf773d2d719f70dc89e5c772cddbc")),
          Optional.empty(),
          Bytes.fromBase64String("A1aVtMxLCUHmBVHXoZzzBgPbW/wj5axDpW9X8l91SGo="),
          Optional.of(
              Lists.newArrayList(
                  Bytes.fromBase64String("A1aVtMxLCUHmBVHXoZzzBgPbW/wj5axDpW9X8l91SGo="),
                  Bytes.fromBase64String("Ko2bVqD+nNlNYL5EE7y3IdOnviftjiizpjRt+HTuFBs="))),
          Optional.empty(),
          Restriction.RESTRICTED);

  private static final PrivateTransactionMetadata PRIVATE_TRANSACTION_METADATA =
      new PrivateTransactionMetadata(Hash.ZERO, Hash.ZERO, publicStateHash);
  private static final PrivateTransactionWithMetadata PRIVATE_TRANSACTION_WITH_METADATA =
      new PrivateTransactionWithMetadata(VALID_PRIVATE_TRANSACTION, PRIVATE_TRANSACTION_METADATA);

  private OnChainPrivacyController onChainPrivacyController;
  private Blockchain blockchain;
  private PrivateStateStorage privateStateStorage;
  private PrivacyController privacyController;

  @Before
  public void setUp() {
    blockchain = mock(Blockchain.class);
    privateStateStorage = mock(PrivateStateStorage.class);
    privacyController = mock(PrivacyController.class);

    onChainPrivacyController =
        new OnChainPrivacyController(blockchain, privateStateStorage, privacyController);
  }

  @Test
  public void canRetrievePrivateTransactions() {
    when(blockchain.getTransactionByHash(any(Hash.class)))
        .thenReturn(Optional.of(PUBLIC_TRANSACTION));
    when(privacyController.retrieveTransaction(any(String.class), any(String.class)))
        .thenReturn(
            new ReceiveResponse(
                RLP.encode(VALID_PRIVATE_TRANSACTION::writeTo).toBase64String().getBytes(),
                "",
                ""));

    final List<PrivateTransactionWithMetadata> privateTransactionWithMetadataList =
        onChainPrivacyController.retrievePrivateTransactions(
            singletonList(new PrivateTransactionMetadata(Hash.ZERO, Hash.ZERO, publicStateHash)),
            "");

    assertThat(privateTransactionWithMetadataList.size()).isEqualTo(1);
    assertThat(privateTransactionWithMetadataList.get(0))
        .isEqualTo(PRIVATE_TRANSACTION_WITH_METADATA);
  }

  @Test
  public void canSerializeAddToGroupPayload() {
    final Bytes expected =
        Bytes.fromHexString(
            "0xf90138f90135f8ef800182520894095e7baea6a6c7c4c2dfeb977efac326af552d87a0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff801ba048b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a36649353a01fffd310ac743f371de3b9f7f9cb56c0b28ad43601b4ab949f53faa07bd2c804a0035695b4cc4b0941e60551d7a19cf30603db5bfc23e5ac43a56f57f25f75486af842a0035695b4cc4b0941e60551d7a19cf30603db5bfc23e5ac43a56f57f25f75486aa02a8d9b56a0fe9cd94d60be4413bcb721d3a7be27ed8e28b3a6346df874ee141b8a72657374726963746564f842a00000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000");

    final Bytes encoded =
        onChainPrivacyController.serializeAddToGroupPayload(
            singletonList(PRIVATE_TRANSACTION_WITH_METADATA));

    assertThat(encoded).isEqualTo(expected);
  }

  @Test
  public void canDeserializeAddToGroupPayload() {
    final Bytes encoded =
        onChainPrivacyController.serializeAddToGroupPayload(
            singletonList(PRIVATE_TRANSACTION_WITH_METADATA));

    final List<PrivateTransactionWithMetadata> privateTransactionWithMetadataList =
        onChainPrivacyController.deserializeAddToGroupPayload(encoded);

    assertThat(privateTransactionWithMetadataList)
        .isEqualTo(singletonList(PRIVATE_TRANSACTION_WITH_METADATA));
  }

  @Test
  public void buildsEmptyTransactionListWhenNoGroupIsTracked() {
    when(blockchain.getChainHeadHash()).thenReturn(Hash.ZERO);
    when(privateStateStorage.getPrivacyGroupHeadBlockMap(any(Hash.class)))
        .thenReturn(Optional.empty());
    final List<PrivateTransactionMetadata> privacyGroupMarkerTransactions =
        onChainPrivacyController.buildTransactionMetadataList(
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
    final List<PrivateTransactionMetadata> privateTransactionMetadataList =
        onChainPrivacyController.buildTransactionMetadataList(
            Bytes32.wrap(Bytes.fromBase64String(PRIVACY_GROUP_ID)));

    assertThat(privateTransactionMetadataList.size()).isEqualTo(0);
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
                    singletonList(
                        new PrivateTransactionMetadata(Hash.ZERO, Hash.ZERO, publicStateHash)))));
    when(blockchain.getBlockHeader(any(Hash.class)))
        .thenReturn(buildBlockHeaderWithParentHash(null));
    final List<PrivateTransactionMetadata> privateTransactionMetadataList =
        onChainPrivacyController.buildTransactionMetadataList(
            Bytes32.wrap(Bytes.fromBase64String(PRIVACY_GROUP_ID)));

    assertThat(privateTransactionMetadataList.size()).isEqualTo(1);
    assertThat(privateTransactionMetadataList.get(0)).isEqualTo(PRIVATE_TRANSACTION_METADATA);
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
                singletonList(
                    new PrivateTransactionMetadata(Hash.ZERO, Hash.ZERO, publicStateHash))));
    when(privateStateStorage.getPrivacyGroupHeadBlockMap(any(Hash.class)))
        .thenReturn(privacyGroupHeadBlockMap, privacyGroupHeadBlockMap, Optional.empty());
    when(privateStateStorage.getPrivateBlockMetadata(any(Bytes32.class), any(Bytes32.class)))
        .thenReturn(privateBlockMetadata, privateBlockMetadata);
    when(blockchain.getBlockHeader(any(Hash.class)))
        .thenReturn(buildBlockHeaderWithParentHash(Hash.ZERO));

    final List<PrivateTransactionMetadata> privateTransactionMetadataList =
        onChainPrivacyController.buildTransactionMetadataList(
            Bytes32.wrap(Bytes.fromBase64String(PRIVACY_GROUP_ID)));

    assertThat(privateTransactionMetadataList.size()).isEqualTo(2);
    assertThat(privateTransactionMetadataList.get(0)).isEqualTo(PRIVATE_TRANSACTION_METADATA);
    assertThat(privateTransactionMetadataList.get(1)).isEqualTo(PRIVATE_TRANSACTION_METADATA);
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
}
