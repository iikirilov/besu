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
package org.hyperledger.besu.ethereum.privacy.privatetransaction;

import org.hyperledger.besu.crypto.SECP256K1.KeyPair;
import org.hyperledger.besu.ethereum.core.Address;
import org.hyperledger.besu.ethereum.core.Wei;
import org.hyperledger.besu.ethereum.privacy.PrivateTransaction;
import org.hyperledger.besu.ethereum.rlp.BytesValueRLPOutput;
import org.hyperledger.besu.ethereum.rlp.RLP;
import org.hyperledger.besu.util.bytes.BytesValue;

import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;

public abstract class GroupCreationTransactionFactory {

  private final static BytesValue DEFAULT_MANAGEMENT_CONTRACT_CODE = BytesValue.fromHexString("");
  private final BytesValue manageManagementContractBinary;

  public GroupCreationTransactionFactory() {
    this (DEFAULT_MANAGEMENT_CONTRACT_CODE);
  }

  public GroupCreationTransactionFactory(final BytesValue manageManagementContractBinary) {
    this.manageManagementContractBinary = manageManagementContractBinary;
  }

  public abstract PrivateTransaction create(
      final BytesValue privacyGroupId,
      final BytesValue privateFrom,
      final List<BytesValue> participants,
      final String name,
      final String description);

  protected PrivateTransaction create(
      final BytesValue privateFrom,
      final BytesValue privacyGroupId,
      final List<BytesValue> participants,
      final String name,
      final String description,
      final long nonce,
      final KeyPair signingKey) {

    // FIXME
    final BytesValueRLPOutput bytesValueRLPOutput = new BytesValueRLPOutput();
    final BytesValueRLPOutput bytesValueRLPOutput1 = new BytesValueRLPOutput();
    bytesValueRLPOutput1.startList();
    participants.forEach(bytesValueRLPOutput1::writeBytesValue);
    bytesValueRLPOutput1.endList();
    bytesValueRLPOutput.startList();
    bytesValueRLPOutput.writeBytesValue(privacyGroupId);
    bytesValueRLPOutput.writeBytesValue(privateFrom);
    bytesValueRLPOutput.writeRLP(bytesValueRLPOutput1.encoded());
    bytesValueRLPOutput.writeBytesValue(BytesValue.wrap(name.getBytes(UTF_8)));
    bytesValueRLPOutput.writeBytesValue(BytesValue.wrap(description.getBytes(UTF_8)));
    bytesValueRLPOutput.endList();
    final BytesValue rlpEncodedParameters = bytesValueRLPOutput.encoded();
    final BytesValue payload = manageManagementContractBinary.concat(rlpEncodedParameters);

    return PrivateTransaction.builder()
        .nonce(nonce)
        .gasPrice(Wei.ZERO)
        .gasLimit(0)
        .value(Wei.ZERO)
        .payload(payload)
        .privateFrom(privateFrom)
        .privacyGroupId(privacyGroupId)
        .signAndBuild(signingKey);
  }
}
