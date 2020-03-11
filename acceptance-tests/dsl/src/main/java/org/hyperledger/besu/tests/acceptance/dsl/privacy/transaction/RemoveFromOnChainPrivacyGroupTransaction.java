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
package org.hyperledger.besu.tests.acceptance.dsl.privacy.transaction;

import org.hyperledger.besu.tests.acceptance.dsl.privacy.PrivacyNode;
import org.hyperledger.besu.tests.acceptance.dsl.transaction.NodeRequests;
import org.hyperledger.besu.tests.acceptance.dsl.transaction.Transaction;

import java.io.IOException;

import org.web3j.protocol.exceptions.TransactionException;
import org.web3j.utils.Base64String;

public class RemoveFromOnChainPrivacyGroupTransaction implements Transaction<String> {
  private final Base64String privacyGroupId;
  private final PrivacyNode remover;
  private final String toRemove;

  public RemoveFromOnChainPrivacyGroupTransaction(
      final String privacyGroupId, final PrivacyNode remove, final PrivacyNode toRemove) {
    this.privacyGroupId = Base64String.wrap(privacyGroupId);
    this.remover = remove;
    this.toRemove = toRemove.getOrion().getDefaultPublicKey();
  }

  @Override
  public String execute(final NodeRequests node) {
    try {
      return node.privacy().privxRemoveFromPrivacyGroup(privacyGroupId, remover, toRemove);
    } catch (IOException | TransactionException e) {
      throw new RuntimeException(e);
    }
  }
}
