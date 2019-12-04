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
package org.hyperledger.besu.ethereum.api.jsonrpc.internal.privacy.methods.eea;

import static org.hyperledger.besu.ethereum.util.PrivacyUtil.getPrivacyGroup;

import org.hyperledger.besu.ethereum.api.jsonrpc.JsonRpcEnclaveErrorConverter;
import org.hyperledger.besu.ethereum.api.jsonrpc.JsonRpcErrorConverter;
import org.hyperledger.besu.ethereum.api.jsonrpc.RpcMethod;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.JsonRpcRequestContext;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.privacy.methods.PrivacySendTransaction;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.response.JsonRpcErrorResponse;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.response.JsonRpcResponse;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.response.JsonRpcSuccessResponse;
import org.hyperledger.besu.ethereum.core.PrivacyParameters;
import org.hyperledger.besu.ethereum.core.Transaction;
import org.hyperledger.besu.ethereum.eth.transactions.TransactionPool;
import org.hyperledger.besu.ethereum.privacy.PrivateTransaction;
import org.hyperledger.besu.ethereum.privacy.PrivateTransactionHandler;

public class EeaSendRawTransaction extends PrivacySendTransaction {

  public EeaSendRawTransaction(
      final PrivacyParameters privacyParameters,
      final PrivateTransactionHandler privateTransactionHandler,
      final TransactionPool transactionPool) {
    super(privacyParameters, privateTransactionHandler, transactionPool);
  }

  @Override
  public String getName() {
    return RpcMethod.EEA_SEND_RAW_TRANSACTION.getMethodName();
  }

  @Override
  public JsonRpcResponse doResponse(final JsonRpcRequestContext requestContext) {
    final PrivateTransaction privateTransaction;
    try {
      privateTransaction = validateAndDecodeRequest(requestContext);
    } catch (ErrorResponseException e) {
      return e.getResponse();
    }

    final String enclaveKey;
    try {
      enclaveKey = privateTransactionHandler.sendToOrion(privateTransaction);
    } catch (final Exception e) {
      return new JsonRpcErrorResponse(
          requestContext.getRequest().getId(),
          JsonRpcEnclaveErrorConverter.convertEnclaveInvalidReason(e.getMessage()));
    }

    final String privacyGroupId;
    try {
      privacyGroupId = getPrivacyGroup(privateTransaction);
    } catch (final Exception e) {
      return new JsonRpcErrorResponse(
          requestContext.getRequest().getId(),
          JsonRpcEnclaveErrorConverter.convertEnclaveInvalidReason(e.getMessage()));
    }

    return validateAndExecute(
        requestContext,
        privateTransaction,
        privacyGroupId,
        () -> {
          final Transaction privacyMarkerTransaction =
              privateTransactionHandler.createPrivacyMarkerTransaction(
                  enclaveKey, privateTransaction);
          return transactionPool
              .addLocalTransaction(privacyMarkerTransaction)
              .either(
                  () ->
                      new JsonRpcSuccessResponse(
                          requestContext.getRequest().getId(),
                          privacyMarkerTransaction.getHash().toString()),
                  errorReason ->
                      new JsonRpcErrorResponse(
                          requestContext.getRequest().getId(),
                          JsonRpcErrorConverter.convertTransactionInvalidReason(errorReason)));
        });
  }
}
