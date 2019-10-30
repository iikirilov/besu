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
package org.hyperledger.besu.ethereum.mainnet;

import org.hyperledger.besu.ethereum.privacy.PrivacyContext;
import org.hyperledger.besu.ethereum.vm.GasCalculator;

public class PrecompiledContractConfiguration {
  private GasCalculator gasCalculator;
  private PrivacyContext privacyContext;

  public PrecompiledContractConfiguration(
      final GasCalculator gasCalculator, final PrivacyContext privacyContext) {
    this.gasCalculator = gasCalculator;
    this.privacyContext = privacyContext;
  }

  public GasCalculator getGasCalculator() {
    return gasCalculator;
  }

  public void setGasCalculator(final GasCalculator gasCalculator) {
    this.gasCalculator = gasCalculator;
  }

  public PrivacyContext getPrivacyContext() {
    return privacyContext;
  }

  public void setPrivacyContext(final PrivacyContext privacyContext) {
    this.privacyContext = privacyContext;
  }
}
