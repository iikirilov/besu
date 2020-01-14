package org.hyperledger.besu.tests.web3j.privacy;

import static org.assertj.core.api.Assertions.assertThat;

import org.hyperledger.besu.tests.acceptance.dsl.privacy.PrivacyAcceptanceTestBase;
import org.hyperledger.besu.tests.acceptance.dsl.privacy.PrivacyNode;
import org.hyperledger.besu.tests.acceptance.dsl.transaction.privacy.PrivacyRequestFactory.PrivxCreatePrivacyGroup;

import org.junit.Before;
import org.junit.Test;
import org.web3j.protocol.besu.response.privacy.PrivacyGroup;
import org.web3j.utils.Base64String;

public class OnChainPrivacyAcceptanceTest extends PrivacyAcceptanceTestBase {
  private PrivacyNode alice;
  private PrivacyNode bob;
  private PrivacyNode charlie;

  @Before
  public void setUp() throws Exception {
    alice =
        privacyBesu.createPrivateTransactionEnabledMinerNode(
            "node1", privacyAccountResolver.resolve(0));
    bob =
        privacyBesu.createPrivateTransactionEnabledNode("node2", privacyAccountResolver.resolve(1));
    charlie =
        privacyBesu.createPrivateTransactionEnabledNode("node3", privacyAccountResolver.resolve(2));
    privacyCluster.start(alice, bob, charlie);
  }

  @Test
  public void nodeCanCreatePrivacyGroup() {
    final PrivxCreatePrivacyGroup privxCreatePrivacyGroup =
        alice.execute(
            privacyTransactions.createOnChainPrivacyGroup(
                "myGroupName", "my group description", alice, bob));

    assertThat(privxCreatePrivacyGroup).isNotNull();

    final PrivacyGroup expected =
        new PrivacyGroup(
            privxCreatePrivacyGroup.getPrivacyGroupId(),
            PrivacyGroup.Type.PANTHEON,
            "myGroupName",
            "my group description",
            Base64String.wrapList(alice.getEnclaveKey(), bob.getEnclaveKey()));

    alice.verify(privateTransactionVerifier.validPrivacyGroupCreated(expected));

    bob.verify(privateTransactionVerifier.validPrivacyGroupCreated(expected));
  }
}
