package org.hyperledger.besu.ethereum.privacy;

import org.hyperledger.besu.crypto.SECP256K1;
import org.hyperledger.besu.enclave.Enclave;
import org.hyperledger.besu.ethereum.core.Address;
import org.hyperledger.besu.ethereum.core.PrivacyParameters;
import org.hyperledger.besu.ethereum.privacy.storage.PrivateStateStorage;
import org.hyperledger.besu.ethereum.storage.StorageProvider;
import org.hyperledger.besu.ethereum.worldstate.WorldStateArchive;
import org.hyperledger.besu.ethereum.worldstate.WorldStatePreimageStorage;
import org.hyperledger.besu.ethereum.worldstate.WorldStateStorage;
import org.hyperledger.besu.util.bytes.BytesValue;

import java.net.URI;
import java.util.Optional;

public class PrivacyContext {
  private boolean enabled;
  private final BytesValue defaultEnclaveAccount;
  private final Address privacyPrecompiledAddress;
  private final Enclave enclave;
  private final PrivateStateStorage privateStateStorage;
  private final WorldStateArchive privateWorldStateArchive;
  private final Optional<SECP256K1.KeyPair> markerSigningKeyPair;

  public PrivacyContext(
      final boolean enabled,
      final BytesValue defaultEnclaveAccount,
      final Address privacyPrecompiledAddress,
      final Enclave enclave,
      final PrivateStateStorage privateStateStorage,
      final WorldStateArchive privateWorldStateArchive,
      final Optional<SECP256K1.KeyPair> markerSigningKeyPair) {
    this.enabled = enabled;
    this.defaultEnclaveAccount = defaultEnclaveAccount;
    this.privacyPrecompiledAddress = privacyPrecompiledAddress;
    this.enclave = enclave;
    this.privateStateStorage = privateStateStorage;
    this.privateWorldStateArchive = privateWorldStateArchive;
    this.markerSigningKeyPair = markerSigningKeyPair;
  }

  public static PrivacyContext init(
      final PrivacyParameters privacyParameters, final StorageProvider privateStorageProvider) {
    return init(
        privacyParameters.isEnabled(),
        privacyParameters.getPrivacyAddress(),
        privacyParameters.getEnclavePublicKey(),
        privacyParameters.getEnclaveUri(),
        privacyParameters.getMarkerSigningKeyPair(),
        privateStorageProvider);
  }

  public static PrivacyContext init(
      final boolean enabled,
      final Address privacyPrecompiledAddress,
      final BytesValue defaultEnclaveAccount,
      final URI enclaveURI,
      final Optional<SECP256K1.KeyPair> markerSigningKeyPair,
      final StorageProvider storageProvider) {

    final WorldStateStorage privateWorldStateStorage = storageProvider.createWorldStateStorage();
    final WorldStatePreimageStorage privatePreimageStorage =
        storageProvider.createWorldStatePreimageStorage();
    final WorldStateArchive privateWorldStateArchive =
        new WorldStateArchive(privateWorldStateStorage, privatePreimageStorage);

    final PrivateStateStorage privateStateStorage = storageProvider.createPrivateStateStorage();

    final Enclave enclave = new Enclave(enclaveURI);

    return new PrivacyContext(
        enabled,
        defaultEnclaveAccount,
        privacyPrecompiledAddress,
        enclave,
        privateStateStorage,
        privateWorldStateArchive,
        markerSigningKeyPair);
  }

  public boolean isEnabled() {
    return enabled;
  }

  public BytesValue getDefaultEnclaveAddress() {
    return defaultEnclaveAccount;
  }

  public Address getPrivacyPrecompiledAddress() {
    return privacyPrecompiledAddress;
  }

  public PrivateStateStorage getPrivateStateStorage() {
    return privateStateStorage;
  }

  public WorldStateArchive getPrivateWorldStateArchive() {
    return privateWorldStateArchive;
  }

  public Enclave getEnclave() {
    return enclave;
  }

  public Optional<SECP256K1.KeyPair> maybeMarkerSigningKeyPair() {
    return markerSigningKeyPair;
  }
}
