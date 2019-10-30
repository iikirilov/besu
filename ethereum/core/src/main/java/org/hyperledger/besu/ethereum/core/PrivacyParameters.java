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
package org.hyperledger.besu.ethereum.core;

import static java.nio.charset.StandardCharsets.UTF_8;

import org.hyperledger.besu.crypto.SECP256K1;
import org.hyperledger.besu.crypto.SECP256K1.KeyPair;
import org.hyperledger.besu.ethereum.storage.StorageProvider;
import org.hyperledger.besu.util.bytes.BytesValue;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Path;
import java.util.Optional;

import com.google.common.io.Files;

public class PrivacyParameters {

  public static final URI DEFAULT_ENCLAVE_URL = URI.create("http://localhost:8888");
  public static final PrivacyParameters DEFAULT = builder().buildDefault();

  public static Builder builder() {
    return new Builder();
  }

  private final Address privacyAddress;
  private final boolean enabled;
  private final URI enclaveUri;
  private final BytesValue enclavePublicKey;
  private final Optional<SECP256K1.KeyPair> markerSigningKeyPair;

  private final StorageProvider privateStorageProvider;

  private PrivacyParameters(
      final boolean enabled,
      final URI enclaveUri,
      final BytesValue enclavePublicKey,
      final Address privacyAddress,
      final Optional<KeyPair> markerSigningKey,
      final StorageProvider privateStorageProvider) {
    this.privacyAddress = privacyAddress;
    this.enabled = enabled;
    this.enclaveUri = enclaveUri;
    this.enclavePublicKey = enclavePublicKey;
    this.markerSigningKeyPair = markerSigningKey;
    this.privateStorageProvider = privateStorageProvider;
  }

  public Address getPrivacyAddress() {
    return privacyAddress;
  }

  public Boolean isEnabled() {
    return enabled;
  }

  public URI getEnclaveUri() {
    return enclaveUri;
  }

  public BytesValue getEnclavePublicKey() {
    return enclavePublicKey;
  }

  public Optional<SECP256K1.KeyPair> getMarkerSigningKeyPair() {
    return markerSigningKeyPair;
  }

  public StorageProvider getPrivateStorageProvider() {
    return privateStorageProvider;
  }

  @Override
  public String toString() {
    return "PrivacyParameters{" + "enabled=" + enabled + ", enclaveUri='" + enclaveUri + '\'' + '}';
  }

  public static class Builder {

    private boolean enabled = false;
    private URI enclaveUrl;
    private Address privacyAddress = Address.DEFAULT_PRIVACY;
    private BytesValue enclavePublicKey;
    private Optional<Path> privateKeyPath = Optional.empty();
    private StorageProvider storageProvider;

    public Builder setPrivacyAddress(final Integer privacyAddress) {
      this.privacyAddress = Address.privacyPrecompiled(privacyAddress);
      return this;
    }

    public Builder setEnclaveUrl(final URI enclaveUrl) {
      this.enclaveUrl = enclaveUrl;
      return this;
    }

    public Builder setEnabled(final boolean enabled) {
      this.enabled = enabled;
      return this;
    }

    public Builder setStorageProvider(final StorageProvider privateStorageProvider) {
      this.storageProvider = privateStorageProvider;
      return this;
    }

    public Builder setPrivateKeyPath(final Path privateKeyPath) {
      this.privateKeyPath = Optional.of(privateKeyPath);
      return this;
    }

    public Builder setEnclavePublicKeyUsingFile(final File publicKeyFile) throws IOException {
      this.enclavePublicKey =
          BytesValue.fromBase64(Files.asCharSource(publicKeyFile, UTF_8).read());
      return this;
    }

    public PrivacyParameters build() throws IOException {
      Optional<KeyPair> markerSigningKey = Optional.empty();
      if (privateKeyPath.isPresent()) {
        markerSigningKey = Optional.of(KeyPair.load(privateKeyPath.get().toFile()));
      }
      return new PrivacyParameters(
          enabled, enclaveUrl, enclavePublicKey, privacyAddress, markerSigningKey, storageProvider);
    }

    private PrivacyParameters buildDefault() {
      return new PrivacyParameters(
          enabled, enclaveUrl, enclavePublicKey, privacyAddress, Optional.empty(), storageProvider);
    }
  }
}
