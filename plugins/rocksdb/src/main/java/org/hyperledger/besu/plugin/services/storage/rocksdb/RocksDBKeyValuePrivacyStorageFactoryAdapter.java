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
package org.hyperledger.besu.plugin.services.storage.rocksdb;

import org.hyperledger.besu.plugin.services.BesuConfiguration;
import org.hyperledger.besu.plugin.services.MetricsSystem;
import org.hyperledger.besu.plugin.services.exception.StorageException;
import org.hyperledger.besu.plugin.services.storage.KeyValueStorage;
import org.hyperledger.besu.plugin.services.storage.PrivacyKeyValueStorageFactory;
import org.hyperledger.besu.plugin.services.storage.SegmentIdentifier;
import org.hyperledger.besu.plugin.services.storage.rocksdb.configuration.DatabaseMetadata;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Takes a public storage factory and enables creating independently versioned privacy storage
 * objects which have the same features as the supported public storage factory
 */
public class RocksDBKeyValuePrivacyStorageFactoryAdapter implements PrivacyKeyValueStorageFactory {
  private static final Logger LOG = LogManager.getLogger();
  private final int DEFAULT_VERSION = 1;
  private static final Set<Integer> SUPPORTED_VERSIONS = Set.of(0, 1);

  private static final String PRIVATE_DATABASE_PATH = "private";
  private final RocksDBKeyValueStorageFactory publicFactory;
  private Integer databaseVersion;

  public RocksDBKeyValuePrivacyStorageFactoryAdapter(
          final RocksDBKeyValueStorageFactory publicFactory) {
    this.publicFactory = publicFactory;
  }

  @Override
  public String getName() {
    return "rocksdb-privacy";
  }

  @Override
  public KeyValueStorage create(
      final SegmentIdentifier segment,
      final BesuConfiguration commonConfiguration,
      final MetricsSystem metricsSystem)
      throws StorageException {
    if (databaseVersion == null) {
      try {
        databaseVersion = readDatabaseVersion(commonConfiguration);
      } catch (final IOException e) {
        LOG.error("Failed to retrieve the RocksDB database meta version: {}", e.getMessage());
        throw new StorageException(e.getMessage(), e);
      }
    }

    return publicFactory.create(segment, commonConfiguration, metricsSystem);
  }

  @Override
  public boolean isSegmentIsolationSupported() {
    return publicFactory.isSegmentIsolationSupported();
  }

  @Override
  public void close() throws IOException {
    publicFactory.close();
  }

  private int readDatabaseVersion(final BesuConfiguration commonConfiguration) throws IOException {
    final Path databaseDir = commonConfiguration.getStoragePath().resolve(PRIVATE_DATABASE_PATH);
    final Path dataDir = commonConfiguration.getDataPath();
    final boolean databaseExists = databaseDir.resolve("IDENTITY").toFile().exists();
    final int databaseVersion;
    if (databaseExists) {
      databaseVersion =
          DatabaseMetadata.lookUpFrom(commonConfiguration.getStoragePath(), dataDir).maybePrivacyVersion().get();
      LOG.info("Existing private database detected at {}. Version {}", dataDir, databaseVersion);
    } else {
      databaseVersion = DEFAULT_VERSION;
      LOG.info(
          "No existing private database detected at {}. Using version {}",
          dataDir,
          databaseVersion);
      Files.createDirectories(databaseDir);
      Files.createDirectories(dataDir);
      new DatabaseMetadata(publicFactory.getVersion(), databaseVersion).writeToDirectory(dataDir);
    }

    if (!SUPPORTED_VERSIONS.contains(databaseVersion)) {
      final String message = "Unsupported RocksDB Metadata version of: " + databaseVersion;
      LOG.error(message);
      throw new StorageException(message);
    }

    return databaseVersion;
  }

  @Override
  public int getSchemaVersion() {
    return databaseVersion;
  }
}
