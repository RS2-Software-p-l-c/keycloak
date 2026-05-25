/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.saml.processing.core.util;

import org.apache.xml.security.encryption.XMLCipher;

import javax.crypto.Cipher;
import java.security.PrivateKey;
import java.util.Collections;
import java.util.List;

/**
 * Default implementation of {@link SamlDecryptionProvider} that performs local
 * key unwrapping using one or more {@link PrivateKey} instances from JKS/PEM configuration.
 *
 * <p>This provider uses the standard JCE {@link Cipher} in {@code UNWRAP_MODE}
 * to decrypt the encrypted symmetric key bytes. When multiple keys are provided,
 * it tries each in order until one succeeds (supporting key rotation scenarios).</p>
 */
public class DefaultSamlDecryptionProvider implements SamlDecryptionProvider {

    private final List<PrivateKey> privateKeys;

    public DefaultSamlDecryptionProvider(List<PrivateKey> privateKeys) {
        if (privateKeys == null || privateKeys.isEmpty()) {
            throw new RuntimeException("Decryption private keys must not be null or empty");
        }
        this.privateKeys = Collections.unmodifiableList(privateKeys);
    }

    @Override
    public byte[] unwrapKey(String algorithmUri, byte[] encryptedKeyBytes) {
        if (algorithmUri == null || algorithmUri.isEmpty()) {
            throw new RuntimeException("Algorithm URI must not be null or empty");
        }
        if (encryptedKeyBytes == null || encryptedKeyBytes.length == 0) {
            throw new RuntimeException("Encrypted key bytes must not be null or empty");
        }

        String jceAlgorithm = mapAlgorithmUri(algorithmUri);
        Exception lastException = null;

        for (PrivateKey privateKey : privateKeys) {
            try {
                Cipher cipher = Cipher.getInstance(jceAlgorithm);
                cipher.init(Cipher.UNWRAP_MODE, privateKey);
                java.security.Key unwrappedKey = cipher.unwrap(
                    encryptedKeyBytes, "AES", Cipher.SECRET_KEY);
                return unwrappedKey.getEncoded();
            } catch (Exception e) {
                lastException = e;
            }
        }

        throw new RuntimeException(
            "Failed to unwrap key with algorithm " + algorithmUri
                + " using " + privateKeys.size() + " available key(s): "
                + (lastException != null ? lastException.getMessage() : "unknown error"),
            lastException);
    }

    @Override
    public void close() {
        // No resources to release for local key unwrapping
    }

    private String mapAlgorithmUri(String algorithmUri) {
        switch (algorithmUri) {
            case XMLCipher.RSA_OAEP:
            case XMLCipher.RSA_OAEP_11:
                return "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
            case XMLCipher.RSA_v1dot5:
                return "RSA/ECB/PKCS1Padding";
            default:
                throw new RuntimeException(
                    "Unsupported key encryption algorithm: " + algorithmUri);
        }
    }
}
