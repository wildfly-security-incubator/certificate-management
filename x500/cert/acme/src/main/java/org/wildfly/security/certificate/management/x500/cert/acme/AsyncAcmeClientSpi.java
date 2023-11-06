/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2023 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wildfly.security.certificate.management.x500.cert.acme;

import io.smallrye.mutiny.Uni;
import org.wildfly.security.certificate.management.x500.cert.X509CertificateChainAndSigningKey;

import java.net.URL;
import java.security.PrivateKey;
import java.security.cert.CRLReason;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

public abstract class AsyncAcmeClientSpi {

    private final AcmeClientSpi delegate;

    public AsyncAcmeClientSpi() {
        AsyncAcmeClientSpi impl = this;

        this.delegate = new AcmeClientSpi() {
            @Override
            public AcmeChallenge proveIdentifierControl(AcmeAccount account, List<AcmeChallenge> challenges) throws AcmeException {
                return impl.proveIdentifierControl(account, challenges);
            }

            @Override
            public void cleanupAfterChallenge(AcmeAccount account, AcmeChallenge challenge) throws AcmeException {
                impl.cleanupAfterChallenge(account, challenge);
            }
        };
    }

    protected abstract AcmeChallenge proveIdentifierControl(AcmeAccount account, List<AcmeChallenge> challenges) throws AcmeException;
    protected abstract void cleanupAfterChallenge(AcmeAccount account, AcmeChallenge challenge) throws AcmeException;

    public Uni<Map<AcmeResource, URL>> getResourceUrls(ElytronRequestContext context, AcmeAccount account, boolean staging) throws AcmeException {
        return context.runBlocking(() -> {
            try {
                return delegate.getResourceUrls(account, staging);
            } catch (AcmeException e) {
                throw new RuntimeException(e);
            }
        });
    }

    public Uni<AcmeMetadata> getMetadata(ElytronRequestContext context, AcmeAccount account, boolean staging) throws AcmeException {
        return context.runBlocking(() -> {
            try {
                return delegate.getMetadata(account, staging);
            } catch (AcmeException e) {
                throw new RuntimeException(e);
            }
        });
    }

    public Uni<Boolean> createAccount(ElytronRequestContext context, AcmeAccount account, boolean staging) throws AcmeException {
        return context.runBlocking(() -> {
            try {
                return delegate.createAccount(account, staging);
            } catch (AcmeException e) {
                throw new RuntimeException(e);
            }
        });
    }

    public Uni<Boolean> createAccount(ElytronRequestContext context, AcmeAccount account, boolean staging, boolean onlyReturnExisting) throws AcmeException {
        return context.runBlocking(() -> {
            try {
                return delegate.createAccount(account, staging, onlyReturnExisting);
            } catch (AcmeException e) {
                throw new RuntimeException(e);
            }
        });
    }

    public Uni<Void> updateAccount(ElytronRequestContext context, AcmeAccount account, boolean staging, boolean termsOfServiceAgreed) throws AcmeException {
        return context.runBlocking(() -> {
            try {
                delegate.updateAccount(account, staging, termsOfServiceAgreed);
                return null;
            } catch (AcmeException e) {
                throw new RuntimeException(e);
            }
        });
    }

    public Uni<Void> updateAccount(ElytronRequestContext context, AcmeAccount account, boolean staging, String[] contactUrls) throws AcmeException {
        return context.runBlocking(() -> {
            try {
                delegate.updateAccount(account, staging, contactUrls);
                return null;
            } catch (AcmeException e) {
                throw new RuntimeException(e);
            }
        });
    }

    public Uni<Void> updateAccount(ElytronRequestContext context, AcmeAccount account, boolean staging, boolean termsOfServiceAgreed, String[] contactUrls) throws AcmeException {
        return context.runBlocking(() -> {
            try {
                delegate.updateAccount(account, staging, termsOfServiceAgreed, contactUrls);
                return null;
            } catch (AcmeException e) {
                throw new RuntimeException(e);
            }
        });
    }

    public Uni<Void> changeAccountKey(ElytronRequestContext context, AcmeAccount account, boolean staging) throws AcmeException {
        return context.runBlocking(() -> {
            try {
                delegate.changeAccountKey(account, staging);
                return null;
            } catch (AcmeException e) {
                throw new RuntimeException(e);
            }
        });
    }

    public Uni<Void> changeAccountKey(ElytronRequestContext context, AcmeAccount account, boolean staging, X509Certificate certificate, PrivateKey privateKey) throws AcmeException {
        return context.runBlocking(() -> {
            try {
                delegate.changeAccountKey(account, staging, certificate, privateKey);
                return null;
            } catch (AcmeException e) {
                throw new RuntimeException(e);
            }
        });
    }

    public Uni<Void> deactivateAccount(ElytronRequestContext context, AcmeAccount account, boolean staging) throws AcmeException {
        return context.runBlocking(() -> {
            try {
                delegate.deactivateAccount(account, staging);
                return null;
            } catch (AcmeException e) {
                throw new RuntimeException(e);
            }
        });
    }

    public Uni<X509CertificateChainAndSigningKey> obtainCertificateChain(ElytronRequestContext context, AcmeAccount account, boolean staging, String... domainNames) throws AcmeException {
        return context.runBlocking(() -> {
            try {
                return delegate.obtainCertificateChain(account, staging, domainNames);
            } catch (AcmeException e) {
                throw new RuntimeException(e);
            }
        });
    }

    public Uni<X509CertificateChainAndSigningKey> obtainCertificateChain(ElytronRequestContext context, AcmeAccount account, boolean staging, String keyAlgorithmName, int keySize,
                                                                         String... domainNames) {
        return context.runBlocking(() -> {
            try {
                return delegate.obtainCertificateChain(account, staging, keyAlgorithmName, keySize, domainNames);
            } catch (AcmeException e) {
                throw new RuntimeException(e);
            }
        });
    }

    public Uni<String> createAuthorization(ElytronRequestContext context, AcmeAccount account, boolean staging, String domainName) throws AcmeException {
        return context.runBlocking(() -> {
            try {
                return delegate.createAuthorization(account, staging, domainName);
            } catch (AcmeException e) {
                throw new RuntimeException(e);
            }
        });
    }

    public Uni<Void> deactivateAuthorization(ElytronRequestContext context, AcmeAccount account, boolean staging, String authorizationUrl) throws AcmeException {
        return context.runBlocking(() -> {
            try {
                delegate.deactivateAuthorization(account, staging, authorizationUrl);
                return null;
            } catch (AcmeException e) {
                throw new RuntimeException(e);
            }
        });
    }

    public Uni<Void> revokeCertificate(ElytronRequestContext context, AcmeAccount account, boolean staging, X509Certificate certificate) throws AcmeException {
        return context.runBlocking(() -> {
            try {
                delegate.revokeCertificate(account, staging, certificate);
                return null;
            } catch (AcmeException e) {
                throw new RuntimeException(e);
            }
        });
    }

    public Uni<Void> revokeCertificate(ElytronRequestContext context, AcmeAccount account, boolean staging, X509Certificate certificate, CRLReason reason) throws AcmeException {
        return context.runBlocking(() -> {
            try {
                delegate.revokeCertificate(account, staging, certificate, reason);
                return null;
            } catch (AcmeException e) {
                throw new RuntimeException(e);
            }
        });
    }

    public Uni<byte[]> getNewNonce(ElytronRequestContext context, final AcmeAccount account, final boolean staging) throws AcmeException {
        return context.runBlocking(() -> {
            try {
                return delegate.getNewNonce(account, staging);
            } catch (AcmeException e) {
                throw new RuntimeException(e);
            }
        });
    }

    Uni<String[]> queryAccountContactUrls(ElytronRequestContext context, AcmeAccount account, boolean staging) throws AcmeException {
        return context.runBlocking(() -> {
            try {
                return delegate.queryAccountContactUrls(account, staging);
            } catch (AcmeException e) {
                throw new RuntimeException(e);
            }
        });
    }

    Uni<String> queryAccountStatus(ElytronRequestContext context, AcmeAccount account, boolean staging) throws AcmeException {
        return context.runBlocking(() -> {
            try {
                return delegate.queryAccountStatus(account, staging);
            } catch (AcmeException e) {
                throw new RuntimeException(e);
            }
        });
    }
}
