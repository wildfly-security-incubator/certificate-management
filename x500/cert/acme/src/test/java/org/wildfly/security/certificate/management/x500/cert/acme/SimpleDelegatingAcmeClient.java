/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2023 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.certificate.management.x500.cert.acme;

import io.smallrye.mutiny.Uni;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.RecordedRequest;
import org.wildfly.security.certificate.management.x500.cert.X509CertificateChainAndSigningKey;

import java.net.URL;
import java.security.PrivateKey;
import java.security.cert.CRLReason;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

public class SimpleDelegatingAcmeClient {
    private AsyncAcmeClientSpi asyncClient;
    private AcmeClientSpi syncClient;

    private final TestBlockingSecurityExecutor blockingExecutor = TestBlockingSecurityExecutor.createTestBlockingExecutor(() -> {
        return Executors.newFixedThreadPool(5);
    });
    private final ElytronRequestContext testContext = new ElytronRequestContext() {
        @Override
        public <T> Uni<T> runBlocking(Supplier<T> function) {
            return blockingExecutor.executeBlocking(function);
        }
    };

    public SimpleDelegatingAcmeClient(boolean useAsync) {

        if (useAsync) {
            this.asyncClient = new AsyncAcmeClientSpi() {
                protected AcmeChallenge proveIdentifierControl(AcmeAccount account, List<AcmeChallenge> challenges) throws AcmeException {
                    return proveIdentifierControlHelper(account, challenges);
                }

                protected void cleanupAfterChallenge(AcmeAccount account, AcmeChallenge challenge) throws AcmeException {
                    // do nothing
                }
            };
        } else {
            this.syncClient = new AcmeClientSpi() {
                public AcmeChallenge proveIdentifierControl(AcmeAccount account, List<AcmeChallenge> challenges) throws AcmeException {
                    return proveIdentifierControlHelper(account, challenges);
                }

                public void cleanupAfterChallenge(AcmeAccount account, AcmeChallenge challenge) throws AcmeException {
                    // do nothing
                }
            };
        }
    }

    public Map<AcmeResource, URL> getResourceUrls(AcmeAccount account, boolean staging) throws AcmeException {
        if (this.syncClient != null) {
            return this.syncClient.getResourceUrls(account, staging);
        } else {
            return this.asyncClient.getResourceUrls(this.testContext, account, staging).await().indefinitely();
        }
    }

    public AcmeMetadata getMetadata(AcmeAccount account, boolean staging) throws AcmeException {
        if (this.syncClient != null) {
            return this.syncClient.getMetadata(account, staging);
        } else {
            return this.asyncClient.getMetadata(this.testContext, account, staging).await().indefinitely();
        }
    }

    public Boolean createAccount(AcmeAccount account, boolean staging) throws AcmeException {
        if (this.syncClient != null) {
            return this.syncClient.createAccount(account, staging);
        } else {
            AtomicReference<String> exceptionMessage = new AtomicReference<>();
            Boolean result = this.asyncClient.createAccount(this.testContext, account, staging)
                    .onFailure().invoke(t -> {
                                exceptionMessage.set(t.getMessage());
                            }
                    )
                    .onFailure().recoverWithNull()
                    .await().indefinitely();
            if (exceptionMessage.get() != null) {
                throw new AcmeException(exceptionMessage.get());
            } else {
                return result;
            }
        }
    }

    public boolean createAccount(AcmeAccount account, boolean staging, boolean onlyReturnExisting) throws AcmeException {
        if (this.syncClient != null) {
            return this.syncClient.createAccount(account, staging, onlyReturnExisting);
        } else {
            AtomicReference<String> exceptionMessage = new AtomicReference<>();
            Boolean result = this.asyncClient.createAccount(this.testContext, account, staging, onlyReturnExisting)
                    .onFailure().invoke(t -> {
                                exceptionMessage.set(t.getMessage());
                            }
                    )
                    .onFailure().recoverWithNull()
                    .await().indefinitely();
            if (exceptionMessage.get() != null) {
                throw new AcmeException(exceptionMessage.get());
            } else {
                return result;
            }
        }
    }

    public void updateAccount(AcmeAccount account, boolean staging, boolean termsOfServiceAgreed) throws AcmeException {
        if (this.syncClient != null) {
            this.syncClient.updateAccount(account, staging, termsOfServiceAgreed);
        } else {
            AtomicReference<String> exceptionMessage = new AtomicReference<>();
            this.asyncClient.updateAccount(this.testContext, account, staging, termsOfServiceAgreed)
                    .onFailure().invoke(t -> {
                                exceptionMessage.set(t.getMessage());
                            }
                    )
                    .onFailure().recoverWithNull()
                    .await().indefinitely();
            if (exceptionMessage.get() != null) {
                throw new AcmeException(exceptionMessage.get());
            }
        }
    }

    public void updateAccount(AcmeAccount account, boolean staging, String[] contactUrls) throws AcmeException {
        if (this.syncClient != null) {
            this.syncClient.updateAccount(account, staging, contactUrls);
        } else {
            AtomicReference<String> exceptionMessage = new AtomicReference<>();
            this.asyncClient.updateAccount(this.testContext, account, staging, contactUrls)
                    .onFailure().invoke(t -> {
                                exceptionMessage.set(t.getMessage());
                            }
                    )
                    .onFailure().recoverWithNull()
                    .await().indefinitely();
            if (exceptionMessage.get() != null) {
                throw new AcmeException(exceptionMessage.get());
            }
        }
    }

    public void updateAccount(AcmeAccount account, boolean staging, boolean termsOfServiceAgreed, String[] contactUrls) throws AcmeException {
        if (this.syncClient != null) {
            this.syncClient.updateAccount(account, staging, termsOfServiceAgreed, contactUrls);
        } else {
            AtomicReference<String> exceptionMessage = new AtomicReference<>();
            this.asyncClient.updateAccount(this.testContext, account, staging, termsOfServiceAgreed, contactUrls)
                    .onFailure().invoke(t -> {
                                exceptionMessage.set(t.getMessage());
                            }
                    )
                    .onFailure().recoverWithNull()
                    .await().indefinitely();
            if (exceptionMessage.get() != null) {
                throw new AcmeException(exceptionMessage.get());
            }
        }
    }

    public void changeAccountKey(AcmeAccount account, boolean staging) throws AcmeException {
        if (this.syncClient != null) {
            this.syncClient.changeAccountKey(account, staging);
        } else {
            AtomicReference<String> exceptionMessage = new AtomicReference<>();
            this.asyncClient.changeAccountKey(this.testContext, account, staging)
                    .onFailure().invoke(t -> {
                                exceptionMessage.set(t.getMessage());
                            }
                    )
                    .onFailure().recoverWithNull()
                    .await().indefinitely();
            if (exceptionMessage.get() != null) {
                throw new AcmeException(exceptionMessage.get());
            }
        }
    }

    public void changeAccountKey(AcmeAccount account, boolean staging, X509Certificate certificate, PrivateKey privateKey) throws AcmeException {
        if (this.syncClient != null) {
            this.syncClient.changeAccountKey(account, staging, certificate, privateKey);
        } else {
            AtomicReference<String> exceptionMessage = new AtomicReference<>();
            this.asyncClient.changeAccountKey(this.testContext, account, staging, certificate, privateKey)
                    .onFailure().invoke(t -> {
                                exceptionMessage.set(t.getMessage());
                            }
                    )
                    .onFailure().recoverWithNull()
                    .await().indefinitely();
            if (exceptionMessage.get() != null) {
                throw new AcmeException(exceptionMessage.get());
            }
        }
    }

    public void deactivateAccount(AcmeAccount account, boolean staging) throws AcmeException {
        if (this.syncClient != null) {
            this.syncClient.deactivateAccount(account, staging);
        } else {
            AtomicReference<String> exceptionMessage = new AtomicReference<>();
            this.asyncClient.deactivateAccount(this.testContext, account, staging)
                    .onFailure().invoke(t -> {
                                exceptionMessage.set(t.getMessage());
                            }
                    )
                    .onFailure().recoverWithNull()
                    .await().indefinitely();
            if (exceptionMessage.get() != null) {
                throw new AcmeException(exceptionMessage.get());

            }
        }
    }

    public X509CertificateChainAndSigningKey obtainCertificateChain(AcmeAccount account, boolean staging, String... domainNames) throws AcmeException {
        if (this.syncClient != null) {
            return this.syncClient.obtainCertificateChain(account, staging, domainNames);
        } else {
            AtomicReference<String> exceptionMessage = new AtomicReference<>();
            X509CertificateChainAndSigningKey result = this.asyncClient.obtainCertificateChain(this.testContext, account, staging, domainNames)
                    .onFailure().invoke(t -> {
                                exceptionMessage.set(t.getMessage());
                            }
                    )
                    .onFailure().recoverWithNull()
                    .await().indefinitely();
            if (exceptionMessage.get() != null) {
                throw new AcmeException(exceptionMessage.get());
            } else {
                return result;
            }
        }
    }

    public X509CertificateChainAndSigningKey obtainCertificateChain(AcmeAccount account, boolean staging, String keyAlgorithmName, int keySize,
                                                                    String... domainNames) throws AcmeException {
        if (this.syncClient != null) {
            return this.syncClient.obtainCertificateChain(account, staging, keyAlgorithmName, keySize, domainNames);
        } else {
            AtomicReference<String> exceptionMessage = new AtomicReference<>();
            X509CertificateChainAndSigningKey result = this.asyncClient.obtainCertificateChain(this.testContext, account, staging, keyAlgorithmName, keySize, domainNames)
                    .onFailure().invoke(t -> {
                                exceptionMessage.set(t.getMessage());
                            }
                    )
                    .onFailure().recoverWithNull()
                    .await().indefinitely();
            if (exceptionMessage.get() != null) {
                throw new AcmeException(exceptionMessage.get());
            } else {
                return result;
            }
        }
    }

    public String createAuthorization(AcmeAccount account, boolean staging, String domainName) throws AcmeException {
        if (this.syncClient != null) {
            return this.syncClient.createAuthorization(account, staging, domainName);
        } else {
            return this.asyncClient.createAuthorization(this.testContext, account, staging, domainName).await().indefinitely();
        }
    }

    public void deactivateAuthorization(AcmeAccount account, boolean staging, String authorizationUrl) throws AcmeException {
        if (this.syncClient != null) {
            this.syncClient.deactivateAuthorization(account, staging, authorizationUrl);
        } else {
            this.asyncClient.deactivateAuthorization(this.testContext, account, staging, authorizationUrl).await().indefinitely();
        }
    }

    public void revokeCertificate(AcmeAccount account, boolean staging, X509Certificate certificate) throws AcmeException {
        if (this.syncClient != null) {
            this.syncClient.revokeCertificate(account, staging, certificate);
        } else {
            this.asyncClient.revokeCertificate(this.testContext, account, staging, certificate).await().indefinitely();
        }
    }

    public void revokeCertificate(AcmeAccount account, boolean staging, X509Certificate certificate, CRLReason reason) throws AcmeException {
        if (this.syncClient != null) {
            this.syncClient.revokeCertificate(account, staging, certificate, reason);
        } else {
            this.asyncClient.revokeCertificate(this.testContext, account, staging, certificate, reason).await().indefinitely();
        }
    }

    public byte[] getNewNonce(final AcmeAccount account, final boolean staging) throws AcmeException {
        if (this.syncClient != null) {
            return this.syncClient.getNewNonce(account, staging);
        } else {
            return this.asyncClient.getNewNonce(this.testContext, account, staging).await().indefinitely();
        }
    }

    String[] queryAccountContactUrls(AcmeAccount account, boolean staging) throws AcmeException {
        if (this.syncClient != null) {
            return this.syncClient.queryAccountContactUrls(account, staging);
        } else {
            return this.asyncClient.queryAccountContactUrls(this.testContext, account, staging).await().indefinitely();
        }
    }

    String queryAccountStatus(AcmeAccount account, boolean staging) throws AcmeException {
        if (this.syncClient != null) {
            return this.syncClient.queryAccountStatus(account, staging);
        } else {
            return this.asyncClient.queryAccountStatus(this.testContext, account, staging).await().indefinitely();
        }
    }

    private static AcmeChallenge proveIdentifierControlHelper(AcmeAccount account, List<AcmeChallenge> challenges) throws AcmeException {
        AcmeChallenge selectedChallenge = null;
        for (AcmeChallenge challenge : challenges) {
            if (challenge.getType() == AcmeChallenge.Type.HTTP_01) {
                AcmeClientSpiTest.getMockWebServerClient().setDispatcher(createChallengeResponseHelper(account, challenge));
                selectedChallenge = challenge;
                break;
            }
        }
        return selectedChallenge;
    }

    private static Dispatcher createChallengeResponseHelper(AcmeAccount account, AcmeChallenge challenge) {
        return new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest recordedRequest) throws InterruptedException {
                String path = recordedRequest.getPath();
                if (path.equals("/.well-known/acme-challenge/" + challenge.getToken())) {
                    try {
                        return new MockResponse()
                                .setHeader("Content-Type", "application/octet-stream")
                                .setBody(challenge.getKeyAuthorization(account));
                    } catch (AcmeException e) {
                        throw new RuntimeException(e);
                    }
                }
                return new MockResponse()
                        .setBody("");
            }
        };
    }

}