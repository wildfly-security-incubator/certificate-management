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

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.RecordedRequest;

import java.util.List;

public class SimpleDelegatingAcmeClient {
    private AsyncAcmeClientSpi asyncClient;
    private AcmeClientSpi syncClient;

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

    public byte[] getNewNonce(final AcmeAccount account, final boolean staging) throws AcmeException {
        if (this.syncClient != null) {
            return this.syncClient.getNewNonce(account, staging);
        } else {
            return this.asyncClient.getNewNonce(account, staging).await().indefinitely();
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