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
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import org.wildfly.common.iteration.CodePointIterator;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.ACCEPT_LANGUAGE;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.BAD_NONCE;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.BASE64_URL;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.INSTANCE;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.JSON_CONTENT_TYPE;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.PROBLEM_JSON_CONTENT_TYPE;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.RATE_LIMITED;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.REPLAY_NONCE;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.RETRY_AFTER;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.TYPE;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.USER_ACTION_REQUIRED;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.USER_AGENT;
import static org.wildfly.security.certificate.management.x500.cert.acme.CertMgmtMessages.acme;

public abstract class AsyncAcmeClientSpi {

    private static final long DEFAULT_RETRY_AFTER_MILLI = 3000;
    private static final String USER_AGENT_STRING = "Elytron ACME Client/" + "1.0.0.Alpha1-SNAPSHOT";
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

    public Uni<byte[]> getNewNonce(final AcmeAccount account, final boolean staging) {
        if (account == null) {
            return Uni.createFrom().failure(new IllegalArgumentException("account"));
        }
        HttpClient httpClient = HttpClient.newHttpClient();

        return getResourceUrl(account, AcmeResource.NEW_NONCE, staging)
                .chain((URL newNonceUrl) -> {
                    final URI newNonceUri;
                    try {
                        newNonceUri = newNonceUrl.toURI();
                    } catch (URISyntaxException e) {
                        throw new RuntimeException(e);
                    }
                    HttpRequest httpRequest = HttpRequest.newBuilder().method("HEAD", HttpRequest.BodyPublishers.noBody())
                            .uri(newNonceUri)
                            .header(ACCEPT_LANGUAGE, Locale.getDefault().toLanguageTag())
                            .header(USER_AGENT, USER_AGENT_STRING).build();
                    return Uni.createFrom().future(httpClient.sendAsync(httpRequest, HttpResponse.BodyHandlers.ofString()));
                }).onFailure().transform(Throwable::getCause)
                .map((httpResponse) -> {
                    int responseCode = httpResponse.statusCode();
                    byte[] nonce;
                    try {
                        if (responseCode != HttpURLConnection.HTTP_NO_CONTENT && responseCode != HttpURLConnection.HTTP_OK) {
                            handleAcmeErrorResponse(httpResponse, responseCode);
                        }
                        nonce = getReplayNonce(httpResponse);
                        if (nonce == null) {
                            throw acme.noNonceProvidedByAcmeServer();
                        }
                    } catch (AcmeException e) {
                        throw new RuntimeException(e);
                    }
                    return nonce;
                });
    }

    private Uni<URL> getResourceUrl(AcmeAccount account, AcmeResource resource, boolean staging) {
        return getResourceUrls(account, staging).map((Map<AcmeResource, URL> e) -> {
            URL resourceUrl = e.get(resource);
            if (resourceUrl == null) {
                throw new RuntimeException(acme.resourceNotSupportedByAcmeServer(resource.getValue()));
            }
            return resourceUrl;
        }).onFailure().transform(Throwable::getCause);
    }

    private static byte[] getReplayNonce(HttpResponse<String> connection) throws AcmeException {
        String nonce = null;
        if (connection.headers().firstValue(REPLAY_NONCE).isPresent()) {
            nonce = connection.headers().firstValue(REPLAY_NONCE).get();
        }
        if (nonce == null) {
            return null;
        }
        return CodePointIterator.ofString(nonce).base64Decode(BASE64_URL, false).drain();
    }

    public Uni<Map<AcmeResource, URL>> getResourceUrls(AcmeAccount account, boolean staging) {
        if (account == null) {
            return Uni.createFrom().failure(new IllegalArgumentException("account"));
        }
        final Map<AcmeResource, URL> resourceUrls = new HashMap<>();
//        final Map<AcmeResource, URL> resourceUrls = account.getResourceUrls(staging);

        Uni<HttpResponse<String>> httpResponseUni = null;
        // TODO do we want caching?
//        if (!resourceUrls.isEmpty()) {
//            return Uni.createFrom().item(resourceUrls);
//        }

        if (staging && account.getServerUrl(true) == null) {
            return Uni.createFrom().failure(acme.noAcmeServerStagingUrlGiven());
        }
        httpResponseUni = sendGetRequest(account.getServerUrl(staging), HttpURLConnection.HTTP_OK, JSON_CONTENT_TYPE);

        return httpResponseUni.map((HttpResponse<String> httpResponse) -> {
            JsonObject directoryJson;
            try {
                directoryJson = getJsonResponse(httpResponse);
            } catch (AcmeException e) {
                throw new RuntimeException(e);
            }
            for (AcmeResource resource : AcmeResource.values()) {
                String resourceUrl = AcmeClientSpiUtils.getOptionalJsonString(directoryJson, resource.getValue());
                URL url;
                try {
                    url = resourceUrl != null ? new URL(resourceUrl) : null;
                } catch (MalformedURLException e) {
                    throw new RuntimeException(acme.unableToRetrieveAcmeServerDirectoryUrls(e));
                }
                resourceUrls.put(resource, url);
            }
            return resourceUrls;
        }).onFailure().transform(Throwable::getCause);
    }

    private Uni<HttpResponse<String>> sendGetRequest(String resourceUrl, int expectedResponseCode, String expectedContentType) {
        HttpClient httpClient = HttpClient.newBuilder().build();
        HttpRequest httpRequest;
        try {
            httpRequest = HttpRequest.newBuilder().GET().uri(new URI(resourceUrl))
                    .header(ACCEPT_LANGUAGE, Locale.getDefault().toLanguageTag())
                    .header(USER_AGENT, USER_AGENT_STRING).build();
            return Uni.createFrom().future(httpClient.sendAsync(httpRequest, HttpResponse.BodyHandlers.ofString()))
                    .onItem().call((HttpResponse<String> httpResponse) -> {
                        try {
                            int responseCode = httpResponse.statusCode();
                            if (responseCode != expectedResponseCode) {
                                handleAcmeErrorResponse(httpResponse, responseCode);
                            }
                            String contentType = httpResponse.headers().firstValue("Content-Type").get();
                            if (!AcmeClientSpiUtils.checkContentType(contentType, expectedContentType)) {
                                return Uni.createFrom().failure(acme.unexpectedContentTypeFromAcmeServer(contentType));
                            }
                        } catch (AcmeException e) {
                            return Uni.createFrom().failure(e);
                        }
                        return Uni.createFrom().item(httpResponse);
                    });
        } catch (Exception e) {
            return Uni.createFrom().failure(new AcmeException(e));
        }
    }

    private static void handleAcmeErrorResponse(HttpResponse<String> connection, int responseCode) throws AcmeException {
        try {
            String responseMessage = connection.body();
            if (!AcmeClientSpiUtils.checkContentType(connection.headers().firstValue("Content-Type").get(), PROBLEM_JSON_CONTENT_TYPE)) {
                throw acme.unexpectedResponseCodeFromAcmeServer(responseCode, responseMessage);
            }
            JsonObject jsonResponse = getJsonResponse(connection);
            String type = AcmeClientSpiUtils.getOptionalJsonString(jsonResponse, TYPE);
            if (type != null) {
                if (type.equals(BAD_NONCE)) {
                    return;
                } else if (type.equals(USER_ACTION_REQUIRED)) {
                    String instance = AcmeClientSpiUtils.getOptionalJsonString(jsonResponse, INSTANCE);
                    if (instance != null) {
                        throw acme.userActionRequired(instance);
                    }
                } else if (type.equals(RATE_LIMITED)) {
                    long retryAfter = getRetryAfter(connection, false);
                    if (retryAfter > 0) {
                        throw acme.rateLimitExceededTryAgainLater(Instant.ofEpochMilli(retryAfter));
                    } else {
                        throw acme.rateLimitExceeded();
                    }
                }
            }
            String problemMessages = AcmeClientSpiUtils.getProblemMessages(jsonResponse);
            if (!problemMessages.isEmpty()) {
                throw new AcmeException(problemMessages);
            } else {
                throw acme.unexpectedResponseCodeFromAcmeServer(responseCode, responseMessage);
            }
        } catch (Exception e) {
            if (e instanceof AcmeException) {
                throw (AcmeException) e;
            } else {
                throw new AcmeException(e);
            }
        }
    }

    private static JsonObject getJsonResponse(HttpResponse<String> connection) throws AcmeException {
        JsonObject jsonResponse;
        try (InputStream inputStream = new ByteArrayInputStream(connection.body().getBytes());
             JsonReader jsonReader = Json.createReader(inputStream)) {
            jsonResponse = jsonReader.readObject();
        } catch (IOException e) {
            throw acme.unableToObtainJsonResponseFromAcmeServer(e);
        }
        return jsonResponse;
    }

    private static long getRetryAfter(HttpResponse<String> connection, boolean useDefaultIfHeaderNotPresent) {
        long retryAfterMilli = -1;
        String retryAfter = connection.headers().firstValue(RETRY_AFTER).get();
        if (retryAfter != null) {
            try {
                retryAfterMilli = Integer.parseInt(retryAfter) * 1000L;
            } catch (NumberFormatException e) {
                long retryAfterDate = Long.parseLong(connection.headers().firstValue(RETRY_AFTER).get());
                if (retryAfterDate != 0) {
                    retryAfterMilli = retryAfterDate - Instant.now().toEpochMilli();
                }
            }
        }

        if (retryAfterMilli == -1) {
            if (useDefaultIfHeaderNotPresent) {
                retryAfterMilli = DEFAULT_RETRY_AFTER_MILLI;
            }
        }
        return retryAfterMilli;
    }
}
