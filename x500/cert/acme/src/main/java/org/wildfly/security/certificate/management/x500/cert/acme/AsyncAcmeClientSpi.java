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

import io.smallrye.mutiny.Multi;
import io.smallrye.mutiny.Uni;
import io.smallrye.mutiny.tuples.Tuple2;
import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonArrayBuilder;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import jakarta.json.JsonReader;
import jakarta.json.JsonString;
import org.wildfly.common.Assert;
import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.certificate.management.asn1.ASN1Encodable;
import org.wildfly.security.certificate.management.x500.GeneralName;
import org.wildfly.security.certificate.management.x500.X500;
import org.wildfly.security.certificate.management.x500.X500AttributeTypeAndValue;
import org.wildfly.security.certificate.management.x500.X500PrincipalBuilder;
import org.wildfly.security.certificate.management.x500.cert.PKCS10CertificateSigningRequest;
import org.wildfly.security.certificate.management.x500.cert.SelfSignedX509CertificateAndSigningKey;
import org.wildfly.security.certificate.management.x500.cert.SubjectAlternativeNamesExtension;
import org.wildfly.security.certificate.management.x500.cert.spi.HttpClientSpi;
import org.wildfly.security.certificate.management.x500.cert.spi.HttpRequestSpi;
import org.wildfly.security.certificate.management.x500.cert.spi.HttpResponseSpi;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.ServiceLoader;

import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.ACCEPT_LANGUAGE;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.PEM_CERTIFICATE_CHAIN_CONTENT_TYPE;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.ACCOUNT;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.ALG;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.AUTHORIZATIONS;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.BAD_NONCE;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.BASE64_URL;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.CERTIFICATE;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.CHALLENGES;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.CONTACT;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.CSR;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.DNS;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.FINALIZE;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.GET;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.IDENTIFIER;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.IDENTIFIERS;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.INSTANCE;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.INVALID;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.JOSE_JSON_CONTENT_TYPE;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.JSON_CONTENT_TYPE;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.JWK;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.KID;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.LOCATION;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.META;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.NONCE;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.OLD_KEY;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.ONLY_RETURN_EXISTING;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.ORDER;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.PENDING;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.POST;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.PROBLEM_JSON_CONTENT_TYPE;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.RATE_LIMITED;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.REPLAY_NONCE;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.RETRY_AFTER;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.STATUS;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.TERMS_OF_SERVICE_AGREED;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.TOKEN;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.TYPE;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.URL;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.USER_ACTION_REQUIRED;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.USER_AGENT;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.VALID;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.VALUE;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.base64UrlEncode;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.getAlgHeaderFromSignatureAlgorithm;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.getJwk;
import static org.wildfly.security.certificate.management.x500.cert.acme.AcmeClientSpi.DEFAULT_EC_KEY_SIZE;
import static org.wildfly.security.certificate.management.x500.cert.acme.AcmeClientSpi.DEFAULT_KEY_ALGORITHM_NAME;
import static org.wildfly.security.certificate.management.x500.cert.acme.AcmeClientSpi.DEFAULT_KEY_SIZE;
import static org.wildfly.security.certificate.management.x500.cert.acme.AcmeClientSpiUtils.EMPTY_PAYLOAD;
import static org.wildfly.security.certificate.management.x500.cert.acme.AcmeClientSpiUtils.checkContentType;
import static org.wildfly.security.certificate.management.x500.cert.acme.AcmeClientSpiUtils.getConvertedInputStream;
import static org.wildfly.security.certificate.management.x500.cert.acme.AcmeClientSpiUtils.getDomainNames;
import static org.wildfly.security.certificate.management.x500.cert.acme.AcmeClientSpiUtils.getEncodedJson;
import static org.wildfly.security.certificate.management.x500.cert.acme.AcmeClientSpiUtils.getEncodedSignature;
import static org.wildfly.security.certificate.management.x500.cert.acme.AcmeClientSpiUtils.getJws;
import static org.wildfly.security.certificate.management.x500.cert.acme.AcmeClientSpiUtils.getOptionalJsonString;
import static org.wildfly.security.certificate.management.x500.cert.acme.CertMgmtMessages.acme;
import static org.wildfly.security.certificate.management.x500.cert.util.KeyUtil.getDefaultCompatibleSignatureAlgorithmName;

import org.wildfly.security.certificate.management.x500.cert.X509CertificateChainAndSigningKey;

import javax.security.auth.x500.X500Principal;

/**
 * Asynchronous SPI for an <a href="https://www.ietf.org/id/draft-ietf-acme-acme-14.txt">Automatic Certificate Management Environment (ACME)</a>
 * client provider to implement. Based on org.wildfly.security.certificate.management.x500.cert.acme.AcmeClientSpi
 *
 */
public abstract class AsyncAcmeClientSpi {

    private static final long DEFAULT_RETRY_AFTER_MILLI = 3000;
    private static final String USER_AGENT_STRING = "Elytron ACME Client/" + "1.0.0.Alpha1-SNAPSHOT";
    public static final String CONTENT_TYPE = "Content-Type";
    public static final int MAX_RETRIES = 60;

    private static HttpClientSpi httpClient = getHttpClientInstance();

    private static HttpClientSpi getHttpClientInstance() {
        if (httpClient != null) {
            return httpClient;
        }
        Iterator<HttpClientSpi> httpClientIterator = ServiceLoader.load(HttpClientSpi.class).iterator();
        if (httpClientIterator.hasNext()) {
            return httpClientIterator.next();
        } else {
            return null;
        }
    }

    /**
     * Returns the implementation of an HttpRequestSpi loaded from classpath
     *
     * @return HttpRequestSpi instance found on classpath
     */

    HttpRequestSpi getNewHttpRequest() {
        Iterator<HttpRequestSpi> httprequestIterator = ServiceLoader.load(HttpRequestSpi.class).iterator();
        if (httprequestIterator.hasNext()) {
            return httprequestIterator.next();
        } else {
            return null;
        }
    }

    /**
     * Prove control of the identifier associated with the given list of challenges.
     * <p>
     * This method should select one challenge from the given list of challenges from the ACME server to prove
     * control of the identifier associated with the challenges as specified by the ACME v2 protocol.
     *
     * @param account the ACME account information to use (must not be {@code null})
     * @param challenges the list of challenges from the ACME server (must not be {@code null})
     * @return the challenge that was selected and used to prove control of the identifier
     * @throws AcmeException if an error occurs while attempting to provide control of the identifier associated
     * with the challenges or if none of the challenge types are supported by this client
     */
    protected abstract AcmeChallenge proveIdentifierControl(AcmeAccount account, List<AcmeChallenge> challenges) throws AcmeException;

    /**
     * Undo the actions that were taken to prove control of the identifier associated with the given challenge.
     *
     * @param account the ACME account information to use (must not be {@code null})
     * @param challenge the challenge (must not be {@code null})
     * @throws AcmeException if an error occurs while attempting to undo the actions that were taken to prove control
     * of the identifier associated with the given challenge
     */
    protected abstract void cleanupAfterChallenge(AcmeAccount account, AcmeChallenge challenge) throws AcmeException;

    /**
     * Get the resource URLs needed to perform operations from the ACME server.
     *
     * @param account the ACME account information to use (must not be {@code null})
     * @param staging whether or not the staging server URL should be used
     * @return an Uni with a map of ACME resources to URLs
     * @throws AcmeException if an error occurs while attempting to get the resource URLs from the ACME server
     */
    public Uni<Map<AcmeResource, URL>> getResourceUrls(AcmeAccount account, boolean staging) {
        if (account == null) {
            return Uni.createFrom().failure(new IllegalArgumentException("account"));
        }

        // TODO do we want caching of resourceURLs with async client? I am using it here same way as for sync client
        final Map<AcmeResource, URL> resourceUrls = account.getResourceUrls(staging);
        if (!resourceUrls.isEmpty()) {
            return Uni.createFrom().item(resourceUrls);
        }

        if (staging && account.getServerUrl(true) == null) {
            return Uni.createFrom().failure(acme.noAcmeServerStagingUrlGiven());
        }

        return sendGetRequest(account.getServerUrl(staging), HttpURLConnection.HTTP_OK, JSON_CONTENT_TYPE).map((HttpResponseSpi httpResponse) -> {
            JsonObject directoryJson;
            try {
                directoryJson = getJsonResponse(httpResponse);
            } catch (AcmeException e) {
                throw new RuntimeException(e);
            }
            for (AcmeResource resource : AcmeResource.values()) {
                String resourceUrl = getOptionalJsonString(directoryJson, resource.getValue());
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

    /**
     * Get the metadata associated with the ACME server.
     *
     * @param account the ACME account information to use (must not be {@code null})
     * @param staging whether or not the staging server URL should be used
     * @return a Uni with the metadata associated with the ACME server (may be {@code null})
     * @throws AcmeException if an error occurs while attempting to get the metadata associated with the ACME server
     */
    public Uni<AcmeMetadata> getMetadata(AcmeAccount account, boolean staging) {
        if (account == null) {
            return Uni.createFrom().failure(new IllegalArgumentException("account"));
        }
        if (staging && account.getServerUrl(true) == null) {
            return Uni.createFrom().failure(acme.noAcmeServerStagingUrlGiven());
        }

        Uni<HttpResponseSpi> httpResponseUni = sendGetRequest(account.getServerUrl(staging), HttpURLConnection.HTTP_OK, JSON_CONTENT_TYPE);

        return httpResponseUni.map((HttpResponseSpi httpResponse) -> {
                    JsonObject directoryJson;
                    try {
                        directoryJson = getJsonResponse(httpResponse);
                    } catch (AcmeException e) {
                        throw new RuntimeException(e);
                    }

                    JsonObject metadata = directoryJson.getJsonObject(META);
                    if (metadata == null) {
                        return null;
                    }
                    AcmeMetadata.Builder metadataBuilder = AcmeMetadata.builder();
                    String termsOfServiceUrl = getOptionalJsonString(metadata, Acme.TERMS_OF_SERVICE);
                    if (termsOfServiceUrl != null) {
                        metadataBuilder.setTermsOfServiceUrl(termsOfServiceUrl);
                    }
                    String websiteUrl = getOptionalJsonString(metadata, Acme.WEBSITE);
                    if (websiteUrl != null) {
                        metadataBuilder.setWebsiteUrl(websiteUrl);
                    }
                    JsonArray caaIdentitiesArray = metadata.getJsonArray(Acme.CAA_IDENTITIES);
                    if (caaIdentitiesArray != null) {
                        final List<String> caaIdentities = new ArrayList<>(caaIdentitiesArray.size());
                        for (JsonString caaIdentity : caaIdentitiesArray.getValuesAs(JsonString.class)) {
                            caaIdentities.add(caaIdentity.getString());
                        }
                        metadataBuilder.setCaaIdentities(caaIdentities.toArray(new String[caaIdentities.size()]));
                    }
                    boolean externalAccountRequired = metadata.getBoolean(Acme.EXTERNAL_ACCOUNT_REQUIRED, false);
                    metadataBuilder.setExternalAccountRequired(externalAccountRequired);
                    return metadataBuilder.build();
                })
                .onFailure().transform(Throwable::getCause);
    }

    /**
     * Get a new nonce for the given account from the ACME server.
     *
     * @param account the ACME account information to use (must not be {@code null})
     * @param staging whether or not the staging server URL should be used
     * @return a Uni with a nonce for the given account
     * @throws AcmeException if an error occurs while attempting to get the new nonce from the ACME server
     */
    public Uni<byte[]> getNewNonce(final AcmeAccount account, final boolean staging) {
        if (account == null) {
            return Uni.createFrom().failure(new IllegalArgumentException("account"));
        }

        return getResourceUrl(account, AcmeResource.NEW_NONCE, staging)
                .chain((URL newNonceUrl) -> {
                    final URI newNonceUri;
                    try {
                        newNonceUri = newNonceUrl.toURI();
                    } catch (URISyntaxException e) {
                        throw new RuntimeException(e);
                    }

                    HttpRequestSpi httpRequest = getNewHttpRequest();
                    httpRequest.setMethod("HEAD");
                    httpRequest.setURI(newNonceUri);
                    httpRequest.setHeader(ACCEPT_LANGUAGE, Collections.singletonList(Locale.getDefault().toLanguageTag()));
                    httpRequest.setHeader(USER_AGENT, Collections.singletonList(USER_AGENT_STRING));
                    return Uni.createFrom().future(httpClient.sendAsyncRequest(httpRequest));
                })
                .onFailure().transform(Throwable::getCause)
                .map((httpResponse) -> {
                    int responseCode = httpResponse.statusCode();
                    byte[] nonce;
                    try {
                        if (responseCode != HttpURLConnection.HTTP_OK && responseCode != HttpURLConnection.HTTP_NO_CONTENT) {
                            handleAcmeErrorResponse(httpResponse, responseCode);
                        }
                        nonce = getReplayNonce(httpResponse);
                        if (nonce == null) {
                            throw acme.noNonceProvidedByAcmeServer();
                        }
                    } catch (AcmeException e) {
                        throw new RuntimeException(e);
                    }
                    account.setNonce(nonce);
                    return nonce;
                });
    }

    /**
     * Create an account with an ACME server using the given account information.
     *
     * @param account the ACME account information to use (must not be {@code null})
     * @param staging whether or not the staging server URL should be used
     * @return Uni with a boolean {@code true} if the account was created, Uni with {@code false} if the account already existed
     * @throws AcmeException if an error occurs while attempting to create or lookup an account with
     * the ACME server
     */
    public Uni<Boolean> createAccount(AcmeAccount account, boolean staging) {
        return createAccount(account, staging, false);
    }

    /**
     * Create an account with an ACME server using the given account information.
     *
     * @param account the ACME account information to use (must not be {@code null})
     * @param staging whether or not the staging server URL should be used
     * @param onlyReturnExisting {@code true} if the ACME server should not create a new account if one does not
     *                           already exist (this allows an existing account's URL to be looked up and populated
     *                           using the account key)
     * @return {@code true} if the account was created, {@code false} if the account already existed
     * @throws AcmeException if an error occurs while attempting to create or lookup an account with the ACME server
     * or if {@code onlyReturnExisting} is set to {@code true} and the account does not exist
     */
    // TODO this should return account and not boolean
    // TODO concurrency problem with account variable between threads and different method calls
    public Uni<Boolean> createAccount(AcmeAccount account, boolean staging, boolean onlyReturnExisting) {
        if (account == null) {
            return Uni.createFrom().failure(new IllegalArgumentException("account"));
        }

        JsonObjectBuilder payloadBuilder = Json.createObjectBuilder();
        if (onlyReturnExisting) {
            payloadBuilder.add(ONLY_RETURN_EXISTING, true);
        } else {
            // create a new account
            payloadBuilder.add(TERMS_OF_SERVICE_AGREED, account.isTermsOfServiceAgreed());
            if (account.getContactUrls() != null && !(account.getContactUrls().length == 0)) {
                JsonArrayBuilder contactBuilder = Json.createArrayBuilder();
                for (String contactUrl : account.getContactUrls()) {
                    contactBuilder.add(contactUrl);
                }
                payloadBuilder.add(CONTACT, contactBuilder.build());
            }
        }

        return getResourceUrl(account, AcmeResource.NEW_ACCOUNT, staging)
                .onItem().transformToUni((URL newAccountUrl) -> {
                    return sendPostRequestWithRetries(account, staging, newAccountUrl.toString(), true, getEncodedJson(payloadBuilder.build()), HttpURLConnection.HTTP_OK, HttpURLConnection.HTTP_CREATED)
                            .onItem().transform(
                                    (HttpResponseSpi response) -> {
                                        try {
                                            account.setAccountUrl(getLocation(response, ACCOUNT));
                                        } catch (AcmeException e) {
                                            throw new RuntimeException(e);
                                        }
                                        return response.statusCode() == HttpURLConnection.HTTP_CREATED;
                                    })
                            .onFailure().transform(Throwable::getCause);
                });
    }

    /**
     * Update the contact URLs for an account with an ACME server.
     *
     * @param account the ACME account information to use (must not be {@code null})
     * @param staging whether or not the staging server URL should be used
     * @param contactUrls the new account contact URLs
     * @throws AcmeException if an error occurs while attempting to update the account
     */
    // TODO I think this hsould return success / failure based on response code
    public Uni<Void> updateAccount(AcmeAccount account, boolean staging, boolean termsOfServiceAgreed, String[] contactUrls) {
        Assert.checkNotNullParam("account", account);
        JsonObjectBuilder payloadBuilder = Json.createObjectBuilder()
                .add(TERMS_OF_SERVICE_AGREED, termsOfServiceAgreed);
        if (contactUrls != null && !(contactUrls.length == 0)) {
            JsonArrayBuilder contactBuilder = Json.createArrayBuilder();
            for (String contactUrl : contactUrls) {
                contactBuilder.add(contactUrl);
            }
            payloadBuilder.add(CONTACT, contactBuilder.build());
        }

        return getAccountUrl(account, staging).onItem().transformToUni((String b) -> {
            return sendPostRequestWithRetries(account, staging, b, false, getEncodedJson(payloadBuilder.build()), HttpURLConnection.HTTP_OK, HttpURLConnection.HTTP_CREATED)
                    .invoke((HttpResponseSpi a) -> {
                        account.setTermsOfServiceAgreed(termsOfServiceAgreed);
                        if (contactUrls != null && !(contactUrls.length == 0)) {
                            account.setContactUrls(contactUrls);
                        }
                    }).onItem().transformToUni((HttpResponseSpi ignored) -> Uni.createFrom().voidItem());
        });
    }

    /**
     * Change the key that is associated with the given ACME account. Account key is used to identify the user and their authorizations, and to sign the API calls to the ACME endpoint.
     *
     * @param account the ACME account information to use (must not be {@code null})
     * @param staging whether or not the staging server URL should be used
     * @throws AcmeException if an error occurs while attempting to change the key that is associated with the given ACME account
     */
    public Uni<Void> changeAccountKey(AcmeAccount account, boolean staging) {
        Assert.checkNotNullParam("account", account);
        SelfSignedX509CertificateAndSigningKey newCertificateAndSigningKey = SelfSignedX509CertificateAndSigningKey.builder()
                .setKeySize(account.getKeySize())
                .setKeyAlgorithmName(account.getKeyAlgorithmName())
                .setDn(account.getDn())
                .build();
        return changeAccountKey(account, staging, newCertificateAndSigningKey.getSelfSignedCertificate(), newCertificateAndSigningKey.getSigningKey());
    }

    /**
     * Change the key that is associated with the given ACME account.
     *
     * @param account the ACME account information to use (must not be {@code null})
     * @param staging whether or not the staging server URL should be used
     * @param certificate the new certificate to associate with the given ACME account (must not be {@code null})
     * @param privateKey the new private key to associate with the given ACME account (must not be {@code null})
     * @throws AcmeException if an error occurs while attempting to change the key that is associated with the given ACME account
     */
    public Uni<Void> changeAccountKey(AcmeAccount account, boolean staging, X509Certificate certificate, PrivateKey privateKey) {
        Assert.checkNotNullParam("account", account);
        Assert.checkNotNullParam("certificate", certificate);
        Assert.checkNotNullParam("privateKey", privateKey);

        return getResourceUrl(account, AcmeResource.KEY_CHANGE, staging).onItem().transformToUni((URL resourceUrl) -> {
            final String keyChangeUrl = resourceUrl.toString();
            final String signatureAlgorithm = getDefaultCompatibleSignatureAlgorithmName(privateKey);
            final String algHeader = getAlgHeaderFromSignatureAlgorithm(signatureAlgorithm);
            final String innerEncodedProtectedHeader = getEncodedProtectedHeader(algHeader, certificate.getPublicKey(), keyChangeUrl);

            return getAccountUrl(account, staging).onItem().transformToUni((String accountURL) -> {
                JsonObjectBuilder innerPayloadBuilder = Json.createObjectBuilder()
                        .add(ACCOUNT, accountURL)
                        .add(OLD_KEY, getJwk(account.getPublicKey(), account.getAlgHeader()));
                final String innerEncodedPayload = getEncodedJson(innerPayloadBuilder.build());
                final String innerEncodedSignature;
                try {
                    innerEncodedSignature = getEncodedSignature(privateKey, signatureAlgorithm, innerEncodedProtectedHeader, innerEncodedPayload);
                    final String outerEncodedPayload = getEncodedJson(getJws(innerEncodedProtectedHeader, innerEncodedPayload, innerEncodedSignature));

                    return sendPostRequestWithRetries(account, staging, keyChangeUrl, false, outerEncodedPayload, HttpURLConnection.HTTP_OK).invoke((HttpResponseSpi response) -> {
                        account.changeCertificateAndPrivateKey(certificate, privateKey); // update account info

                    });
                } catch (AcmeException e) {
                    throw new RuntimeException(e);
                }
            });
        }).onItem().transformToUni((HttpResponseSpi ignored) -> Uni.createFrom().voidItem());
    }

    /**
     * Obtain a certificate chain using the given ACME account.
     *
     * @param account the ACME account information to use (must not be {@code null})
     * @param staging whether or not the staging server URL should be used
     * @param domainNames the domain names to request the certificate for (must not be {@code null})
     * @return the X509 certificate chain and private key
     * @throws AcmeException if an occur occurs while attempting to obtain the certificate
     */
    public Uni<X509CertificateChainAndSigningKey> obtainCertificateChain(AcmeAccount account, boolean staging, String... domainNames) throws AcmeException {
        return obtainCertificateChain(account, staging, null, -1, domainNames);
    }

    // TODO is it better to send Tuples instead of having this class?
    class OrderUrlInformation {
        String orderUrl;
        String finalizeOrderUrl;

        public void setOrderUrl(String orderUrl) {
            this.orderUrl = orderUrl;
        }

        public void setFinalizeOrderUrl(String finalizeOrderUrl) {
            this.finalizeOrderUrl = finalizeOrderUrl;
        }
    }

    /**
     * Obtain a certificate chain using the given ACME account.
     *
     * @param account the ACME account information to use (must not be {@code null})
     * @param staging whether or not the staging server URL should be used
     * @param keyAlgorithmName the optional key algorithm name to use when generating the key pair (may be {@code null})
     * @param keySize the optional key size to use when generating the key pair (-1 to indicate that the default key size should be used)
     * @param domainNames the domain names to request the certificate for (must not be {@code null})
     * @return the X509 certificate chain and private key
     * @throws AcmeException if an occur occurs while attempting to obtain the certificate
     */
    public Uni<X509CertificateChainAndSigningKey> obtainCertificateChain(final AcmeAccount account, final boolean staging, final String keyAlgorithmName, final int keySize,
                                                                         String... domainNames) throws AcmeException {
        Assert.checkNotNullParam("account", account);
        Assert.checkNotNullParam("domainNames", domainNames);
        final LinkedHashSet<String> domainNamesSet = getDomainNames(domainNames);
        final OrderUrlInformation orderUrlInfo = new OrderUrlInformation();

        // create a new order
        return getResourceUrl(account, AcmeResource.NEW_ORDER, staging).onItem().transformToUni((URL newOrderUrl) -> {
            JsonArrayBuilder identifiersBuilder = Json.createArrayBuilder();
            for (String domainName : domainNamesSet) {
                JsonObject identifier = Json.createObjectBuilder()
                        .add(TYPE, DNS)
                        .add(VALUE, domainName)
                        .build();
                identifiersBuilder.add(identifier);
            }
            JsonObjectBuilder payloadBuilder = Json.createObjectBuilder()
                    .add(IDENTIFIERS, identifiersBuilder.build());
            return sendPostRequestWithRetries(account, staging, newOrderUrl.toString(), false, getEncodedJson(payloadBuilder.build()), HttpURLConnection.HTTP_CREATED)
                    .onItem()
                    .transformToMulti((HttpResponseSpi connection) -> {
                        String orderUrl;
                        JsonObject jsonResponse = null;
                        try {
                            orderUrl = getLocation(connection, ORDER);
                            jsonResponse = getJsonResponse(connection);
                        } catch (AcmeException e) {
                            throw new RuntimeException(e);
                        }
                        final String finalizeOrderUrl = jsonResponse.getString(FINALIZE);
                        orderUrlInfo.setOrderUrl(orderUrl);
                        orderUrlInfo.setFinalizeOrderUrl(finalizeOrderUrl);
                        final JsonArray authorizationsArray = jsonResponse.getJsonArray(AUTHORIZATIONS);
                        final List<String> authorizationUrls = new ArrayList<>(authorizationsArray.size());
                        for (JsonString authorization : authorizationsArray.getValuesAs(JsonString.class)) {
                            authorizationUrls.add(authorization.getString());
                        }
                        // respond to challenges for each authorization resource
                        return Multi
                                .createFrom()
                                .iterable(authorizationUrls);

                    }).onItem().transformToUniAndConcatenate((String authorizationUrl) -> {
                        // poll the authorization resources until server has finished validating the challenge responses
                        return sendPostAsGetRequest(account, staging, authorizationUrl, JSON_CONTENT_TYPE, HttpURLConnection.HTTP_OK)
                                .onItem().transformToUni(responseSpi -> {
                                    try {
                                        JsonObject jsonObjectResponse = getJsonResponse(responseSpi);
                                        return respondToChallenges(account, staging, jsonObjectResponse);
                                    } catch (AcmeException e) {
                                        throw new RuntimeException(e);
                                    }
                                }).onItem().transform(acmeChallenge -> {
                                    return Tuple2.of(authorizationUrl, acmeChallenge);
                                });
                    }).onItem().transformToUniAndConcatenate(authUrlWithAcmeChallenge -> {
                        return pollResourceUntilFinalized(account, staging, authUrlWithAcmeChallenge.getItem1()).onItem().transform(jsonResponse -> {
                            if (!jsonResponse.getString(STATUS).equals(VALID)) {
                                throw new RuntimeException(acme.challengeResponseFailedValidationByAcmeServer());
                            }
                            return authUrlWithAcmeChallenge.getItem2();
                        });
                    }).select().where(Objects::nonNull).collect().asList().onItem().transformToUni((acmeChallenges) -> {
                        // create and submit a CSR now that we've fulfilled the server's requirements
                        List<GeneralName> generalNames = new ArrayList<>(domainNamesSet.size());
                        for (String domainName : domainNamesSet) {
                            generalNames.add(new GeneralName.DNSName(domainName));
                        }
                        X500PrincipalBuilder principalBuilder = new X500PrincipalBuilder();
                        principalBuilder.addItem(X500AttributeTypeAndValue.create(X500.OID_AT_COMMON_NAME, ASN1Encodable.ofUtf8String(((GeneralName.DNSName) generalNames.get(0)).getName())));
                        X500Principal dn = principalBuilder.build();
                        String keyAlgorithmName2 = keyAlgorithmName;
                        int keySize2 = keySize;
                        if (keyAlgorithmName2 == null) {
                            keyAlgorithmName2 = DEFAULT_KEY_ALGORITHM_NAME;
                        }
                        if (keySize2 == -1) {
                            if (keyAlgorithmName2.equals("EC")) {
                                keySize2 = DEFAULT_EC_KEY_SIZE;
                            } else {
                                keySize2 = DEFAULT_KEY_SIZE;
                            }
                        }

                        SelfSignedX509CertificateAndSigningKey selfSignedX509CertificateAndSigningKey = SelfSignedX509CertificateAndSigningKey.builder()
                                .setDn(dn)
                                .setKeyAlgorithmName(keyAlgorithmName2)
                                .setKeySize(keySize2)
                                .build();
                        PKCS10CertificateSigningRequest.Builder csrBuilder = PKCS10CertificateSigningRequest.builder()
                                .setCertificate(selfSignedX509CertificateAndSigningKey.getSelfSignedCertificate())
                                .setSigningKey(selfSignedX509CertificateAndSigningKey.getSigningKey())
                                .setSubjectDn(dn);
                        csrBuilder.addExtension(new SubjectAlternativeNamesExtension(false, generalNames));

                        JsonObjectBuilder payloadBuilder2 = Json.createObjectBuilder()
                                .add(CSR, base64UrlEncode(csrBuilder.build().getEncoded()));
                        return sendPostRequestWithRetries(account, staging, orderUrlInfo.finalizeOrderUrl, false, getEncodedJson(payloadBuilder2.build()), HttpURLConnection.HTTP_OK).onItem().transformToUni((connection2) -> {
                            return pollResourceUntilFinalized(account, staging, orderUrlInfo.orderUrl).onItem().transform((JsonObject jsonResponse) -> {
                                if (!jsonResponse.getString(STATUS).equals(VALID)) {
                                    throw new RuntimeException(acme.noCertificateWillBeIssuedByAcmeServer());
                                }

                                // download the certificate chain
                                String certificateUrl = AcmeClientSpiUtils.getOptionalJsonString(jsonResponse, CERTIFICATE);
                                if (certificateUrl == null) {
                                    throw new RuntimeException(acme.noCertificateUrlProvidedByAcmeServer());
                                }
                                return certificateUrl;
                            }).onItem().transformToUni((String certificateUrl) -> {
                                // download the certificate chain
                                return sendPostAsGetRequest(account, staging, certificateUrl, PEM_CERTIFICATE_CHAIN_CONTENT_TYPE, HttpURLConnection.HTTP_OK).onItem().transform((HttpResponseSpi certResponse) -> {
                                    X509Certificate[] certificateChain;
                                    try {
                                        certificateChain = getPemCertificateChain(certResponse);
                                    } catch (AcmeException e) {
                                        throw new RuntimeException(e);
                                    }
                                    PrivateKey privateKey = selfSignedX509CertificateAndSigningKey.getSigningKey();
                                    return new X509CertificateChainAndSigningKey(certificateChain, privateKey);
                                });

                            }).onItemOrFailure().invoke(() -> {
                                try {
                                    for (AcmeChallenge challenge : acmeChallenges) {
                                        cleanupAfterChallenge(account, challenge);
                                    }
                                } catch (AcmeException e) {
                                    throw new RuntimeException(e);
                                }
                            });
                        });
                    });
        });
    }



    private static String getLocation(HttpResponseSpi connection, String urlType) throws AcmeException {
        List<String> locationHeaderValues = connection.getHeaderValues(LOCATION);
        String location = locationHeaderValues != null && !locationHeaderValues.isEmpty() ? locationHeaderValues.get(0) : null;
        if (location == null) {
            throw acme.noLocationUrlProvidedByAcmeServer(urlType);
        }
        return location;
    }

    private Uni<HttpResponseSpi> sendPostRequestWithRetries(AcmeAccount account, boolean staging, String resourceUrl, boolean useJwk, String encodedPayload,
                                                            int... expectedResponseCodes) {
        return sendPostRequestWithRetries(account, staging, resourceUrl, useJwk, encodedPayload, null, expectedResponseCodes);
    }

    private Uni<HttpResponseSpi> sendPostRequestWithRetries(AcmeAccount account, boolean staging, String resourceUrl, boolean useJwk, String encodedPayload,
                                                            String expectedContentType, int... expectedResponseCodes) {
        URI resourceUri;
        try {
            resourceUri = new URI(resourceUrl);
        } catch (URISyntaxException e) {
            return Uni.createFrom().failure(e);
        }
        final URI finalResourceUri = resourceUri;
        return getEncodedProtectedHeader(useJwk, resourceUrl, account, staging).onItem().transformToUni((String encodedProtectedHeader) -> {
            HttpRequestSpi httpRequest = getNewHttpRequest();
            String encodedSignature;
            try {
                encodedSignature = getEncodedSignature(account.getPrivateKey(), account.getSignature(), encodedProtectedHeader, encodedPayload);
            } catch (AcmeException e) {
                return Uni.createFrom().failure(e);
            }
            JsonObject jws = getJws(encodedProtectedHeader, encodedPayload, encodedSignature);
            httpRequest.setURI(finalResourceUri);
            httpRequest.setMethod(POST);
            httpRequest.setHeader(Acme.CONTENT_TYPE, Collections.singletonList(JOSE_JSON_CONTENT_TYPE));
            httpRequest.setHeader(ACCEPT_LANGUAGE, Collections.singletonList(Locale.getDefault().toLanguageTag()));
            httpRequest.setHeader(USER_AGENT, Collections.singletonList(USER_AGENT_STRING));
            httpRequest.setBody(jws.toString());
            return Uni
                    .createFrom()
                    .future(httpClient.sendAsyncRequest(httpRequest))
                    .onItem()
                    .transformToUni((HttpResponseSpi httpResponse) -> {
                        int responseCode = httpResponse.statusCode();
                        try {
                            for (int expectedResponseCode : expectedResponseCodes) {
                                account.setNonce(getReplayNonce(httpResponse)); // update the account nonce
                                if (expectedResponseCode == responseCode) {
                                    if (expectedContentType != null) {
                                        List<String> contentTypeHeaderValues = httpResponse.getHeaderValues(Acme.CONTENT_TYPE);
                                        String contentType = contentTypeHeaderValues != null && !contentTypeHeaderValues.isEmpty() ? contentTypeHeaderValues.get(0) : null;
                                        if (!checkContentType(contentType, expectedContentType)) {
                                            return Uni.createFrom().failure(acme.unexpectedContentTypeFromAcmeServer(contentType));
                                        }
                                    }
                                    return Uni.createFrom().item(httpResponse);
                                }
                            }
                            handleAcmeErrorResponse(httpResponse, responseCode);
                        } catch (AcmeException e) {
                            return Uni.createFrom().failure(e);
                        }
                        return Uni.createFrom().failure(acme.badAcmeNonce()); // request failed
                    })
                    .onFailure()
                    .retry().atMost(MAX_RETRIES); // retry MAX_RETRIES times
        });
    }

    Uni<String> queryAccountStatus(AcmeAccount account, boolean staging) {
        Assert.checkNotNullParam("account", account);
        return getAccountUrl(account, staging).onItem().transformToUni((String accountUrl) -> {
            return sendPostAsGetRequest(account, staging, accountUrl, null, HttpURLConnection.HTTP_OK)
                    .map((HttpResponseSpi response) -> {
                        JsonObject jsonResponse = null;
                        try {
                            jsonResponse = getJsonResponse(response);
                        } catch (AcmeException e) {
                            throw new RuntimeException(e);
                        }
                        return jsonResponse.getString(STATUS);
                    });
        });
    }

    Uni<String[]> queryAccountContactUrls(AcmeAccount account, boolean staging) {
        Assert.checkNotNullParam("account", account);
        return getAccountUrl(account, staging).onItem().transformToUni((String accountUrl) -> {
            return sendPostAsGetRequest(account, staging, accountUrl, null, HttpURLConnection.HTTP_OK).map((HttpResponseSpi response) -> {
                JsonObject jsonResponse = null;
                try {
                    jsonResponse = getJsonResponse(response);
                } catch (AcmeException e) {
                    throw new RuntimeException(e);
                }
                JsonArray contactsArray = jsonResponse.getJsonArray(CONTACT);
                if (contactsArray != null && !contactsArray.isEmpty()) {
                    List<String> contacts = new ArrayList<>(contactsArray.size());
                    for (JsonString contact : contactsArray.getValuesAs(JsonString.class)) {
                        contacts.add(contact.getString());
                    }
                    return contacts.toArray(new String[contacts.size()]);
                }
                return null;
            });
        });
    }

    private Uni<HttpResponseSpi> sendPostAsGetRequest(AcmeAccount account, boolean staging, String resourceUrl,
                                                      String expectedContentType, int... expectedResponseCodes) {
        // payload of the JWS must be a zero-length octet string
        return sendPostRequestWithRetries(account, staging, resourceUrl, false, "",
                expectedContentType, expectedResponseCodes);
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

    private static byte[] getReplayNonce(HttpResponseSpi httpResponse) {
        String nonce = httpResponse.getHeaderValues(REPLAY_NONCE).get(0);
        if (nonce == null) {
            return null;
        }
        return CodePointIterator.ofString(nonce).base64Decode(BASE64_URL, false).drain();
    }

    private static String getEncodedProtectedHeader(String algHeader, PublicKey publicKey, String resourceUrl) {
        JsonObject protectedHeader = Json.createObjectBuilder()
                .add(ALG, algHeader)
                .add(JWK, getJwk(publicKey, algHeader))
                .add(URL, resourceUrl)
                .build();
        return getEncodedJson(protectedHeader);
    }

    private Uni<String> getEncodedProtectedHeader(boolean useJwk, String resourceUrl, AcmeAccount account, boolean staging) {
        JsonObjectBuilder protectedHeaderBuilder = Json.createObjectBuilder().add(ALG, account.getAlgHeader());
        if (useJwk) {
            return getNonce(account, staging).onItem().transform((byte[] nonce) -> {
                protectedHeaderBuilder.add(NONCE, base64UrlEncode(nonce))
                        .add(URL, resourceUrl);
                protectedHeaderBuilder.add(JWK, getJwk(account.getPublicKey(), account.getAlgHeader()));
                return getEncodedJson(protectedHeaderBuilder.build());
            });
        } else {
            return getNonce(account, staging).onItem().transformToUni((byte[] nonce) -> {
                protectedHeaderBuilder.add(NONCE, base64UrlEncode(nonce))
                        .add(URL, resourceUrl);
                return getAccountUrl(account, staging).onItem().transform((String accountUrl) -> {
                    protectedHeaderBuilder.add(KID, accountUrl);
                    return getEncodedJson(protectedHeaderBuilder.build());
                });
            });
        }
    }

    private Uni<byte[]> getNonce(AcmeAccount account, boolean staging) {
        byte[] nonce = account.getNonce();
        if (nonce == null) {
            return getNewNonce(account, staging);
        }
        return Uni.createFrom().item(nonce);
    }

    private Uni<String> getAccountUrl(AcmeAccount account, boolean staging) {
        String accountUrl = account.getAccountUrl();
        if (accountUrl == null) {
            return createAccount(account, staging, true).map((Boolean ignored) -> {
                        String obtainedAccountUrl = account.getAccountUrl();
                        if (obtainedAccountUrl == null) {
                            try {
                                throw acme.acmeAccountDoesNotExist();
                            } catch (AcmeException e) {
                                throw new RuntimeException(e);
                            }
                        }
                        return obtainedAccountUrl;
                    }
            );
        }
        return Uni.createFrom().item(accountUrl);
    }

    private Uni<HttpResponseSpi> sendGetRequest(String resourceUrl, int expectedResponseCode, String expectedContentType) {
        HttpRequestSpi httpRequest;
        try {
            httpRequest = getNewHttpRequest();
            httpRequest.setMethod(GET);
            httpRequest.setURI(new URI(resourceUrl));
            httpRequest.setHeader(ACCEPT_LANGUAGE, Collections.singletonList(Locale.getDefault().toLanguageTag()));
            httpRequest.setHeader(USER_AGENT, Collections.singletonList(USER_AGENT_STRING));

            return Uni.createFrom().future(httpClient.sendAsyncRequest(httpRequest))
                    .chain((HttpResponseSpi httpResponse) -> {
                        try {
                            int responseCode = httpResponse.statusCode();
                            if (responseCode != expectedResponseCode) {
                                handleAcmeErrorResponse(httpResponse, responseCode);
                            }
                            String contentType = httpResponse.getHeaderValues(CONTENT_TYPE).get(0);
                            if (!checkContentType(contentType, expectedContentType)) {
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

    private static void handleAcmeErrorResponse(HttpResponseSpi connection, int responseCode) throws AcmeException {
        try {
            String responseMessage = connection.body();
            List<String> headerValues = connection.getHeaderValues(CONTENT_TYPE);
            if (headerValues.isEmpty() || !checkContentType(headerValues.get(0), PROBLEM_JSON_CONTENT_TYPE)) {
                throw acme.unexpectedResponseCodeFromAcmeServer(responseCode, responseMessage);
            }
            JsonObject jsonResponse = getJsonResponse(connection);
            String type = getOptionalJsonString(jsonResponse, TYPE);
            if (type != null) {
                switch (type) {
                    case BAD_NONCE:
                        return;
                    case USER_ACTION_REQUIRED:
                        String instance = getOptionalJsonString(jsonResponse, INSTANCE);
                        if (instance != null) {
                            throw acme.userActionRequired(instance);
                        }
                        break;
                    case RATE_LIMITED:
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

    private static JsonObject getJsonResponse(HttpResponseSpi connection) throws AcmeException {
        JsonObject jsonResponse;
        try (InputStream inputStream = new ByteArrayInputStream(connection.body().getBytes());
             JsonReader jsonReader = Json.createReader(inputStream)) {
            jsonResponse = jsonReader.readObject();
        } catch (IOException e) {
            throw acme.unableToObtainJsonResponseFromAcmeServer(e);
        }
        return jsonResponse;
    }

    private static long getRetryAfter(HttpResponseSpi connection, boolean useDefaultIfHeaderNotPresent) {
        long retryAfterMilli = -1;
        String retryAfter = connection.getHeaderValues(RETRY_AFTER) != null && !connection.getHeaderValues(RETRY_AFTER).isEmpty() ? connection.getHeaderValues(RETRY_AFTER).get(0) : null;
        if (retryAfter != null) {
            try {
                retryAfterMilli = Integer.parseInt(retryAfter) * 1000L;
            } catch (NumberFormatException e) {
                long retryAfterDate = Long.parseLong(connection.getHeaderValues(RETRY_AFTER).get(0));
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

    private static X509Certificate[] getPemCertificateChain(HttpResponseSpi httpResponseSpi) throws AcmeException {
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            Collection<? extends Certificate> reply;
            try (InputStream inputStream = new BufferedInputStream(getConvertedInputStream(new ByteArrayInputStream(httpResponseSpi.body().getBytes())))) {
                reply = certificateFactory.generateCertificates(inputStream);
            }
            return X500.asX509CertificateArray(reply.toArray(new Certificate[reply.size()]));
        } catch (CertificateException | IOException e) {
            throw acme.unableToDownloadCertificateChainFromAcmeServer(e);
        }
    }

    private Uni<JsonObject> pollResourceUntilFinalized(AcmeAccount account, boolean staging, String resourceUrl) {

        Uni<JsonObject> responseJsonObject =
                sendPostAsGetRequest(account, staging, resourceUrl, JSON_CONTENT_TYPE, HttpURLConnection.HTTP_OK)
                        .onItem()
                        .transform((HttpResponseSpi httpResponseSpi) -> {

                            JsonObject jsonResponse;
                            try {
                                jsonResponse = getJsonResponse(httpResponseSpi);
                            } catch (AcmeException e) {
                                throw new RuntimeException(e);
                            }
                            String status = jsonResponse.getString(STATUS);
                            if (!status.equals(VALID) && !status.equals(INVALID)) {
                                // server still processing the client response, try again after some time
                                throw new RuntimeException("status is pending");
                            }
                            return jsonResponse;
                        });

//        return responseJsonObject.onFailure().transform(failure -> {
//            int iteration = index.getAndIncrement();
//            if (iteration >= MAX_RETRIES) {
//                failure.addSuppressed(
//                        new IllegalStateException("Retries exhausted: " + iteration + "/" + numRetries, failure));
//                return failure;
//            } else {
//                Duration delay = getNextDelay(firstBackoff, maxBackoff, jitterFactor, iteration);
//                return Uni.createFrom().item((long) iteration).onItem().delayIt()
//                        .onExecutor(executor).by(delay);
//            }
//        }).retry().atMost(50);
        // TODO there is no delay now but we should use the header. mutiny should allow configuration of the delay based on the failure or the delay should be a function that is configurable so that we can extract RETRY_AFTER header value from the response.
//        return responseJsonObject.onFailure().retry().withBackOff(Duration.ofSeconds(3) ,Duration.ofSeconds(3)).atMost(MAX_RETRIES);
        // TODO DO NOT BRUTE FORCE, MUST have a delay based on header
        return responseJsonObject.onFailure().retry().atMost(MAX_RETRIES);
    }

    private Uni<AcmeChallenge> respondToChallenges(AcmeAccount account, boolean staging, JsonObject authorization) throws AcmeException {
        List<AcmeChallenge> challenges = null;
        if (authorization.getString(STATUS).equals(PENDING)) {
            JsonObject identifier = authorization.getJsonObject(IDENTIFIER);
            JsonArray challengeArray = authorization.getJsonArray(CHALLENGES);
            challenges = new ArrayList<>(challengeArray.size());
            for (JsonObject challenge : challengeArray.getValuesAs(JsonObject.class)) {
                challenges.add(new AcmeChallenge(AcmeChallenge.Type.forName(challenge.getString(TYPE)), challenge.getString(URL),
                        challenge.getString(TOKEN), identifier.getString(TYPE), identifier.getString(VALUE)));
            }
        }
        if (challenges != null && !challenges.isEmpty()) {
            AcmeChallenge selectedChallenge = proveIdentifierControl(account, challenges);
            return sendPostRequestWithRetries(account, staging, selectedChallenge.getUrl(), false, getEncodedJson(EMPTY_PAYLOAD), HttpURLConnection.HTTP_OK)
                    .map((HttpResponseSpi ignored) -> selectedChallenge).onFailure().invoke(() -> {
                        try {
                            cleanupAfterChallenge(account, selectedChallenge);
                        } catch (AcmeException e) {
                            throw new RuntimeException(e);
                        }
                    });
        }
        return null;
    }
}
