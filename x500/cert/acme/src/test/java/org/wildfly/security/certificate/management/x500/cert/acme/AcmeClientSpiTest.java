/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2018 Red Hat, Inc., and individual contributors
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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.ACCOUNT;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.BASE64_URL;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.ORDER;

import org.apache.commons.io.IOUtils;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.matchers.Times;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;
import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.certificate.management.x500.cert.X509CertificateChainAndSigningKey;

import java.io.BufferedInputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CRLReason;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;

import javax.security.auth.x500.X500Principal;

import mockit.Mock;
import mockit.MockUp;
import okhttp3.mockwebserver.MockWebServer;


/**
 * Tests for the Automatic Certificate Management Environment (ACME) client SPI. These tests simulate a mock Let's Encrypt
 * server by using messages that were actually sent from Boulder (Let's Encrypt's testing server) to our ACME client.
 * Wireshark was used to record the messages. The use of these recorded messages prevents us from having to integrate the
 * complex Boulder setup into the Elytron testsuite.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
@RunWith(Parameterized.class)
public class AcmeClientSpiTest {

    private static AcmeAccount.Builder populateBasicBuilder() throws Exception {
        AcmeAccount.Builder builder = AcmeAccount.builder()
                .setTermsOfServiceAgreed(true)
                .setContactUrls(new String[] { "mailto:admin@anexample.com" } )
                .setServerUrl("http://localhost:4001/directory");
        return builder;
    }

    private static AcmeAccount.Builder populateBuilder() throws Exception {
        AcmeAccount.Builder builder = AcmeAccount.builder()
                .setTermsOfServiceAgreed(true)
                .setContactUrls(new String[] { "mailto:admin@myexample.com" } )
                .setServerUrl("http://localhost:4001/directory");
        return builder;
    }

    private static final String KEYSTORE = "account.keystore";
    private static final char[] KEYSTORE_PASSWORD = "elytron".toCharArray();
    private static final String ACCOUNT_1_V2 = "account1v2";
    private static final String ACCOUNT_2_V2 = "account2v2";
    private static final String ACCOUNT_3_V2 = "account3v2";
    private static final String ACCOUNT_4_V2 = "account4v2";
    private static final String ACCOUNT_5_V2 = "account5v2";
    private static final String ACCOUNT_6_V2 = "account6v2";
    private static final String ACCOUNT_7_V2 = "account7v2";
    private static final String ACCOUNT_8_V2 = "account8v2";
    private static final String ACCOUNT_9_V2 = "account9v2";
    private static final String REVOKE_ALIAS_V2 = "revokealiasv2";
    private static final String REVOKE_WITH_REASON_ALIAS_V2 = "revokewithreasonaliasv2";
    private static final String NEW_KEY_ALIAS_V2 = "newkeyv2";
    private static final String NEW_EC_KEY_ALIAS_V2 = "neweckeyv2";
    private static HashMap<String, X509Certificate> aliasToCertificateMap;
    private static HashMap<String, PrivateKey> aliasToPrivateKeyMap;
    private static ClientAndServer server; // used to simulate a Let's Encrypt server instance
    private static MockWebServer client; // used to simulate a WildFly instance

    @Parameter
    public static SimpleDelegatingAcmeClient acmeClient = null;

    @Parameters
    public static Iterable<? extends Object> data() {
        return Arrays.asList(new SimpleDelegatingAcmeClient(false), new SimpleDelegatingAcmeClient(true));
    }

    private static void mockRetryAfter() {
        Class<?> classToMock;
        try {
            classToMock = Class.forName("org.wildfly.security.certificate.management.x500.cert.acme.AcmeClientSpi", true, AcmeAccount.class.getClassLoader());
        } catch (ClassNotFoundException e) {
            throw new NoClassDefFoundError(e.getMessage());
        }
        new MockUp<Object>(classToMock) {
            @Mock
            private long getRetryAfter(HttpURLConnection connection, boolean useDefaultIfHeaderNotPresent) throws AcmeException {
                return 0;
            }
        };
    }

    @BeforeClass
    public static void setUp() throws Exception {
        mockRetryAfter(); // no need to sleep in between polling attempts during testing
        KeyStore keyStore = KeyStore.getInstance("jks");
        try (InputStream is = AcmeClientSpiTest.class.getResourceAsStream(KEYSTORE)) {
            keyStore.load(is, KEYSTORE_PASSWORD);
        }

        int numAliases = keyStore.size();
        aliasToCertificateMap = new HashMap<>(numAliases);
        aliasToPrivateKeyMap = new HashMap<>(numAliases);
        final Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            aliasToCertificateMap.put(alias, (X509Certificate) keyStore.getCertificate(alias));
            aliasToPrivateKeyMap.put(alias, (PrivateKey) keyStore.getKey(alias, KEYSTORE_PASSWORD));
        }
        server = new ClientAndServer(4001);
        client = new MockWebServer();
        client.start(5002); // this is the port our mock Let's Encrypt server will use to access the client, can also use client.start(InetAddress.getByName("172.17.0.1"), 5002); when running boulder server locally
    }

    @AfterClass
    public static void shutdownMockClientAndServer() throws Exception {
        if (client != null) {
            client.shutdown();
        }
        if (server != null) {
            server.stop();
        }
    }

    @Before
    public void resetServerExpectations() {
        server = (ClientAndServer) server.reset();
    }

    @Test
    public void testCreateAccount() throws Exception {
        final String NEW_ACCT_LOCATION = "http://localhost:4001/acme/acct/384";
        server = setupTestCreateAccount();
        AcmeAccount account = populateBasicAccount(ACCOUNT_1_V2);
        assertNull(account.getAccountUrl());
        acmeClient.createAccount(account, false);
        assertEquals(NEW_ACCT_LOCATION, account.getAccountUrl());
    }

    @Test
    public void testCreateAccountMissingLocationURL() throws Exception {
        server = setupTestCreateAccount(true);
        AcmeAccount account = populateBasicAccount(ACCOUNT_1_V2);
        assertNull(account.getAccountUrl());

        try {
            acmeClient.createAccount(account, false);
            fail("Expected AcmeException not thrown");
        } catch(AcmeException e) {
            assertTrue(e.getMessage().contains(ACCOUNT));
        }
    }

    @Test
    public void testCreateAccountOnlyReturnExisting() throws Exception {
        final String NEW_ACCT_LOCATION_1 = "http://localhost:4001/acme/acct/387";
        server = setupTestCreateAccountOnlyReturnExisting();
        AcmeAccount account = populateBasicAccount(ACCOUNT_2_V2);
        acmeClient.createAccount(account, false);
        assertEquals(NEW_ACCT_LOCATION_1, account.getAccountUrl());
        AcmeAccount sameAccount = populateBasicAccount(ACCOUNT_2_V2);

        // the key corresponding to ACCOUNT_2 is associated with an already registered account
        acmeClient.createAccount(sameAccount, false, true);
        assertEquals(account.getAccountUrl(), sameAccount.getAccountUrl());

        AcmeAccount newAccount = populateBasicAccount(ACCOUNT_3_V2);
        try {
            // the key corresponding to ACCOUNT_3 is not associated with an already registered account
            acmeClient.createAccount(newAccount, false, true);
            fail("Expected AcmeException not thrown");
        } catch (AcmeException expected) {
        }
    }

    @Test
    public void testCreateAccountWithECPublicKey() throws Exception {
        final String NEW_ACCT_LOCATION = "http://localhost:4001/acme/acct/389";
        server = setupTestCreateAccountWithECPublicKey();
        AcmeAccount account = populateBasicAccount(ACCOUNT_4_V2);
        assertNull(account.getAccountUrl());
        acmeClient.createAccount(account, false);
        assertEquals(NEW_ACCT_LOCATION, account.getAccountUrl());
    }

    @Test
    public void testUpdateAccount() throws Exception {
        final String ACCT_LOCATION = "http://localhost:4001/acme/acct/5";
        server = setupTestUpdateAccount();
        AcmeAccount account = populateAccount(ACCOUNT_1_V2);
        account.setAccountUrl(ACCT_LOCATION);
        String[] contacts = new String[] { "mailto:certificates@examples.com", "mailto:admin@examples.com"};
        acmeClient.updateAccount(account, false, false, contacts);
        assertFalse(account.isTermsOfServiceAgreed());

        String[] updatedContacts = acmeClient.queryAccountContactUrls(account, false);
        assertArrayEquals(contacts, updatedContacts);

        acmeClient.updateAccount(account, false, false, null);
        updatedContacts = acmeClient.queryAccountContactUrls(account, false);
        assertArrayEquals(contacts, updatedContacts);
    }

    @Test
    public void testDeactivateAccount() throws Exception {
        final String ACCT_LOCATION = "http://localhost:4001/acme/acct/17";
        server = setupTestDeactivateAccount();
        AcmeAccount account = populateAccount(ACCOUNT_5_V2);
        account.setAccountUrl(ACCT_LOCATION);
        assertEquals(Acme.VALID, acmeClient.queryAccountStatus(account, false));

        acmeClient.deactivateAccount(account, false);
        try {
            acmeClient.obtainCertificateChain(account, false, "172.17.0.1");
            fail("Expected AcmeException not thrown");
        } catch (AcmeException e) {
            assertTrue(e.getMessage().contains("deactivated"));
        }
    }

    @Test
    public void testGetNonce() throws Exception {
        final String NEW_NONCE_RESPONSE = "zincG439TOpiDIeJBbmInMOo_xnZV0jpUstA4VZgSiyuFy0";
        server = setupTestGetNonce();
        AcmeAccount account = populateBasicAccount(ACCOUNT_1_V2);
        account.setNonce(CodePointIterator.ofString("rtJAy_mcjDFGnnzCOAbGMGM6w8P3qU0bRDMf8sjt5IU").base64Decode(BASE64_URL, false).drain());
        String nonce = ByteIterator.ofBytes(account.getNonce()).base64Encode(BASE64_URL, false).drainToString();
        assertNotNull(nonce);

        String newNonce = ByteIterator.ofBytes(acmeClient.getNewNonce(account, false)).base64Encode(BASE64_URL, false).drainToString();
        assertNotEquals(nonce,newNonce);
        assertEquals(NEW_NONCE_RESPONSE, newNonce);
    }

    @Test
    public void testObtainCertificateChain() throws Exception {
        server = setupTestObtainCertificate();
        AcmeAccount account = populateAccount(ACCOUNT_3_V2);
        String domainName = "fjsljghasldfjgkv2.com"; // randomly generated domain name
        obtainCertificateChain(null, -1, account, domainName);
    }

    @Test
    public void testObtainCertificateChainMissingLocationURL() throws Exception {
        server = setupTestObtainCertificate(true);
        AcmeAccount account = populateAccount(ACCOUNT_3_V2);
        String domainName = "fjsljghasldfjgkv2.com"; // randomly generated domain name
        try {
            obtainCertificateChain(null, -1, account, domainName);
            fail("Expected AcmeException not thrown");
        } catch(AcmeException e) {
            assertTrue(e.getMessage().contains(ORDER));
        }
    }

    @Test
    public void testObtainCertificateChainWithKeySize() throws Exception {
        server = setupTestObtainCertificateWithKeySize();
        AcmeAccount account = populateAccount(ACCOUNT_6_V2);
        String domainName = "inlneseppwkfwewv2.com"; // randomly generated domain name
        obtainCertificateChain("RSA", 4096, account, domainName);
    }

    @Test
    public void testObtainCertificateChainWithECPublicKey() throws Exception {
        server = setupTestObtainCertificateWithECPublicKey();
        AcmeAccount account = populateAccount(ACCOUNT_7_V2);
        String domainName = "mndelkdnbcilohgv2.com"; // randomly generated domain name
        obtainCertificateChain("EC", 256, account, domainName);
    }

    @Test
    public void testObtainCertificateChainWithUnsupportedPublicKey() throws Exception {
        try {
            server = setupTestObtainCertificateWithUnsupportedPublicKey();
            AcmeAccount account = populateAccount(ACCOUNT_7_V2);
            String domainName = "iraclzlcqgaymrc.com";
            obtainCertificateChain("DSA", 2048, account, domainName);
            fail("Expected AcmeException not thrown");
        } catch (AcmeException expected) {
        }
    }

    private void obtainCertificateChain(String keyAlgorithmName, int keySize, AcmeAccount account, String domainName) throws Exception {
        X509CertificateChainAndSigningKey certificateChainAndSigningKey = acmeClient.obtainCertificateChain(account, false, keyAlgorithmName, keySize, domainName);
        PrivateKey privateKey = certificateChainAndSigningKey.getSigningKey();

        X509Certificate[] replyCertificates = certificateChainAndSigningKey.getCertificateChain();
        assertTrue(replyCertificates.length == 2);
        X509Certificate signedCert = replyCertificates[0];
        X509Certificate caCert = replyCertificates[1];
        assertTrue(signedCert.getSubjectDN().getName().contains(domainName));
        assertEquals(caCert.getSubjectDN(), signedCert.getIssuerDN());
        assertEquals("CN=cackling cryptographer fake ROOT", caCert.getIssuerDN().getName());
        if (keyAlgorithmName != null && keySize != -1) {
            assertEquals(keyAlgorithmName, privateKey.getAlgorithm());
            assertEquals(keyAlgorithmName, signedCert.getPublicKey().getAlgorithm());
            if (keyAlgorithmName.equals("EC")) {
                assertEquals(keySize, ((ECPublicKey) signedCert.getPublicKey()).getParams().getCurve().getField().getFieldSize());
            } else if (keyAlgorithmName.equals("RSA")) {
                assertEquals(keySize, ((RSAPublicKey) signedCert.getPublicKey()).getModulus().bitLength());
            }
        } else {
            if (signedCert.getPublicKey().getAlgorithm().equals("RSA")) {
                assertEquals(AcmeClientSpi.DEFAULT_KEY_SIZE, ((RSAPublicKey) signedCert.getPublicKey()).getModulus().bitLength());
                assertEquals("RSA", privateKey.getAlgorithm());
            } else if (signedCert.getPublicKey().getAlgorithm().equals("EC")) {
                assertEquals(AcmeClientSpi.DEFAULT_EC_KEY_SIZE, ((RSAPublicKey) signedCert.getPublicKey()).getModulus().bitLength());
                assertEquals("EC", privateKey.getAlgorithm());
            }
        }
    }

    @Test
    public void testRevokeCertificateWithoutReason() throws Exception {
        server = setupTestRevokeCertificate();
        AcmeAccount account = populateBasicAccount(ACCOUNT_1_V2);
        revokeCertificate(account, null);
    }

    @Test
    public void testRevokeCertificateWithReason() throws Exception {
        server = setupTestRevokeCertificateWithReason();
        AcmeAccount account = populateBasicAccount(ACCOUNT_1_V2);
        revokeCertificate(account, CRLReason.KEY_COMPROMISE);

    }

    private void revokeCertificate(AcmeAccount account, CRLReason reason) throws Exception {
        X509Certificate certificateToRevoke;
        if (reason == null) {
            certificateToRevoke = aliasToCertificateMap.get(REVOKE_ALIAS_V2);
        } else {
            certificateToRevoke = aliasToCertificateMap.get(REVOKE_WITH_REASON_ALIAS_V2);
        }
        acmeClient.revokeCertificate(account, false, certificateToRevoke, reason);
    }

    @Test
    public void testChangeAccountKey() throws Exception {
        server = setupTestChangeAccountKey();
        AcmeAccount account = populateAccount(ACCOUNT_6_V2);
        X509Certificate oldCertificate = account.getCertificate();
        X500Principal oldDn = account.getDn();
        acmeClient.changeAccountKey(account, false);
        assertTrue(! oldCertificate.equals(account.getCertificate()));
        assertEquals(oldDn, account.getDn());
        assertEquals(Acme.VALID, acmeClient.queryAccountStatus(account, false));
    }

    @Test
    public void testChangeAccountKeySpecifyCertificateAndPrivateKey() throws Exception {
        server = setupTestChangeAccountKeySpecifyCertificateAndPrivateKey();
        AcmeAccount account = populateAccount(ACCOUNT_8_V2);
        X500Principal oldDn = account.getDn();

        // RSA account key
        X509Certificate newCertificate = aliasToCertificateMap.get(NEW_KEY_ALIAS_V2);
        PrivateKey newPrivateKey = aliasToPrivateKeyMap.get(NEW_KEY_ALIAS_V2);
        acmeClient.changeAccountKey(account, false, newCertificate, newPrivateKey);
        assertEquals(newCertificate, account.getCertificate());
        assertEquals(newPrivateKey, account.getPrivateKey());
        assertEquals(oldDn, account.getDn());
        assertEquals(Acme.VALID, acmeClient.queryAccountStatus(account, false));

        // ECDSA account key
        newCertificate = aliasToCertificateMap.get(NEW_EC_KEY_ALIAS_V2);
        newPrivateKey = aliasToPrivateKeyMap.get(NEW_EC_KEY_ALIAS_V2);
        acmeClient.changeAccountKey(account, false, newCertificate, newPrivateKey);
        assertEquals(newCertificate, account.getCertificate());
        assertEquals(newPrivateKey, account.getPrivateKey());
        assertEquals(oldDn, account.getDn());
        assertEquals(Acme.VALID, acmeClient.queryAccountStatus(account, false));

        // attempting to change the account key to a key that is already in use for a different account should fail
        account = populateAccount(ACCOUNT_9_V2);
        X509Certificate oldCertificate = account.getCertificate();
        PrivateKey oldPrivateKey = account.getPrivateKey();
        try {
            acmeClient.changeAccountKey(account, false, newCertificate, newPrivateKey);
            fail("Expected AcmeException not thrown");
        } catch (AcmeException expected) {
        }
        assertEquals(oldCertificate, account.getCertificate());
        assertEquals(oldPrivateKey, account.getPrivateKey());
    }

    @Test
    public void testGetMetadata() throws Exception {
        server = setupTestGetMetadata();
        AcmeAccount account = populateBasicAccount(ACCOUNT_8_V2);
        AcmeMetadata metadata = acmeClient.getMetadata(account, false);
        assertNotNull(metadata);
        assertEquals("https://boulder:4431/terms/v7", metadata.getTermsOfServiceUrl());
        assertEquals("https://github.com/letsencrypt/boulder", metadata.getWebsiteUrl());
        assertArrayEquals(new String[] { "happy-hacker-ca.invalid", "happy-hacker2-ca.invalid" }, metadata.getCAAIdentities());
        assertTrue(metadata.isExternalAccountRequired());

        metadata = acmeClient.getMetadata(account, false);
        assertNotNull(metadata);
        assertEquals("https://boulder:4431/terms/v7", metadata.getTermsOfServiceUrl());
        assertNull(metadata.getWebsiteUrl());
        assertNull(metadata.getCAAIdentities());
        assertFalse(metadata.isExternalAccountRequired());

        metadata = acmeClient.getMetadata(account, false);
        assertNull(metadata);
    }

    /**
     * Class used to build up a mock Let's Encrypt server instance.
     */
    private class AcmeMockServerBuilder {

        ClientAndServer server;

        AcmeMockServerBuilder(ClientAndServer server) {
            this.server = server;
        }

        public AcmeMockServerBuilder addDirectoryResponseBody(String directoryResponseBody) {
            server.when(
                    request()
                            .withMethod("GET")
                            .withPath("/directory")
                            .withBody(""),
                    Times.once())
                    .respond(
                            response()
                                    .withHeader("Cache-Control", "public, max-age=0, no-cache")
                                    .withHeader("Content-Type", "application/json")
                                    .withBody(directoryResponseBody));
            return this;
        }

        public AcmeMockServerBuilder addNewNonceResponse(String newNonce) {
            server.when(
                    request()
                            .withMethod("HEAD")
                            .withPath("/acme/new-nonce")
                            .withBody(""),
                    Times.once())
                    .respond(
                            response()
                                    .withHeader("Cache-Control", "public, max-age=0, no-cache")
                                    .withHeader("Replay-Nonce", newNonce)
                                    .withStatusCode(204));
            return this;
        }

        public AcmeMockServerBuilder addNewAccountRequestAndResponse(String expectedNewAccountRequestBody, String newAccountResponseBody,
                                                                     String newAccountReplayNonce, String newAccountLocation, int newAccountStatusCode) {
            return addNewAccountRequestAndResponse(expectedNewAccountRequestBody, newAccountResponseBody, newAccountReplayNonce, newAccountLocation,
                    newAccountStatusCode, false);
        }

        public AcmeMockServerBuilder addNewAccountRequestAndResponse(String expectedNewAccountRequestBody, String newAccountResponseBody, String newAccountReplayNonce,
                                                                     String newAccountLocation, int newAccountStatusCode, boolean useProblemContentType) {
            String link = "<https://boulder:4431/terms/v7>;rel=\"terms-of-service\"";
            return addPostRequestAndResponse(expectedNewAccountRequestBody, "/acme/new-acct", newAccountResponseBody, newAccountReplayNonce,
                    link, newAccountLocation, newAccountStatusCode, useProblemContentType);
        }

        public AcmeMockServerBuilder updateAccountRequestAndResponse(String expectedUpdateAccountRequestBody, String updateAccountResponseBody, String updateAccountReplayNonce,
                                                                     String accountUrl, int updateAccountStatusCode) {
            String link = "<https://boulder:4431/terms/v7>;rel=\"terms-of-service\"";
            return addPostRequestAndResponse(expectedUpdateAccountRequestBody, accountUrl, updateAccountResponseBody, updateAccountReplayNonce,
                    link, "", updateAccountStatusCode, false);
        }

        public AcmeMockServerBuilder orderCertificateRequestAndResponse(String expectedOrderCertificateRequestBody, String orderCertificateResponseBody, String orderCertificateReplayNonce,
                                                                        String orderLocation, int orderCertificateStatusCode, boolean useProblemContentType) {
            return addPostRequestAndResponse(expectedOrderCertificateRequestBody, "/acme/new-order", orderCertificateResponseBody, orderCertificateReplayNonce,
                    "", orderLocation, orderCertificateStatusCode, useProblemContentType);
        }

        public AcmeMockServerBuilder addAuthorizationResponseBody(String expectedAuthorizationUrl, String expectedAuthorizationRequestBody, String authorizationResponseBody, String authorizationReplayNonce) {
            server.when(
                    request()
                            .withMethod("POST")
                            .withPath(expectedAuthorizationUrl)
                            .withBody(expectedAuthorizationRequestBody == null ? "" : expectedAuthorizationRequestBody),
                    Times.exactly(10))
                    .respond(
                            response()
                                    .withHeader("Cache-Control", "public, max-age=0, no-cache")
                                    .withHeader("Content-Type", "application/json")
                                    .withHeader("Replay-Nonce", authorizationReplayNonce)
                                    .withBody(authorizationResponseBody));
            return this;
        }

        public AcmeMockServerBuilder addChallengeRequestAndResponse(String expectedChallengeRequestBody, String expectedChallengeUrl, String challengeResponseBody,
                                                                    String challengeReplayNonce, String challengeLocation, String challengeLink,
                                                                    int challengeStatusCode, boolean useProblemContentType, String verifyChallengePath,
                                                                    String challengeFileContents, String expectedAuthorizationUrl, String authorizationResponseBody,
                                                                    String authorizationReplayNonce) {
            server.when(
                    request()
                            .withMethod("POST")
                            .withPath(expectedChallengeUrl)
                            .withHeader("Content-Type", "application/jose+json")
                            .withBody(expectedChallengeRequestBody),
                    Times.once())
                    .respond(request -> {
                        HttpResponse response = response()
                                .withHeader("Cache-Control", "public, max-age=0, no-cache")
                                .withHeader("Content-Type", useProblemContentType ? "application/problem+json" : "application/json")
                                .withHeader("Replay-Nonce", challengeReplayNonce)
                                .withBody(challengeResponseBody)
                                .withStatusCode(challengeStatusCode);
                        if (! challengeLocation.isEmpty()) {
                            response = response.withHeader("Location", challengeLocation);
                        }
                        if (! challengeLink.isEmpty()) {
                            response = response.withHeader("Link", challengeLink);
                        }

                        byte[] challengeResponseBytes = null;
                        try {
                            URL verifyChallengeUrl = new URL(client.url(verifyChallengePath).toString());
                            HttpURLConnection connection = (HttpURLConnection) verifyChallengeUrl.openConnection();
                            connection.setRequestMethod("GET");
                            connection.connect();
                            try (InputStream inputStream = new BufferedInputStream(connection.getResponseCode() < 400 ? connection.getInputStream() : connection.getErrorStream())) {
                                challengeResponseBytes = IOUtils.toByteArray(inputStream);
                            }
                        } catch (Exception e) {
                            //
                        }
                        if (challengeFileContents.equals(new String(challengeResponseBytes, StandardCharsets.UTF_8))) {
                            addAuthorizationResponseBody(expectedAuthorizationUrl, null, authorizationResponseBody, authorizationReplayNonce);
                        }
                        return response;
                    });
            return this;
        }

        public AcmeMockServerBuilder addFinalizeRequestAndResponse(String finalResponseBody, String finalizeReplayNonce,
                                                                   String finalizeUrl, String finalizeOrderLocation, int finalizeStatusCode) {
            return addFinalizeRequestAndResponse(finalResponseBody, finalizeReplayNonce, finalizeUrl, finalizeOrderLocation, finalizeStatusCode, false);
        }

        public AcmeMockServerBuilder addFinalizeRequestAndResponse(String finalResponseBody, String finalizeReplayNonce,
                                                                   String finalizeUrl, String orderLocation, int finalizeStatusCode, boolean useProblemContentType) {
            return addPostRequestAndResponse("", finalizeUrl, finalResponseBody, finalizeReplayNonce, "",
                    orderLocation, finalizeStatusCode, useProblemContentType);
        }

        public AcmeMockServerBuilder addCertificateRequestAndResponse(String certificateUrl, String expectedCertificateRequestBody, String certificateResponseBody, String certificateReplayNonce, int certificateStatusCode) {
            HttpResponse response = response()
                    .withHeader("Cache-Control", "public, max-age=0, no-cache")
                    .withHeader("Content-Type", "application/pem-certificate-chain")
                    .withHeader("Replay-Nonce", certificateReplayNonce)
                    .withBody(certificateResponseBody)
                    .withStatusCode(certificateStatusCode);
            server.when(
                    request()
                            .withMethod("POST")
                            .withPath(certificateUrl)
                            .withBody(expectedCertificateRequestBody),
                    Times.once())
                    .respond(response);

            return this;
        }

        public AcmeMockServerBuilder addCheckOrderRequestAndResponse(String orderUrl, String expectedCheckCertificateRequestBody, String checkCertificateResponseBody, String checkOrderReplayNonce, int checkCertificateStatusCode) {
            HttpResponse response = response()
                    .withHeader("Cache-Control", "public, max-age=0, no-cache")
                    .withHeader("Content-Type", "application/json")
                    .withHeader("Replay-Nonce", checkOrderReplayNonce)
                    .withBody(checkCertificateResponseBody)
                    .withStatusCode(checkCertificateStatusCode);
            server.when(
                    request()
                            .withMethod("POST")
                            .withPath(orderUrl)
                            .withBody(expectedCheckCertificateRequestBody),
                    Times.once())
                    .respond(response);

            return this;
        }

        public AcmeMockServerBuilder addRevokeCertificateRequestAndResponse(String expectedRevokeCertificateRequestBody, String revokeCertificateReplayNonce, int revokeCertificateStatusCode) {
            return addPostRequestAndResponse(expectedRevokeCertificateRequestBody, "/acme/revoke-cert", "", revokeCertificateReplayNonce,
                    "", "", revokeCertificateStatusCode, false);
        }

        public AcmeMockServerBuilder addChangeKeyRequestAndResponse(String expectedChangeKeyRequestBody, String changeKeyResponseBody, String changeKeyReplaceNonce, int changeKeyResponseCode) {
            return addPostRequestAndResponse(expectedChangeKeyRequestBody, "/acme/key-change", changeKeyResponseBody, changeKeyReplaceNonce,
                    "", "", changeKeyResponseCode, false);
        }

        public AcmeMockServerBuilder addPostRequestAndResponse(String expectedPostRequestBody, String postPath, String responseBody, String replayNonce, String link, String location, int responseCode, boolean useProblemContentType) {
            HttpResponse response = response()
                    .withHeader("Cache-Control", "public, max-age=0, no-cache")
                    .withHeader("Replay-Nonce", replayNonce)
                    .withStatusCode(responseCode);
            if (! responseBody.isEmpty()) {
                response = response
                        .withHeader("Content-Type", useProblemContentType ? "application/problem+json" : "application/json")
                        .withBody(responseBody);

            }
            if (! link.isEmpty()) {
                response = response.withHeader("Link", link);
            }
            if (location != null && ! location.isEmpty()) {
                response = response.withHeader("Location", location);
            }
            HttpRequest request = request()
                    .withMethod("POST")
                    .withPath(postPath) ;
            if (! expectedPostRequestBody.isEmpty()) {
                request = request.withBody(expectedPostRequestBody);
            }
            server.when(
                    request,
                    Times.once())
                    .respond(response);

            return this;
        }

        public ClientAndServer build() {
            return server;
        }
    }

    public static MockWebServer getMockWebServerClient() {
        return client;
    }

    /* -- Helper methods used to set up the messages that should be sent from the mock Let's Encrypt server to our ACME client. -- */
    private ClientAndServer setupTestCreateAccount(boolean missingLocationURL) {

        // set up a mock Let's Encrypt server
        final String DIRECTORY_RESPONSE_BODY = "{" + System.lineSeparator()  +
                "  \"wnR-SBn2GN4\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator()  +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator()  +
                "  \"meta\": {" + System.lineSeparator()  +
                "    \"caaIdentities\": [" + System.lineSeparator()  +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator()  +
                "    ]," + System.lineSeparator()  +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator()  +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator()  +
                "  }," + System.lineSeparator()  +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator()  +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator()  +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator()  +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator()  +
                "}";

        final String NEW_NONCE_RESPONSE = "zincwl_lThkXLp0V7HAAcQEbIrx1R-gTI_ZQ8INAsrR5aQU";

        final String NEW_ACCT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJoOE9lZTViZURSZ3hOUGVfZU1FOUg2Vm83NEZ1ZzhIZ3Jpa2ZiZkNhVTNsS0Y2NDhRRzFYMWtHRFpUaEF5OGRhcUo4YnY2YzNQSmRueDJIcjhqT3psNTA5Ym5NNmNDV2Z5d1RwY0lab1V6UVFaTFlfSzhHTURBeWdsc1FySXRnQ2lRYWxJcWJ1SkVrb2MzV1FBSXhKMjN4djliSzV4blZRa1RXNHJWQkFjWU5Rd29CakdZT1dTaXpUR2ZqZ21RcVRYbG9hYW1GWkpuOTdIbmIxcWp5NVZZbTA2YnV5cXdBYUdIczFDTHUzY0xaZ1FwVkhRNGtGc3prOFlPNVVBRWppb2R1Z1dwWlVSdTlUdFJLek4wYmtFZGVRUFlWcGF1cFVxMWNxNDdScDJqcVZVWGRpUUxla3l4clFidDhBMnVHNEx6RFF1LWI0Y1pwcG16YzNobGhTR3cifSwibm9uY2UiOiJ6aW5jd2xfbFRoa1hMcDBWN0hBQWNRRWJJcngxUi1nVElfWlE4SU5Bc3JSNWFRVSIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL25ldy1hY2N0In0\",\"payload\":\"eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJtYWlsdG86YWRtaW5AYW5leGFtcGxlLmNvbSJdfQ\",\"signature\":\"RPIM6OGU33uPXurdKJuKwXNkJbgEXcUr9QxEBjynhzROWGreB_p6esSlTxTkkNmP8EIBmcc2g5FjkBHjwIhqcvVC5AHhJ0XMq-WhRqlMdwQFn55nuG5O4nOrfr-5u31jw8DGnHs0Lv3_X4rVfLomT8y1eZ_IzPdZzw_QaEJWWIlrn-H_AkcmbZUxvozJ1yvadQ6cUUl9Hw6Kj8sSSdcUQ9tGtfAOiiXDtH-42-G0pMUivnJKyF5m8HdMXqKeFvRk4gvei-NdCzK44uehvoRTULQFbeu-h8YzWBZJwP1LXX8LSyLacxrXH8vukN8qjbBXXrB-QcimuPba4jmF124IDg\"}";

        final String NEW_ACCT_RESPONSE_BODY = "{" + System.lineSeparator()  +
                "  \"key\": {" + System.lineSeparator()  +
                "    \"kty\": \"RSA\"," + System.lineSeparator()  +
                "    \"n\": \"h8Oee5beDRgxNPe_eME9H6Vo74Fug8HgrikfbfCaU3lKF648QG1X1kGDZThAy8daqJ8bv6c3PJdnx2Hr8jOzl509bnM6cCWfywTpcIZoUzQQZLY_K8GMDAyglsQrItgCiQalIqbuJEkoc3WQAIxJ23xv9bK5xnVQkTW4rVBAcYNQwoBjGYOWSizTGfjgmQqTXloaamFZJn97Hnb1qjy5VYm06buyqwAaGHs1CLu3cLZgQpVHQ4kFszk8YO5UAEjiodugWpZURu9TtRKzN0bkEdeQPYVpaupUq1cq47Rp2jqVUXdiQLekyxrQbt8A2uG4LzDQu-b4cZppmzc3hlhSGw\"," + System.lineSeparator()  +
                "    \"e\": \"AQAB\"" + System.lineSeparator()  +
                "  }," + System.lineSeparator()  +
                "  \"contact\": [" + System.lineSeparator()  +
                "    \"mailto:admin@anexample.com\"" + System.lineSeparator()  +
                "  ]," + System.lineSeparator()  +
                "  \"initialIp\": \"10.77.77.1\"," + System.lineSeparator()  +
                "  \"createdAt\": \"2019-07-12T16:52:19.171896513Z\"," + System.lineSeparator()  +
                "  \"status\": \"valid\"" + System.lineSeparator()  +
                "}";

        final String NEW_ACCT_REPLAY_NONCE = "taroOQPjumKybWIQEmqmB2DZ8ouIQ5uBoaDQZosCDyUzbJs";
        final String NEW_ACCT_LOCATION = "http://localhost:4001/acme/acct/384";

        return new AcmeMockServerBuilder(server)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY)
                .addNewNonceResponse(NEW_NONCE_RESPONSE)
                .addNewAccountRequestAndResponse(NEW_ACCT_REQUEST_BODY, NEW_ACCT_RESPONSE_BODY, NEW_ACCT_REPLAY_NONCE, missingLocationURL ? null : NEW_ACCT_LOCATION, 201)
                .build();
    }

    private ClientAndServer setupTestCreateAccount() {
        return setupTestCreateAccount(false);
    }

    private ClientAndServer setupTestCreateAccountOnlyReturnExisting() {

        // set up a mock Let's Encrypt server
        final String DIRECTORY_RESPONSE_BODY_1 = "{" + System.lineSeparator()  +
                "  \"uwKlE_UCMLQ\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator()  +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator()  +
                "  \"meta\": {" + System.lineSeparator()  +
                "    \"caaIdentities\": [" + System.lineSeparator()  +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator()  +
                "    ]," + System.lineSeparator()  +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator()  +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator()  +
                "  }," + System.lineSeparator()  +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator()  +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator()  +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator()  +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator()  +
                "}";

        final String NEW_NONCE_RESPONSE_1 = "taro5SS8kLFXO5cjVun3PmV2OlNxMd3fXvbM3pdwwxakjOM";

        final String NEW_ACCT_REQUEST_BODY_1 = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJzeWVfcW5QeUZLRnRQX0ZLM3FkbENadG1HSGJ3emM1Z0JRMU9ydEIxZXZQSHNxdkZYUWp0MGRPTHRRT01mZTIzUmhrZVRhdDJsSlYxUENWcGNJWE8zc2pvSV82WFNyNnhUbWNkSmN0QmVVc3BleS1TN1RjRDdNd1ZfWUVCbVNGa09SRWdLMFBidDYyVGQtUURjZnlJZjJOdWJsc1FFYlNQaEp6TUNfeWw0VWM5aFRHYlByVFp6dFlxMHpla21XWEUxNTZ0QlEwRFBWZmFiczhfUE5qUGhMbFJSZDlMVHVwako2cTk1VFdHRUlrdjdUeGxQVDN3ZHJ1b2dLU2g2aTdlMVVzUk1ITTJISU40aUdZajFGVkU3NVlvanIzYzdweGJOU01QejFYa3NlNDdXTUt1NkYxWHlNckhJUVF3RUtvN1pnZUx6UmpldTExaDE5Uy12WExzMVEifSwibm9uY2UiOiJ0YXJvNVNTOGtMRlhPNWNqVnVuM1BtVjJPbE54TWQzZlh2Yk0zcGR3d3hha2pPTSIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL25ldy1hY2N0In0\",\"payload\":\"eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJtYWlsdG86YWRtaW5AYW5leGFtcGxlLmNvbSJdfQ\",\"signature\":\"Kk5vvHVInimOZcOvuPF2Ug0xz6uLLLpSagcvzTrrjebUuWHmjGa-e7Cdvoik8mXT7_5PqZuqJn-09NRYFTHA21vddbc2vZzkV628ip7JJaD8w0NE3hSgctP602Lg2EMPP8m5zCrtIpF95_WVr4XMgKklRBLHXPpCUq2m74K5rs49pMwUSqVTRjpTfXrBupqwiyav-08dLvr8UbVz4F3Qru8Zkhgk_SvZsSJyKSVeX2JD4Dlwbw8GfhK68rBhlCyW5XQw9ESF73jY17DZIXLWXbwybWAqyymGr0Nn92YuBW6DEm4M4L4ech3xEAhBvtdeVYTWSpdz812G1HS-3mUMsQ\"}";

        final String NEW_ACCT_RESPONSE_BODY_1 = "{" + System.lineSeparator()  +
                "  \"key\": {" + System.lineSeparator()  +
                "    \"kty\": \"RSA\"," + System.lineSeparator()  +
                "    \"n\": \"sye_qnPyFKFtP_FK3qdlCZtmGHbwzc5gBQ1OrtB1evPHsqvFXQjt0dOLtQOMfe23RhkeTat2lJV1PCVpcIXO3sjoI_6XSr6xTmcdJctBeUspey-S7TcD7MwV_YEBmSFkOREgK0Pbt62Td-QDcfyIf2NublsQEbSPhJzMC_yl4Uc9hTGbPrTZztYq0zekmWXE156tBQ0DPVfabs8_PNjPhLlRRd9LTupjJ6q95TWGEIkv7TxlPT3wdruogKSh6i7e1UsRMHM2HIN4iGYj1FVE75Yojr3c7pxbNSMPz1Xkse47WMKu6F1XyMrHIQQwEKo7ZgeLzRjeu11h19S-vXLs1Q\"," + System.lineSeparator()  +
                "    \"e\": \"AQAB\"" + System.lineSeparator()  +
                "  }," + System.lineSeparator()  +
                "  \"contact\": [" + System.lineSeparator()  +
                "    \"mailto:admin@anexample.com\"" + System.lineSeparator()  +
                "  ]," + System.lineSeparator()  +
                "  \"initialIp\": \"10.77.77.1\"," + System.lineSeparator()  +
                "  \"createdAt\": \"2019-07-12T18:19:27Z\"," + System.lineSeparator()  +
                "  \"status\": \"valid\"" + System.lineSeparator()  +
                "}";

        final String NEW_ACCT_REPLAY_NONCE_1 = "zincDL7vtuouQnFx6xo2JNdqIZczLS7C0mrF06CyYc_kzSA";
        final String NEW_ACCT_LOCATION_1 = "http://localhost:4001/acme/acct/387";


        final String DIRECTORY_RESPONSE_BODY_2 = "{" + System.lineSeparator()  +
                "  \"ICJvijdsr6w\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator()  +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator()  +
                "  \"meta\": {" + System.lineSeparator()  +
                "    \"caaIdentities\": [" + System.lineSeparator()  +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator()  +
                "    ]," + System.lineSeparator()  +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator()  +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator()  +
                "  }," + System.lineSeparator()  +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator()  +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator()  +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator()  +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator()  +
                "}";

        final String NEW_NONCE_RESPONSE_2 = "taroJafrl2Lz_cpp7Vd_LXnWw1CAjX1Q0ege5VktFeKoFNw";

        final String NEW_ACCT_REQUEST_BODY_2 = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJzeWVfcW5QeUZLRnRQX0ZLM3FkbENadG1HSGJ3emM1Z0JRMU9ydEIxZXZQSHNxdkZYUWp0MGRPTHRRT01mZTIzUmhrZVRhdDJsSlYxUENWcGNJWE8zc2pvSV82WFNyNnhUbWNkSmN0QmVVc3BleS1TN1RjRDdNd1ZfWUVCbVNGa09SRWdLMFBidDYyVGQtUURjZnlJZjJOdWJsc1FFYlNQaEp6TUNfeWw0VWM5aFRHYlByVFp6dFlxMHpla21XWEUxNTZ0QlEwRFBWZmFiczhfUE5qUGhMbFJSZDlMVHVwako2cTk1VFdHRUlrdjdUeGxQVDN3ZHJ1b2dLU2g2aTdlMVVzUk1ITTJISU40aUdZajFGVkU3NVlvanIzYzdweGJOU01QejFYa3NlNDdXTUt1NkYxWHlNckhJUVF3RUtvN1pnZUx6UmpldTExaDE5Uy12WExzMVEifSwibm9uY2UiOiJ0YXJvSmFmcmwyTHpfY3BwN1ZkX0xYbld3MUNBalgxUTBlZ2U1Vmt0RmVLb0ZOdyIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL25ldy1hY2N0In0\",\"payload\":\"eyJvbmx5UmV0dXJuRXhpc3RpbmciOnRydWV9\",\"signature\":\"BYz8MmioQYWkUaLtX-WDpbtwug22XQ6EwGWXTrqdQfIUavE6gOykdtWQ85OnVQBxyTZ2yL8VDeT-keoXDblsW8JZGwdiEFhs-Qa5XuNsf4i3Ypr6CvfdurlTyLgfvLBINVf9Gg7iVJfa4ky0o7bQ2xTrDIs_KdExbSS455ykGIgudUC3FM1zptXDuvKNB8nRNAlm_6VKBvhon29Bv_rXD4qtenPA-1msRms6eI0TQiGjcjVraWls06aSaK2kV28fGairfIhy0VCHPlXXmBDn5Y22mVWEJGs9bzSwjzeAQRvKeJ-gRJY8gck73HyGlYTEHXm-emCxp99QyxzzgjF-3w\"}";

        final String NEW_ACCT_RESPONSE_BODY_2 = "";

        final String NEW_ACCT_REPLAY_NONCE_2 = "zincZZ9vYu6kBpmZ4nc6zeAh12XuqZdL1b4O5XKtrxe8Phc";
        final String NEW_ACCT_LOCATION_2 = "http://localhost:4001/acme/acct/387";

        final String DIRECTORY_RESPONSE_BODY_3 = "{" + System.lineSeparator()  +
                "  \"gHEVwDX1V0w\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator()  +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator()  +
                "  \"meta\": {" + System.lineSeparator()  +
                "    \"caaIdentities\": [" + System.lineSeparator()  +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator()  +
                "    ]," + System.lineSeparator()  +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator()  +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator()  +
                "  }," + System.lineSeparator()  +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator()  +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator()  +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator()  +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator()  +
                "}";

        final String NEW_NONCE_RESPONSE_3 = "taroNkY-FLXLmfEVGBxpKnY6NZg5hZc-U0ppPGjJHzY0hqA";

        final String NEW_ACCT_REQUEST_BODY_3 = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJuWVJ5RGQ4b1ZPZ3hTRlVzX2xoYllvMjNGWEFHelVJRTl0dFVCdEJ3N3VHc1U5aEpsSi1RYXlxbHJfZGwwUHNoYjVaeFk4a0h0ZEY5QkVOX1F1Slp4emlzMWNzNFhUY0YzbjVBRUswcFVtS3VQSGt3ck9PNExFN1l3RHBEM0Q1YjRHVjFpVFUyY1ZyRmhMVmI1WmQtTnl6NVRJOWlCbDM3N0FJRmt6aU00Rmx2aS1CV19UZEJmTVVFVURtNW85dFBCU2N2M255YThhSFpJYmdyaW5Ubm1IMFBQMk1vNW50czJjd19zU0d0aENXWkhqWVp1MjRmWE5wb1RjTE1OVldBLTJPSjR0dWtGamlwWC03ckhZRUJiclRSd2FIVnlTOEd2UFp5bjU5b3VYZzAwVWhCdEhRTHROUldPQy1tV29TdFBXOWxjOHNCQm1YdlJiTzdFUkU1dVEifSwibm9uY2UiOiJ0YXJvTmtZLUZMWExtZkVWR0J4cEtuWTZOWmc1aFpjLVUwcHBQR2pKSHpZMGhxQSIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL25ldy1hY2N0In0\",\"payload\":\"eyJvbmx5UmV0dXJuRXhpc3RpbmciOnRydWV9\",\"signature\":\"ZXIi2tBFFy3CkhryuzwRouXxMkWDVQU2QDQPNFmVBdL4KHCTwWEY465rtrfC7LHI3I-6t6f2PeQwCJQAFqmdrGi19y1OGvw9HkNt2ydHJJmYqV0QVckkztNyOmJiIMQrZO5MBf0LxlEPJzHUndp-nROCN_eqMfWw9USKDPRbeF_LPbcc4FCds9u7NARNZS6DLR6ZeRBeYc3krZamDXPoDENeQywp4D6hVHzGSyy0-dQz5ubUcL1TIZc-fas2HYMQBGCmYWGolurz9BCPw8Epr5-bPyzXiviv0YHzhglHJJ3GQxZrFwt7ktB6BF_kwUq00s8iWroFfQTYjzNJGaW4BQ\"}";

        final String NEW_ACCT_RESPONSE_BODY_3 = "{" + System.lineSeparator()  +
                "  \"type\": \"urn:ietf:params:acme:error:accountDoesNotExist\"," + System.lineSeparator()  +
                "  \"detail\": \"No account exists with the provided key\"," + System.lineSeparator()  +
                "  \"status\": 400" + System.lineSeparator()  +
                "}";

        final String NEW_ACCT_REPLAY_NONCE_3 = "zincV6rCJkzqPJkWh2h7V7WNx1H7i702ZoeHrqDW14PqS_I";
        final String NEW_ACCT_LOCATION_3 = "";

        return new AcmeMockServerBuilder(server)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY_1)
                .addNewNonceResponse(NEW_NONCE_RESPONSE_1)
                .addNewAccountRequestAndResponse(NEW_ACCT_REQUEST_BODY_1, NEW_ACCT_RESPONSE_BODY_1, NEW_ACCT_REPLAY_NONCE_1, NEW_ACCT_LOCATION_1, 201)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY_2)
                .addNewNonceResponse(NEW_NONCE_RESPONSE_2)
                .addNewAccountRequestAndResponse(NEW_ACCT_REQUEST_BODY_2, NEW_ACCT_RESPONSE_BODY_2, NEW_ACCT_REPLAY_NONCE_2, NEW_ACCT_LOCATION_2, 200)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY_3)
                .addNewNonceResponse(NEW_NONCE_RESPONSE_3)
                .addNewAccountRequestAndResponse(NEW_ACCT_REQUEST_BODY_3, NEW_ACCT_RESPONSE_BODY_3, NEW_ACCT_REPLAY_NONCE_3, NEW_ACCT_LOCATION_3, 400, true)
                .build();
    }

    private ClientAndServer setupTestCreateAccountWithECPublicKey() {

        // set up a mock Let's Encrypt server
        final String DIRECTORY_RESPONSE_BODY = "{" + System.lineSeparator()  +
                "  \"Z7Y00Dy_3Sg\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator()  +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator()  +
                "  \"meta\": {" + System.lineSeparator()  +
                "    \"caaIdentities\": [" + System.lineSeparator()  +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator()  +
                "    ]," + System.lineSeparator()  +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator()  +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator()  +
                "  }," + System.lineSeparator()  +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator()  +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator()  +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator()  +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator()  +
                "}";

        final String NEW_NONCE_RESPONSE = "zincl7lAw10tD4XFE7ox5RjhT8cJCV_E-WH9dsTk9XEyjSM";

        final String NEW_ACCT_RESPONSE_BODY = "{" + System.lineSeparator()  +
                "  \"key\": {" + System.lineSeparator()  +
                "    \"kty\": \"EC\"," + System.lineSeparator()  +
                "    \"crv\": \"P-256\"," + System.lineSeparator()  +
                "    \"x\": \"7lOVNI-Bdpr7ul6yiTEM3HebXC_wIC6eOsRH-KJa_qI\"," + System.lineSeparator()  +
                "    \"y\": \"8qCLlwQYodZLDH_PpRBNlKGU0Zi7TyDQJisJYu6UtRI\"" + System.lineSeparator()  +
                "  }," + System.lineSeparator()  +
                "  \"contact\": [" + System.lineSeparator()  +
                "    \"mailto:admin@anexample.com\"" + System.lineSeparator()  +
                "  ]," + System.lineSeparator()  +
                "  \"initialIp\": \"10.77.77.1\"," + System.lineSeparator()  +
                "  \"createdAt\": \"2019-07-12T18:33:03.388635187Z\"," + System.lineSeparator()  +
                "  \"status\": \"valid\"" + System.lineSeparator()  +
                "}";

        final String NEW_ACCT_REPLAY_NONCE = "taro8nLXKU--IKNClMMk4Kfan_ntlWxjMCsVbGZgXAgUr5k";
        final String NEW_ACCT_LOCATION = "http://localhost:4001/acme/acct/389";

        return new AcmeMockServerBuilder(server)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY)
                .addNewNonceResponse(NEW_NONCE_RESPONSE)
                .addNewAccountRequestAndResponse("", NEW_ACCT_RESPONSE_BODY, NEW_ACCT_REPLAY_NONCE, NEW_ACCT_LOCATION, 201)
                .build();

    }

    private ClientAndServer setupTestUpdateAccount() {

        // set up a mock Let's Encrypt server
        final String ACCT_PATH = "/acme/acct/5";
        final String DIRECTORY_RESPONSE_BODY = "{" + System.lineSeparator()  +
                "  \"s9YSaVf283g\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator()  +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator()  +
                "  \"meta\": {" + System.lineSeparator()  +
                "    \"caaIdentities\": [" + System.lineSeparator()  +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator()  +
                "    ]," + System.lineSeparator()  +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator()  +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator()  +
                "  }," + System.lineSeparator()  +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator()  +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator()  +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator()  +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator()  +
                "}" + System.lineSeparator() ;

        final String NEW_NONCE_RESPONSE = "zincBBJG7qwuzAVpZZuNp2fjrxKQXRijNtcQ_1P8A51q0jg";

        final String UPDATE_ACCT_REQUEST_BODY_1 = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvNSIsIm5vbmNlIjoiemluY0JCSkc3cXd1ekFWcFpadU5wMmZqcnhLUVhSaWpOdGNRXzFQOEE1MXEwamciLCJ1cmwiOiJodHRwOi8vbG9jYWxob3N0OjQwMDEvYWNtZS9hY2N0LzUifQ\",\"payload\":\"eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6ZmFsc2UsImNvbnRhY3QiOlsibWFpbHRvOmNlcnRpZmljYXRlc0BleGFtcGxlcy5jb20iLCJtYWlsdG86YWRtaW5AZXhhbXBsZXMuY29tIl19\",\"signature\":\"KWpsGaL3JkrOBvFlRnuluQ-jz6HB5NFzWBF06Y3dzImdgnngR5NVr8XoO76_Pofn84kA9QvyNeQJKyLvHljg3t3KrTIrmOcdMDtDvYOQNtxf0eontk17Si-vS3J1VjlCv2tBHSi_DB9vCHhSw6yRKr6RXYu79PU1Vgl42E_evhxOsxIL-ZFqWW9sW5O-gaRRjwQMrWJaCORetZiwwnEoqUllfneT6-A-DFZyCUEioB56mYMIKxri2X0r1viWtAybHpDUOVY42JSSweIf2JpLz-JdtJsi1FSQUjJKT-UOF1zHE8OgP8dDcEdMyhgmjU2GQYfd2-2cLes-gKAy5fIsag\"}";

        final String UPDATE_ACCT_RESPONSE_BODY_1 = "{" + System.lineSeparator() +
                "  \"key\": {" + System.lineSeparator() +
                "    \"kty\": \"RSA\"," + System.lineSeparator() +
                "    \"n\": \"h8Oee5beDRgxNPe_eME9H6Vo74Fug8HgrikfbfCaU3lKF648QG1X1kGDZThAy8daqJ8bv6c3PJdnx2Hr8jOzl509bnM6cCWfywTpcIZoUzQQZLY_K8GMDAyglsQrItgCiQalIqbuJEkoc3WQAIxJ23xv9bK5xnVQkTW4rVBAcYNQwoBjGYOWSizTGfjgmQqTXloaamFZJn97Hnb1qjy5VYm06buyqwAaGHs1CLu3cLZgQpVHQ4kFszk8YO5UAEjiodugWpZURu9TtRKzN0bkEdeQPYVpaupUq1cq47Rp2jqVUXdiQLekyxrQbt8A2uG4LzDQu-b4cZppmzc3hlhSGw\"," + System.lineSeparator() +
                "    \"e\": \"AQAB\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"contact\": [" + System.lineSeparator() +
                "    \"mailto:admin@examples.com\"" + System.lineSeparator() +
                "    \"mailto:certificates@examples.com\"," + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"initialIp\": \"10.77.77.1\"," + System.lineSeparator() +
                "  \"createdAt\": \"2019-07-12T16:52:19Z\"," + System.lineSeparator() +
                "  \"status\": \"valid\"" + System.lineSeparator() +
                "}";

        final String UPDATE_ACCT_REPLAY_NONCE_1 = "taroYkIDLLAJW-Jo26PcEW8PjeJnfC6PQTyIOY4kEVj69V4";

        final String UPDATE_ACCT_REQUEST_BODY_2 = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvNSIsIm5vbmNlIjoidGFyb1lrSURMTEFKVy1KbzI2UGNFVzhQamVKbmZDNlBRVHlJT1k0a0VWajY5VjQiLCJ1cmwiOiJodHRwOi8vbG9jYWxob3N0OjQwMDEvYWNtZS9hY2N0LzUifQ\",\"payload\":\"\",\"signature\":\"hEXtEjuzm4DIwHdwF3-eVDuLwJYrMvIxXwwXYIY7zJjdgUTt9QDPZj6ItALeXr2JKhTH2klBihhaYPEhqDYjfTm3ia5hDYGUNQdXiOzrasONOx1zy3dIowkFoFnWHQs6qWZcrPOzqT5GofudBItb5Vy4c5g11TRJy5cntUzkclqINFSl2fhCHVy6IZwSEp6EmFuN6uCqnQzWEIfZQ_3NpmCFUtKXCag3WxmvXxhL0IrfxQWxKYjgaX89VoP_5gAc2OA_GIiBMtmkmvQNIws9lfZo8eM6mlsonIHIOQm1gJ2OWxK05I1fIfAfX2RgTCZek8bAdfmwP_IAd-XmJsh1LQ\"}";

        final String UPDATE_ACCT_RESPONSE_BODY_2 = "{" + System.lineSeparator() +
                "  \"key\": {" + System.lineSeparator() +
                "    \"kty\": \"RSA\"," + System.lineSeparator() +
                "    \"n\": \"h8Oee5beDRgxNPe_eME9H6Vo74Fug8HgrikfbfCaU3lKF648QG1X1kGDZThAy8daqJ8bv6c3PJdnx2Hr8jOzl509bnM6cCWfywTpcIZoUzQQZLY_K8GMDAyglsQrItgCiQalIqbuJEkoc3WQAIxJ23xv9bK5xnVQkTW4rVBAcYNQwoBjGYOWSizTGfjgmQqTXloaamFZJn97Hnb1qjy5VYm06buyqwAaGHs1CLu3cLZgQpVHQ4kFszk8YO5UAEjiodugWpZURu9TtRKzN0bkEdeQPYVpaupUq1cq47Rp2jqVUXdiQLekyxrQbt8A2uG4LzDQu-b4cZppmzc3hlhSGw\"," + System.lineSeparator() +
                "    \"e\": \"AQAB\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"contact\": [" + System.lineSeparator() +
                "    \"mailto:certificates@examples.com\"," + System.lineSeparator() +
                "    \"mailto:admin@examples.com\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"initialIp\": \"10.77.77.1\"," + System.lineSeparator() +
                "  \"createdAt\": \"2019-07-12T16:52:19Z\"," + System.lineSeparator() +
                "  \"status\": \"valid\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String UPDATE_ACCT_REPLAY_NONCE_2 = "zincgt5sXshHjq3Je_kVdG2rtB34uFrpeaiWShTaC4IK-Dg";

        final String UPDATE_ACCT_REQUEST_BODY_3 = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvNSIsIm5vbmNlIjoiemluY2d0NXNYc2hIanEzSmVfa1ZkRzJydEIzNHVGcnBlYWlXU2hUYUM0SUstRGciLCJ1cmwiOiJodHRwOi8vbG9jYWxob3N0OjQwMDEvYWNtZS9hY2N0LzUifQ\",\"payload\":\"eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6ZmFsc2V9\",\"signature\":\"DCKNu7139HQhf67-7GpRc207rpxiP9UqkKXpOoCZytMqOHvRr-gha1ZBDsB0sSm254e1H8suuzwhLkuK1rXdYaJcOvi4zpYy_rnASu_QVYvIjwfqqC11yoWa7v_JKnoHJuxtqguaM3IkyUhVq_JWXKCG3KJgQUwY6ckzs9nSuU0ryFqM6wKZZAabXkPdbhyXHWB2g3xleRrfSoyJmS_2O0-in1s_vwpBcEZG10BrG8-atrplC5FxGbt4CsB7YrWhBR0ZnWKqSCQgtEDvxERBfK8SqUdL45VGFe2c2Nz6wM_RDmUXujIiW-Os7QSt7DDcqxqpCPq4tDxkMQo8S5IVFQ\"}";

        final String UPDATE_ACCT_RESPONSE_BODY_3 = "{" + System.lineSeparator() +
                "  \"key\": {" + System.lineSeparator() +
                "    \"kty\": \"RSA\"," + System.lineSeparator() +
                "    \"n\": \"h8Oee5beDRgxNPe_eME9H6Vo74Fug8HgrikfbfCaU3lKF648QG1X1kGDZThAy8daqJ8bv6c3PJdnx2Hr8jOzl509bnM6cCWfywTpcIZoUzQQZLY_K8GMDAyglsQrItgCiQalIqbuJEkoc3WQAIxJ23xv9bK5xnVQkTW4rVBAcYNQwoBjGYOWSizTGfjgmQqTXloaamFZJn97Hnb1qjy5VYm06buyqwAaGHs1CLu3cLZgQpVHQ4kFszk8YO5UAEjiodugWpZURu9TtRKzN0bkEdeQPYVpaupUq1cq47Rp2jqVUXdiQLekyxrQbt8A2uG4LzDQu-b4cZppmzc3hlhSGw\"," + System.lineSeparator() +
                "    \"e\": \"AQAB\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"contact\": [" + System.lineSeparator() +
                "    \"mailto:certificates@examples.com\"," + System.lineSeparator() +
                "    \"mailto:admin@examples.com\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"initialIp\": \"10.77.77.1\"," + System.lineSeparator() +
                "  \"createdAt\": \"2019-07-12T16:52:19Z\"," + System.lineSeparator() +
                "  \"status\": \"valid\"" + System.lineSeparator() +
                "}" + System.lineSeparator() ;

        final String UPDATE_ACCT_REPLAY_NONCE_3 = "taroAi0lfzbfT2NuMa7mwJXkoehtNOed0rreDzTYXUNpmiY";

        final String UPDATE_ACCT_REQUEST_BODY_4 = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvNSIsIm5vbmNlIjoidGFyb0FpMGxmemJmVDJOdU1hN213Slhrb2VodE5PZWQwcnJlRHpUWVhVTnBtaVkiLCJ1cmwiOiJodHRwOi8vbG9jYWxob3N0OjQwMDEvYWNtZS9hY2N0LzUifQ\",\"payload\":\"\",\"signature\":\"OcSx7GrtlfvGpnM_G-JdtZ6ldxCd8__0XGDqiFFKUD0BZyET8agwKzGySDHXke4LnlsZ8DVwgvwAqiKbCB8QPzA2byO7SQxQZRw3H1_ac0_0NdofEdcAdNy107Tr74bqDVGoZpG2JG8dHgqAY55q6rph3eS4iXy9zrYXnOI4NDWxIYIB_FpnX_bUVBEYHbqEMiG5A_kFNH5VJ8fANmkdMGMHTGMXfSWAfiwd3f_RgyMlD3l2-AtaETogV5FqfHLkpfZEUjdy4kPMbvuQwiRZhT5rrqPOK4hq4AQh99AzzrxSPTAkvDSFrr5gag-7zsA_jeLhvRdB-RIRpfLFhM-8WQ\"}";

        final String UPDATE_ACCT_RESPONSE_BODY_4 = "{" + System.lineSeparator() +
                "  \"key\": {" + System.lineSeparator() +
                "    \"kty\": \"RSA\"," + System.lineSeparator() +
                "    \"n\": \"h8Oee5beDRgxNPe_eME9H6Vo74Fug8HgrikfbfCaU3lKF648QG1X1kGDZThAy8daqJ8bv6c3PJdnx2Hr8jOzl509bnM6cCWfywTpcIZoUzQQZLY_K8GMDAyglsQrItgCiQalIqbuJEkoc3WQAIxJ23xv9bK5xnVQkTW4rVBAcYNQwoBjGYOWSizTGfjgmQqTXloaamFZJn97Hnb1qjy5VYm06buyqwAaGHs1CLu3cLZgQpVHQ4kFszk8YO5UAEjiodugWpZURu9TtRKzN0bkEdeQPYVpaupUq1cq47Rp2jqVUXdiQLekyxrQbt8A2uG4LzDQu-b4cZppmzc3hlhSGw\"," + System.lineSeparator() +
                "    \"e\": \"AQAB\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"contact\": [" + System.lineSeparator() +
                "    \"mailto:certificates@examples.com\"," + System.lineSeparator() +
                "    \"mailto:admin@examples.com\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"initialIp\": \"10.77.77.1\"," + System.lineSeparator() +
                "  \"createdAt\": \"2019-07-12T16:52:19Z\"," + System.lineSeparator() +
                "  \"status\": \"valid\"" + System.lineSeparator() +
                "}" + System.lineSeparator() ;

        final String UPDATE_ACCT_REPLAY_NONCE_4 = "zincF9GthBQVUdM6nr0SjD4s5WT6NF7yIPlf79ZvLi0onJ0";

        return new AcmeMockServerBuilder(server)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY)
                .addNewNonceResponse(NEW_NONCE_RESPONSE)
                .updateAccountRequestAndResponse(UPDATE_ACCT_REQUEST_BODY_1, UPDATE_ACCT_RESPONSE_BODY_1, UPDATE_ACCT_REPLAY_NONCE_1, ACCT_PATH, 200)
                .updateAccountRequestAndResponse(UPDATE_ACCT_REQUEST_BODY_2, UPDATE_ACCT_RESPONSE_BODY_2, UPDATE_ACCT_REPLAY_NONCE_2, ACCT_PATH, 200)
                .updateAccountRequestAndResponse(UPDATE_ACCT_REQUEST_BODY_3, UPDATE_ACCT_RESPONSE_BODY_3, UPDATE_ACCT_REPLAY_NONCE_3, ACCT_PATH, 200)
                .updateAccountRequestAndResponse(UPDATE_ACCT_REQUEST_BODY_4, UPDATE_ACCT_RESPONSE_BODY_4, UPDATE_ACCT_REPLAY_NONCE_4, ACCT_PATH, 200)
                .build();
    }

    private ClientAndServer setupTestDeactivateAccount() {
        final String ACCT_PATH = "/acme/acct/17";

        // set up a mock Let's Encrypt server
        final String DIRECTORY_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"uvnr4pUXRhY\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator() +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator() +
                "  \"meta\": {" + System.lineSeparator() +
                "    \"caaIdentities\": [" + System.lineSeparator() +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator() +
                "    ]," + System.lineSeparator() +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator() +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator() +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator() +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator() +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String NEW_NONCE_RESPONSE = "zinchEUilHEBz4iXwM6Xm_W6C6_dmdK0dxD8jnyQoblcorE";

        final String QUERY_ACCT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMTciLCJub25jZSI6InppbmNoRVVpbEhFQno0aVh3TTZYbV9XNkM2X2RtZEswZHhEOGpueVFvYmxjb3JFIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvYWNjdC8xNyJ9\",\"payload\":\"\",\"signature\":\"KxQxrfXUolF0Hcag8v5Y7eHnq_pbXaRQUZRPkg0b1e1BhSn9nXMbl_9uTL6bDTrhl5P8inemfxH3h2v2RHTDeF2vGgTVP-YcdzlrYx_aqn_3iAOs9KCHsBx9Upyn3qrIN-Do48rffkfnCDRJQmc8sNNWDkbFFCI_BuGzsuSz-pyfcLzVPGyKwHqKghYbOdieXIBoxx7GUO4rxpOLIH4r2g2kvoLGRAggbzmz8ogYoe8JYTM-Rai6CUaBoZVOI2LKj87k5Yv509-QhMkavFy41mHmXk23e2d96olhJm429iNZq9Jpdh6IZAWQIX8p_kpEkAF1RdOxCEVQdy4MEkb2Ug\"}";

        final String QUERY_ACCT_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"key\": {" + System.lineSeparator() +
                "    \"kty\": \"RSA\"," + System.lineSeparator() +
                "    \"n\": \"gtzybTJ9uGLGmKifHStiqOdQhlP0kVG4RiWyrpSG4Za1SUBqBiCrdAQFugOUsADsv0glSeuFybdiLbNzrCVWz6ZgA23DKj2jQzqQsVR_lek9rJ-JdsqQ7yEnkXmtPZolC805LEJvd5mAZf-bq5cikMWSXUwt55i8HAPgmqu_kKhl_4fgiMV4RlK8FpS4q2mtUPmhy8embNckhJwQUxKJewTosZA265m3-sVO8oXTAvVJneg1xrXHUnwD0QJ562zOT1Ly42WOL72c1h6aotgWDDMFBWAl7qF7wg-I8VCRNeyJuhhr6HEOP22NB3_ly_vjtImJPXF9GZACD4zhMaRQmw\"," + System.lineSeparator() +
                "    \"e\": \"AQAB\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"contact\": [" + System.lineSeparator() +
                "    \"mailto:admin@anexample.com\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"initialIp\": \"10.77.77.1\"," + System.lineSeparator() +
                "  \"createdAt\": \"2019-07-16T19:41:43Z\"," + System.lineSeparator() +
                "  \"status\": \"valid\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String QUERY_ACCT_REPLAY_NONCE = "taroynNYu8XNbXtJvzVFq0gN2e0eiU9T2z_Vv22I3weQdq0";

        final String UPDATE_ACCT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMTciLCJub25jZSI6InRhcm95bk5ZdThYTmJYdEp2elZGcTBnTjJlMGVpVTlUMnpfVnYyMkkzd2VRZHEwIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvYWNjdC8xNyJ9\",\"payload\":\"eyJzdGF0dXMiOiJkZWFjdGl2YXRlZCJ9\",\"signature\":\"aqZ478VXBfPra-jqaiZ6LrqXBBU73fVj_db0egoRQXz-IYItPM6TRuP2u0aOLoEqwCoLkSSKylzdSDiY1bTtpEi3LjI5LxzblHYoY9_qZzrSnFPVJTueVWXsMvSz7u6z8gP6R8WK637bCez9hhGVgH225leaGissqRb85UmRXL6qlsniyYwwlrLqaFmExrcFzVGEz0lp9hKgyeCXSht2niDWQHvsOSFJEUVtUncrtktnyE9pdH2ZHR9Jo7LicH7x2EwkiVaSlxbK5A35l4KzWPCjfp-kwq-zKEuP6pT6tjimRW--ySg3zeHn4vKKOaSA1mGKXh-Bb3WYZPUe2rQ1vg\"}";

        final String UPDATE_ACCT_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"key\": {" + System.lineSeparator() +
                "    \"kty\": \"RSA\"," + System.lineSeparator() +
                "    \"n\": \"gtzybTJ9uGLGmKifHStiqOdQhlP0kVG4RiWyrpSG4Za1SUBqBiCrdAQFugOUsADsv0glSeuFybdiLbNzrCVWz6ZgA23DKj2jQzqQsVR_lek9rJ-JdsqQ7yEnkXmtPZolC805LEJvd5mAZf-bq5cikMWSXUwt55i8HAPgmqu_kKhl_4fgiMV4RlK8FpS4q2mtUPmhy8embNckhJwQUxKJewTosZA265m3-sVO8oXTAvVJneg1xrXHUnwD0QJ562zOT1Ly42WOL72c1h6aotgWDDMFBWAl7qF7wg-I8VCRNeyJuhhr6HEOP22NB3_ly_vjtImJPXF9GZACD4zhMaRQmw\"," + System.lineSeparator() +
                "    \"e\": \"AQAB\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"contact\": [" + System.lineSeparator() +
                "    \"mailto:admin@anexample.com\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"initialIp\": \"10.77.77.1\"," + System.lineSeparator() +
                "  \"createdAt\": \"2019-07-16T19:41:43Z\"," + System.lineSeparator() +
                "  \"status\": \"deactivated\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String UPDATE_ACCT_REPLAY_NONCE = "zincva7_lpvREqT5DgWxNxrRyAVtho7l4ijemb_9_YlZJrY";

        final String ORDER_CERT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMTciLCJub25jZSI6InppbmN2YTdfbHB2UkVxVDVEZ1d4TnhyUnlBVnRobzdsNGlqZW1iXzlfWWxaSnJZIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvbmV3LW9yZGVyIn0\",\"payload\":\"eyJpZGVudGlmaWVycyI6W3sidHlwZSI6ImRucyIsInZhbHVlIjoiMTcyLjE3LjAuMSJ9XX0\",\"signature\":\"a9LHneyMzSv8j8xWk1yWDD_n4sRGElhSCIO5PJBGshqAQQ4hrsKodxUCHBeQsQ16sCRoOWkI0k0RpOARdGVKoVkPRP1qs8wUhIJV62ljC4uXrMg4mjfQKZXbU8MBluf1k0nRdeKTlUhg7p8l9-sZzF5DUPV82g3VyP7kESWzmBJP6RlIrH0sPyfA-k9xAl9fr1SKSEGVQt0xvPk4mj6RihEBmYaGFVjAFum_gBrbo4YWWgBkLWB2Y9CmBqOHngDA7WuBSWaDme6WOMQX043EttYXaRDm_grz14ig6kmEkFYJEqD5fUMR8XcQ5rVuUYXCiEfqjivMh5HXTblN4dsXXQ\"}";

        final String ORDER_CERT_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"type\": \"urn:ietf:params:acme:error:unauthorized\"," + System.lineSeparator() +
                "  \"detail\": \"Account is not valid, has status \\\"deactivated\\\"\"," + System.lineSeparator() +
                "  \"status\": 403" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String ORDER_CERT_REPLAY_NONCE = "taroVNa0UnQN4LSCL9zs6QzJC4-_hwQwWigp7oPQiexJJs0";
        final String ORDER_LOCATION = "";

        return new AcmeMockServerBuilder(server)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY)
                .addNewNonceResponse(NEW_NONCE_RESPONSE)
                .updateAccountRequestAndResponse(QUERY_ACCT_REQUEST_BODY, QUERY_ACCT_RESPONSE_BODY, QUERY_ACCT_REPLAY_NONCE, ACCT_PATH, 200)
                .updateAccountRequestAndResponse(UPDATE_ACCT_REQUEST_BODY, UPDATE_ACCT_RESPONSE_BODY, UPDATE_ACCT_REPLAY_NONCE, ACCT_PATH, 200)
                .orderCertificateRequestAndResponse(ORDER_CERT_REQUEST_BODY, ORDER_CERT_RESPONSE_BODY, ORDER_CERT_REPLAY_NONCE, ORDER_LOCATION, 403, true)
                .build();
    }

    private ClientAndServer setupTestGetNonce() {

        // set up a mock Let's Encrypt server
        final String DIRECTORY_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"68bTwETzqeg\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator() +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator() +
                "  \"meta\": {" + System.lineSeparator() +
                "    \"caaIdentities\": [" + System.lineSeparator() +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator() +
                "    ]," + System.lineSeparator() +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator() +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator() +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator() +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator() +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String NEW_NONCE_RESPONSE = "zincG439TOpiDIeJBbmInMOo_xnZV0jpUstA4VZgSiyuFy0";

        return new AcmeMockServerBuilder(server)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY)
                .addNewNonceResponse(NEW_NONCE_RESPONSE)
                .build();
    }

    private ClientAndServer setupTestObtainCertificate(boolean missingLocationURL) {
        // set up a mock Let's Encrypt server
        final String DIRECTORY_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"UZT0cQcZznY\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator() +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator() +
                "  \"meta\": {" + System.lineSeparator() +
                "    \"caaIdentities\": [" + System.lineSeparator() +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator() +
                "    ]," + System.lineSeparator() +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator() +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator() +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator() +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator() +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String NEW_NONCE_RESPONSE = "zincZ90pZVS1o4ZQnDGedloqnC9spanlU1V1wWLntNiniwA";

        final String QUERY_ACCT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJuWVJ5RGQ4b1ZPZ3hTRlVzX2xoYllvMjNGWEFHelVJRTl0dFVCdEJ3N3VHc1U5aEpsSi1RYXlxbHJfZGwwUHNoYjVaeFk4a0h0ZEY5QkVOX1F1Slp4emlzMWNzNFhUY0YzbjVBRUswcFVtS3VQSGt3ck9PNExFN1l3RHBEM0Q1YjRHVjFpVFUyY1ZyRmhMVmI1WmQtTnl6NVRJOWlCbDM3N0FJRmt6aU00Rmx2aS1CV19UZEJmTVVFVURtNW85dFBCU2N2M255YThhSFpJYmdyaW5Ubm1IMFBQMk1vNW50czJjd19zU0d0aENXWkhqWVp1MjRmWE5wb1RjTE1OVldBLTJPSjR0dWtGamlwWC03ckhZRUJiclRSd2FIVnlTOEd2UFp5bjU5b3VYZzAwVWhCdEhRTHROUldPQy1tV29TdFBXOWxjOHNCQm1YdlJiTzdFUkU1dVEifSwibm9uY2UiOiJ6aW5jWjkwcFpWUzFvNFpRbkRHZWRsb3FuQzlzcGFubFUxVjF3V0xudE5pbml3QSIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL25ldy1hY2N0In0\",\"payload\":\"eyJvbmx5UmV0dXJuRXhpc3RpbmciOnRydWV9\",\"signature\":\"SiAzvfBH1yTZPpkTDXS129mVo5IskhJYTB3_hIClPVxOPl_cGSVd4qBCuJnBCoK3kpmHUML6QEJfhjQi4hzY6xljWP71YvJZDT_y4RERcJzFPBvvIJx6-Qcw9O_B9aY43AuspyiCOMgs6iBTfObl50BjuCsiWqOh7OF4STOdl1iZpQWeIdClJr20KRXzHikq1drPsKXyg0AOYKs6Wjv_GIbcQZ-bvesS6PNxH7r_hJFiDrvdu9I-mBrmg-85DGh98e-jmO7LHvqFCtrQp4IujRj7_9TDOjlqRudNlLP_KJn4Waa7VrUcgkEMYoXYvdmASnC5FKTTphXoz5dU42Sl8g\"}";

        final String QUERY_ACCT_RESPONSE_BODY= "";

        final String QUERY_ACCT_REPLAY_NONCE = "taroRaxMHOS9esn17VtzFmVBE954tN9DLvYoIp-efS2RlO8";
        final String ACCT_LOCATION = "http://localhost:4001/acme/acct/8";


        final String ORDER_CERT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvOCIsIm5vbmNlIjoidGFyb1JheE1IT1M5ZXNuMTdWdHpGbVZCRTk1NHROOURMdllvSXAtZWZTMlJsTzgiLCJ1cmwiOiJodHRwOi8vbG9jYWxob3N0OjQwMDEvYWNtZS9uZXctb3JkZXIifQ\",\"payload\":\"eyJpZGVudGlmaWVycyI6W3sidHlwZSI6ImRucyIsInZhbHVlIjoiZmpzbGpnaGFzbGRmamdrdjIuY29tIn1dfQ\",\"signature\":\"d2j2FmrpIKJiDG68OtAtqIbOm62LVifnjbOzHGZiex2pruKvzXrnrARp0iGzeMo-TLlx0L6ZoMkYKWIDlfUGKt_td4Ah3I02AMDzccTgBYeSfNJbjClt6ZI63YSNY2ZKp5XtY3plG_V3PPRDGyO7LJhothwat-ifYrs3FlApEeqKHpOUZThnJxS866bugPpgttmePp8nv7i2wGL5gdxmzWwEyf5rEFbC26uJXkzvL2FCFqdqm1dfF8Ee6LZrHP3XojsozEGiP2oVlZXu_2f9KCDAyAc9AALeot8OuRlVhDfGWRegqaiDx0WZ_J1_vpC-PBZ0QfM5Ue11N1xQRhRkDw\"}";

        final String ORDER_CERT_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"status\": \"pending\"," + System.lineSeparator() +
                "  \"expires\": \"2019-07-22T14:33:01.811142415Z\"," + System.lineSeparator() +
                "  \"identifiers\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns\"," + System.lineSeparator() +
                "      \"value\": \"fjsljghasldfjgkv2.com\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"authorizations\": [" + System.lineSeparator() +
                "    \"http://localhost:4001/acme/authz/v2/33\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"finalize\": \"http://localhost:4001/acme/finalize/8/38\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String ORDER_CERT_REPLAY_NONCE = "zincRETf91sqQsqgJ8JVzGxZqZ0be7Bn2tGeU7AYqSsT3-s";
        final String ORDER_LOCATION = "http://localhost:4001/acme/order/8/38";

        final String AUTHZ_URL = "/acme/authz/v2/33";
        final String AUTHZ_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvOCIsIm5vbmNlIjoiemluY1JFVGY5MXNxUXNxZ0o4SlZ6R3hacVowYmU3Qm4ydEdlVTdBWXFTc1QzLXMiLCJ1cmwiOiJodHRwOi8vbG9jYWxob3N0OjQwMDEvYWNtZS9hdXRoei92Mi8zMyJ9\",\"payload\":\"\",\"signature\":\"mNrjytqKNBd0JhUycZHW0dp4tQi67YrGvAKys5zOGi2t1HCKYtY53OKDXYSDTSI6tu3aZLzxlYJvK7Ufq153BXga1IOpoL6uD8vHqNWTU16FqjcMO7phBu0NLZqsf_6G0J3aiG6G1YWCNF-QrIhKhuazp1Ru0xX5hBaVvY2VCpUC7A4IKAgV5U5eKzJaWHuZgdfCSu1HDT57ShpV1F9yRwVU2JtZI07gNnPqE0CanAu423hJXEDgole-0vXbgRMTo5CiI5s_SA9t4iZD3O8cd2FA1eXpT8N9HqU5uvvs5cuD4gJCVyA5TiGEUucYJ7UfWjfLAGWbtFTpO0HjGyx-4A\"}";
        final String AUTHZ_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"identifier\": {" + System.lineSeparator() +
                "    \"type\": \"dns\"," + System.lineSeparator() +
                "    \"value\": \"fjsljghasldfjgkv2.com\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"status\": \"pending\"," + System.lineSeparator() +
                "  \"expires\": \"2019-07-22T14:33:01Z\"," + System.lineSeparator() +
                "  \"challenges\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"http-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/v2/33/9Q-rVw\"," + System.lineSeparator() +
                "      \"token\": \"qB-dx1r8U2JsP0uXCLVmMKcFcgMRVESXnGX1n0Eb9io\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/v2/33/cJNUZw\"," + System.lineSeparator() +
                "      \"token\": \"qB-dx1r8U2JsP0uXCLVmMKcFcgMRVESXnGX1n0Eb9io\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"tls-alpn-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/v2/33/TYojGA\"," + System.lineSeparator() +
                "      \"token\": \"qB-dx1r8U2JsP0uXCLVmMKcFcgMRVESXnGX1n0Eb9io\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String AUTHZ_REPLAY_NONCE = "taroG7xr6bCfeG1Ffcl7AxcmlGeDKuY0SmK3NsNMDSXazxM";

        final String CHALLENGE_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvOCIsIm5vbmNlIjoidGFyb0c3eHI2YkNmZUcxRmZjbDdBeGNtbEdlREt1WTBTbUszTnNOTURTWGF6eE0iLCJ1cmwiOiJodHRwOi8vbG9jYWxob3N0OjQwMDEvYWNtZS9jaGFsbGVuZ2UvdjIvMzMvOVEtclZ3In0\",\"payload\":\"e30\",\"signature\":\"Nig_RPCHfP5UGJ6erD3mKe4UdO3lc4Z_aefE9_ulVqfhQS1n_MSOR_TDILoR3zBHAPCXkmsImTKMV23T4Rf6YBHpmz4OJoHawmg100tbyvvS1dXCkitMGaTe9IaBEFi4ktUWDJkytQfn0oisHDt7UcystUgKiqPPfnxnCYsLdArfTZTadfu7iZaVSSN7LieN5pnHQwo_0DLcycBxWDyIvVJ8GZlyhapsTdAqkiATYb7kg0OlFZNDgdmXodAgc3lXmc2rGZvop1tNWbKcejI9yXBtnRQXXFEVEblUpwfTdeNJpeUcawuT8jxGD9TCc4NdIFz_ExlvMzWeWdoR0vyI_Q\"}";
        final String CHALLENGE_URL = "/acme/challenge/v2/33/9Q-rVw";

        final String CHALLENGE_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"type\": \"http-01\"," + System.lineSeparator() +
                "  \"status\": \"pending\"," + System.lineSeparator() +
                "  \"url\": \"http://localhost:4001/acme/challenge/v2/33/9Q-rVw\"," + System.lineSeparator() +
                "  \"token\": \"qB-dx1r8U2JsP0uXCLVmMKcFcgMRVESXnGX1n0Eb9io\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String CHALLENGE_REPLAY_NONCE = "zincn-OjDeCVuF7tlIX4TzeMCO6S1uxL8J6S8vlsiR0bJ9o";
        final String CHALLENGE_LOCATION = "http://localhost:4001/acme/challenge/v2/33/9Q-rVw";
        final String CHALLENGE_LINK = "<http://localhost:4001/acme/authz/v2/33>;rel=\"up\"";
        final String VERIFY_CHALLENGE_URL = "/.well-known/acme-challenge/qB-dx1r8U2JsP0uXCLVmMKcFcgMRVESXnGX1n0Eb9io";
        final String CHALLENGE_FILE_CONTENTS = "qB-dx1r8U2JsP0uXCLVmMKcFcgMRVESXnGX1n0Eb9io.ufCzRanjh1vid9iOZQJFYLBw91fP4XHc6_APvqfq8_E"; //******* FJ FIX

        final String UPDATED_AUTHZ_REPLAY_NONCE = "taro017s3xOBGzihgQW-BaBy-9GZXwTO509S5MZncYW4mpE";
        final String UPDATED_AUTHZ_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"identifier\": {" + System.lineSeparator() +
                "    \"type\": \"dns\"," + System.lineSeparator() +
                "    \"value\": \"fjsljghasldfjgkv2.com\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"status\": \"valid\"," + System.lineSeparator() +
                "  \"expires\": \"2019-08-21T14:33:01Z\"," + System.lineSeparator() +
                "  \"challenges\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"http-01\"," + System.lineSeparator() +
                "      \"status\": \"valid\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/v2/33/9Q-rVw\"," + System.lineSeparator() +
                "      \"token\": \"qB-dx1r8U2JsP0uXCLVmMKcFcgMRVESXnGX1n0Eb9io\"," + System.lineSeparator() +
                "      \"validationRecord\": [" + System.lineSeparator() +
                "        {" + System.lineSeparator() +
                "          \"url\": \"http://fjsljghasldfjgkv2.com/.well-known/acme-challenge/qB-dx1r8U2JsP0uXCLVmMKcFcgMRVESXnGX1n0Eb9io\"," + System.lineSeparator() +
                "          \"hostname\": \"fjsljghasldfjgkv2.com\"," + System.lineSeparator() +
                "          \"port\": \"5002\"," + System.lineSeparator() +
                "          \"addressesResolved\": [" + System.lineSeparator() +
                "            \"172.17.0.1\"" + System.lineSeparator() +
                "          ]," + System.lineSeparator() +
                "          \"addressUsed\": \"172.17.0.1\"" + System.lineSeparator() +
                "        }" + System.lineSeparator() +
                "      ]" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/v2/33/cJNUZw\"," + System.lineSeparator() +
                "      \"token\": \"qB-dx1r8U2JsP0uXCLVmMKcFcgMRVESXnGX1n0Eb9io\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"tls-alpn-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/v2/33/TYojGA\"," + System.lineSeparator() +
                "      \"token\": \"qB-dx1r8U2JsP0uXCLVmMKcFcgMRVESXnGX1n0Eb9io\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String FINALIZE_URL = "/acme/finalize/8/38";

        final String FINALIZE_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"status\": \"valid\"," + System.lineSeparator() +
                "  \"expires\": \"2019-07-22T14:33:01Z\"," + System.lineSeparator() +
                "  \"identifiers\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns\"," + System.lineSeparator() +
                "      \"value\": \"fjsljghasldfjgkv2.com\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"authorizations\": [" + System.lineSeparator() +
                "    \"http://localhost:4001/acme/authz/v2/33\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"finalize\": \"http://localhost:4001/acme/finalize/8/38\"," + System.lineSeparator() +
                "  \"certificate\": \"http://localhost:4001/acme/cert/ffd1a2730985d8e32ab1ac438aefc65518e5\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String FINALIZE_REPLAY_NONCE = "zincl2Z7DtAW_lUYY_g0XB2mg2s2im_ipXMJ2WrBXVXDn6g";
        final String FINALIZE_LOCATION = "http://localhost:4001/acme/order/8/38";

        final String CHECK_ORDER_URL = "/acme/order/8/38";
        final String CHECK_ORDER_REPLAY_NONCE = "taroqeMgGanpdqBR-8RJMZb0dUuK8xIyiFKuJpO_wQ1Ldj8";

        final String CHECK_ORDER_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvOCIsIm5vbmNlIjoiemluY2wyWjdEdEFXX2xVWVlfZzBYQjJtZzJzMmltX2lwWE1KMldyQlhWWERuNmciLCJ1cmwiOiJodHRwOi8vbG9jYWxob3N0OjQwMDEvYWNtZS9vcmRlci84LzM4In0\",\"payload\":\"\",\"signature\":\"SEp14i23-CUnsolmHaGlJlRayBtU6yZHw6CGTpWAQWaVtwz5K-6P3SEfIJd2Hwr_-R14Qh1H_7ClbXgRiwvkDKaP0N8Ya1rzrUWO9j5er1dam1uQ7HXiwuh46XZ48ey_tKc9h4y_hWMv76kk6nq6q4vjVsgjdgciYBrn-NTFPU53yWytIO0QRhtkLEiJhboihDY0sdpjKJVvOmOc4uapsmK3BIr7sdDbtUEIlbAgqEIhLCUwT3Pdi_h8H7WcG6csqtjs7vsfnbFMf2mx90Wv08J4tVohB0bRq0FS6OztvxyYGOrwRVAOj4JV2hMKzOmkhIQvHJ7F4Jb4cQkhQDOQzw\"}";
        final String CHECK_ORDER_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"status\": \"valid\"," + System.lineSeparator() +
                "  \"expires\": \"2019-07-22T14:33:01Z\"," + System.lineSeparator() +
                "  \"identifiers\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns\"," + System.lineSeparator() +
                "      \"value\": \"fjsljghasldfjgkv2.com\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"authorizations\": [" + System.lineSeparator() +
                "    \"http://localhost:4001/acme/authz/v2/33\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"finalize\": \"http://localhost:4001/acme/finalize/8/38\"," + System.lineSeparator() +
                "  \"certificate\": \"http://localhost:4001/acme/cert/ffd1a2730985d8e32ab1ac438aefc65518e5\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String CERT_URL = "/acme/cert/ffd1a2730985d8e32ab1ac438aefc65518e5";
        final String CERT_REPLAY_NONCE = "zinclGQoEFMTDud-yvqcyzMsVhgC2LOBhQit5x9-U1OHQdQ";

        final String CERT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvOCIsIm5vbmNlIjoidGFyb3FlTWdHYW5wZHFCUi04UkpNWmIwZFV1Szh4SXlpRkt1SnBPX3dRMUxkajgiLCJ1cmwiOiJodHRwOi8vbG9jYWxob3N0OjQwMDEvYWNtZS9jZXJ0L2ZmZDFhMjczMDk4NWQ4ZTMyYWIxYWM0MzhhZWZjNjU1MThlNSJ9\",\"payload\":\"\",\"signature\":\"lNDwbsEVCt7C99EkenioR8OJEEP0wWnz98Wue-_rL1GOqHXSsxpn-PjFRLMaUVCV4Hi44lolzoxyzjnBYDFtWnkWFsaGw09JdJ_oHi4x3EG74yk2bi-1O6fE2CVAT6-4trP7BljbskEdxyPpYa7kKRzybEAv9tP-DIObk_hhQONA8R5hgpAls81kXxMMFyW5HOx30YwujKGWR_XvPpkSEfg4DFxZh7n-UqrE0DONA3cQe9eDIPb3yfIxv5WGSTis2d4UnmVegLkJhYhDtLa4L_bzR78uwyIHg86CCbblWqo2SQLR94gYRudj3d1qckZBROGKtepabnSLonW9jfhSCw\"}";
        final String CERT_RESPONSE_BODY = "-----BEGIN CERTIFICATE-----" + System.lineSeparator() +
                "MIIFSDCCBDCgAwIBAgITAP/RonMJhdjjKrGsQ4rvxlUY5TANBgkqhkiG9w0BAQsF" + System.lineSeparator() +
                "ADAfMR0wGwYDVQQDDBRoMnBweSBoMmNrZXIgZmFrZSBDQTAeFw0xOTA3MTUxMzMz" + System.lineSeparator() +
                "MDJaFw0xOTEwMTMxMzMzMDJaMCAxHjAcBgNVBAMTFWZqc2xqZ2hhc2xkZmpna3Yy" + System.lineSeparator() +
                "LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJdYcAK/Wc60J0yN" + System.lineSeparator() +
                "OUj6ZOzP8jJFCDAMfkHXlK7io/jYAHdBGuDlFM6ov65ZBdQGpgxQ5fkJ/FoLjISo" + System.lineSeparator() +
                "UGuPOH1CeMu5w/by1fPiQZ9SbdpoI1D7geoJZXjiuksuGRg/Jjg11FD3eCrCOthO" + System.lineSeparator() +
                "f+I750q/p7/qpKZMTvCRCyCIFyhABY/gxX7AtvGuysRwLhnh4+D5dlJuYGDM5cc9" + System.lineSeparator() +
                "Lf/r1sU7HNDEm+BY9BQZl3EIyfMqU2NZnnUEgkQTjGRa1KkDhpyQX6ojlepZAdOn" + System.lineSeparator() +
                "wn7xG4HLW3aFJvjpVcZOaWF+8ARx7c/1+rn9zG+NVKmpAiTh3LsN5ta8ZYeQ5OgZ" + System.lineSeparator() +
                "p9DYlJECAwEAAaOCAnowggJ2MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggr" + System.lineSeparator() +
                "BgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUiXSw9phY" + System.lineSeparator() +
                "9D/I5V0B9/VLD3orfoUwHwYDVR0jBBgwFoAU+3hPEvlgFYMsnxd/NBmzLjbqQYkw" + System.lineSeparator() +
                "ZAYIKwYBBQUHAQEEWDBWMCIGCCsGAQUFBzABhhZodHRwOi8vMTI3LjAuMC4xOjQw" + System.lineSeparator() +
                "MDIvMDAGCCsGAQUFBzAChiRodHRwOi8vYm91bGRlcjo0NDMwL2FjbWUvaXNzdWVy" + System.lineSeparator() +
                "LWNlcnQwIAYDVR0RBBkwF4IVZmpzbGpnaGFzbGRmamdrdjIuY29tMCcGA1UdHwQg" + System.lineSeparator() +
                "MB4wHKAaoBiGFmh0dHA6Ly9leGFtcGxlLmNvbS9jcmwwQAYDVR0gBDkwNzAIBgZn" + System.lineSeparator() +
                "gQwBAgEwKwYDKgMEMCQwIgYIKwYBBQUHAgEWFmh0dHA6Ly9leGFtcGxlLmNvbS9j" + System.lineSeparator() +
                "cHMwggECBgorBgEEAdZ5AgQCBIHzBIHwAO4AdQAW6GnB0ZXq18P4lxrj8HYB94zh" + System.lineSeparator() +
                "tp0xqFIYtoN/MagVCAAAAWv2DRpoAAAEAwBGMEQCIE/rONbtJZRC1zabAJZ5i3L/" + System.lineSeparator() +
                "7oDs/ZcJer6p+0OfliP+AiAtmgs5VWHfNmTBiSPNnkVLSMHnzA2ONOQSLFJ1Xsed" + System.lineSeparator() +
                "0AB1AN2ZNPyl5ySAyVZofYE0mQhJskn3tWnYx7yrP1zB825kAAABa/YNGmkAAAQD" + System.lineSeparator() +
                "AEYwRAIgHqL89OFhmhOAeSBf4qCMuQAsOoA7wEXpPotoR7fN5c8CIHz21nM018rT" + System.lineSeparator() +
                "q8/xAWaiXb0EUC9RJzfUO9AHZ9VCwDWZMA0GCSqGSIb3DQEBCwUAA4IBAQAOlUUt" + System.lineSeparator() +
                "rUX4aWPGnhIRZDNzeNu8cWyS56aSGGncRzMywNHdLb2BuUz20HTgBI58y6p16azY" + System.lineSeparator() +
                "RNpA5v971YxYZu39IFqRYcBQ4FR8iORrwqPW1Kgh2OMA5qcbGNEEYq1NQQgcKTtR" + System.lineSeparator() +
                "dBjUgSTzf2KOmwo8FWYm2Swy2aXObH8ByxO4RPLXs4wwDMr9OGUN8SmGE59zNvqI" + System.lineSeparator() +
                "v90YxY7QsgL0dXy8Q2vlfwTAbucyKEBJkO00tdiUZb+vnrS3PZswZHx6QNBdKRNQ" + System.lineSeparator() +
                "vjkL5lqSQzBDpc9TykM3wzpRgN03N34mLs3a69N5XFnz5dUt/PEDGU4Vcvmn/M0c" + System.lineSeparator() +
                "jwsnZrDGIuXlHoTQ" + System.lineSeparator() +
                "-----END CERTIFICATE-----" + System.lineSeparator() +
                "" + System.lineSeparator() +
                "-----BEGIN CERTIFICATE-----" + System.lineSeparator() +
                "MIIERTCCAy2gAwIBAgICElowDQYJKoZIhvcNAQELBQAwKzEpMCcGA1UEAwwgY2Fj" + System.lineSeparator() +
                "a2xpbmcgY3J5cHRvZ3JhcGhlciBmYWtlIFJPT1QwHhcNMTYwMzIyMDI0NzUyWhcN" + System.lineSeparator() +
                "MjEwMzIxMDI0NzUyWjAfMR0wGwYDVQQDDBRoMnBweSBoMmNrZXIgZmFrZSBDQTCC" + System.lineSeparator() +
                "ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMIKR3maBcUSsncXYzQT13D5" + System.lineSeparator() +
                "Nr+Z3mLxMMh3TUdt6sACmqbJ0btRlgXfMtNLM2OU1I6a3Ju+tIZSdn2v21JBwvxU" + System.lineSeparator() +
                "zpZQ4zy2cimIiMQDZCQHJwzC9GZn8HaW091iz9H0Go3A7WDXwYNmsdLNRi00o14U" + System.lineSeparator() +
                "joaVqaPsYrZWvRKaIRqaU0hHmS0AWwQSvN/93iMIXuyiwywmkwKbWnnxCQ/gsctK" + System.lineSeparator() +
                "FUtcNrwEx9Wgj6KlhwDTyI1QWSBbxVYNyUgPFzKxrSmwMO0yNff7ho+QT9x5+Y/7" + System.lineSeparator() +
                "XE59S4Mc4ZXxcXKew/gSlN9U5mvT+D2BhDtkCupdfsZNCQWp27A+b/DmrFI9NqsC" + System.lineSeparator() +
                "AwEAAaOCAX0wggF5MBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGG" + System.lineSeparator() +
                "MH8GCCsGAQUFBwEBBHMwcTAyBggrBgEFBQcwAYYmaHR0cDovL2lzcmcudHJ1c3Rp" + System.lineSeparator() +
                "ZC5vY3NwLmlkZW50cnVzdC5jb20wOwYIKwYBBQUHMAKGL2h0dHA6Ly9hcHBzLmlk" + System.lineSeparator() +
                "ZW50cnVzdC5jb20vcm9vdHMvZHN0cm9vdGNheDMucDdjMB8GA1UdIwQYMBaAFOmk" + System.lineSeparator() +
                "P+6epeby1dd5YDyTpi4kjpeqMFQGA1UdIARNMEswCAYGZ4EMAQIBMD8GCysGAQQB" + System.lineSeparator() +
                "gt8TAQEBMDAwLgYIKwYBBQUHAgEWImh0dHA6Ly9jcHMucm9vdC14MS5sZXRzZW5j" + System.lineSeparator() +
                "cnlwdC5vcmcwPAYDVR0fBDUwMzAxoC+gLYYraHR0cDovL2NybC5pZGVudHJ1c3Qu" + System.lineSeparator() +
                "Y29tL0RTVFJPT1RDQVgzQ1JMLmNybDAdBgNVHQ4EFgQU+3hPEvlgFYMsnxd/NBmz" + System.lineSeparator() +
                "LjbqQYkwDQYJKoZIhvcNAQELBQADggEBAKvePfYXBaAcYca2e0WwkswwJ7lLU/i3" + System.lineSeparator() +
                "GIFM8tErKThNf3gD3KdCtDZ45XomOsgdRv8oxYTvQpBGTclYRAqLsO9t/LgGxeSB" + System.lineSeparator() +
                "jzwY7Ytdwwj8lviEGtiun06sJxRvvBU+l9uTs3DKBxWKZ/YRf4+6wq/vERrShpEC" + System.lineSeparator() +
                "KuQ5+NgMcStQY7dywrsd6x1p3bkOvowbDlaRwru7QCIXTBSb8TepKqCqRzr6YREt" + System.lineSeparator() +
                "doIw2FE8MKMCGR2p+U3slhxfLTh13MuqIOvTuA145S/qf6xCkRc9I92GpjoQk87Z" + System.lineSeparator() +
                "v1uhpkgT9uwbRw0Cs5DMdxT/LgIUSfUTKU83GNrbrQNYinkJ77i6wG0=" + System.lineSeparator() +
                "-----END CERTIFICATE-----" + System.lineSeparator();

        return new AcmeMockServerBuilder(server)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY)
                .addNewNonceResponse(NEW_NONCE_RESPONSE)
                .addNewAccountRequestAndResponse(QUERY_ACCT_REQUEST_BODY, QUERY_ACCT_RESPONSE_BODY, QUERY_ACCT_REPLAY_NONCE, ACCT_LOCATION, 200)
                .orderCertificateRequestAndResponse(ORDER_CERT_REQUEST_BODY, ORDER_CERT_RESPONSE_BODY, ORDER_CERT_REPLAY_NONCE, missingLocationURL ? null : ORDER_LOCATION, 201, false)
                .addAuthorizationResponseBody(AUTHZ_URL, AUTHZ_REQUEST_BODY, AUTHZ_RESPONSE_BODY, AUTHZ_REPLAY_NONCE)
                .addChallengeRequestAndResponse(CHALLENGE_REQUEST_BODY, CHALLENGE_URL, CHALLENGE_RESPONSE_BODY, CHALLENGE_REPLAY_NONCE, CHALLENGE_LOCATION, CHALLENGE_LINK, 200, false, VERIFY_CHALLENGE_URL, CHALLENGE_FILE_CONTENTS, AUTHZ_URL, UPDATED_AUTHZ_RESPONSE_BODY, UPDATED_AUTHZ_REPLAY_NONCE)
                .addFinalizeRequestAndResponse(FINALIZE_RESPONSE_BODY, FINALIZE_REPLAY_NONCE, FINALIZE_URL, FINALIZE_LOCATION, 200)
                .addCheckOrderRequestAndResponse(CHECK_ORDER_URL, CHECK_ORDER_REQUEST_BODY, CHECK_ORDER_RESPONSE_BODY, CHECK_ORDER_REPLAY_NONCE, 200)
                .addCertificateRequestAndResponse(CERT_URL, CERT_REQUEST_BODY, CERT_RESPONSE_BODY, CERT_REPLAY_NONCE, 200)
                .build();
    }

    private ClientAndServer setupTestObtainCertificate() {
        return setupTestObtainCertificate(false);
    }

    private ClientAndServer setupTestObtainCertificateWithKeySize() {

        // set up a mock Let's Encrypt server
        final String DIRECTORY_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"z8YaUV3YTsY\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator() +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator() +
                "  \"meta\": {" + System.lineSeparator() +
                "    \"caaIdentities\": [" + System.lineSeparator() +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator() +
                "    ]," + System.lineSeparator() +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator() +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator() +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator() +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator() +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String NEW_NONCE_RESPONSE = "zincV4PrcvXgFFHASC7eaoGW3hq-VNrQjsBOxMRhZjST6s8";

        final String QUERY_ACCT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJpcVZkd3laNGl0VlNoOFVWX2Z3NlpnVjh3Mk56SEtGdzZWeWl5cGRLMmlyUkk0T3BMdWhJNEhqQ3pSTHR0WkJPX3ZLRjFZaTB1dVdMaFFzMnVpWlJ5eXFCa0R6SXU3UnIwZWp2T2UtLVc2aWhLanE2WnNCQ2Q3eDhMUl9yYXp1X242V1BkQWJZeWZxdnBuS0V0bGZxdW4yMWJnWk1yT1R4YW0tS0FNS2kyNlJlVi1oVDlYU05kbWpoWnhtSzZzQ0NlTl9JOTVEUXZ1VG55VFctUUJFd2J2MVVOTEEtOXRIR3QyUzQ0a2JvT0JtemV6RGdPSVlfNFpNd3MtWXZucFd5VElsU0k3TmlNMVhKb1NXMHlSLWdjaFlRT1FuSEU2QUhtdk5KbV9zSTlZN0ZhQmJVeVJpS0RnTi1vZlR3cXNzdzZ2ejVucUxUanU3Y2dzWld4S1dESHcifSwibm9uY2UiOiJ6aW5jVjRQcmN2WGdGRkhBU0M3ZWFvR1czaHEtVk5yUWpzQk94TVJoWmpTVDZzOCIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL25ldy1hY2N0In0\",\"payload\":\"eyJvbmx5UmV0dXJuRXhpc3RpbmciOnRydWV9\",\"signature\":\"gRo90mq436foiLKrfV1u60yA9P7Zow6VujoSib6QeqidIfM5Oi2dMg6qr5lnA43-BFrPlPrSEQ00AY2N1__hpbR8WDrheHVaizYh3ntmeQ3GoXqsu7pvXDMveIicr8JYNaGO2Lz78tw21LCIpz6Iyei_tOeIHdp7tBkB813eAdL6W9g7y6o7F-HqJf2zYfZ8p-inphteEXy_N2WYSxOUsVInEmmV2evPJZ-Q_wGPam1KqyOWavCxln5KdcgeXp_MCCl9nPPOSb74XjJhyJwJs6SEbp8S38dFswRUgTY38evzx_xvlQRVWb7UrZmEPWGvUAkgPejccslZoT_ajHtcig\"}";

        final String QUERY_ACCT_RESPONSE_BODY= "";

        final String QUERY_ACCT_REPLAY_NONCE = "taroq4c6_F5_CIj2KA3dyxojYl4TX3k2jHoGBqchbp9D3ks";
        final String ACCT_LOCATION = "http://localhost:4001/acme/acct/10";


        final String ORDER_CERT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMTAiLCJub25jZSI6InRhcm9xNGM2X0Y1X0NJajJLQTNkeXhvallsNFRYM2syakhvR0JxY2hicDlEM2tzIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvbmV3LW9yZGVyIn0\",\"payload\":\"eyJpZGVudGlmaWVycyI6W3sidHlwZSI6ImRucyIsInZhbHVlIjoiaW5sbmVzZXBwd2tmd2V3djIuY29tIn1dfQ\",\"signature\":\"Ec9GvU8kMXffSZ2nsXDzNxkZDRwQKJRZrDk4ijg4C-Xsvpk5ggfb9gN7-5LFJzhpxqBSjgZsA6EBG_bRNPN7th5mJWqhOfIGU4UbxOuIdirvprlBbuv_EHucGIncwlFfju5uAnJsnQQrZzsWj6yvaj2vpgvdSpzanmIsDbO4dRN9NDwntORy95Px54FGt9TxBrI1kGXLGwA6SX5qOSeLu-aMqys2kzf5Tnox-rmnvAKVaym3vWSX2wBHmnVGiynIAupW9Znakeqw2lOWWQdG_0ybXphvyAjnMgPgjSd28b02lz9Rs3N25Pg5zT4BnrRDrJY734-tIC5VoY2cm3wb3g\"}";
        final String ORDER_CERT_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"status\": \"pending\"," + System.lineSeparator() +
                "  \"expires\": \"2019-07-23T20:20:42.047150201Z\"," + System.lineSeparator() +
                "  \"identifiers\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns\"," + System.lineSeparator() +
                "      \"value\": \"inlneseppwkfwewv2.com\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"authorizations\": [" + System.lineSeparator() +
                "    \"http://localhost:4001/acme/authz/v2/47\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"finalize\": \"http://localhost:4001/acme/finalize/10/69\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String ORDER_CERT_REPLAY_NONCE = "zincTg-qOV-A1AthHGt9XKWZjPyd7459Ab5bFS2Rsb-k2pU";
        final String ORDER_LOCATION = "http://localhost:4001/acme/order/10/69";

        final String AUTHZ_URL = "/acme/authz/v2/47";
        final String AUTHZ_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMTAiLCJub25jZSI6InppbmNUZy1xT1YtQTFBdGhIR3Q5WEtXWmpQeWQ3NDU5QWI1YkZTMlJzYi1rMnBVIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvYXV0aHovdjIvNDcifQ\",\"payload\":\"\",\"signature\":\"F2rVeV76ynMI6nt_4oncsrx4m7-hnraZPz0rUyVHHkaoRUicAFgI0MlXszbFEzMhJ4vztfq5ovhBWfWKKxK2oUZGLqW834-HHKByyAiOUSgOSw0naLxFs96U09OAPQGBTcd1z9bsVmXG8orVIxxoKVDjQzkxfb0L1QC0FdNx-Vl0R6CKDdgLbUPKR2pbagSVKMJ8HPFWuYYnUeQZqmr3i0vkjNQRHO6pFcLPRXSHwywKO73JaGDbynOSu-MAWmkSQ2TaMfNQxrmaSjgRvB1K0wJXjCz3nyO7xYraC10ldbLwEmTu-DDIVJ0zyMgAEp3NGYYx-77qUHp_2UCrrY5KhA\"}";
        final String AUTHZ_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"identifier\": {" + System.lineSeparator() +
                "    \"type\": \"dns\"," + System.lineSeparator() +
                "    \"value\": \"inlneseppwkfwewv2.com\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"status\": \"pending\"," + System.lineSeparator() +
                "  \"expires\": \"2019-07-23T20:20:42Z\"," + System.lineSeparator() +
                "  \"challenges\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"http-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/v2/47/z7sh0A\"," + System.lineSeparator() +
                "      \"token\": \"215ACi-BkIjZ28ynW7kiDco21cv4wxRyByykbgxl9Pc\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/v2/47/mlvrMA\"," + System.lineSeparator() +
                "      \"token\": \"215ACi-BkIjZ28ynW7kiDco21cv4wxRyByykbgxl9Pc\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"tls-alpn-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/v2/47/_wf1QQ\"," + System.lineSeparator() +
                "      \"token\": \"215ACi-BkIjZ28ynW7kiDco21cv4wxRyByykbgxl9Pc\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String AUTHZ_REPLAY_NONCE = "tarozNXDL3x4apxYH38Mz3y3oDRdMLMp8fujKrf8JtplOww";

        final String CHALLENGE_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMTAiLCJub25jZSI6InRhcm96TlhETDN4NGFweFlIMzhNejN5M29EUmRNTE1wOGZ1aktyZjhKdHBsT3d3IiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvY2hhbGxlbmdlL3YyLzQ3L3o3c2gwQSJ9\",\"payload\":\"e30\",\"signature\":\"V-wYzOrZNxeHBxcVEoGvo5ISccYRSBVRiTajcmSla04f9SCm1nvgeE7u0N0Uc07ATlEqBTSvqN0v3iiLGuMxff-xEePQ15DsEUv8aN231ZiUvGalZYtV8UCM_8yz9Ixc4dgFJEBzY3zhyV3yKiPteF1hh6QMyTmk9erOuWJqIuWuluKo3vbF1K5A7z5E0Uq1uSysMQ5h-c5wqY7eDQzrGZ-PadSzUXXzAMKXqpNizpPRF3PfE0D6R3AiutunSgNCkd4qYgEGqZ1Xx8_caJ_s_2dHuNPbyDHShesAL9vp0SIs0etfzCbAYJFut6erA5hfyJDyIRl4VadC9obNSn_zqA\"}";
        final String CHALLENGE_URL = "/acme/challenge/v2/47/z7sh0A";

        final String CHALLENGE_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"type\": \"http-01\"," + System.lineSeparator() +
                "  \"status\": \"pending\"," + System.lineSeparator() +
                "  \"url\": \"http://localhost:4001/acme/challenge/v2/47/z7sh0A\"," + System.lineSeparator() +
                "  \"token\": \"215ACi-BkIjZ28ynW7kiDco21cv4wxRyByykbgxl9Pc\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String CHALLENGE_REPLAY_NONCE = "zincdmVABCB6HjsLMqEUskJi720sehqIUtrhyOeUOZ3IrCU";
        final String CHALLENGE_LOCATION = "http://localhost:4001/acme/challenge/v2/47/z7sh0A";
        final String CHALLENGE_LINK = "<http://localhost:4001/acme/authz/v2/47>;rel=\"up\"";
        final String VERIFY_CHALLENGE_URL = "/.well-known/acme-challenge/215ACi-BkIjZ28ynW7kiDco21cv4wxRyByykbgxl9Pc";
        final String CHALLENGE_FILE_CONTENTS = "215ACi-BkIjZ28ynW7kiDco21cv4wxRyByykbgxl9Pc.N6GU8Z78VIOWz1qOEJObBvhcmfflldy-TQWkizoonrU";

        final String UPDATED_AUTHZ_REPLAY_NONCE = "taroT16QLPZ628OzZtwZU6yA6-hnbfWexEyGOC-H5ji3hJw";
        final String UPDATED_AUTHZ_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"identifier\": {" + System.lineSeparator() +
                "    \"type\": \"dns\"," + System.lineSeparator() +
                "    \"value\": \"inlneseppwkfwewv2.com\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"status\": \"valid\"," + System.lineSeparator() +
                "  \"expires\": \"2019-08-22T20:20:42Z\"," + System.lineSeparator() +
                "  \"challenges\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"http-01\"," + System.lineSeparator() +
                "      \"status\": \"valid\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/v2/47/z7sh0A\"," + System.lineSeparator() +
                "      \"token\": \"215ACi-BkIjZ28ynW7kiDco21cv4wxRyByykbgxl9Pc\"," + System.lineSeparator() +
                "      \"validationRecord\": [" + System.lineSeparator() +
                "        {" + System.lineSeparator() +
                "          \"url\": \"http://inlneseppwkfwewv2.com/.well-known/acme-challenge/215ACi-BkIjZ28ynW7kiDco21cv4wxRyByykbgxl9Pc\"," + System.lineSeparator() +
                "          \"hostname\": \"inlneseppwkfwewv2.com\"," + System.lineSeparator() +
                "          \"port\": \"5002\"," + System.lineSeparator() +
                "          \"addressesResolved\": [" + System.lineSeparator() +
                "            \"172.17.0.1\"" + System.lineSeparator() +
                "          ]," + System.lineSeparator() +
                "          \"addressUsed\": \"172.17.0.1\"" + System.lineSeparator() +
                "        }" + System.lineSeparator() +
                "      ]" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/v2/47/mlvrMA\"," + System.lineSeparator() +
                "      \"token\": \"215ACi-BkIjZ28ynW7kiDco21cv4wxRyByykbgxl9Pc\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"tls-alpn-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/v2/47/_wf1QQ\"," + System.lineSeparator() +
                "      \"token\": \"215ACi-BkIjZ28ynW7kiDco21cv4wxRyByykbgxl9Pc\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String FINALIZE_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMTAiLCJub25jZSI6InRhcm9UMTZRTFBaNjI4T3padHdaVTZ5QTYtaG5iZldleEV5R09DLUg1amkzaEp3IiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvZmluYWxpemUvMTAvNjkifQ\",\"payload\":\"eyJjc3IiOiJNSUlFdHpDQ0FwOENBUUF3SURFZU1Cd0dBMVVFQXd3VmFXNXNibVZ6WlhCd2QydG1kMlYzZGpJdVkyOXRNSUlDSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQWc4QU1JSUNDZ0tDQWdFQXBjMDZSYnJSRDF2Y3pCQ3k1ZnhodXNTSTdPLW96MlYzd293NURIdUFlN2h3LTNaWDd1SG1Pb21PUHlSLUQ3NGtONEdpckNTSWlUcE1GRC1GcUxFR3hCbXhPMjY3dUlvTnY2SjVrZHlJT0VjMkl4RldacnRyTExWd2NHeC1ROWRhcWZVMWk4cW5YMWx2RkMydUM4Vlp6OU14U0MwV29jNjN3RTVCRnJVQjFPSTQxZDlINVpwYVhRSGctY1ZraXBWWEN2TWJFVnZ1MFVKNkV5eS1JX2pSSFh3QnFYcXhZa2NtMXJuTkFBUUxKc3U3ZThyU3JIV0dNREktcy1lLUsyYm51VGZnelBJSmZZQ19peHplQ0hXU3lnQmV4d1NUd0VfOC04QWJ2SlotQmVjZl9ndnVSQm42TGtYX1FkUndnRWN5d1pGUldka1VvMG90M2xRbFF5a3g1VjFZZ1k3YXMtaEFDZmpSdXRlSFAzUXkyNE1rSmJwLV9rLThDNFp1aGRUQ1pmNlJoRWR1MGpGNF85blhLUkhGUkVOZFUzZThtaENEdFBkblBVeFFoVmoyVjdmZ1hIV2RMZThzdUpkLTlaRjBKdkpqUVJVNEdtWE5qNkxpd3dDWjBQamZZSV9mai1XTFVKVWstMXVSZk0xUDRqRE5jQ01yNjlMdVhoS0U1b2JRYXVEOUxoOF8ydmtQeG1nSTc4T1E3STZ4T2JOWWg2M0hiUHBpelJZcUwtcW53SHcyck45dXZ5S2xTSnh6NW9LVWJPTzdHa3B4bV9TQWg4ZmduOTNYbTZEZFlMbk1zZFlHdGFKSjRnRHBpUVVLTldWeC04SW4wcXBFWUxtNEdsVVNTNWViUnJWQ0JkSjI4TGNaRF8zYktCMHNMMlRVdXk2eE96LS1KdmZLVnBzQ0F3RUFBYUJTTUZBR0NTcUdTSWIzRFFFSkRqRkRNRUV3SUFZRFZSMFJCQmt3RjRJVmFXNXNibVZ6WlhCd2QydG1kMlYzZGpJdVkyOXRNQjBHQTFVZERnUVdCQlQycUd6RUQyTlVidkxnSGhsVVlDZXREczJ0N1RBTkJna3Foa2lHOXcwQkFRd0ZBQU9DQWdFQW1hcVNwY1EzYlZBbEZuNUROYkhfNEFWaHdBdVV1VzlpUkNNSkt4TS16aEVUT1hOdElVdWFsLUFlTEdkMkFCQkdHLUJQcmtVUkR6a21BbTlKOWJHcEJ5UzFDV1A4d19XcmdvRTdlcmp4NjUwSGRFc05JTk80dzhHck4zb2VCdFVUV01KaC0wdWNULXRBN20yUGstaWpPN0NRYW90cmZuUUxXY0pPV3JYM3FWU09vZ204dVpRWWlKM0tENTdXSTNmenZHUTdaM2pNSXhQdk45b0xkLVY3S1JmRGdmNXdXaDJYYVNTM2RWRkY5TFJKaTR3X1RRWjk0eDhtLXE4Y1gxMU9ybXliNGVUYmZiZDJ2MkptRVJhWE8zeUs5SkFpV2lrTHdwbzk0MFMxVHUyWm10YWNmLVQ2elp3eFdONG5UMEJob3dkc3duNmdmQkdFUE9URUduVHZDZ2RiUHFScTZBbWQ0R2NKOFNVVjhJRmpXTC1zTG92VzlSc2VJaDY4dzJab0t3NTFua2ZGX3RXdkVxY0RILWtOajdHRHZCc0xaYTIyWnptV3lNTjRTQlJjdjZKX19OcnlidWowODhVVmlyc2JWcnMzMmQzMFVfOG1TbXBqaURqcmw1dFlyTVd1NUp6U3RNalczUEgzY0hTcFdXM1V6VEVpN2JjQVE1N2ZmZW1VRjlaa2FTOWltdHl4eXZYeW8yNTA2NzNjdEh4aUNCbHhXVm9VTGtZTmswZ3NfdDhLWkEyMUkyblhKQzNOT2dKMi1BRWFPaFQ5X3lkekpvMzh0UmR0MkkwSy0zZ1ZqSUxiYXhWZEJuWGU4cnYwRllaSmFyWXhfdHhXa1VtcE1GZ3dTSllNS0tUa2FzZzZJb1N6bURDcXFKb3d0RmpIMWtSUHRHMWdSMjFVNUVJIn0\",\"signature\":\"RQ9ONpJ_ZFH7x2d0KKvEiv_enItUtRUS2tpvpt9tQVSihOOj9x-UVbSpb5QAc8MNzqAYA_vLzVYu3vj7TwMtUaVTthsaKh6-cb_0NZYqmch6JqNrUcl9G8A2zLXKzkQDbgdNWSKhg19c56HtmW4I2R3YLYZ-j9_zV7C6b0UGgIabLv6WU2wjE7teeCIRNCabkM9aQr_PLf-muaScL_xLDkfr8q5d0UeO2UoXkxwyQDOfY3y5QTHD9eyW7PG3iXSKCZCex3RLZt3PKbZJX2o2Ia8R6z8ZO3IDG3Nqs6OMzgn3hdqB1zA4TJ98NRP3p5RcQkGy7BhPaZEKjkynEZDzCA\"}";
        final String FINALIZE_URL = "/acme/finalize/10/69";

        final String FINALIZE_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"status\": \"valid\"," + System.lineSeparator() +
                "  \"expires\": \"2019-07-23T20:20:42Z\"," + System.lineSeparator() +
                "  \"identifiers\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns\"," + System.lineSeparator() +
                "      \"value\": \"inlneseppwkfwewv2.com\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"authorizations\": [" + System.lineSeparator() +
                "    \"http://localhost:4001/acme/authz/v2/47\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"finalize\": \"http://localhost:4001/acme/finalize/10/69\"," + System.lineSeparator() +
                "  \"certificate\": \"http://localhost:4001/acme/cert/ff4d6960900116d153bd9079b2ef4ceb686e\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String FINALIZE_REPLAY_NONCE = "zincMfatmlrYZzGRlf2Lob__5LTX8HmpWUDRDcl7nR6e27Y";
        final String FINALIZE_LOCATION = "http://localhost:4001/acme/order/10/69";

        final String CHECK_ORDER_URL = "/acme/order/10/69";
        final String CHECK_ORDER_REPLAY_NONCE = "taroYphvMFXUwHY9NvweFKTFO2ZEHkqXXAAFIGgwRq1XUk8";

        final String CHECK_ORDER_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMTAiLCJub25jZSI6InppbmNNZmF0bWxyWVp6R1JsZjJMb2JfXzVMVFg4SG1wV1VEUkRjbDduUjZlMjdZIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvb3JkZXIvMTAvNjkifQ\",\"payload\":\"\",\"signature\":\"N2BAMYSzcrwWhEjFkwBcKSqwe2z2C0p8rOIyF3K-roYwUMX-pA4pjA1dEgpn28YmcuL-oQ3r1dVGirf6lP7-ge1jVClLvoe0xMJnt8wtL5-RfM4huwxCf8nJHilXGAIjexU-23U1gqORTNseUEjmq5C0qM4VO-jI1gctmmpBhh1ND34C0LqwvbgBuErJu3i2aTOJeVa9zslvRNv54qQIH44NN4jaJP_rOkIf5Ip3ol9lhUNp9aWhF1cPrxy8dRoV8wB-zrSidqZcyrdW5S-kBpTU54xQNyerKWJuSBxYMlWWqwwJTxJIDULf3sOBUMIdHITHnD0NVmXA9Hyt4Qi_hQ\"}";
        final String CHECK_ORDER_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"status\": \"valid\"," + System.lineSeparator() +
                "  \"expires\": \"2019-07-23T20:20:42Z\"," + System.lineSeparator() +
                "  \"identifiers\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns\"," + System.lineSeparator() +
                "      \"value\": \"inlneseppwkfwewv2.com\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"authorizations\": [" + System.lineSeparator() +
                "    \"http://localhost:4001/acme/authz/v2/47\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"finalize\": \"http://localhost:4001/acme/finalize/10/69\"," + System.lineSeparator() +
                "  \"certificate\": \"http://localhost:4001/acme/cert/ff4d6960900116d153bd9079b2ef4ceb686e\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String CERT_URL = "/acme/cert/ff4d6960900116d153bd9079b2ef4ceb686e";
        final String CERT_REPLAY_NONCE = "zincKaLFWirFsBTqH1JdVRy2kiSYehDe_Jl_POZcX9Oio2o";

        final String CERT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMTAiLCJub25jZSI6InRhcm9ZcGh2TUZYVXdIWTlOdndlRktURk8yWkVIa3FYWEFBRklHZ3dScTFYVWs4IiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvY2VydC9mZjRkNjk2MDkwMDExNmQxNTNiZDkwNzliMmVmNGNlYjY4NmUifQ\",\"payload\":\"\",\"signature\":\"Ba_xGjJri5ZxNyav1uTH7TPgmzrtCNwwYcVUUn7TX4lhWKPUjYM0QDqUnbDMjt34rY1xe3apIoH4xvLCwaQ-R90ad8sXYr0nBVwRTUPFY0ytDQAFBfwUMLRJ61d8PXZOXp3TNJ6QE-OzgONGDXaw1P2MUvbXbacA5ePsi3_D50fi9RVJGO88Znj-GmgmRm7nP1QlN2Ce-puNt1FoQhM3KFBslnDc5gQPPG1iV7QXyx7o8driUeqY5x87oOXjUfDjzw1LjNEh4ULAGXBeRwZ7jTJSqVYQHh_bnC3nkMxoBRq9sJGoVoNlwhy_d4pavYzUe1oreb1HVeEePicg-PKZ4w\"}";
        final String CERT_RESPONSE_BODY = "-----BEGIN CERTIFICATE-----" + System.lineSeparator() +
                "MIIGSjCCBTKgAwIBAgITAP9NaWCQARbRU72QebLvTOtobjANBgkqhkiG9w0BAQsF" + System.lineSeparator() +
                "ADAfMR0wGwYDVQQDDBRoMnBweSBoMmNrZXIgZmFrZSBDQTAeFw0xOTA3MTYxOTIw" + System.lineSeparator() +
                "NDNaFw0xOTEwMTQxOTIwNDNaMCAxHjAcBgNVBAMTFWlubG5lc2VwcHdrZndld3Yy" + System.lineSeparator() +
                "LmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKXNOkW60Q9b3MwQ" + System.lineSeparator() +
                "suX8YbrEiOzvqM9ld8KMOQx7gHu4cPt2V+7h5jqJjj8kfg++JDeBoqwkiIk6TBQ/" + System.lineSeparator() +
                "haixBsQZsTtuu7iKDb+ieZHciDhHNiMRVma7ayy1cHBsfkPXWqn1NYvKp19ZbxQt" + System.lineSeparator() +
                "rgvFWc/TMUgtFqHOt8BOQRa1AdTiONXfR+WaWl0B4PnFZIqVVwrzGxFb7tFCehMs" + System.lineSeparator() +
                "viP40R18Aal6sWJHJta5zQAECybLu3vK0qx1hjAyPrPnvitm57k34MzyCX2Av4sc" + System.lineSeparator() +
                "3gh1ksoAXscEk8BP/PvAG7yWfgXnH/4L7kQZ+i5F/0HUcIBHMsGRUVnZFKNKLd5U" + System.lineSeparator() +
                "JUMpMeVdWIGO2rPoQAn40brXhz90MtuDJCW6fv5PvAuGboXUwmX+kYRHbtIxeP/Z" + System.lineSeparator() +
                "1ykRxURDXVN3vJoQg7T3Zz1MUIVY9le34Fx1nS3vLLiXfvWRdCbyY0EVOBplzY+i" + System.lineSeparator() +
                "4sMAmdD432CP34/li1CVJPtbkXzNT+IwzXAjK+vS7l4ShOaG0Grg/S4fP9r5D8Zo" + System.lineSeparator() +
                "CO/DkOyOsTmzWIetx2z6Ys0WKi/qp8B8Nqzfbr8ipUicc+aClGzjuxpKcZv0gIfH" + System.lineSeparator() +
                "4J/d15ug3WC5zLHWBrWiSeIA6YkFCjVlcfvCJ9KqRGC5uBpVEkuXm0a1QgXSdvC3" + System.lineSeparator() +
                "GQ/92ygdLC9k1LsusTs/vib3ylabAgMBAAGjggJ8MIICeDAOBgNVHQ8BAf8EBAMC" + System.lineSeparator() +
                "BaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAw" + System.lineSeparator() +
                "HQYDVR0OBBYEFPaobMQPY1Ru8uAeGVRgJ60Oza3tMB8GA1UdIwQYMBaAFPt4TxL5" + System.lineSeparator() +
                "YBWDLJ8XfzQZsy426kGJMGQGCCsGAQUFBwEBBFgwVjAiBggrBgEFBQcwAYYWaHR0" + System.lineSeparator() +
                "cDovLzEyNy4wLjAuMTo0MDAyLzAwBggrBgEFBQcwAoYkaHR0cDovL2JvdWxkZXI6" + System.lineSeparator() +
                "NDQzMC9hY21lL2lzc3Vlci1jZXJ0MCAGA1UdEQQZMBeCFWlubG5lc2VwcHdrZndl" + System.lineSeparator() +
                "d3YyLmNvbTAnBgNVHR8EIDAeMBygGqAYhhZodHRwOi8vZXhhbXBsZS5jb20vY3Js" + System.lineSeparator() +
                "MEAGA1UdIAQ5MDcwCAYGZ4EMAQIBMCsGAyoDBDAkMCIGCCsGAQUFBwIBFhZodHRw" + System.lineSeparator() +
                "Oi8vZXhhbXBsZS5jb20vY3BzMIIBBAYKKwYBBAHWeQIEAgSB9QSB8gDwAHUA3Zk0" + System.lineSeparator() +
                "/KXnJIDJVmh9gTSZCEmySfe1adjHvKs/XMHzbmQAAAFr/HHFxQAABAMARjBEAiAX" + System.lineSeparator() +
                "5d7ffdn8ctWiJWoPxYtGOwG5yaiqTpHSaiBagPd2xQIgGi68uA+M6MHf80Ko0rgk" + System.lineSeparator() +
                "Mtp5dkS7p9C8R11o2WCdnBsAdwAW6GnB0ZXq18P4lxrj8HYB94zhtp0xqFIYtoN/" + System.lineSeparator() +
                "MagVCAAAAWv8ccXFAAAEAwBIMEYCIQD/+kWwYf5pRIKjg5j2VcvUY9IOsKaem/wX" + System.lineSeparator() +
                "1C/GFU9+VQIhAOHY9SmknOkqMl8HwEYGeD7uksNwTBMzi19Hqowh4s55MA0GCSqG" + System.lineSeparator() +
                "SIb3DQEBCwUAA4IBAQAS1xht2BdputK1iEdEPG6357zcv5F65aBSOdqIc5WeEoa1" + System.lineSeparator() +
                "Jx06Wyc+5dQH65iCRF7qXQGb9gP0Bwi6JrfouQMQwjNjERg20CfqfLZdJqeUR+SO" + System.lineSeparator() +
                "wTZTqVrTQsdKPGUeGrdusC7gHMyvFagqf4J/gonHZvlI3FdGOEP3MiyHeQlsALRW" + System.lineSeparator() +
                "6WAX3okXEEm91chmdXuU3TRN/ZRNumU6z1J4RHYCW405qxKQWQB8NUIADBSVfm7x" + System.lineSeparator() +
                "J8KlZBgRH37R1FbIWHmD5W83cTEYRxPeYfS0HGel0wuPnt/JmbJzMcEeh75tDsRI" + System.lineSeparator() +
                "w/XRgmIMfizJa4LJLcXnUE+9ccraCB/quPldjjEN" + System.lineSeparator() +
                "-----END CERTIFICATE-----" + System.lineSeparator() +
                "" + System.lineSeparator() +
                "-----BEGIN CERTIFICATE-----" + System.lineSeparator() +
                "MIIERTCCAy2gAwIBAgICElowDQYJKoZIhvcNAQELBQAwKzEpMCcGA1UEAwwgY2Fj" + System.lineSeparator() +
                "a2xpbmcgY3J5cHRvZ3JhcGhlciBmYWtlIFJPT1QwHhcNMTYwMzIyMDI0NzUyWhcN" + System.lineSeparator() +
                "MjEwMzIxMDI0NzUyWjAfMR0wGwYDVQQDDBRoMnBweSBoMmNrZXIgZmFrZSBDQTCC" + System.lineSeparator() +
                "ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMIKR3maBcUSsncXYzQT13D5" + System.lineSeparator() +
                "Nr+Z3mLxMMh3TUdt6sACmqbJ0btRlgXfMtNLM2OU1I6a3Ju+tIZSdn2v21JBwvxU" + System.lineSeparator() +
                "zpZQ4zy2cimIiMQDZCQHJwzC9GZn8HaW091iz9H0Go3A7WDXwYNmsdLNRi00o14U" + System.lineSeparator() +
                "joaVqaPsYrZWvRKaIRqaU0hHmS0AWwQSvN/93iMIXuyiwywmkwKbWnnxCQ/gsctK" + System.lineSeparator() +
                "FUtcNrwEx9Wgj6KlhwDTyI1QWSBbxVYNyUgPFzKxrSmwMO0yNff7ho+QT9x5+Y/7" + System.lineSeparator() +
                "XE59S4Mc4ZXxcXKew/gSlN9U5mvT+D2BhDtkCupdfsZNCQWp27A+b/DmrFI9NqsC" + System.lineSeparator() +
                "AwEAAaOCAX0wggF5MBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGG" + System.lineSeparator() +
                "MH8GCCsGAQUFBwEBBHMwcTAyBggrBgEFBQcwAYYmaHR0cDovL2lzcmcudHJ1c3Rp" + System.lineSeparator() +
                "ZC5vY3NwLmlkZW50cnVzdC5jb20wOwYIKwYBBQUHMAKGL2h0dHA6Ly9hcHBzLmlk" + System.lineSeparator() +
                "ZW50cnVzdC5jb20vcm9vdHMvZHN0cm9vdGNheDMucDdjMB8GA1UdIwQYMBaAFOmk" + System.lineSeparator() +
                "P+6epeby1dd5YDyTpi4kjpeqMFQGA1UdIARNMEswCAYGZ4EMAQIBMD8GCysGAQQB" + System.lineSeparator() +
                "gt8TAQEBMDAwLgYIKwYBBQUHAgEWImh0dHA6Ly9jcHMucm9vdC14MS5sZXRzZW5j" + System.lineSeparator() +
                "cnlwdC5vcmcwPAYDVR0fBDUwMzAxoC+gLYYraHR0cDovL2NybC5pZGVudHJ1c3Qu" + System.lineSeparator() +
                "Y29tL0RTVFJPT1RDQVgzQ1JMLmNybDAdBgNVHQ4EFgQU+3hPEvlgFYMsnxd/NBmz" + System.lineSeparator() +
                "LjbqQYkwDQYJKoZIhvcNAQELBQADggEBAKvePfYXBaAcYca2e0WwkswwJ7lLU/i3" + System.lineSeparator() +
                "GIFM8tErKThNf3gD3KdCtDZ45XomOsgdRv8oxYTvQpBGTclYRAqLsO9t/LgGxeSB" + System.lineSeparator() +
                "jzwY7Ytdwwj8lviEGtiun06sJxRvvBU+l9uTs3DKBxWKZ/YRf4+6wq/vERrShpEC" + System.lineSeparator() +
                "KuQ5+NgMcStQY7dywrsd6x1p3bkOvowbDlaRwru7QCIXTBSb8TepKqCqRzr6YREt" + System.lineSeparator() +
                "doIw2FE8MKMCGR2p+U3slhxfLTh13MuqIOvTuA145S/qf6xCkRc9I92GpjoQk87Z" + System.lineSeparator() +
                "v1uhpkgT9uwbRw0Cs5DMdxT/LgIUSfUTKU83GNrbrQNYinkJ77i6wG0=" + System.lineSeparator() +
                "-----END CERTIFICATE-----" + System.lineSeparator();

        return new AcmeMockServerBuilder(server)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY)
                .addNewNonceResponse(NEW_NONCE_RESPONSE)
                .addNewAccountRequestAndResponse(QUERY_ACCT_REQUEST_BODY, QUERY_ACCT_RESPONSE_BODY, QUERY_ACCT_REPLAY_NONCE, ACCT_LOCATION, 200)
                .orderCertificateRequestAndResponse(ORDER_CERT_REQUEST_BODY, ORDER_CERT_RESPONSE_BODY, ORDER_CERT_REPLAY_NONCE, ORDER_LOCATION, 201, false)
                .addAuthorizationResponseBody(AUTHZ_URL, AUTHZ_REQUEST_BODY, AUTHZ_RESPONSE_BODY, AUTHZ_REPLAY_NONCE)
                .addChallengeRequestAndResponse(CHALLENGE_REQUEST_BODY, CHALLENGE_URL, CHALLENGE_RESPONSE_BODY, CHALLENGE_REPLAY_NONCE, CHALLENGE_LOCATION, CHALLENGE_LINK, 200, false, VERIFY_CHALLENGE_URL, CHALLENGE_FILE_CONTENTS, AUTHZ_URL, UPDATED_AUTHZ_RESPONSE_BODY, UPDATED_AUTHZ_REPLAY_NONCE)
                .addFinalizeRequestAndResponse(FINALIZE_RESPONSE_BODY, FINALIZE_REPLAY_NONCE, FINALIZE_URL, FINALIZE_LOCATION, 200)
                .addCheckOrderRequestAndResponse(CHECK_ORDER_URL, CHECK_ORDER_REQUEST_BODY, CHECK_ORDER_RESPONSE_BODY, CHECK_ORDER_REPLAY_NONCE, 200)
                .addCertificateRequestAndResponse(CERT_URL, CERT_REQUEST_BODY, CERT_RESPONSE_BODY, CERT_REPLAY_NONCE, 200)
                .build();
    }

    private ClientAndServer setupTestObtainCertificateWithECPublicKey() {

        // set up a mock Let's Encrypt server
        final String DIRECTORY_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"NuqiRM5JoYM\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator() +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator() +
                "  \"meta\": {" + System.lineSeparator() +
                "    \"caaIdentities\": [" + System.lineSeparator() +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator() +
                "    ]," + System.lineSeparator() +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator() +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator() +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator() +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator() +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String NEW_NONCE_RESPONSE = "zincSXuSpK7AwtV-oYU5T5SJvgPaBqAVOxMjkji64l85_y8";

        final String QUERY_ACCT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJxTjcwc2VsZEVrVTlKV0RMUkNibkp2QWo2WWs3UnV4QktUV0dNLTZaMUxsQlpXV1A1OGthbWU5cDA1THFLa05rdC1Yakc3Wkt5T1FQUXZ4cU5oRURKLTNpck93V0NzWi1BRk5aYU5BMlFoZ0dRYnB2MkRkRDIzMWdqVUZRT3dlS2pLdlhDdUg1TFlxVjVObUx0TFBNbjBsTFpFX21NVlB3dnhLTV9FLTBjRFhqeDZzTU9BbWtvVWkzWGRaOU0tUUNNc1BxTUhnbUt1T2xCUnVXdmRJNVRDaUcyemNXMFo2T0Y5T0lybVhoWTBFeVNDTjc3RkJ2dkJNN2NsYkNiN1gxS0ZGLVNpUDQ3a013VlNyR2h1eER6dVpzaU4wOThxT3IwVG8yd1BzQ2V5SzZwT3ZST3VwQi1ZX01yXy1QRjl5dnE5bXkzLVBXeVAtcnB3T09XVWZYZXcifSwibm9uY2UiOiJ6aW5jU1h1U3BLN0F3dFYtb1lVNVQ1U0p2Z1BhQnFBVk94TWpramk2NGw4NV95OCIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL25ldy1hY2N0In0\",\"payload\":\"eyJvbmx5UmV0dXJuRXhpc3RpbmciOnRydWV9\",\"signature\":\"ZMrVBL6EgK0jBPc21fmZWNAIlItMgtMCEkEjiPCu0xsyTpU4Wr2xHVxP1wNzhr4lK7vAxklm5aeN5wfDVWtmjZ-dTqING-llpc06ukw-luO31Tbaal29b38U3FX_6Sx2N7HJkgxHiRzVH3QzhjteB9S_Xab8j-LMUI8f7gi-RUAL2QUzln5bLOBvhII8IJhgdvzz4VBijko3Cgy7W5Lgdq2-HWrFx68Zel1ood0-n5it65RtSLFIN-j4vAvZ2r1XAHrfayxx4BwcRI4BxoXbIeSMZBizl1p7apm8cyWko_y8TJ-0xONax02s4KJjDptcmV4ZrLqcJhL8jUoPdiT_Pg\"}";

        final String QUERY_ACCT_RESPONSE_BODY= "";

        final String QUERY_ACCT_REPLAY_NONCE = "taroTILAcaXhDviw7yl1tHtpd2fv3r4LiBpUDvZ1iNUhLL0";
        final String ACCT_LOCATION = "http://localhost:4001/acme/acct/18";


        final String ORDER_CERT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMTgiLCJub25jZSI6InRhcm9USUxBY2FYaER2aXc3eWwxdEh0cGQyZnYzcjRMaUJwVUR2WjFpTlVoTEwwIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvbmV3LW9yZGVyIn0\",\"payload\":\"eyJpZGVudGlmaWVycyI6W3sidHlwZSI6ImRucyIsInZhbHVlIjoibW5kZWxrZG5iY2lsb2hndjIuY29tIn1dfQ\",\"signature\":\"hsEho6EPU1k0mK775bj0oSreG8s38RFm80TO_ltQMOET_7FjkTv1Bm0Z2SFlHmJI1WtKHYB11cile_EJXJOGUP-F0nNIkp-E5FUl-Kq81uR-meGPDAYjJAJq_yqWxm1k6a3UmOvBF9wIsp9et-_yCSl9-7NH7SRJ7mCGnE791hIzPbdvPH-vMTdRfsVKr75UmAj1c5ZWoxqsA8CcTl0ojYD9bJfT2lRvaPcYisMM5I7jdjmrVmuQ_EznEYZyZBY_zmxE8nDK6_exeu4SEeyNoS0hGiU75uEa14jBprlLPtNqcDMsgbHn_sNryzlX1PGQt7fzdU9sWDwwgBhex2zmFA\"}";

        final String ORDER_CERT_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"status\": \"pending\"," + System.lineSeparator() +
                "  \"expires\": \"2019-07-23T19:57:55.887357634Z\"," + System.lineSeparator() +
                "  \"identifiers\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns\"," + System.lineSeparator() +
                "      \"value\": \"mndelkdnbcilohgv2.com\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"authorizations\": [" + System.lineSeparator() +
                "    \"http://localhost:4001/acme/authz/v2/46\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"finalize\": \"http://localhost:4001/acme/finalize/18/68\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String ORDER_CERT_REPLAY_NONCE = "zincEh5_TsAbCPq_V2N78rG3_dUxcZnA6ISd3UBdGC3LN2E";
        final String ORDER_LOCATION = "http://localhost:4001/acme/order/18/68";

        final String AUTHZ_URL = "/acme/authz/v2/46";
        final String AUTHZ_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMTgiLCJub25jZSI6InppbmNFaDVfVHNBYkNQcV9WMk43OHJHM19kVXhjWm5BNklTZDNVQmRHQzNMTjJFIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvYXV0aHovdjIvNDYifQ\",\"payload\":\"\",\"signature\":\"MAVAt8kSDWcy6rZRLz5ClGgXmLSTCRY5V0dhrDnA-3DMdnQyTnFI8NnmuxVBVpCLN1Sse2YGn1yrHp5I6L83Ob90OvCiWMZCi0or1hqxrmDErVE4q-BOKdV6sbrgejwNsDSkdtDaGSvGR8qSBeqFV6VWvny395qXY6ASzpkXgyeSXFGEQ-tlPW_CTAaHS7Eo_IKHQ8puJeOqxhUkgseQogtkC2ExddOnAiZq9M__SV6jysxJmqn-4vNdBmFJtq2F0aHrbWdf-9zUWnrxtgUPP-WvWCfUtejS5CcjDv8kcnvOumKm64b8eHMoGtPSxuGfZ_K1Qoh605KuiwD5lfaSkQ\"}";
        final String AUTHZ_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"identifier\": {" + System.lineSeparator() +
                "    \"type\": \"dns\"," + System.lineSeparator() +
                "    \"value\": \"mndelkdnbcilohgv2.com\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"status\": \"pending\"," + System.lineSeparator() +
                "  \"expires\": \"2019-07-23T19:57:55Z\"," + System.lineSeparator() +
                "  \"challenges\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"http-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/v2/46/1EAfog\"," + System.lineSeparator() +
                "      \"token\": \"6PAmWU2m3sPP7Lqfz2NAlpztc-Qqw3o9rTbQtrFUrdY\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/v2/46/OHt9Vw\"," + System.lineSeparator() +
                "      \"token\": \"6PAmWU2m3sPP7Lqfz2NAlpztc-Qqw3o9rTbQtrFUrdY\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"tls-alpn-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/v2/46/WXhsUg\"," + System.lineSeparator() +
                "      \"token\": \"6PAmWU2m3sPP7Lqfz2NAlpztc-Qqw3o9rTbQtrFUrdY\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String AUTHZ_REPLAY_NONCE = "taroi1V-ebsk9OogUGWzggfhZzPb_caysV4CnnQ4OdjClZ0";

        final String CHALLENGE_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMTgiLCJub25jZSI6InRhcm9pMVYtZWJzazlPb2dVR1d6Z2dmaFp6UGJfY2F5c1Y0Q25uUTRPZGpDbFowIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvY2hhbGxlbmdlL3YyLzQ2LzFFQWZvZyJ9\",\"payload\":\"e30\",\"signature\":\"XAvtgCZ15XD37k4syk2smvoIoFm-WeXgqnKr74_L8W-AYou4roOQCRAMPE7rmboEFB4ZILxrec__6GN9OS99tdQ9o4T1CLgkwuZUDQFXFBI98tOKF_sjtTrVNQnMitmN2noAWxFBdl-6Mt_FO5tt8l2HG7TGPxriJe2oPDxoMBZszHGzz5GFYEhVcwpTiDWlri3ggXiHQyEWnei-TmO_O5p5a6hJm-TNEziyWDCvmlupRpwDyv9ANJccsrVg6OYVW3jQ1rDscAPqIILQr8EhzA4QyZw9FhrfgGJdn6ru1Wwl86Y8SfTojIq3wKmcac5c3iXBeIKkkq9clGONJpiNwQ\"}";
        final String CHALLENGE_URL = "/acme/challenge/v2/46/1EAfog";

        final String CHALLENGE_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"type\": \"http-01\"," + System.lineSeparator() +
                "  \"status\": \"pending\"," + System.lineSeparator() +
                "  \"url\": \"http://localhost:4001/acme/challenge/v2/46/1EAfog\"," + System.lineSeparator() +
                "  \"token\": \"6PAmWU2m3sPP7Lqfz2NAlpztc-Qqw3o9rTbQtrFUrdY\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String CHALLENGE_REPLAY_NONCE = "zincA0YMk-y4X0yRFWdOVUMHoGsfBE6qgdMPYPcX9-Q-zY4";
        final String CHALLENGE_LOCATION = "http://localhost:4001/acme/challenge/v2/46/1EAfog";
        final String CHALLENGE_LINK = "<http://localhost:4001/acme/authz/v2/46>;rel=\"up\"";
        final String VERIFY_CHALLENGE_URL = "/.well-known/acme-challenge/6PAmWU2m3sPP7Lqfz2NAlpztc-Qqw3o9rTbQtrFUrdY";
        final String CHALLENGE_FILE_CONTENTS = "6PAmWU2m3sPP7Lqfz2NAlpztc-Qqw3o9rTbQtrFUrdY.2NVC_ENUU-TZ83gkUxQvXl7_ixvttxk_dPlNqIyXGKY";

        final String UPDATED_AUTHZ_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"identifier\": {" + System.lineSeparator() +
                "    \"type\": \"dns\"," + System.lineSeparator() +
                "    \"value\": \"mndelkdnbcilohgv2.com\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"status\": \"valid\"," + System.lineSeparator() +
                "  \"expires\": \"2019-08-22T19:57:55Z\"," + System.lineSeparator() +
                "  \"challenges\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"http-01\"," + System.lineSeparator() +
                "      \"status\": \"valid\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/v2/46/1EAfog\"," + System.lineSeparator() +
                "      \"token\": \"6PAmWU2m3sPP7Lqfz2NAlpztc-Qqw3o9rTbQtrFUrdY\"," + System.lineSeparator() +
                "      \"validationRecord\": [" + System.lineSeparator() +
                "        {" + System.lineSeparator() +
                "          \"url\": \"http://mndelkdnbcilohgv2.com/.well-known/acme-challenge/6PAmWU2m3sPP7Lqfz2NAlpztc-Qqw3o9rTbQtrFUrdY\"," + System.lineSeparator() +
                "          \"hostname\": \"mndelkdnbcilohgv2.com\"," + System.lineSeparator() +
                "          \"port\": \"5002\"," + System.lineSeparator() +
                "          \"addressesResolved\": [" + System.lineSeparator() +
                "            \"172.17.0.1\"" + System.lineSeparator() +
                "          ]," + System.lineSeparator() +
                "          \"addressUsed\": \"172.17.0.1\"" + System.lineSeparator() +
                "        }" + System.lineSeparator() +
                "      ]" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/v2/46/OHt9Vw\"," + System.lineSeparator() +
                "      \"token\": \"6PAmWU2m3sPP7Lqfz2NAlpztc-Qqw3o9rTbQtrFUrdY\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"tls-alpn-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/v2/46/WXhsUg\"," + System.lineSeparator() +
                "      \"token\": \"6PAmWU2m3sPP7Lqfz2NAlpztc-Qqw3o9rTbQtrFUrdY\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String UPDATED_AUTHZ_REPLAY_NONCE = "taro_CYDgtDCXgc4gmxsCnwXERad3qCJ6bOEG3ZKVdqMKCQ";

        final String FINALIZE_URL = "/acme/finalize/18/68";

        final String FINALIZE_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"status\": \"valid\"," + System.lineSeparator() +
                "  \"expires\": \"2019-07-23T19:57:55Z\"," + System.lineSeparator() +
                "  \"identifiers\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns\"," + System.lineSeparator() +
                "      \"value\": \"mndelkdnbcilohgv2.com\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"authorizations\": [" + System.lineSeparator() +
                "    \"http://localhost:4001/acme/authz/v2/46\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"finalize\": \"http://localhost:4001/acme/finalize/18/68\"," + System.lineSeparator() +
                "  \"certificate\": \"http://localhost:4001/acme/cert/ff1093811c2dca68b305c777d1d6b058cb14\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String FINALIZE_REPLAY_NONCE = "zinclJZorHeTFZcnqLLeS1ZgNtVjKLFXeA-sZDk6Od996nI";
        final String FINALIZE_LOCATION = "http://localhost:4001/acme/order/18/68";

        final String CHECK_ORDER_URL = "/acme/order/18/68";
        final String CHECK_ORDER_REPLAY_NONCE = "taroRCnVpN7wg7EQvwrBvKkNUdyXISuSwN1_Y1huVn4IQOo";

        final String CHECK_ORDER_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMTgiLCJub25jZSI6InppbmNsSlpvckhlVEZaY25xTExlUzFaZ050VmpLTEZYZUEtc1pEazZPZDk5Nm5JIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvb3JkZXIvMTgvNjgifQ\",\"payload\":\"\",\"signature\":\"arc3WgxoV-CTvgMRboJhSQmNTNNE6NAHGdPkB6Io3j3fqPSqqyYtAKTKa0fTBhNS2uS7Vh5FOYPPG-11T9f-_asncxD0C43MYX-mWHtvCH_SmhXTyB2rm4kiWoRVjYHuffDgOrauPvmk4WbUY64sq7-7TSUpfDD9Ds6ll8ZDysA-7yG4UZjnGLgN4r-14uyWiSS4PQJYFLdzDsTnmLMjKL09uuC3hW3Sc-T3x8yQ9ONY6wstpyHbLVGL9ZikRpDf4ZWUJDXg-apngRHVwF7eUXAD6nNsERdnF7qBHll-51ItH-LKzfgXu7H9q-I8d1y3RNMx-lqvIuAmi5K2_FmkiQ\"}";
        final String CHECK_ORDER_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"status\": \"valid\"," + System.lineSeparator() +
                "  \"expires\": \"2019-07-23T19:57:55Z\"," + System.lineSeparator() +
                "  \"identifiers\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns\"," + System.lineSeparator() +
                "      \"value\": \"mndelkdnbcilohgv2.com\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"authorizations\": [" + System.lineSeparator() +
                "    \"http://localhost:4001/acme/authz/v2/46\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"finalize\": \"http://localhost:4001/acme/finalize/18/68\"," + System.lineSeparator() +
                "  \"certificate\": \"http://localhost:4001/acme/cert/ff1093811c2dca68b305c777d1d6b058cb14\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String CERT_URL = "/acme/cert/ff1093811c2dca68b305c777d1d6b058cb14";
        final String CERT_REPLAY_NONCE = "zinctQYf_mnOJoVGDbAM1CdUSVnq_1X0yixRU_nAWuCrZkU";

        final String CERT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMTgiLCJub25jZSI6InRhcm9SQ25WcE43d2c3RVF2d3JCdktrTlVkeVhJU3VTd04xX1kxaHVWbjRJUU9vIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvY2VydC9mZjEwOTM4MTFjMmRjYTY4YjMwNWM3NzdkMWQ2YjA1OGNiMTQifQ\",\"payload\":\"\",\"signature\":\"BY_MtgoIMBOVgh34tkd8qMAWehaC3_II8ghIdkuXVTLqMETipZ97c0uD5zDJGw4BVStxnYvGHgdwk1aOSz8y5-i8IhbFS1dZYOgscaZp5V57VXIvar5t4mKklevafg9Vj3O2fNg5NKdGaJEn7ZgHutGcEyJrqEWqUq4nfYAn5dUZeABrfpxjzR4nksLSQjCdzZcmOHT-OYgb5UiI-IjCJcsZlBcIV_Y9oGKUDJ_BMg7sYS-NIQ7EatToVvY6NasB0gFPJ95vz_oz0cTRU439VCHF7u-YowXO2cXF9M8kak5Oaept8QFQFRBKDODqEIzLjBcP1Um6_ybPO0sLiJG4uw\"}";
        final String CERT_RESPONSE_BODY = "-----BEGIN CERTIFICATE-----" + System.lineSeparator() +
                "MIIEoTCCA4mgAwIBAgITAP8Qk4EcLcposwXHd9HWsFjLFDANBgkqhkiG9w0BAQsF" + System.lineSeparator() +
                "ADAfMR0wGwYDVQQDDBRoMnBweSBoMmNrZXIgZmFrZSBDQTAeFw0xOTA3MTYxODU3" + System.lineSeparator() +
                "NTZaFw0xOTEwMTQxODU3NTZaMCAxHjAcBgNVBAMTFW1uZGVsa2RuYmNpbG9oZ3Yy" + System.lineSeparator() +
                "LmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNWdSNeeqVApfg5V6xDRpqac" + System.lineSeparator() +
                "CeW/MR8M8aaMAy37FLeVHewJ9+N/Lk6iov3/lNp6hTuzoljFZTD3/bD3+RVTkAKj" + System.lineSeparator() +
                "ggKeMIICmjAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsG" + System.lineSeparator() +
                "AQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFLUOwBDYB0/t83fH65E9+EhK" + System.lineSeparator() +
                "c+e4MB8GA1UdIwQYMBaAFPt4TxL5YBWDLJ8XfzQZsy426kGJMGYGCCsGAQUFBwEB" + System.lineSeparator() +
                "BFowWDAiBggrBgEFBQcwAYYWaHR0cDovLzEyNy4wLjAuMTo0MDAyLzAyBggrBgEF" + System.lineSeparator() +
                "BQcwAoYmaHR0cDovLzEyNy4wLjAuMTo0MDAwL2FjbWUvaXNzdWVyLWNlcnQwIAYD" + System.lineSeparator() +
                "VR0RBBkwF4IVbW5kZWxrZG5iY2lsb2hndjIuY29tMCcGA1UdHwQgMB4wHKAaoBiG" + System.lineSeparator() +
                "Fmh0dHA6Ly9leGFtcGxlLmNvbS9jcmwwYQYDVR0gBFowWDAIBgZngQwBAgEwTAYD" + System.lineSeparator() +
                "KgMEMEUwIgYIKwYBBQUHAgEWFmh0dHA6Ly9leGFtcGxlLmNvbS9jcHMwHwYIKwYB" + System.lineSeparator() +
                "BQUHAgIwEwwRRG8gV2hhdCBUaG91IFdpbHQwggEDBgorBgEEAdZ5AgQCBIH0BIHx" + System.lineSeparator() +
                "AO8AdQDdmTT8peckgMlWaH2BNJkISbJJ97Vp2Me8qz9cwfNuZAAAAWv8XOpXAAAE" + System.lineSeparator() +
                "AwBGMEQCID2B0PeB+cxwEuSIr0xakdkDi4zStQffSeXwy5Xi2z3XAiA9b2uo0QJu" + System.lineSeparator() +
                "W/rZoKjPxO53Q7LclMQYnHucagWfy7irXwB2ABboacHRlerXw/iXGuPwdgH3jOG2" + System.lineSeparator() +
                "nTGoUhi2g38xqBUIAAABa/xc6lYAAAQDAEcwRQIhAOdHz0WsKkHx9La5p6A4nfGP" + System.lineSeparator() +
                "HpeOvcNss3feW8qXvGKbAiAleyPIvJjZlXGMR/H5doyiG/uuJ3QLpGnzXH7tegx2" + System.lineSeparator() +
                "hjANBgkqhkiG9w0BAQsFAAOCAQEAJv2VRPTuDr73+G0aWZMgTSIyCfSutstBRf4S" + System.lineSeparator() +
                "skZy5OBdtvCJ+KZ//4aO8GzBLIK2oO15zb6J0LzGLBN8fh44zBEXyB82xV77xZsU" + System.lineSeparator() +
                "h3iXHVr/xJryq5vfxKLQdmSOxljZqIUb1ewk6z0lgVSCkSCysRYFFCO6FUVtCQtL" + System.lineSeparator() +
                "6QvB8fdtnIP0badkB5N2QJzJ7wqxi2J6HPVhEiCTRHzKjK1d5z8daaVQjd1XU4+x" + System.lineSeparator() +
                "GgpK++cGcpLrkQ8uCXGfIHz78wnnLxco19K6F41D1zGlevAAaHiG++NafW3/kJIN" + System.lineSeparator() +
                "hk6FdLvhm+dFuaXMBzFr9sSzXQo9tsady2/VwR55xlTaXeD31w==" + System.lineSeparator() +
                "-----END CERTIFICATE-----" + System.lineSeparator() +
                "" + System.lineSeparator() +
                "-----BEGIN CERTIFICATE-----" + System.lineSeparator() +
                "MIIERTCCAy2gAwIBAgICElowDQYJKoZIhvcNAQELBQAwKzEpMCcGA1UEAwwgY2Fj" + System.lineSeparator() +
                "a2xpbmcgY3J5cHRvZ3JhcGhlciBmYWtlIFJPT1QwHhcNMTYwMzIyMDI0NzUyWhcN" + System.lineSeparator() +
                "MjEwMzIxMDI0NzUyWjAfMR0wGwYDVQQDDBRoMnBweSBoMmNrZXIgZmFrZSBDQTCC" + System.lineSeparator() +
                "ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMIKR3maBcUSsncXYzQT13D5" + System.lineSeparator() +
                "Nr+Z3mLxMMh3TUdt6sACmqbJ0btRlgXfMtNLM2OU1I6a3Ju+tIZSdn2v21JBwvxU" + System.lineSeparator() +
                "zpZQ4zy2cimIiMQDZCQHJwzC9GZn8HaW091iz9H0Go3A7WDXwYNmsdLNRi00o14U" + System.lineSeparator() +
                "joaVqaPsYrZWvRKaIRqaU0hHmS0AWwQSvN/93iMIXuyiwywmkwKbWnnxCQ/gsctK" + System.lineSeparator() +
                "FUtcNrwEx9Wgj6KlhwDTyI1QWSBbxVYNyUgPFzKxrSmwMO0yNff7ho+QT9x5+Y/7" + System.lineSeparator() +
                "XE59S4Mc4ZXxcXKew/gSlN9U5mvT+D2BhDtkCupdfsZNCQWp27A+b/DmrFI9NqsC" + System.lineSeparator() +
                "AwEAAaOCAX0wggF5MBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGG" + System.lineSeparator() +
                "MH8GCCsGAQUFBwEBBHMwcTAyBggrBgEFBQcwAYYmaHR0cDovL2lzcmcudHJ1c3Rp" + System.lineSeparator() +
                "ZC5vY3NwLmlkZW50cnVzdC5jb20wOwYIKwYBBQUHMAKGL2h0dHA6Ly9hcHBzLmlk" + System.lineSeparator() +
                "ZW50cnVzdC5jb20vcm9vdHMvZHN0cm9vdGNheDMucDdjMB8GA1UdIwQYMBaAFOmk" + System.lineSeparator() +
                "P+6epeby1dd5YDyTpi4kjpeqMFQGA1UdIARNMEswCAYGZ4EMAQIBMD8GCysGAQQB" + System.lineSeparator() +
                "gt8TAQEBMDAwLgYIKwYBBQUHAgEWImh0dHA6Ly9jcHMucm9vdC14MS5sZXRzZW5j" + System.lineSeparator() +
                "cnlwdC5vcmcwPAYDVR0fBDUwMzAxoC+gLYYraHR0cDovL2NybC5pZGVudHJ1c3Qu" + System.lineSeparator() +
                "Y29tL0RTVFJPT1RDQVgzQ1JMLmNybDAdBgNVHQ4EFgQU+3hPEvlgFYMsnxd/NBmz" + System.lineSeparator() +
                "LjbqQYkwDQYJKoZIhvcNAQELBQADggEBAKvePfYXBaAcYca2e0WwkswwJ7lLU/i3" + System.lineSeparator() +
                "GIFM8tErKThNf3gD3KdCtDZ45XomOsgdRv8oxYTvQpBGTclYRAqLsO9t/LgGxeSB" + System.lineSeparator() +
                "jzwY7Ytdwwj8lviEGtiun06sJxRvvBU+l9uTs3DKBxWKZ/YRf4+6wq/vERrShpEC" + System.lineSeparator() +
                "KuQ5+NgMcStQY7dywrsd6x1p3bkOvowbDlaRwru7QCIXTBSb8TepKqCqRzr6YREt" + System.lineSeparator() +
                "doIw2FE8MKMCGR2p+U3slhxfLTh13MuqIOvTuA145S/qf6xCkRc9I92GpjoQk87Z" + System.lineSeparator() +
                "v1uhpkgT9uwbRw0Cs5DMdxT/LgIUSfUTKU83GNrbrQNYinkJ77i6wG0=" + System.lineSeparator() +
                "-----END CERTIFICATE-----" + System.lineSeparator();

        return new AcmeMockServerBuilder(server)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY)
                .addNewNonceResponse(NEW_NONCE_RESPONSE)
                .addNewAccountRequestAndResponse(QUERY_ACCT_REQUEST_BODY, QUERY_ACCT_RESPONSE_BODY, QUERY_ACCT_REPLAY_NONCE, ACCT_LOCATION, 200)
                .orderCertificateRequestAndResponse(ORDER_CERT_REQUEST_BODY, ORDER_CERT_RESPONSE_BODY, ORDER_CERT_REPLAY_NONCE, ORDER_LOCATION, 201, false)
                .addAuthorizationResponseBody(AUTHZ_URL, AUTHZ_REQUEST_BODY, AUTHZ_RESPONSE_BODY, AUTHZ_REPLAY_NONCE)
                .addChallengeRequestAndResponse(CHALLENGE_REQUEST_BODY, CHALLENGE_URL, CHALLENGE_RESPONSE_BODY, CHALLENGE_REPLAY_NONCE, CHALLENGE_LOCATION, CHALLENGE_LINK, 200, false, VERIFY_CHALLENGE_URL, CHALLENGE_FILE_CONTENTS, AUTHZ_URL, UPDATED_AUTHZ_RESPONSE_BODY, UPDATED_AUTHZ_REPLAY_NONCE)
                .addFinalizeRequestAndResponse(FINALIZE_RESPONSE_BODY, FINALIZE_REPLAY_NONCE, FINALIZE_URL, FINALIZE_LOCATION, 200)
                .addCheckOrderRequestAndResponse(CHECK_ORDER_URL, CHECK_ORDER_REQUEST_BODY, CHECK_ORDER_RESPONSE_BODY, CHECK_ORDER_REPLAY_NONCE, 200)
                .addCertificateRequestAndResponse(CERT_URL, CERT_REQUEST_BODY, CERT_RESPONSE_BODY, CERT_REPLAY_NONCE,  200)
                .build();
    }

    private ClientAndServer setupTestObtainCertificateWithUnsupportedPublicKey() {

        // set up a mock Let's Encrypt server
        final String DIRECTORY_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"Cd6YLrbpxmk\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator() +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator() +
                "  \"meta\": {" + System.lineSeparator() +
                "    \"caaIdentities\": [" + System.lineSeparator() +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator() +
                "    ]," + System.lineSeparator() +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator() +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator() +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator() +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator() +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String NEW_NONCE_RESPONSE = "zincntRzrBcL6fSvrCekkI48w39j89-rUjvGi7QYg9rdnys";

        final String QUERY_ACCT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJxTjcwc2VsZEVrVTlKV0RMUkNibkp2QWo2WWs3UnV4QktUV0dNLTZaMUxsQlpXV1A1OGthbWU5cDA1THFLa05rdC1Yakc3Wkt5T1FQUXZ4cU5oRURKLTNpck93V0NzWi1BRk5aYU5BMlFoZ0dRYnB2MkRkRDIzMWdqVUZRT3dlS2pLdlhDdUg1TFlxVjVObUx0TFBNbjBsTFpFX21NVlB3dnhLTV9FLTBjRFhqeDZzTU9BbWtvVWkzWGRaOU0tUUNNc1BxTUhnbUt1T2xCUnVXdmRJNVRDaUcyemNXMFo2T0Y5T0lybVhoWTBFeVNDTjc3RkJ2dkJNN2NsYkNiN1gxS0ZGLVNpUDQ3a013VlNyR2h1eER6dVpzaU4wOThxT3IwVG8yd1BzQ2V5SzZwT3ZST3VwQi1ZX01yXy1QRjl5dnE5bXkzLVBXeVAtcnB3T09XVWZYZXcifSwibm9uY2UiOiJ6aW5jbnRSenJCY0w2ZlN2ckNla2tJNDh3MzlqODktclVqdkdpN1FZZzlyZG55cyIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL25ldy1hY2N0In0\",\"payload\":\"eyJvbmx5UmV0dXJuRXhpc3RpbmciOnRydWV9\",\"signature\":\"TDqm_Jpezttg3kUIskpO18JthPtxzm4Q6-bXhYUiiD409_LLHyWt8gpmdSZ2g1EdnvegpKRfGHe-svggQVwJc5sJZrg_s3KrfpC2LwaxvmK6J5czRakBY1HLDhvB-dfDufp9Hua5wTyCM3VJhBzuwxT04C8mBD6TXVMhwt-ELWTviageuVidWJNw9STAfohS3cfU2kDkbLENn93VdnuGwr5PIuvTB7pBbyy7C0VmIDWlh2E9kXTnv2QPmYiIZOkTfHgN1EbRoWdJx4QKIWazOCfTuMT41YJs460a2CnXAk51eo6XlS5gmSlNGux3Qg2S0bzOY1IIMoFQH0MYDGiSMw\"}";

        final String QUERY_ACCT_RESPONSE_BODY= "";

        final String QUERY_ACCT_REPLAY_NONCE = "taroJmBHDyFedEWgCGh75dU3FcP5ubQTK2-WTPz7vZoN3NI";
        final String ACCT_LOCATION = "http://localhost:4001/acme/acct/18";


        final String ORDER_CERT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMTgiLCJub25jZSI6InRhcm9KbUJIRHlGZWRFV2dDR2g3NWRVM0ZjUDV1YlFUSzItV1RQejd2Wm9OM05JIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvbmV3LW9yZGVyIn0\",\"payload\":\"eyJpZGVudGlmaWVycyI6W3sidHlwZSI6ImRucyIsInZhbHVlIjoiaXJhY2x6bGNxZ2F5bXJjLmNvbSJ9XX0\",\"signature\":\"GgDQPFBK5AtUwG0100zmtcN0vaqWItG8neHt_UmyWme0zpdcdlDv7Kl_ayTPTRB0dzCEu3mrCbUsk2cHZu80_xkkmuTuGu4RRIpElhVAgkj8h5Gs5nmj1Rx8tY31GIyHgE4WhmQMurDaQUWEVzK8TMNFMuql_gr6b3vT577sTneDVQxRy5yLYzjDw60eQsm687CSHb8JgbUlh3qzz4NvC-bQxMAkHQctLU2WH7xyOyWNTWl49zFDaeaa_xC3FE01goHyToDEMOIuMKvvwXf4XooivWMSMqRlaaGwB81f3wzSNwjNdqsrY-pp2O5WJS2660RfRbWfwjIoQbAV6lNBmw\"}";

        final String ORDER_CERT_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"status\": \"pending\"," + System.lineSeparator() +
                "  \"expires\": \"2019-07-29T16:28:22.889849436Z\"," + System.lineSeparator() +
                "  \"identifiers\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns\"," + System.lineSeparator() +
                "      \"value\": \"iraclzlcqgaymrc.com\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"authorizations\": [" + System.lineSeparator() +
                "    \"http://localhost:4001/acme/authz/v2/67\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"finalize\": \"http://localhost:4001/acme/finalize/18/99\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String ORDER_CERT_REPLAY_NONCE = "zinc-xZ1copze4zkgzj2cwJVZ0lg2pZtUEZjaYVTpChDbMs";
        final String ORDER_LOCATION = "http://localhost:4001/acme/order/18/99";

        final String AUTHZ_REPLAY_NONCE = "tarolh01L8-AR79io0VLNh2X_gInZpiTubW0QhHIE2BPKK4";
        final String AUTHZ_URL = "/acme/authz/v2/67";
        final String AUTHZ_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMTgiLCJub25jZSI6InppbmMteFoxY29wemU0emtnemoyY3dKVlowbGcycFp0VUVaamFZVlRwQ2hEYk1zIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvYXV0aHovdjIvNjcifQ\",\"payload\":\"\",\"signature\":\"DNpOi-b2YLtBrbIC98LUcovvbYwq0xq5nyc3KOS8e6rl90vf9-ZCLUeWfzjXjXfN4Hgie1zZMySIVb9Blbm9bb2GrhiPdCGv8SixFLEyB5i_ZNDuU15nUrs1dQricv9PH9TTf6YrBJGjQtSH4nkQIRX9K6rzQAX-mPRQtk7TXOxU1cztj0DRpnw9MgqOj3zX54N-2tl9hoeUFyErFGDxRxKHFiEAxuvlaNv30VN9OXyRLxl3qURNhJR1_9T_P5uk1QEraUruAZR5DX1mVYMJLwQKxrkAIEzAJscFj6d8DE01XO2On49x3UKLAdXpyJQeVzP2lJ1uRymwMYzpAu2whA\"}";
        final String AUTHZ_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"identifier\": {" + System.lineSeparator() +
                "    \"type\": \"dns\"," + System.lineSeparator() +
                "    \"value\": \"iraclzlcqgaymrc.com\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"status\": \"pending\"," + System.lineSeparator() +
                "  \"expires\": \"2019-07-29T16:28:22Z\"," + System.lineSeparator() +
                "  \"challenges\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"http-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/v2/67/jabkIQ\"," + System.lineSeparator() +
                "      \"token\": \"d2fs_-qypCU68P4jck7U9k1JGdN-SlQbjfWUCIo8SAQ\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/v2/67/nOqZzg\"," + System.lineSeparator() +
                "      \"token\": \"d2fs_-qypCU68P4jck7U9k1JGdN-SlQbjfWUCIo8SAQ\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"tls-alpn-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/v2/67/5jeSaw\"," + System.lineSeparator() +
                "      \"token\": \"d2fs_-qypCU68P4jck7U9k1JGdN-SlQbjfWUCIo8SAQ\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String CHALLENGE_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMTgiLCJub25jZSI6InRhcm9saDAxTDgtQVI3OWlvMFZMTmgyWF9nSW5acGlUdWJXMFFoSElFMkJQS0s0IiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvY2hhbGxlbmdlL3YyLzY3L2phYmtJUSJ9\",\"payload\":\"e30\",\"signature\":\"KOQARJFyGIZpsavmvmyjBPgnY4nSdBGlYCf4HukPe1iOLh-gwY6HTbh8SCjlNfEviWglwwUGUKeQGZaGhXu8dUZg7KnzqD5cN5unHXrJVlt3Atv-ysFXYYswTTihk7gRjHaNkFJ88hoomYdOG5jD_ijQUQyheqU_qsRJXNHw8z1dTdys_gwdDmML3PQNJ-5kkSYnIoBLViI1c8OhHWiBBOWzbeGUNc_nE9M_qJyBqcGRofctGcKlrGaajI4Zbf6Rp6Bc3L2oy1cDC_Ys4UJ-1k_wOeFeRLhhtjftKT3RTFTT9YsEGRxWaEwKnUAsWew8HkCfQjLf7phY6ZjMogubAg\"}";
        final String CHALLENGE_URL = "/acme/challenge/v2/67/jabkIQ";

        final String CHALLENGE_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"type\": \"http-01\"," + System.lineSeparator() +
                "  \"status\": \"pending\"," + System.lineSeparator() +
                "  \"url\": \"http://localhost:4001/acme/challenge/v2/67/jabkIQ\"," + System.lineSeparator() +
                "  \"token\": \"d2fs_-qypCU68P4jck7U9k1JGdN-SlQbjfWUCIo8SAQ\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String CHALLENGE_REPLAY_NONCE = "zinc45dbw3ymv3Jy609ZCbK-JFYQ7-bukseiA0C9MCG1RaI";
        final String CHALLENGE_LOCATION = "http://localhost:4001/acme/challenge/v2/67/jabkIQ";
        final String CHALLENGE_LINK = "<http://localhost:4001/acme/authz/v2/67>;rel=\"up\"";
        final String VERIFY_CHALLENGE_URL = "/.well-known/acme-challenge/d2fs_-qypCU68P4jck7U9k1JGdN-SlQbjfWUCIo8SAQ";
        final String CHALLENGE_FILE_CONTENTS = "d2fs_-qypCU68P4jck7U9k1JGdN-SlQbjfWUCIo8SAQ.2NVC_ENUU-TZ83gkUxQvXl7_ixvttxk_dPlNqIyXGKY";

        final String UPDATED_AUTHZ_REPLAY_NONCE = "taroU2YGBQVFTtrEh8v1qkH5DxOMYWG0rO4ABhGAzt2A6yc";
        final String UPDATED_AUTHZ_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"identifier\": {" + System.lineSeparator() +
                "    \"type\": \"dns\"," + System.lineSeparator() +
                "    \"value\": \"iraclzlcqgaymrc.com\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"status\": \"valid\"," + System.lineSeparator() +
                "  \"expires\": \"2019-08-28T16:28:22Z\"," + System.lineSeparator() +
                "  \"challenges\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"http-01\"," + System.lineSeparator() +
                "      \"status\": \"valid\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/v2/67/jabkIQ\"," + System.lineSeparator() +
                "      \"token\": \"d2fs_-qypCU68P4jck7U9k1JGdN-SlQbjfWUCIo8SAQ\"," + System.lineSeparator() +
                "      \"validationRecord\": [" + System.lineSeparator() +
                "        {" + System.lineSeparator() +
                "          \"url\": \"http://iraclzlcqgaymrc.com/.well-known/acme-challenge/d2fs_-qypCU68P4jck7U9k1JGdN-SlQbjfWUCIo8SAQ\"," + System.lineSeparator() +
                "          \"hostname\": \"iraclzlcqgaymrc.com\"," + System.lineSeparator() +
                "          \"port\": \"5002\"," + System.lineSeparator() +
                "          \"addressesResolved\": [" + System.lineSeparator() +
                "            \"172.17.0.1\"" + System.lineSeparator() +
                "          ]," + System.lineSeparator() +
                "          \"addressUsed\": \"172.17.0.1\"" + System.lineSeparator() +
                "        }" + System.lineSeparator() +
                "      ]" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/v2/67/nOqZzg\"," + System.lineSeparator() +
                "      \"token\": \"d2fs_-qypCU68P4jck7U9k1JGdN-SlQbjfWUCIo8SAQ\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"tls-alpn-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/v2/67/5jeSaw\"," + System.lineSeparator() +
                "      \"token\": \"d2fs_-qypCU68P4jck7U9k1JGdN-SlQbjfWUCIo8SAQ\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String FINALIZE_URL = "/acme/finalize/18/99";

        final String FINALIZE_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"type\": \"urn:ietf:params:acme:error:malformed\"," + System.lineSeparator() +
                "  \"detail\": \"Error finalizing order :: invalid public key in CSR: unknown key type *dsa.PublicKey\"," + System.lineSeparator() +
                "  \"status\": 400" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String FINALIZE_REPLAY_NONCE = "zincIG_1w_6ME9wlbC5CmT7FQ9h2LLtLFzONU5qh1bkaDh8";
        final String FINALIZE_LOCATION = "";

        return new AcmeMockServerBuilder(server)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY)
                .addNewNonceResponse(NEW_NONCE_RESPONSE)
                .addNewAccountRequestAndResponse(QUERY_ACCT_REQUEST_BODY, QUERY_ACCT_RESPONSE_BODY, QUERY_ACCT_REPLAY_NONCE, ACCT_LOCATION, 200)
                .orderCertificateRequestAndResponse(ORDER_CERT_REQUEST_BODY, ORDER_CERT_RESPONSE_BODY, ORDER_CERT_REPLAY_NONCE, ORDER_LOCATION, 201, false)
                .addAuthorizationResponseBody(AUTHZ_URL, AUTHZ_REQUEST_BODY, AUTHZ_RESPONSE_BODY, AUTHZ_REPLAY_NONCE)
                .addChallengeRequestAndResponse(CHALLENGE_REQUEST_BODY, CHALLENGE_URL, CHALLENGE_RESPONSE_BODY, CHALLENGE_REPLAY_NONCE, CHALLENGE_LOCATION, CHALLENGE_LINK, 200, false, VERIFY_CHALLENGE_URL, CHALLENGE_FILE_CONTENTS, AUTHZ_URL, UPDATED_AUTHZ_RESPONSE_BODY, UPDATED_AUTHZ_REPLAY_NONCE)
                .addFinalizeRequestAndResponse(FINALIZE_RESPONSE_BODY, FINALIZE_REPLAY_NONCE, FINALIZE_URL, FINALIZE_LOCATION, 400, true)
                .build();
    }

    private ClientAndServer setupTestRevokeCertificate() {

        // set up a mock Let's Encrypt server
        final String DIRECTORY_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator() +
                "  \"meta\": {" + System.lineSeparator() +
                "    \"caaIdentities\": [" + System.lineSeparator() +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator() +
                "    ]," + System.lineSeparator() +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator() +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator() +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator() +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator() +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"," + System.lineSeparator() +
                "  \"kgIgyHU3yA0\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String NEW_NONCE_RESPONSE = "taroDvhk2H7ErEkhFCq8zux1hCbY0KzFQDEFGjMaSvvCC_k";

        final String QUERY_ACCT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJoOE9lZTViZURSZ3hOUGVfZU1FOUg2Vm83NEZ1ZzhIZ3Jpa2ZiZkNhVTNsS0Y2NDhRRzFYMWtHRFpUaEF5OGRhcUo4YnY2YzNQSmRueDJIcjhqT3psNTA5Ym5NNmNDV2Z5d1RwY0lab1V6UVFaTFlfSzhHTURBeWdsc1FySXRnQ2lRYWxJcWJ1SkVrb2MzV1FBSXhKMjN4djliSzV4blZRa1RXNHJWQkFjWU5Rd29CakdZT1dTaXpUR2ZqZ21RcVRYbG9hYW1GWkpuOTdIbmIxcWp5NVZZbTA2YnV5cXdBYUdIczFDTHUzY0xaZ1FwVkhRNGtGc3prOFlPNVVBRWppb2R1Z1dwWlVSdTlUdFJLek4wYmtFZGVRUFlWcGF1cFVxMWNxNDdScDJqcVZVWGRpUUxla3l4clFidDhBMnVHNEx6RFF1LWI0Y1pwcG16YzNobGhTR3cifSwibm9uY2UiOiJ0YXJvRHZoazJIN0VyRWtoRkNxOHp1eDFoQ2JZMEt6RlFERUZHak1hU3Z2Q0NfayIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL25ldy1hY2N0In0\",\"payload\":\"eyJvbmx5UmV0dXJuRXhpc3RpbmciOnRydWV9\",\"signature\":\"WpICzZNwgHJckeO7fn8rytSB23poud38FEg1fwmVvd3rag-KLZ5rOrqmOzr6BIUpaY0DEeZ03QzQFYIoywVNg8Apvbh12RZvkWW_VuIfpnJOz6dWOhV-lM5aH9oVy7mW9nNVqzqlTEyWRXPGo8XSD_vWtxSu-zLbHOTvnURiiCOO3DM96xRZrnvexTI97RRO6cBrI4HzjSBpat03YOkwxEWzrbqdZD7RVgUxTh6ELK7BE1U87IF2iBO_V1VllUZdH9P2EiTtFBwj5xkBXhyeBiTj2BqWzb4-Y5o_W0b5hMX1IQiPa-zb56L-SkcEJMNu-hJSGmPy6uoRJVAwCHcP-w\"}";

        final String QUERY_ACCT_RESPONSE_BODY= "";

        final String QUERY_ACCT_REPLAY_NONCE = "zincgzgBIqMgfFmkcIQYn6rGST-aEs9SOGlh0b8u4QYFqiA";
        final String ACCT_LOCATION = "http://localhost:4001/acme/acct/5";

        final String REVOKE_CERT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvNSIsIm5vbmNlIjoiemluY2d6Z0JJcU1nZkZta2NJUVluNnJHU1QtYUVzOVNPR2xoMGI4dTRRWUZxaUEiLCJ1cmwiOiJodHRwOi8vbG9jYWxob3N0OjQwMDEvYWNtZS9yZXZva2UtY2VydCJ9\",\"payload\":\"eyJjZXJ0aWZpY2F0ZSI6Ik1JSUZUVENDQkRXZ0F3SUJBZ0lUQVA4b01Ib3hOS19JbWdkN3lzelh3S2RXd3pBTkJna3Foa2lHOXcwQkFRc0ZBREFmTVIwd0d3WURWUVFEREJSb01uQndlU0JvTW1OclpYSWdabUZyWlNCRFFUQWVGdzB4T1RBM01UWXhOalE0TWpkYUZ3MHhPVEV3TVRReE5qUTRNamRhTUNFeEh6QWRCZ05WQkFNVEZtbHViRzVsYzJWd2NIZHJabmRsZDNaNE1pNWpiMjB3Z2dFaU1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRQ1NaQllqclZ0S05jbFVhQV9nZ3hJaGNSVVdrOUVJbXBJMG5heWQwaURsYUdUWkxicTZVNHZvUWxzNkRDZmpzdzIwU2QzdTgzb2RqTDU2QUdOeHBIUzZaYTVjN3RLS1hGUmgwOVFjVEkzdFJwbWF5bFgwZXhWd2tVcllSaUdLSXA3Mjg2YzhWdi1qenk4VkkyLXlnaFpvLThHRDNjVm9XdFhEWnpWNWxnZlFGeGhDc2tUUjhWUXB6b0FOMm5Fai01UVRNdi1HdUhfSDJ5U3FNLWtTN0NwR2JUaDZZSUp2OVZfblFUaC1FTEFnY29ic01UN24tU2dfRTdUQ21nNmxqaWduaGRwdzZGMElMdWlfX3pJYzFEbG0yRC1UVi0tWm4yQnp1b2FkeFJlZ05TcXMyRkkyUDF3MXlSSHFHYmtTOEpabEY0LWg3MVhWV01kazFtWUVaRTVCQWdNQkFBR2pnZ0otTUlJQ2VqQU9CZ05WSFE4QkFmOEVCQU1DQmFBd0hRWURWUjBsQkJZd0ZBWUlLd1lCQlFVSEF3RUdDQ3NHQVFVRkJ3TUNNQXdHQTFVZEV3RUJfd1FDTUFBd0hRWURWUjBPQkJZRUZObThPaFpQbWYweWdhNUR6MHNGaTB3TXZ3cWJNQjhHQTFVZEl3UVlNQmFBRlB0NFR4TDVZQldETEo4WGZ6UVpzeTQyNmtHSk1HUUdDQ3NHQVFVRkJ3RUJCRmd3VmpBaUJnZ3JCZ0VGQlFjd0FZWVdhSFIwY0Rvdkx6RXlOeTR3TGpBdU1UbzBNREF5THpBd0JnZ3JCZ0VGQlFjd0FvWWthSFIwY0RvdkwySnZkV3hrWlhJNk5EUXpNQzloWTIxbEwybHpjM1ZsY2kxalpYSjBNQ0VHQTFVZEVRUWFNQmlDRm1sdWJHNWxjMlZ3Y0hkclpuZGxkM1o0TWk1amIyMHdKd1lEVlIwZkJDQXdIakFjb0JxZ0dJWVdhSFIwY0RvdkwyVjRZVzF3YkdVdVkyOXRMMk55YkRCQUJnTlZIU0FFT1RBM01BZ0dCbWVCREFFQ0FUQXJCZ01xQXdRd0pEQWlCZ2dyQmdFRkJRY0NBUllXYUhSMGNEb3ZMMlY0WVcxd2JHVXVZMjl0TDJOd2N6Q0NBUVVHQ2lzR0FRUUIxbmtDQkFJRWdmWUVnZk1BOFFCM0FCYm9hY0hSbGVyWHdfaVhHdVB3ZGdIM2pPRzJuVEdvVWhpMmczOHhxQlVJQUFBQmFfdm1ZVElBQUFRREFFZ3dSZ0loQUt0b2NobEprQm5idFduQzFLUjlVZ2p0TXZldFFjeUEyaTRvVE9rVjVTUFVBaUVBdEFqeXd6RW11eHRJcmc0US1oWExHTllqbVlFSWROSUxnVDBTZGVkUE5kQUFkZ0FvZGhvWWtDZjc3enpRMWhvQmpYYXdVRmNweDZkQkc4eTk5Z1QwWFVKaFV3QUFBV3Y3NW1FekFBQUVBd0JITUVVQ0lGVVJmVkJfUWVaV3N1dk1LVVpUVDJDaVAzR182OVkzVUNhV0pfNExYbWozQWlFQXBkQXVXMVU1T2Z5TF9ZcGVBRVBBbVpyOVpvNWFDejRsWU0zcTluTGh4V0l3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQURtODV2cHZFaU9VWWNQRXB3bE9RdlRJYW4ybm1MMWN0ejhUN0xLbmJpQ3pYX2lYcjNUY2FrSEV3NUVNVUk0ZEFEN3ZTRklIclhDem5GZTVlYTVQWGh2bi1KQjFFVnQtVnZmV3lGQXlWLVBuVzc0dDBGa1p5Z1ZQSGdwbktnVWozemFSMHhfRDlZMEEybW16REZCYkpHNmpDR0k1V3lmSnY2c0gyS2xuTDRvaWhGS1VQVm9HY3VNZWhySkd3TWNUMllhRnM3dDhXaHROTkM4ek9HbkxHODdiQUM4SjUxY0VEdjlGeUYyaUtBc0NLY1JNWFRnd0Q2Y2pRVExacnZ1ZnJQN1FTR3pzYWdRYXlPZEVNZkl3N2UydXZoSS1iRWtMdFdxb1BKcmZFV2Y4YU1CY2RLVEhXQXc4NGhDOXR0am52S0xGbFVvNjlHYWhmZm5KV2ZEN1RucyJ9\",\"signature\":\"A14QNG3HbUD341rmJ7ibxiIMlcCuDIUrLWtvcmnH-byrBetX5J5VrXaiHOOPYKK2YCjDJEr2f29Cq3i6Q0IlC2UGAPGOEETYKNDBv3zHrtNe7I0VMXMqfB8ClNydSoNdAL9OB1m9syZT7ijZxq_RldTWLsCIDDdWom1xEgb3RUCpTTMUMhsTQZdf5t3y0CNa5p7wfCT8ejLcQ3aYMUm-chDjn4nC8YBdGVSlpacLdafrsDeoTFSF8yhCL9pBk_hz8FMXFKS3ctCBGVJTIHeWPWvnYJn4owEAjbmVqC_khACM-Zo7N-Gx7--47_qyG4dW2IvYansrMrlIwLlwDtmPig\"}";
        final String REVOKE_CERT_REPLAY_NONCE = "taroo4s_zllDSu1x5i0l1x595sQJalOjAPXRnz6oc7vMiHc";

        return new AcmeMockServerBuilder(server)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY)
                .addNewNonceResponse(NEW_NONCE_RESPONSE)
                .addNewAccountRequestAndResponse(QUERY_ACCT_REQUEST_BODY, QUERY_ACCT_RESPONSE_BODY, QUERY_ACCT_REPLAY_NONCE, ACCT_LOCATION, 200)
                .addRevokeCertificateRequestAndResponse(REVOKE_CERT_REQUEST_BODY, REVOKE_CERT_REPLAY_NONCE, 200)
                .build();
    }

    private ClientAndServer setupTestRevokeCertificateWithReason() {

        // set up a mock Let's Encrypt server
        final String DIRECTORY_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"oBarDLD1zzc\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator() +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator() +
                "  \"meta\": {" + System.lineSeparator() +
                "    \"caaIdentities\": [" + System.lineSeparator() +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator() +
                "    ]," + System.lineSeparator() +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator() +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator() +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator() +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator() +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String NEW_NONCE_RESPONSE = "zincwFvSlMEm-Dg4LsDtx1JBKaWnu2qiBYBUG6jSZLiexMY";

        final String QUERY_ACCT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJoOE9lZTViZURSZ3hOUGVfZU1FOUg2Vm83NEZ1ZzhIZ3Jpa2ZiZkNhVTNsS0Y2NDhRRzFYMWtHRFpUaEF5OGRhcUo4YnY2YzNQSmRueDJIcjhqT3psNTA5Ym5NNmNDV2Z5d1RwY0lab1V6UVFaTFlfSzhHTURBeWdsc1FySXRnQ2lRYWxJcWJ1SkVrb2MzV1FBSXhKMjN4djliSzV4blZRa1RXNHJWQkFjWU5Rd29CakdZT1dTaXpUR2ZqZ21RcVRYbG9hYW1GWkpuOTdIbmIxcWp5NVZZbTA2YnV5cXdBYUdIczFDTHUzY0xaZ1FwVkhRNGtGc3prOFlPNVVBRWppb2R1Z1dwWlVSdTlUdFJLek4wYmtFZGVRUFlWcGF1cFVxMWNxNDdScDJqcVZVWGRpUUxla3l4clFidDhBMnVHNEx6RFF1LWI0Y1pwcG16YzNobGhTR3cifSwibm9uY2UiOiJ6aW5jd0Z2U2xNRW0tRGc0THNEdHgxSkJLYVdudTJxaUJZQlVHNmpTWkxpZXhNWSIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL25ldy1hY2N0In0\",\"payload\":\"eyJvbmx5UmV0dXJuRXhpc3RpbmciOnRydWV9\",\"signature\":\"bFUmpw50SUd29FFzPgpZw-lkSzl8tlO4ZEUkxRNyL3NSfBZvKDUpPA9P4gg7NkKq-kLl09O2_w_9zoDu_AxIpfylnBuQmK3PGA_f61tQHjWG41hX7NaPUqPieFiEMD4EC7-z4oEN2O79hdCLzhtujwkX8kUav7q60VoUDdmLongJkoQJYHqYJisYmmvGBf28qe3jq9KmgeLav33z8xdsg3i-Cc7jZDWdRMtY72PqEMT53WhYBof15HXrrSZf5b6AAEOX8xMfPkMvx0p_TG2RCEiYY-L7yxgE634_-ye146uUL47X7h5ajmuqu3EsOL4456cjpcKGyhpU9aAhCDKHNQ\"}";

        final String QUERY_ACCT_RESPONSE_BODY= "";

        final String QUERY_ACCT_REPLAY_NONCE = "taroaIprXC7Gi1SYzYi8ETK0IooQwJyv-Qsv4ALL-xw8uu0";
        final String ACCT_LOCATION = "http://localhost:4001/acme/acct/5";

        final String REVOKE_CERT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvNSIsIm5vbmNlIjoidGFyb2FJcHJYQzdHaTFTWXpZaThFVEswSW9vUXdKeXYtUXN2NEFMTC14dzh1dTAiLCJ1cmwiOiJodHRwOi8vbG9jYWxob3N0OjQwMDEvYWNtZS9yZXZva2UtY2VydCJ9\",\"payload\":\"eyJjZXJ0aWZpY2F0ZSI6Ik1JSUZSVENDQkMyZ0F3SUJBZ0lUQVA4S2RpM2JyejdmaTlHYkpDM2pQRGxUT2pBTkJna3Foa2lHOXcwQkFRc0ZBREFmTVIwd0d3WURWUVFEREJSb01uQndlU0JvTW1OclpYSWdabUZyWlNCRFFUQWVGdzB4T1RBM01UWXhOekV5TURkYUZ3MHhPVEV3TVRReE56RXlNRGRhTUI0eEhEQWFCZ05WQkFNVEUyMXVaR1ZzYTJSdVltTnBiRzlvWnk1amIyMHdnZ0VpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFDSXhLNzVXS0dCSzJ4Y0F1QWVfTmJPRnJvcUJaU3hHUFZFOWd0Y0lMRF9HU0hSYzFWbHNmc2x1UXpsdThiSDNnaW91OFdEUU85NDNYaUxWdldJSU1oSGQ4MzJZM0xRdXMwQnlUeEtlUnVubXdhVjdHWkZoQTNrTEFJclpzUUNRNGxMUUtLTHB4N09PcVREZUhSY1Q4UHV1NDNqQXh6NTItZ0ZFc1MzOFM2WS14aGxmdTZSN1ZvMUJnenlNNFV2MkVLQVNwbDh0N2twOFdiRzUwejhSYzd4SjR1VnZEa3dSQmhJWUtPTmttaHFPVkJvNGlIT0ZoU3JFRGhzRXJERHZjdi00dzdLZU43ZDhURmtucjR1R1U2emtrWDFZYi1GX2ZSSEpzMFhXYTFJSTlGcDFmTXNnQ3lPb0R4MERKSFBIVDE0WS10TVc1bHlRTS1MT2ZYMnJ5RzdBZ01CQUFHamdnSjVNSUlDZFRBT0JnTlZIUThCQWY4RUJBTUNCYUF3SFFZRFZSMGxCQll3RkFZSUt3WUJCUVVIQXdFR0NDc0dBUVVGQndNQ01Bd0dBMVVkRXdFQl93UUNNQUF3SFFZRFZSME9CQllFRkREdmMwX1JzRG1pTjhrUlFBbmxicWNfUUJ5Mk1COEdBMVVkSXdRWU1CYUFGUHQ0VHhMNVlCV0RMSjhYZnpRWnN5NDI2a0dKTUdRR0NDc0dBUVVGQndFQkJGZ3dWakFpQmdnckJnRUZCUWN3QVlZV2FIUjBjRG92THpFeU55NHdMakF1TVRvME1EQXlMekF3QmdnckJnRUZCUWN3QW9Za2FIUjBjRG92TDJKdmRXeGtaWEk2TkRRek1DOWhZMjFsTDJsemMzVmxjaTFqWlhKME1CNEdBMVVkRVFRWE1CV0NFMjF1WkdWc2EyUnVZbU5wYkc5b1p5NWpiMjB3SndZRFZSMGZCQ0F3SGpBY29CcWdHSVlXYUhSMGNEb3ZMMlY0WVcxd2JHVXVZMjl0TDJOeWJEQkFCZ05WSFNBRU9UQTNNQWdHQm1lQkRBRUNBVEFyQmdNcUF3UXdKREFpQmdnckJnRUZCUWNDQVJZV2FIUjBjRG92TDJWNFlXMXdiR1V1WTI5dEwyTndjekNDQVFNR0Npc0dBUVFCMW5rQ0JBSUVnZlFFZ2ZFQTd3QjJBQmJvYWNIUmxlclh3X2lYR3VQd2RnSDNqT0cyblRHb1VoaTJnMzh4cUJVSUFBQUJhX3Y4QzRFQUFBUURBRWN3UlFJaEFQbC1wWUdvcGZGb0xwSS1VT2pQN2J3YjQ2UmhlYXl6a1VUZDFxV3U4TUhiQWlBa0xFaG5fNllXTm1iWEtxNmtiNk9aQzFSNy1ud1NKNk41X1BQNm9KQlhvZ0IxQU4yWk5QeWw1eVNBeVZab2ZZRTBtUWhKc2tuM3RXbll4N3lyUDF6QjgyNWtBQUFCYV92OERYWUFBQVFEQUVZd1JBSWdXZkRRU2Rfamo1SzV5ZHh6MFU2Z0xpVV9LcGtZek44bG9DTHZNUXVPSDlFQ0lHT0d5eWJNcXA2ZVRtUFZxeXdDcEVEa0xRS0J2NE1DNV9McmtqN3JaMmhxTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElCQVFBUjZTLWl6NlUteU41YTNVSmJlVVR1TU9XZUNkZWFPdVBMYy1GUnpSUExxamlvb240U2VOSnp4QXNBVnNrQmtjN3ZfRGpNWFVTR3BYSm1IUVkwM1pJYUNoSWRuVXRyUTdLX0FhaXFLck1IeTV5U29JSUFENzFKU09kT1RRdTBvRDBVZVZBdUVJMlExcVBZcnNoYmZ6UGhraWxBV3BwaGhTc1l1U0g0aFlHQVRyck4zaEE5ckF3UkN4eVFmTUpUQXBiWnc5T0dZOVp5MW12NWU3cDh6WXZsanlRWEFmUmpTaEhjQ1R2UVhXUFNIb2VGVTRMa1ViMHdlXy1uRzNtdDdfTGhYckpNUFZ2T1VNQlB6R2RQSDE3dDFYeWYzVEdaV2x0Wkdjc0MzcmRjdWkxaGJkcHpxNU5zcHV3Qlg4b0F4d0Rnck9CajF4VldfRkFMSXd3NTBCMHkiLCJyZWFzb24iOjF9\",\"signature\":\"bmgU30KFfJ5QLUBFF6b2e1mBV0W3YgKJHHS3goSyxzaANUocAEBYaEAId4EglE8op1HqvVBul5o7hCA6UfkNRE_hv0Y6c5xS_OQPRt0sRk_KRe6rVeVZd2ov5IqXmjdGq7xOnyRFXq1ErPfb3KSoz1IUOagemSZzUgbPNwIIJMSnQuRXW8ScOECssoDTy_R4OL6drkyxN8qXP7dJUQ4T4rTRBXnSEv1fUHFBZLRvVb2jqMc-Iiwp6hjdahBlWqPudiMyD8pinghyns0m5btw_OmOWERMEI4lIsOJjVg2Tu7HALDiLGSk6dyUV1HXyAeWBVr1QJBFeq2Gw3rD-26d1w\"}";
        final String REVOKE_CERT_REPLAY_NONCE = "zinci0BXolnLRwsa-i7xBiVz4Zy0LDbw7hjIv9UvBDP10CQ";

        return new AcmeMockServerBuilder(server)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY)
                .addNewNonceResponse(NEW_NONCE_RESPONSE)
                .addNewAccountRequestAndResponse(QUERY_ACCT_REQUEST_BODY, QUERY_ACCT_RESPONSE_BODY, QUERY_ACCT_REPLAY_NONCE, ACCT_LOCATION, 200)
                .addRevokeCertificateRequestAndResponse(REVOKE_CERT_REQUEST_BODY, REVOKE_CERT_REPLAY_NONCE, 200)
                .build();
    }

    private ClientAndServer setupTestChangeAccountKey() {

        // set up a mock Let's Encrypt server
        final String DIRECTORY_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"uBZzMh54N6Q\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator() +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator() +
                "  \"meta\": {" + System.lineSeparator() +
                "    \"caaIdentities\": [" + System.lineSeparator() +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator() +
                "    ]," + System.lineSeparator() +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator() +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator() +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator() +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator() +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String NEW_NONCE_RESPONSE = "taroUPFo0aLcaedcnx3SpPDbSr2j84m3qw8rW2tZJnZm2FE";

        final String QUERY_ACCT_REQUEST_BODY_1 = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJpcVZkd3laNGl0VlNoOFVWX2Z3NlpnVjh3Mk56SEtGdzZWeWl5cGRLMmlyUkk0T3BMdWhJNEhqQ3pSTHR0WkJPX3ZLRjFZaTB1dVdMaFFzMnVpWlJ5eXFCa0R6SXU3UnIwZWp2T2UtLVc2aWhLanE2WnNCQ2Q3eDhMUl9yYXp1X242V1BkQWJZeWZxdnBuS0V0bGZxdW4yMWJnWk1yT1R4YW0tS0FNS2kyNlJlVi1oVDlYU05kbWpoWnhtSzZzQ0NlTl9JOTVEUXZ1VG55VFctUUJFd2J2MVVOTEEtOXRIR3QyUzQ0a2JvT0JtemV6RGdPSVlfNFpNd3MtWXZucFd5VElsU0k3TmlNMVhKb1NXMHlSLWdjaFlRT1FuSEU2QUhtdk5KbV9zSTlZN0ZhQmJVeVJpS0RnTi1vZlR3cXNzdzZ2ejVucUxUanU3Y2dzWld4S1dESHcifSwibm9uY2UiOiJ0YXJvVVBGbzBhTGNhZWRjbngzU3BQRGJTcjJqODRtM3F3OHJXMnRaSm5abTJGRSIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL25ldy1hY2N0In0\",\"payload\":\"eyJvbmx5UmV0dXJuRXhpc3RpbmciOnRydWV9\",\"signature\":\"XzrLN-kD_C0TAN7NhxdUJqIeAbUw2WWp5pwnK5tPkF177gUStWbyuCKpK68lMgmQa_EpImAUNQ8wT-oXP4ARZCYcuJZ-Hii1qXYGkXC9DCGuEPffk4c4M6F7JhA4FdlV_0nAV5i5Q6nILtn7nARqSc239jPJasM-ZjGdhfc7UCObpufoZqCChQn5N8MfLnZA8-SZK9M5pm9SM72JjUc3L9FRvFCG8p7iU_A0Lt7g9yD9LyddtONuVrzhmIm43e3pU3CaarhxA7vHlS-Vahnl-8fFCwEnsaC3b_EMfZYxBvvI28n4tn7QgwcOy6kLaNp1TXs0vxP23v_3y5dO79GSig\"}";

        final String QUERY_ACCT_RESPONSE_BODY_1 = "";

        final String QUERY_ACCT_REPLAY_NONCE_1 = "zinchourU8rrtvhVwzICl7mpth8YWPTP-7Z4aU2UNEXVONs";

        final String ACCT_PATH = "/acme/acct/10";
        final String ACCT_LOCATION = "http://localhost:4001" + ACCT_PATH;

        final String CHANGE_KEY_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"key\": {" + System.lineSeparator() +
                "    \"kty\": \"RSA\"," + System.lineSeparator() +
                "    \"n\": \"iqVdwyZ4itVSh8UV_fw6ZgV8w2NzHKFw6VyiypdK2irRI4OpLuhI4HjCzRLttZBO_vKF1Yi0uuWLhQs2uiZRyyqBkDzIu7Rr0ejvOe--W6ihKjq6ZsBCd7x8LR_razu_n6WPdAbYyfqvpnKEtlfqun21bgZMrOTxam-KAMKi26ReV-hT9XSNdmjhZxmK6sCCeN_I95DQvuTnyTW-QBEwbv1UNLA-9tHGt2S44kboOBmzezDgOIY_4ZMws-YvnpWyTIlSI7NiM1XJoSW0yR-gchYQOQnHE6AHmvNJm_sI9Y7FaBbUyRiKDgN-ofTwqssw6vz5nqLTju7cgsZWxKWDHw\"," + System.lineSeparator() +
                "    \"e\": \"AQAB\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"contact\": [" + System.lineSeparator() +
                "    \"mailto:admin@anexample.com\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"initialIp\": \"10.77.77.1\"," + System.lineSeparator() +
                "  \"createdAt\": \"2019-07-15T19:53:57Z\"," + System.lineSeparator() +
                "  \"status\": \"valid\"" + System.lineSeparator() +
                "}" + System.lineSeparator();
        final String CHANGE_KEY_REPLAY_NONCE = "zinchourU8rrtvhVwzICl7mpth8YWPTP-7Z4aU2UNEXVONs";

        final String QUERY_ACCT_RESPONSE_BODY_2 = "{" + System.lineSeparator() +
                "  \"key\": {" + System.lineSeparator() +
                "    \"kty\": \"RSA\"," + System.lineSeparator() +
                "    \"n\": \"rDYXH58ys0MT97z_7gLkNFmQSXR_eb49c_55Wk3eSQpT3sUyq1YuKGWRc92-nBz6twdXa3VixAoXkxWhCxu0A_rbo_eTXe8WlVpCBKr5rM6wAlKENDrSQZD6MdzLLGaA207a_WFG7UPDUKH2_qH98CN5eleDn0TUYa6RYFF6j5D_T1Jg5nhC9I3P4zQ-WDNYvYEkEqPUgzK4cPOBXiMB_XFb2wf8mpm2pN8Fr5XOpQYeY1YXH-HGuYG5StUq__BDForbbQ_R7HSemdMglwujM46LteCvAr-Z5XBa2ue7mRK2RAkk_3-3Tmuj8ewyNGFw_AANvl8nyhZ-BU4VZvw-HQ\"," + System.lineSeparator() +
                "    \"e\": \"AQAB\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"contact\": [" + System.lineSeparator() +
                "    \"mailto:admin@anexample.com\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"initialIp\": \"10.77.77.1\"," + System.lineSeparator() +
                "  \"createdAt\": \"2019-07-15T19:53:57Z\"," + System.lineSeparator() +
                "  \"status\": \"valid\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String QUERY_ACCT_REPLAY_NONCE_2 = "taroG712eL8LB6nca1rdSadsNXQftZ5wOLN8unyyuakUuLE";

        return new AcmeMockServerBuilder(server)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY)
                .addNewNonceResponse(NEW_NONCE_RESPONSE)
                .addNewAccountRequestAndResponse(QUERY_ACCT_REQUEST_BODY_1, QUERY_ACCT_RESPONSE_BODY_1, QUERY_ACCT_REPLAY_NONCE_1, ACCT_LOCATION, 200)
                .addChangeKeyRequestAndResponse("", CHANGE_KEY_RESPONSE_BODY, CHANGE_KEY_REPLAY_NONCE, 200)
                .updateAccountRequestAndResponse("", QUERY_ACCT_RESPONSE_BODY_2, QUERY_ACCT_REPLAY_NONCE_2, ACCT_PATH, 200)
                .build();
    }

    private ClientAndServer setupTestChangeAccountKeySpecifyCertificateAndPrivateKey() {

        // set up a mock Let's Encrypt server
        final String DIRECTORY_RESPONSE_BODY_1 = "{" + System.lineSeparator() +
                "  \"TYncJ3PO4D4\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator() +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator() +
                "  \"meta\": {" + System.lineSeparator() +
                "    \"caaIdentities\": [" + System.lineSeparator() +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator() +
                "    ]," + System.lineSeparator() +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator() +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator() +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator() +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator() +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String NEW_NONCE_RESPONSE_1 = "taroB2vNcCe_AiZTt8UrCXGdVZu-QRTyK0xRn4JxvZIMi5A";

        final String QUERY_ACCT_REQUEST_BODY_1 = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJvVVZ6QWlpeEUwelEzeWozUExpenEtcFpuWmZBa29IbXFoOWZneGh6b1FRZ3VGd01OS1Q5TmpZT1hiU3FfWS13dl9nYkstTFdKM2VxYjBNUy1xbkN3Snc0WVJzeHE1ZDVyWGhiSE5yZFhWN01jTWFVSlV5ZkFxWDBCQ2x1OGp6VEFadE5mNzZtbnVLUUlvazFsSGM2R1h4clVuMm15V2JndUJuOUQwTmdvcUdWY0lqdExlaTc5UVZTUk5ZSk5LR29VT05YQ3lRU3B2NllQQ25MWmwtOThyUFhJSU1XNXNOMURZZ19vbU45OHZmOE93YTdZQUV2NmFNT2NjZkVHcVRYQ2RySEhiTU9UbkJQQ3h3WXlfY0pUbm5OTzc0U0lyeVNEVXdSMGtBeVotbGQtVDNHdlQ2cUxyRXI3M2NqT0NkT1hlUzE1d1BnYkx5Njhua2VIQTg4YlEifSwibm9uY2UiOiJ0YXJvQjJ2TmNDZV9BaVpUdDhVckNYR2RWWnUtUVJUeUsweFJuNEp4dlpJTWk1QSIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL25ldy1hY2N0In0\",\"payload\":\"eyJvbmx5UmV0dXJuRXhpc3RpbmciOnRydWV9\",\"signature\":\"F6cupngqe1glshhJVgx2MCZphUssWMuLp9oJRQdjLQKIk8XgCG3LABffPY0_lMY6LwWRkWL2NYAvmogiNPMcQY7VVT9DmkxuNdfa0FUR4zyIVnkRP2q-fF3Kh3jq1AP2iZ41iyTCvXnfMZ18V2snefpb8vZW8vc4OLnv5Qo7UQdPCIdinEbPF_PtOr1egvFL9GObKfHQA8fGGOlHQgL_aabaYZKr4IF3K7LzRMYEgfOZw5QflL4K8ealBExod0OZ7wLHanh90l1p99AhpbFw5EG5PWLya97fTTHhZX4HtatqRGO8cDUMiRJXMcsQJiM_GK4WGbU2vbRSgLV4cKvygg\"}";

        final String QUERY_ACCT_RESPONSE_BODY_1 = "";

        final String QUERY_ACCT_REPLAY_NONCE_1 = "zinclA1oBJ6JeZd9nfhpplP2mTyta5d2skeNcS6RxGmGvL0";

        final String ACCT_PATH = "/acme/acct/15";
        final String ACCT_LOCATION = "http://localhost:4001" + ACCT_PATH;

        final String CHANGE_KEY_REQUEST_BODY_1 = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMTUiLCJub25jZSI6InppbmNsQTFvQko2SmVaZDluZmhwcGxQMm1UeXRhNWQyc2tlTmNTNlJ4R21HdkwwIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUva2V5LWNoYW5nZSJ9\",\"payload\":\"eyJwcm90ZWN0ZWQiOiJleUpoYkdjaU9pSlNVekkxTmlJc0ltcDNheUk2ZXlKbElqb2lRVkZCUWlJc0ltdDBlU0k2SWxKVFFTSXNJbTRpT2lKMFkxVmtTRVp3UzBVMFh6RXlMVTV0VG5GSkxUUjZjM1F4WVZSS2MyeHdUVWxCYVdWMWFVdEJlSEJOYVVVNFlYZHBkVnBHTFZSeFRsbGFVM0JoVmxCRGFraE1ORTV3Tm5GbWFrWmxhbXRRTXpOblRqWnNUVWxMTlROUVpXbHJUalZCWVU5MFVGTmxiVzlZTUdWQ1FWaHJTbkZpTXpSWldqQTBSRE5YY0U1SVoxaG1kVzVPWTBGVWVuRXphVGc0U0ZKemJHUnhMVGxSV1ZKQ05rZG1WbE5HTjFCVGQwSkxOa1JLYWs1aFh6UklSRGROZVdFd2R6VkJSMmxSVDBWVU9IRldPRWRyVlVOMk5HVk9WMVZIWDE5V00zSm9SakJvVUdGUExVVXljREJwUzNsaFdYbEpRa2hHTVc1SWF6aFhhVTV4YkZKdk9GbGtabVpuUlVsbFVGaEViMWN0WTFGV1duUkpVbXc1Wm5WT1VucEVRVmcyTjNoSVFtTkZVSEpEVFRaUVNUaFlUbDlVZUdwb05sbDVibmxZYjJwRFdqRXdNbGw2Y3paZlZWZE9jVkY2UTE5V01HZHNXWEZCZVdOVlZVaFNSVlpQU25jaWZTd2lkWEpzSWpvaWFIUjBjRG92TDJ4dlkyRnNhRzl6ZERvME1EQXhMMkZqYldVdmEyVjVMV05vWVc1blpTSjkiLCJwYXlsb2FkIjoiZXlKaFkyTnZkVzUwSWpvaWFIUjBjRG92TDJ4dlkyRnNhRzl6ZERvME1EQXhMMkZqYldVdllXTmpkQzh4TlNJc0ltOXNaRXRsZVNJNmV5SmxJam9pUVZGQlFpSXNJbXQwZVNJNklsSlRRU0lzSW00aU9pSnZWVlo2UVdscGVFVXdlbEV6ZVdvelVFeHBlbkV0Y0ZwdVdtWkJhMjlJYlhGb09XWm5lR2g2YjFGUlozVkdkMDFPUzFRNVRtcFpUMWhpVTNGZldTMTNkbDluWWtzdFRGZEtNMlZ4WWpCTlV5MXhia04zU25jMFdWSnplSEUxWkRWeVdHaGlTRTV5WkZoV04wMWpUV0ZWU2xWNVprRnhXREJDUTJ4MU9HcDZWRUZhZEU1bU56WnRiblZMVVVsdmF6RnNTR00yUjFoNGNsVnVNbTE1VjJKbmRVSnVPVVF3VG1kdmNVZFdZMGxxZEV4bGFUYzVVVlpUVWs1WlNrNUxSMjlWVDA1WVEzbFJVM0IyTmxsUVEyNU1XbXd0T1RoeVVGaEpTVTFYTlhOT01VUlpaMTl2YlU0NU9IWm1PRTkzWVRkWlFVVjJObUZOVDJOalprVkhjVlJZUTJSeVNFaGlUVTlVYmtKUVEzaDNXWGxmWTBwVWJtNU9UemMwVTBseWVWTkVWWGRTTUd0QmVWb3RiR1F0VkROSGRsUTJjVXh5UlhJM00yTnFUME5rVDFobFV6RTFkMUJuWWt4NU5qaHVhMlZJUVRnNFlsRWlmWDAiLCJzaWduYXR1cmUiOiJFOGl5UzI0c0lTTFRhQXFRcTV6V0xCZHM1bG1EbnBRZ19lSUc3T08yR0pJT3FyU0RzeXNzV1MyNy1WTGpTMTB3Wjh6Yjh5UmpRenhUTzN6QkFPVmJtMzM0a0ZNTDBTS1oyMzc3LU93ZnA5cFFnRFVDcm5EODhRNlJLdV9mLUZnWERNaXotTm1DWHBsV2FrOGFKaVNZNGZjRlBWcWN2RWFac3VaU0xNTHNlR3RMVW5YVHY0bU92QWhnVzNTRnNmdGx1b2xreXBva2RiTUlIU3dVQ0VWT3lmdkw4dmFIMkZDelF0UFE0d0E2MkhZdXYxd3FhVTlzeEZIbEc0ZFc2S3FXOEg2R3BvVkRQTFVYZDJYdlA3SUYzVnhFUUZ1UHpGdGRDcDZ5OXZwWmpiSlF5a3MzMHd1bGlXY1BzLUg1Q1dqeWs2ZUpYbElKZl81QktQRUdQcWpOYncifQ\",\"signature\":\"jfpnAAv7TuZmhpiu06Go_RDZUl2CFHCTts-4anHfNtJ915UkCIFnMgZbuhh3GV6zz2aAy3x2k0X34HYTvVZVrX8NgsNM-NSKhelcbQZiFmIBaTOxFerwW-Lbz8LxE7cpwhMsegXLyJ0P9_sY-MTxC3tXy5KoIIuLaYbzTbPdpxFxIszNWwijT1wxB2gTK-5eZBlmrAn3LsihIUWBf3_KXWnA9yKhdSuO84VbZxjeBQBkx4Gi4e9eqfdDiqfNyQOUGiOtt8CpDot5V8mVRNoRHfm_YBvnY2JVTEG9Dla7GiEXJjGWSqqcU59gDbfohLQ_-SluJImjhZVj3fdT4hIZxg\"}";
        final String CHANGE_KEY_RESPONSE_BODY_1 = "{" + System.lineSeparator() +
                "  \"key\": {" + System.lineSeparator() +
                "    \"kty\": \"RSA\"," + System.lineSeparator() +
                "    \"n\": \"tcUdHFpKE4_12-NmNqI-4zst1aTJslpMIAieuiKAxpMiE8awiuZF-TqNYZSpaVPCjHL4Np6qfjFejkP33gN6lMIK53PeikN5AaOtPSemoX0eBAXkJqb34YZ04D3WpNHgXfunNcATzq3i88HRsldq-9QYRB6GfVSF7PSwBK6DJjNa_4HD7Mya0w5AGiQOET8qV8GkUCv4eNWUG__V3rhF0hPaO-E2p0iKyaYyIBHF1nHk8WiNqlRo8YdffgEIePXDoW-cQVZtIRl9fuNRzDAX67xHBcEPrCM6PI8XN_Txjh6YynyXojCZ102Yzs6_UWNqQzC_V0glYqAycUUHREVOJw\"," + System.lineSeparator() +
                "    \"e\": \"AQAB\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"contact\": [" + System.lineSeparator() +
                "    \"mailto:admin@anexample.com\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"initialIp\": \"10.77.77.1\"," + System.lineSeparator() +
                "  \"createdAt\": \"2019-07-16T18:34:15Z\"," + System.lineSeparator() +
                "  \"status\": \"valid\"" + System.lineSeparator() +
                "}" + System.lineSeparator();
        final String CHANGE_KEY_REPLAY_NONCE_1 = "taroT_9EWZxd3CTvF_SqM668S0Zen8GMFA6ashC_kNXpV_Q";

        final String QUERY_ACCT_REQUEST_BODY_2 = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMTUiLCJub25jZSI6InRhcm9UXzlFV1p4ZDNDVHZGX1NxTTY2OFMwWmVuOEdNRkE2YXNoQ19rTlhwVl9RIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvYWNjdC8xNSJ9\",\"payload\":\"\",\"signature\":\"WD-dG54NEs9xNDOpIdCRkJlXIdxDBd4NxcIhAtlsVyExsCfssOpMfTqzD2V4cFPYY6pchpC-OLb8E4soqhaRChuPPeUPOGyZNNY-NQohAb2mydJ_VC8Aw7oTOJEnP_Md5Aj_tDagG3XiyanA57Y1TdBkjoYBnOaUn0XF957R_yd36Paayi_VNNXIiDW-OgCLlISOhgBplCl9YUfX98a0E8FsdwMJ-rNNOm221jG2HWYqH4FkIBJXnoNQ2wjp-s0yoa7G3dlWaq2lAkapdnRsI461lNFIUUO-RcqWOWkcmzacYz63N21mmmhC5V86fArfYgQQ4m-mG2TnJAcBAr3BVA\"}";
        final String QUERY_ACCT_RESPONSE_BODY_2 = "{" + System.lineSeparator() +
                "  \"key\": {" + System.lineSeparator() +
                "    \"kty\": \"RSA\"," + System.lineSeparator() +
                "    \"n\": \"tcUdHFpKE4_12-NmNqI-4zst1aTJslpMIAieuiKAxpMiE8awiuZF-TqNYZSpaVPCjHL4Np6qfjFejkP33gN6lMIK53PeikN5AaOtPSemoX0eBAXkJqb34YZ04D3WpNHgXfunNcATzq3i88HRsldq-9QYRB6GfVSF7PSwBK6DJjNa_4HD7Mya0w5AGiQOET8qV8GkUCv4eNWUG__V3rhF0hPaO-E2p0iKyaYyIBHF1nHk8WiNqlRo8YdffgEIePXDoW-cQVZtIRl9fuNRzDAX67xHBcEPrCM6PI8XN_Txjh6YynyXojCZ102Yzs6_UWNqQzC_V0glYqAycUUHREVOJw\"," + System.lineSeparator() +
                "    \"e\": \"AQAB\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"contact\": [" + System.lineSeparator() +
                "    \"mailto:admin@anexample.com\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"initialIp\": \"10.77.77.1\"," + System.lineSeparator() +
                "  \"createdAt\": \"2019-07-16T18:34:15Z\"," + System.lineSeparator() +
                "  \"status\": \"valid\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String QUERY_ACCT_REPLAY_NONCE_2 = "zincUdT4h9977dwelONIhrRAY0y4eNr8Egi4RnxGruD__BM";

        final String CHANGE_KEY_RESPONSE_BODY_2 = "{" + System.lineSeparator() +
                "  \"key\": {" + System.lineSeparator() +
                "    \"kty\": \"EC\"," + System.lineSeparator() +
                "    \"crv\": \"P-256\"," + System.lineSeparator() +
                "    \"x\": \"oFHd02a_U5NKSa2PJ6WINJULW6yf1ulD1E0k4kFaND8\"," + System.lineSeparator() +
                "    \"y\": \"IuWTLWr2LVgFImwyL4iFWmXnOgnrvAtoQI24zmCVWxQ\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"contact\": [" + System.lineSeparator() +
                "    \"mailto:admin@anexample.com\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"initialIp\": \"10.77.77.1\"," + System.lineSeparator() +
                "  \"createdAt\": \"2019-07-16T18:34:15Z\"," + System.lineSeparator() +
                "  \"status\": \"valid\"" + System.lineSeparator() +
                "}" + System.lineSeparator();
        final String CHANGE_KEY_REPLAY_NONCE_2 = "taroHhqe8NYqAP4AbuPA7eJ28zwxVhX1mLJKVmT3GDpRyxk";

        final String QUERY_ACCT_RESPONSE_BODY_3 = "{" + System.lineSeparator() +
                "  \"key\": {" + System.lineSeparator() +
                "    \"kty\": \"EC\"," + System.lineSeparator() +
                "    \"crv\": \"P-256\"," + System.lineSeparator() +
                "    \"x\": \"oFHd02a_U5NKSa2PJ6WINJULW6yf1ulD1E0k4kFaND8\"," + System.lineSeparator() +
                "    \"y\": \"IuWTLWr2LVgFImwyL4iFWmXnOgnrvAtoQI24zmCVWxQ\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"contact\": [" + System.lineSeparator() +
                "    \"mailto:admin@anexample.com\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"initialIp\": \"10.77.77.1\"," + System.lineSeparator() +
                "  \"createdAt\": \"2019-07-16T18:34:15Z\"," + System.lineSeparator() +
                "  \"status\": \"valid\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String QUERY_ACCT_REPLAY_NONCE_3 = "zincDJqwmTm91qlWCUF_rZVHkFLmKkwsfC6RIi3v2qDuMpI";


        final String DIRECTORY_RESPONSE_BODY_2 = "{" + System.lineSeparator() +
                "  \"QITnD3KQgok\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator() +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator() +
                "  \"meta\": {" + System.lineSeparator() +
                "    \"caaIdentities\": [" + System.lineSeparator() +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator() +
                "    ]," + System.lineSeparator() +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator() +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator() +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator() +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator() +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String NEW_NONCE_RESPONSE_2 = "taroqEiLet3GDdD7tfNXg31kPXlnghRxH8DH_zb54VceySE";

        final String QUERY_ACCT_REQUEST_BODY_4 = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJ0UnJDWmNjVEZlaVliZ1pHYjhGeXZQcW1PdDhzRVRzOWdOckhmS09JV01HMDNOeU1KdmY5eFFYMnJsR1BRb3F0akdjM2hMY1Y5V1FQVjV4YXYxRmZXMDZhU3I1ZGU3QXVhRDBQai1HLVZzVkl4TWVqQWF4Nkh4ODRvdnVwZXg0WEFOak5YVzk0U1RzaEtDQTVJckRqYzB3VEtiaERYd0x2SmMzdnBBbFIyOHREZkd3Tk9NdzZ2S2ZGTy16ZXI2V3AxMlozdTQ3anI1Zkk1OWhkRnhkRVktVXFNd2xQQ2RjUjlzYnhGcDRocmlFejYwZUk4XzRoM3RBTldwM0FIN2VhM25zWFAtZnNPbmZGcXI4a1lqX0pBNnBDZFVGN2xRYVBqVTljRGU3eEcydk00MlNxam4xLVRCaFdQaVBldVNDdVBxVjlzMTJhLS1VZm5JT1h3aV9ZOFEifSwibm9uY2UiOiJ0YXJvcUVpTGV0M0dEZEQ3dGZOWGczMWtQWGxuZ2hSeEg4REhfemI1NFZjZXlTRSIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL25ldy1hY2N0In0\",\"payload\":\"eyJvbmx5UmV0dXJuRXhpc3RpbmciOnRydWV9\",\"signature\":\"bzKtJjljhaduL8HBZWRJszXmvFWWRx92FTBOjjTm6N7az2OO1H57JZh3QC91qkXoA9DL1MAFDTGNYdpbaXJjSFLv1pR8cze7WT7YwTbpJR5KkK_8eX9yeqtBVN10LquOW5h9rsjpKltOnqbOMUm5DxlrKGaq3tRAspS_d2nhLSnWusLhWSCZmhIzLWt0RYAe8dHNUQslTRpBgtGJh043oK2ATvacsG6d5odSLydWMAJ0VDXerdAd8OlDf92wFWsktQ5wpJP_akmsyKf25ltfHkCV8aBwNoTaUD-NEHKnkAySEekinSnAkU6p2gBMiBGOLWx29yk4cwNSLY-3Q0HCSg\"}";

        final String QUERY_ACCT_RESPONSE_BODY_4 = "";

        final String QUERY_ACCT_REPLAY_NONCE_4 = "zinczbEJm6qqVs5WKmsLutzywkaDZA7OJB4YUPQclWu421o";

        final String ACCT_PATH_2 = "/acme/acct/16";
        final String ACCT_LOCATION_2 = "http://localhost:4001" + ACCT_PATH_2;

        final String CHANGE_KEY_RESPONSE_BODY_3 = "{" + System.lineSeparator() +
                "  \"type\": \"urn:ietf:params:acme:error:malformed\"," + System.lineSeparator() +
                "  \"detail\": \"New key is already in use for a different account\"," + System.lineSeparator() +
                "  \"status\": 409" + System.lineSeparator() +
                "}" + System.lineSeparator();
        final String CHANGE_KEY_REPLAY_NONCE_3 = "taroB0hwHnLlKJUeBu0AnphMWEHyk6NkFsC2VzRNYxUVy2E";

        return new AcmeMockServerBuilder(server)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY_1)
                .addNewNonceResponse(NEW_NONCE_RESPONSE_1)
                .addNewAccountRequestAndResponse(QUERY_ACCT_REQUEST_BODY_1, QUERY_ACCT_RESPONSE_BODY_1, QUERY_ACCT_REPLAY_NONCE_1, ACCT_LOCATION, 200)
                .addChangeKeyRequestAndResponse(CHANGE_KEY_REQUEST_BODY_1, CHANGE_KEY_RESPONSE_BODY_1, CHANGE_KEY_REPLAY_NONCE_1, 200)
                .updateAccountRequestAndResponse(QUERY_ACCT_REQUEST_BODY_2, QUERY_ACCT_RESPONSE_BODY_2, QUERY_ACCT_REPLAY_NONCE_2, ACCT_PATH, 200)
                .addChangeKeyRequestAndResponse("", CHANGE_KEY_RESPONSE_BODY_2, CHANGE_KEY_REPLAY_NONCE_2, 200)
                .updateAccountRequestAndResponse("", QUERY_ACCT_RESPONSE_BODY_3, QUERY_ACCT_REPLAY_NONCE_3, ACCT_PATH, 200)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY_2)
                .addNewNonceResponse(NEW_NONCE_RESPONSE_2)
                .addNewAccountRequestAndResponse(QUERY_ACCT_REQUEST_BODY_4, QUERY_ACCT_RESPONSE_BODY_4, QUERY_ACCT_REPLAY_NONCE_4, ACCT_LOCATION_2, 200)
                .addChangeKeyRequestAndResponse("", CHANGE_KEY_RESPONSE_BODY_3, CHANGE_KEY_REPLAY_NONCE_3, 409)
                .build();
    }

    private ClientAndServer setupTestGetMetadata() {

        // set up a mock Let's Encrypt server
        final String DIRECTORY_RESPONSE_BODY_1 = "{" + System.lineSeparator()  +
                "  \"JDkpnLkaC1Q\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator()  +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator()  +
                "  \"meta\": {" + System.lineSeparator()  +
                "    \"caaIdentities\": [" + System.lineSeparator()  +
                "      \"happy-hacker-ca.invalid\"," + System.lineSeparator()  +
                "      \"happy-hacker2-ca.invalid\"" + System.lineSeparator()  +
                "    ]," + System.lineSeparator()  +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator()  +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"," + System.lineSeparator()  +
                "    \"externalAccountRequired\": true" + System.lineSeparator()  +
                "  }," + System.lineSeparator()  +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator()  +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator()  +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator()  +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator()  +
                "}";

        final String DIRECTORY_RESPONSE_BODY_2 = "{" + System.lineSeparator() +
                "  \"LRkPnZpS4yE\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator() +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator() +
                "  \"meta\": {" + System.lineSeparator() +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator() +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator() +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator() +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String DIRECTORY_RESPONSE_BODY_3 = "{" + System.lineSeparator() +
                "  \"N6HzXUZ-eWI\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator() +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator() +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator() +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator() +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator() +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        return new AcmeMockServerBuilder(server)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY_1)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY_2)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY_3)
                .build();
    }

    private AcmeAccount populateBasicAccount(String alias) throws Exception{
        AcmeAccount account = populateBasicBuilder()
                .setKey(aliasToCertificateMap.get(alias), aliasToPrivateKeyMap.get(alias))
                .build();
        return account;
    }

    private AcmeAccount populateAccount(String alias) throws Exception{
        AcmeAccount account = populateBuilder()
                .setKey(aliasToCertificateMap.get(alias), aliasToPrivateKeyMap.get(alias))
                .build();
        return account;
    }
}
