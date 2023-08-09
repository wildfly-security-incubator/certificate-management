/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

import java.time.Instant;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;
import org.jboss.logging.annotations.ValidIdRange;
import org.jboss.logging.annotations.ValidIdRanges;

/**
 * Log messages and exceptions for Elytron.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@MessageLogger(projectCode = "CERT_MGMT", length = 5)
@ValidIdRanges({
    @ValidIdRange(min = 2000, max = 2999)
})
interface CertMgmtMessages extends BasicLogger {

    CertMgmtMessages log = Logger.getMessageLogger(CertMgmtMessages.class, "org.wildfly.security.certificate.management");
    CertMgmtMessages acme = Logger.getMessageLogger(CertMgmtMessages.class, "org.wildfly.security.certificate.management.x500.cert.acme");

    @Message(id = 2000, value = "Unable to determine key size")
    IllegalArgumentException unableToDetermineKeySize();

    @Message(id = 2001, value = "Unable to determine default compatible signature algorithm name for key algorithm name \"%s\"")
    IllegalArgumentException unableToDetermineDefaultCompatibleSignatureAlgorithmName(String keyAlgorithmName);

    @Message(id = 2002, value = "Failed to generate ACME account key pair")
    IllegalArgumentException acmeAccountKeyPairGenerationFailed(@Cause Exception cause);

    @Message(id = 2003, value = "No ACME server URL given")
    IllegalArgumentException noAcmeServerUrlGiven();

    @Message(id = 2004, value = "Unsupported ACME account signature algorithm \"%s\"")
    IllegalArgumentException unsupportedAcmeAccountSignatureAlgorithm(String signatureAlgorithm);

    @Message(id = 2005, value = "Unable to create ACME signature")
    IllegalArgumentException unableToCreateAcmeSignature(@Cause Exception cause);

    @Message(id = 2006, value = "Unable to retrieve ACME server directory URLs")
    AcmeException unableToRetrieveAcmeServerDirectoryUrls(@Cause Exception cause);

    @Message(id = 2007, value = "No nonce provided by ACME server")
    AcmeException noNonceProvidedByAcmeServer();

    @Message(id = 2008, value = "No %s location URL provided by ACME server")
    AcmeException noLocationUrlProvidedByAcmeServer(String urlType);

    @Message(id = 2009, value = "Unable to obtain new nonce from ACME server")
    AcmeException unableToObtainNewNonceFromAcmeServer();

    @Message(id = 2010, value = "Unable to obtain JSON response from ACME server")
    AcmeException unableToObtainJsonResponseFromAcmeServer(@Cause Exception cause);

    @Message(id = 2011, value = "Unexpected HTTP status code in response from ACME server \"%d\": \"%s\"")
    AcmeException unexpectedResponseCodeFromAcmeServer(int responseCode, String responseMessage);

    @Message(id = 2012, value = "Bad ACME replay nonce, maximum retries attempted")
    AcmeException badAcmeNonce();

    @Message(id = 2013, value = "Unexpected content type in response from ACME server \"%s\"")
    AcmeException unexpectedContentTypeFromAcmeServer(String contentType);

    @Message(id = 2014, value = "Invalid content type in response from ACME server")
    AcmeException invalidContentTypeFromAcmeServer();

    @Message(id = 2015, value = "Domain name is null")
    AcmeException domainNameIsNull();

    @Message(id = 2016, value = "Domain names is empty")
    AcmeException domainNamesIsEmpty();

    @Message(id = 2017, value = "No certificate URL provided by ACME server")
    AcmeException noCertificateUrlProvidedByAcmeServer();

    @Message(id = 2018, value = "No certificate will be issued by the ACME server")
    AcmeException noCertificateWillBeIssuedByAcmeServer();

    @Message(id = 2019, value = "Unable to get encoded form of certificate to be revoked")
    AcmeException unableToGetEncodedFormOfCertificateToBeRevoked(@Cause Exception cause);

    @Message(id = 2020, value = "Unable to determine key authorization string")
    AcmeException unableToDetermineKeyAuthorizationString(@Cause Exception cause);

    @Message(id = 2021, value = "Challenge response failed validation by the ACME server")
    AcmeException challengeResponseFailedValidationByAcmeServer();

    @Message(id = 2022, value = "Unable to download certificate chain from ACME server")
    AcmeException unableToDownloadCertificateChainFromAcmeServer(@Cause Exception cause);

    @Message(id = 2023, value = "ACME account does not exist")
    AcmeException acmeAccountDoesNotExist();

    @Message(id = 2024, value = "User action required since the ACME server's terms of service have changed, visit \"%s\" for details")
    AcmeException userActionRequired(String url);

    @Message(id = 2025, value = "Rate limit has been exceeded, try again after \"%s\"")
    AcmeException rateLimitExceededTryAgainLater(Instant instant);

    @Message(id = 2026, value = "Rate limit has been exceeded")
    AcmeException rateLimitExceeded();

    @Message(id = 2027, value = "Resource not supported by the ACME server \"%s\"")
    AcmeException resourceNotSupportedByAcmeServer(String resource);

    @Message(id = 2028, value = "Unsupported ACME account public key type \"%s\"")
    IllegalArgumentException unsupportedAcmeAccountPublicKeyType(String keyAlgorithmName);

    @Message(id = 2029, value = "Unable to determine curve parameter from alg header \"%s\"")
    IllegalArgumentException unableToDetermineCurveParameterFromAlgHeader(String algHeader);

    @Message(id = 2030, value = "No ACME server staging URL given")
    AcmeException noAcmeServerStagingUrlGiven();
}
