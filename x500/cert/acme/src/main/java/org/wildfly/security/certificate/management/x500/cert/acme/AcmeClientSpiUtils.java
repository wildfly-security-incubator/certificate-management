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

import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonString;
import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.certificate.management.asn1.DERDecoder;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.IDN;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.util.LinkedHashSet;
import java.util.Locale;

import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.ALG;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.BASE64_URL;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.DETAIL;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.JWK;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.PAYLOAD;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.PROTECTED;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.SIGNATURE;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.SUBPROBLEMS;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.TITLE;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.TYPE;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.URL;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.base64UrlEncode;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.getJwk;
import static org.wildfly.security.certificate.management.x500.cert.acme.CertMgmtMessages.acme;

/**
 * Methods shared by AcmeClientSpi and AsyncAcmeClientSpi
 */
public class AcmeClientSpiUtils {

    private static final int[] CONTENT_TYPE_DELIMS = new int[] {';', '='};
    private static final String CHARSET = "charset";
    private static final String UTF_8 = "utf-8";
    static final int MAX_RETRIES = 10;
    static final JsonObject EMPTY_PAYLOAD = Json.createObjectBuilder().build();

    public static String getProblemMessage(JsonObject jsonResponse) {
        String type = getOptionalJsonString(jsonResponse, TYPE);
        String detail = getOptionalJsonString(jsonResponse, DETAIL);
        String title = getOptionalJsonString(jsonResponse, TITLE);
        String problemMessage = null;
        if (detail != null) {
            problemMessage = detail;
        } else if (title != null) {
            problemMessage = title;
        } else if (type != null) {
            problemMessage = type;
        }
        return problemMessage;
    }


    public static String getOptionalJsonString(JsonObject jsonObject, String name) {
        JsonString value = jsonObject.getJsonString(name);
        if (value == null) {
            return null;
        }
        return value.getString();
    }

    public static String getProblemMessages(JsonObject errorResponse) {
        StringBuilder problemMessages = new StringBuilder();
        String mainProblem = AcmeClientSpiUtils.getProblemMessage(errorResponse);
        if (mainProblem != null) {
            problemMessages.append(AcmeClientSpiUtils.getProblemMessage(errorResponse));
        }
        JsonArray subproblems = errorResponse.getJsonArray(SUBPROBLEMS);
        if (subproblems != null && !subproblems.isEmpty()) {
            problemMessages.append(":");
            for (JsonObject subproblem : subproblems.getValuesAs(JsonObject.class)) {
                problemMessages.append("\n").append(AcmeClientSpiUtils.getProblemMessage(subproblem));
            }
        }
        return problemMessages.toString();
    }



    public static void skipDelims(CodePointIterator di, CodePointIterator cpi, int... delims) throws AcmeException {
        while ((!di.hasNext()) && cpi.hasNext()) {
            if (!isDelim(cpi.next(), delims)) {
                throw acme.invalidContentTypeFromAcmeServer();
            }
        }
    }

    public static boolean isDelim(int c, int... delims) {
        for (int delim : delims) {
            if (delim == c) {
                return true;
            }
        }
        return false;
    }

    public static LinkedHashSet<String> getDomainNames(String[] domainNames) throws AcmeException {
        if (domainNames.length == 0) {
            throw acme.domainNamesIsEmpty();
        }
        final LinkedHashSet<String> domainNamesSet = new LinkedHashSet<>();
        for (String domainName : domainNames) {
            domainNamesSet.add(getSanitizedDomainName(domainName));
        }
        return domainNamesSet;
    }
    public static String getSanitizedDomainName(String domainName) throws AcmeException {
        if (domainName == null) {
            throw acme.domainNameIsNull();
        }
        domainName = IDN.toASCII(domainName.trim());
        return domainName.toLowerCase(Locale.ROOT);
    }



    public static boolean checkContentType(String contentType, String expectedMediaType) throws AcmeException {
        if (contentType == null) {
            return false;
        }
        CodePointIterator cpi = CodePointIterator.ofString(contentType);
        CodePointIterator di = cpi.delimitedBy(CONTENT_TYPE_DELIMS);
        String mediaType = di.drainToString().trim();
        AcmeClientSpiUtils.skipDelims(di, cpi, CONTENT_TYPE_DELIMS);
        while (di.hasNext()) {
            String parameter = di.drainToString().trim();
            AcmeClientSpiUtils.skipDelims(di, cpi, CONTENT_TYPE_DELIMS);
            if (parameter.equalsIgnoreCase(CHARSET)) {
                String value = di.drainToString().trim();
                if (!value.equalsIgnoreCase(UTF_8)) {
                    return false;
                }
            }
        }
        return mediaType.equalsIgnoreCase(expectedMediaType);
    }

    public static String getEncodedProtectedHeader(String algHeader, PublicKey publicKey, String resourceUrl) {
        JsonObject protectedHeader = Json.createObjectBuilder()
                .add(ALG, algHeader)
                .add(JWK, getJwk(publicKey, algHeader))
                .add(URL, resourceUrl)
                .build();
        return getEncodedJson(protectedHeader);
    }

    public static String getEncodedJson(JsonObject jsonObject) {
        return CodePointIterator.ofString(jsonObject.toString()).asUtf8().base64Encode(BASE64_URL, false).drainToString();
    }

    public static String getEncodedSignature(PrivateKey privateKey, Signature signature, String encodedProtectedHeader, String encodedPayload) throws AcmeException {
        final byte[] signatureBytes;
        try {
            signature.update((encodedProtectedHeader + "." + encodedPayload).getBytes(StandardCharsets.UTF_8));
            signatureBytes = signature.sign();
            if (privateKey instanceof ECPrivateKey) {
                // need to convert the DER encoded signature to concatenated bytes
                DERDecoder derDecoder = new DERDecoder(signatureBytes);
                derDecoder.startSequence();
                byte[] r = derDecoder.drainElementValue();
                byte[] s = derDecoder.drainElementValue();
                derDecoder.endSequence();
                int rLength = r.length;
                int sLength = s.length;
                int rActual = rLength;
                int sActual = sLength;
                while (rActual > 0 && r[rLength - rActual] == 0) {
                    rActual--;
                }
                while (sActual > 0 && s[sLength - sActual] == 0) {
                    sActual--;
                }
                int rawLength = Math.max(rActual, sActual);
                int signatureByteLength = getECSignatureByteLength(signature.getAlgorithm());
                rawLength = Math.max(rawLength, signatureByteLength / 2);
                byte[] concatenatedSignatureBytes = new byte[rawLength * 2];
                System.arraycopy(r, rLength - rActual, concatenatedSignatureBytes, rawLength - rActual, rActual);
                System.arraycopy(s, sLength - sActual, concatenatedSignatureBytes, 2 * rawLength - sActual, sActual);
                return base64UrlEncode(concatenatedSignatureBytes);
            }
            return base64UrlEncode(signatureBytes);
        } catch (SignatureException e) {
            throw acme.unableToCreateAcmeSignature(e);
        }
    }

    private static int getECSignatureByteLength(String signatureAlgorithm) throws AcmeException {
        switch(signatureAlgorithm) {
            case "SHA256withECDSA":
                return 64;
            case "SHA384withECDSA":
                return 96;
            case "SHA512withECDSA":
                return 132;
            default:
                throw acme.unsupportedAcmeAccountSignatureAlgorithm(signatureAlgorithm);
        }
    }


    public static String getEncodedSignature(PrivateKey privateKey, String signatureAlgorithm, String encodedProtectedHeader, String encodedPayload) throws AcmeException {
        try {
            Signature signature = Signature.getInstance(signatureAlgorithm);
            signature.initSign(privateKey);
            return getEncodedSignature(privateKey, signature, encodedProtectedHeader, encodedPayload);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw acme.unableToCreateAcmeSignature(e);
        }
    }


    public static JsonObject getJws(String encodedProtectedHeader, String encodedPayload, String encodedSignature) {
        return Json.createObjectBuilder()
                .add(PROTECTED, encodedProtectedHeader)
                .add(PAYLOAD, encodedPayload)
                .add(SIGNATURE, encodedSignature)
                .build();
    }

    public static InputStream getConvertedInputStream(InputStream inputStream) throws IOException {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
            String currentLine;
            while ((currentLine = reader.readLine()) != null) {
                // ignore any blank lines to avoid parsing issues on IBM JDK
                if (! currentLine.trim().isEmpty()) {
                    sb.append(currentLine + System.lineSeparator());
                }
            }
        }
        return new ByteArrayInputStream(sb.toString().getBytes(StandardCharsets.UTF_8));
    }
}
