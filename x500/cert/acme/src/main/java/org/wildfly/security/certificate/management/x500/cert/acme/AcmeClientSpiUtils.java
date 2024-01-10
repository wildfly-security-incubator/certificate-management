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

import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonString;
import org.wildfly.common.iteration.CodePointIterator;

import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.DETAIL;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.SUBPROBLEMS;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.TITLE;
import static org.wildfly.security.certificate.management.x500.cert.acme.Acme.TYPE;
import static org.wildfly.security.certificate.management.x500.cert.acme.CertMgmtMessages.acme;

public class AcmeClientSpiUtils {

    private static final int[] CONTENT_TYPE_DELIMS = new int[] {';', '='};
    private static final String CHARSET = "charset";
    private static final String UTF_8 = "utf-8";
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
}
