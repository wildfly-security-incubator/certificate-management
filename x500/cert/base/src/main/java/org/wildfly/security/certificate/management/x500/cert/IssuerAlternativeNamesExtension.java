/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.certificate.management.x500.cert;

import java.util.List;

import org.wildfly.common.Assert;
import org.wildfly.security.certificate.management.asn1.ASN1Encoder;
import org.wildfly.security.certificate.management.x500.GeneralName;
import org.wildfly.security.certificate.management.x500.X500;

/**
 * The issuer alternative names extension as defined by <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.7">RFC 5280 § 4.2.1.7</a>.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class IssuerAlternativeNamesExtension extends X509CertificateExtension {
    private final List<GeneralName> issuerAlternativeNames;

    /**
     * Construct a new instance.
     *
     * @param critical {@code true} to mark this extension critical, {@code false} otherwise
     * @param issuerAlternativeNames the list of alternative names (must not be {@code null})
     */
    public IssuerAlternativeNamesExtension(final boolean critical, final List<GeneralName> issuerAlternativeNames) {
        super(critical);
        Assert.checkNotNullParam("issuerAlternativeNames", issuerAlternativeNames);
        this.issuerAlternativeNames = issuerAlternativeNames;
    }

    public String getId() {
        return X500.OID_CE_ISSUER_ALT_NAME;
    }

    public void encodeTo(final ASN1Encoder encoder) {
        encoder.startSequence();
        for (GeneralName name : issuerAlternativeNames) {
            name.encodeTo(encoder);
        }
        encoder.endSequence();
    }
}
