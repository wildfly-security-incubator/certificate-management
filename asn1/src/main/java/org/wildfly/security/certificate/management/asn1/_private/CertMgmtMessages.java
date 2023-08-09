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

package org.wildfly.security.certificate.management.asn1._private;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;
import org.jboss.logging.annotations.ValidIdRange;
import org.jboss.logging.annotations.ValidIdRanges;
import org.wildfly.security.certificate.management.asn1.ASN1Exception;

/**
 * Log messages and exceptions for Elytron.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@MessageLogger(projectCode = "CERT_MGMT", length = 5)
@ValidIdRanges({
        @ValidIdRange(min = 0, max = 999)
})
public interface CertMgmtMessages extends BasicLogger {

    CertMgmtMessages log = Logger.getMessageLogger(CertMgmtMessages.class, "org.wildfly.security.certificate.management");

    @Message(id = 0, value = "Unable to load OIDs database from properties file")
    IllegalStateException unableToLoadOidsFromPropertiesFile(@Cause Throwable cause);

    @Message(id = 1, value = "Unexpected ASN.1 tag encountered")
    ASN1Exception asnUnexpectedTag();

    @Message(id = 2, value = "No sequence to end")
    IllegalStateException noSequenceToEnd();

    @Message(id = 3, value = "No set to end")
    IllegalStateException noSetToEnd();

    @Message(id = 4, value = "No explicitly tagged element to end")
    IllegalStateException noExplicitlyTaggedElementToEnd();

    @Message(id = 5, value = "Unexpected end of input")
    ASN1Exception asnUnexpectedEndOfInput();

    @Message(id = 6, value = "Invalid number of unused bits")
    ASN1Exception asnInvalidNumberOfUnusedBits();

    @Message(id = 7, value = "Non-zero length encountered for null type tag")
    ASN1Exception asnNonZeroLengthForNullTypeTag();

    @Message(id = 8, value = "Invalid high-tag-number form")
    ASN1Exception asnInvalidHighTagNumberForm();

    @Message(id = 9, value = "Length encoding exceeds 4 bytes")
    ASN1Exception asnLengthEncodingExceeds4bytes();

    @Message(id = 10, value = "Invalid OID character")
    ASN1Exception asnInvalidOidCharacter();

    @Message(id = 11, value = "OID must have at least 2 components")
    ASN1Exception asnOidMustHaveAtLeast2Components();

    @Message(id = 12, value = "Invalid value for first OID component; expected 0, 1, or 2")
    ASN1Exception asnInvalidValueForFirstOidComponent();

    @Message(id = 13, value = "Invalid value for second OID component; expected a value between 0 and 39 (inclusive)")
    ASN1Exception asnInvalidValueForSecondOidComponent();

    @Message(id = 14, value = "Invalid length")
    ASN1Exception asnInvalidLength();

    @Message(id = 15, value = "Unknown tag type: %d")
    ASN1Exception asnUnknownTagType(int type);

    @Message(id = 16, value = "Unexpected character byte for printable string")
    ASN1Exception asnUnexpectedCharacterByteForPrintableString();

    @Message(id = 17, value = "Invalid length encountered for boolean type tag")
    ASN1Exception asnInvalidLengthForBooleanTypeTag();

}