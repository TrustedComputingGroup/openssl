/*
 * Copyright 1999-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/asn1t.h>
#include <openssl/x509v3.h>

int i2r_ISSUER_SERIAL(X509V3_EXT_METHOD *method,
                      ISSUER_SERIAL *iss,
                      BIO *out, int indent);

static int i2r_AUTHORITY_ATTRIBUTE_ID_SYNTAX(X509V3_EXT_METHOD *method,
                                             AUTHORITY_ATTRIBUTE_ID_SYNTAX *aids,
                                             BIO *out, int indent)
{
    int i;
    ISSUER_SERIAL *aid;
    for (i = 0; i < sk_ISSUER_SERIAL_num(aids); i++) {
        BIO_printf(out, "%*sIssuer-Serials:\n", indent, "");
        aid = sk_ISSUER_SERIAL_value(aids, i);
        i2r_ISSUER_SERIAL(method, aid, out, indent + 4);
        BIO_puts(out, "\n");
    }
    return 1;
}

ASN1_ITEM_TEMPLATE(AUTHORITY_ATTRIBUTE_ID_SYNTAX) =
        ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, AUTHORITY_ATTRIBUTE_ID_SYNTAX, ISSUER_SERIAL)
ASN1_ITEM_TEMPLATE_END(AUTHORITY_ATTRIBUTE_ID_SYNTAX)

IMPLEMENT_ASN1_FUNCTIONS(AUTHORITY_ATTRIBUTE_ID_SYNTAX)

const X509V3_EXT_METHOD ossl_v3_authority_attribute_identifier = {
    NID_authority_attribute_identifier, X509V3_EXT_MULTILINE,
    ASN1_ITEM_ref(AUTHORITY_ATTRIBUTE_ID_SYNTAX),
    0, 0, 0, 0,
    0,
    0,
    0, 0,
    (X509V3_EXT_I2R)i2r_AUTHORITY_ATTRIBUTE_ID_SYNTAX,
    0,
    NULL
};