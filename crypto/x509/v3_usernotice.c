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


ASN1_ITEM_TEMPLATE(USER_NOTICE_SYNTAX) =
    ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, USER_NOTICE_SYNTAX, USERNOTICE)
ASN1_ITEM_TEMPLATE_END(USER_NOTICE_SYNTAX)

IMPLEMENT_ASN1_FUNCTIONS(USER_NOTICE_SYNTAX)

static int i2r_USER_NOTICE_SYNTAX(X509V3_EXT_METHOD *method,
                                  USER_NOTICE_SYNTAX *uns,
                                  BIO *out, int indent)
{
    int i;
    USERNOTICE *unotice;
    for (i = 0; i < sk_USERNOTICE_num(uns); i++) {
        BIO_printf(out, "%*sUser Notices:\n", indent, "");
        unotice = sk_USERNOTICE_value(uns, i);
        print_notice(out, unotice, indent + 2);
        BIO_puts(out, "\n");
    }
    return 1;
}

const X509V3_EXT_METHOD ossl_v3_user_notice = {
    NID_user_notice, 0,
    ASN1_ITEM_ref(USER_NOTICE_SYNTAX),
    0, 0, 0, 0,
    0,
    0,
    0, 0,
    (X509V3_EXT_I2R)i2r_USER_NOTICE_SYNTAX,
    0,
    NULL
};