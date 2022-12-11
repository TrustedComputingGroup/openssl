/*
 * Copyright 1999-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/x509v3.h>
#include "ext_dat.h"

static int i2r_IOBO(X509V3_EXT_METHOD *method,
                    GENERAL_NAME *gn, BIO *out,
                    int indent)
{
    BIO_printf(out, "%*s", indent, "");
    GENERAL_NAME_print(out, gn);
    return BIO_puts(out, "\n");
}

const X509V3_EXT_METHOD ossl_v3_issued_on_behalf_of = {
    NID_issued_on_behalf_of, 0, ASN1_ITEM_ref(GENERAL_NAME),
    0, 0, 0, 0,
    0, 0,
    0, 0,
    (X509V3_EXT_I2R)i2r_IOBO,
    0,
    NULL
};
