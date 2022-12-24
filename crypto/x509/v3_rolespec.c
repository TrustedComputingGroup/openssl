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
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include "ext_dat.h"
#include "x509_local.h"

ASN1_SEQUENCE(ROLE_SPEC_CERT_ID) = {
    ASN1_EXP(ROLE_SPEC_CERT_ID, roleName, GENERAL_NAME, 0),
    ASN1_EXP(ROLE_SPEC_CERT_ID, roleCertIssuer, GENERAL_NAME, 1),
    ASN1_IMP_OPT(ROLE_SPEC_CERT_ID, roleCertSerialNumber, ASN1_INTEGER, 2),
    ASN1_IMP_SEQUENCE_OF_OPT(ROLE_SPEC_CERT_ID, roleCertLocator, GENERAL_NAME, 3),
} ASN1_SEQUENCE_END(ROLE_SPEC_CERT_ID)

IMPLEMENT_ASN1_FUNCTIONS(ROLE_SPEC_CERT_ID)

ASN1_ITEM_TEMPLATE(ROLE_SPEC_CERT_ID_SYNTAX) =
    ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, ROLE_SPEC_CERT_ID_SYNTAX, ROLE_SPEC_CERT_ID)
ASN1_ITEM_TEMPLATE_END(ROLE_SPEC_CERT_ID_SYNTAX)

IMPLEMENT_ASN1_FUNCTIONS(ROLE_SPEC_CERT_ID_SYNTAX)

// This was copied from crypto/x509/x_attrib.c
static int ASN1_INTEGER_print_bio(BIO *bio, const ASN1_INTEGER *num)
{
    BIGNUM *num_bn;
    int result = 0;
    char *hex;

    num_bn = ASN1_INTEGER_to_BN(num, NULL);
    if (num_bn == NULL)
        return -1;
    if ((hex = BN_bn2hex(num_bn))) {
        result = BIO_write(bio, "0x", 2) > 0;
        result = result && BIO_write(bio, hex, strlen(hex)) > 0;
        OPENSSL_free(hex);
    }
    BN_free(num_bn);

    return result;
}

static int i2r_ROLE_SPEC_CERT_ID(X509V3_EXT_METHOD *method,
                                 ROLE_SPEC_CERT_ID *rscid,
                                 BIO *out, int indent)
{
    BIO_printf(out, "%*sRole Name: ", indent, "");
    GENERAL_NAME_print(out, rscid->roleName);
    BIO_puts(out, "\n");
    BIO_printf(out, "%*sRole Certificate Issuer: ", indent, "");
    GENERAL_NAME_print(out, rscid->roleCertIssuer);
    if (rscid->roleCertSerialNumber) {
        BIO_puts(out, "\n");
        BIO_printf(out, "%*sRole Certificate Serial Number: ", indent, "");
        ASN1_INTEGER_print_bio(out, rscid->roleCertSerialNumber);
    }
    if (rscid->roleCertLocator) {
        BIO_puts(out, "\n");
        BIO_printf(out, "%*sRole Certificate Locator:\n", indent, "");
        ossl_print_gens(out, rscid->roleCertLocator, indent);
    }
    BIO_puts(out, "\n");
    return 1; 
}

static int i2r_ROLE_SPEC_CERT_ID_SYNTAX(X509V3_EXT_METHOD *method,
                                        ROLE_SPEC_CERT_ID_SYNTAX *rscids,
                                        BIO *out, int indent)
{
    ROLE_SPEC_CERT_ID *rscid;
    int i;
    for (i = 0; i < sk_ROLE_SPEC_CERT_ID_num(rscids); i++) {
        if (i > 0)
            BIO_puts(out, "\n");
        BIO_printf(out, "%*sRole Specification Certificate Identifier #%d:\n", indent, "", i+1);
        rscid = sk_ROLE_SPEC_CERT_ID_value(rscids, i);
        if (i2r_ROLE_SPEC_CERT_ID(method, rscid, out, indent + 4) != 1) {
            return 0;
        }
    }
    return 1;
}

const X509V3_EXT_METHOD ossl_v3_role_spec_cert_identifier = {
    NID_role_spec_cert_identifier, X509V3_EXT_MULTILINE,
    ASN1_ITEM_ref(ROLE_SPEC_CERT_ID_SYNTAX),
    0, 0, 0, 0,
    0, 0,
    0,
    0,
    (X509V3_EXT_I2R)i2r_ROLE_SPEC_CERT_ID_SYNTAX,
    NULL,
    NULL
};