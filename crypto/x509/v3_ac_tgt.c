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
#include "crypto/asn1.h"

static int i2r_ISSUER_SERIAL(X509V3_EXT_METHOD *method,
                             ISSUER_SERIAL *iss,
                             BIO *out, int indent);
static int i2r_OBJECT_DIGEST_INFO(X509V3_EXT_METHOD *method,
                                  OBJECT_DIGEST_INFO *odi,
                                  BIO *out, int indent);
static int i2r_TARGET_CERT(X509V3_EXT_METHOD *method,
                           TARGET_CERT *tc,
                           BIO *out, int indent);
static int i2r_TARGET(X509V3_EXT_METHOD *method,
                      TARGET *target,
                      BIO *out, int indent);
static int i2r_TARGETING_INFORMATION(X509V3_EXT_METHOD *method,
                                     TARGETING_INFORMATION *tinfo,
                                     BIO *out, int indent);

ASN1_SEQUENCE(ISSUER_SERIAL) = {
    ASN1_SIMPLE(ISSUER_SERIAL, issuer, GENERAL_NAMES),
    ASN1_SIMPLE(ISSUER_SERIAL, serial, ASN1_INTEGER),
    ASN1_OPT(ISSUER_SERIAL, issuerUID, ASN1_BIT_STRING),
} ASN1_SEQUENCE_END(ISSUER_SERIAL)

ASN1_SEQUENCE(OBJECT_DIGEST_INFO) = {
    ASN1_SIMPLE(OBJECT_DIGEST_INFO, digestedObjectType, ASN1_ENUMERATED),
    ASN1_OPT(OBJECT_DIGEST_INFO, otherObjectTypeID, ASN1_OBJECT),
    ASN1_SIMPLE(OBJECT_DIGEST_INFO, digestAlgorithm, X509_ALGOR),
    ASN1_SIMPLE(OBJECT_DIGEST_INFO, objectDigest, ASN1_BIT_STRING),
} ASN1_SEQUENCE_END(OBJECT_DIGEST_INFO)

ASN1_SEQUENCE(TARGET_CERT) = {
    ASN1_SIMPLE(TARGET_CERT, targetCertificate, ISSUER_SERIAL),
    ASN1_OPT(TARGET_CERT, targetName, GENERAL_NAME),
    ASN1_OPT(TARGET_CERT, certDigestInfo, OBJECT_DIGEST_INFO),
} ASN1_SEQUENCE_END(TARGET_CERT)

ASN1_CHOICE(TARGET) = {
    ASN1_EXP(TARGET, choice.targetName, GENERAL_NAME, 0),
    ASN1_EXP(TARGET, choice.targetGroup, GENERAL_NAME, 1),
    ASN1_IMP(TARGET, choice.targetCert, TARGET_CERT, 2),
} ASN1_CHOICE_END(TARGET)

ASN1_ITEM_TEMPLATE(TARGETS) =
    ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, Targets, TARGET)
ASN1_ITEM_TEMPLATE_END(TARGETS)

ASN1_ITEM_TEMPLATE(TARGETING_INFORMATION) =
    ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, TargetingInformation, TARGETS)
ASN1_ITEM_TEMPLATE_END(TARGETING_INFORMATION)

IMPLEMENT_ASN1_FUNCTIONS(ISSUER_SERIAL)
IMPLEMENT_ASN1_FUNCTIONS(OBJECT_DIGEST_INFO)
IMPLEMENT_ASN1_FUNCTIONS(TARGET_CERT)
IMPLEMENT_ASN1_FUNCTIONS(TARGET)
IMPLEMENT_ASN1_FUNCTIONS(TARGETS)
IMPLEMENT_ASN1_FUNCTIONS(TARGETING_INFORMATION)

static int i2r_ISSUER_SERIAL(X509V3_EXT_METHOD *method,
                             ISSUER_SERIAL *iss,
                             BIO *out, int indent)
{
    if (iss->issuer != NULL) {
        BIO_printf(out, "%*sIssuer Names:\n", indent, "");
        ossl_print_gens(out, iss->issuer, indent);
        BIO_puts(out, "\n");
    }
    if (iss->serial != NULL) {
        BIO_printf(out, "%*sIssuer Serial: ", indent, "");
        if (i2a_ASN1_INTEGER(out, iss->serial) <= 0)
            return 0;
        BIO_puts(out, "\n");
    }
    if (iss->issuerUID != NULL) {
        BIO_printf(out, "%*sIssuer UID: ", indent, "");
        if (i2a_ASN1_STRING(out, iss->issuerUID, V_ASN1_BIT_STRING) <= 0)
            return 0;
        BIO_puts(out, "\n");
    }
    return 1;
}

static int i2r_OBJECT_DIGEST_INFO(X509V3_EXT_METHOD *method,
                           OBJECT_DIGEST_INFO *odi,
                           BIO *out, int indent)
{
    int64_t dot = 0;
    int sig_nid;
    X509_ALGOR *digalg;
    ASN1_STRING *sig;

    if (odi == NULL) {
        ERR_raise(ERR_LIB_ASN1, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    digalg = odi->digestAlgorithm;
    sig = odi->objectDigest;
    if (!ASN1_ENUMERATED_get_int64(&dot, odi->digestedObjectType)) {
        return 0;
    }
    switch (dot) {
    case (ODI_TYPE_PUBLIC_KEY):
        BIO_printf(out, "%*sDigest Type: Public Key\n", indent, "");
        break;
    case (ODI_TYPE_PUBLIC_KEY_CERT):
        BIO_printf(out, "%*sDigest Type: Public Key Certificate\n", indent, "");
        break;
    case (ODI_TYPE_OTHER): {
        BIO_printf(out, "%*sDigest Type: Other\n", indent, "");
        break;
    }
    }
    if (odi->otherObjectTypeID != NULL) {
        BIO_printf(out, "%*sDigest Type Identifier: ", indent, "");
        i2a_ASN1_OBJECT(out, odi->otherObjectTypeID);
        BIO_puts(out, "\n");
    }
    if (BIO_printf(out, "%*sSignature Algorithm: ", indent, "") <= 0)
        return 0;
    if (i2a_ASN1_OBJECT(out, odi->digestAlgorithm->algorithm) <= 0)
        return 0;
    BIO_puts(out, "\n");
    if (BIO_printf(out, "\n%*sSignature Value: ", indent, "") <= 0)
        return 0;
    sig_nid = OBJ_obj2nid(odi->digestAlgorithm->algorithm);
    if (sig_nid != NID_undef) {
        int pkey_nid, dig_nid;
        const EVP_PKEY_ASN1_METHOD *ameth;
        if (OBJ_find_sigid_algs(sig_nid, &dig_nid, &pkey_nid)) {
            ameth = EVP_PKEY_asn1_find(NULL, pkey_nid);
            if (ameth && ameth->sig_print)
                return ameth->sig_print(out, digalg, sig, indent + 4, 0);
        }
    }
    if (BIO_write(out, "\n", 1) != 1)
        return 0;
    if (sig)
        return X509_signature_dump(out, sig, indent + 4);
    return 1;
}

static int i2r_TARGET_CERT(X509V3_EXT_METHOD *method,
                           TARGET_CERT *tc,
                           BIO *out, int indent)
{
    BIO_printf(out, "%*s", indent, "");
    if (tc->targetCertificate != NULL) {
        BIO_puts(out, "Target Certificate:\n");
        i2r_ISSUER_SERIAL(method, tc->targetCertificate, out, indent + 2);
    }
    if (tc->targetName != NULL) {
        // BIO_puts(out, "Target Name: ");
        BIO_printf(out, "%*sTarget Name: ", indent, "");
        GENERAL_NAME_print(out, tc->targetName);
        BIO_puts(out, "\n");
    }
    if (tc->certDigestInfo != NULL) {
        BIO_printf(out, "%*sCertificate Digest Info:\n", indent, "");
        i2r_OBJECT_DIGEST_INFO(method, tc->certDigestInfo, out, indent + 2);
    }
    BIO_puts(out, "\n");
    return 1;
}

static int i2r_TARGET(X509V3_EXT_METHOD *method,
                      TARGET *target,
                      BIO *out, int indent)
{
    switch (target->type) {
    case (TGT_TARGET_NAME):
        BIO_printf(out, "%*sTarget Name: ", indent, "");
        GENERAL_NAME_print(out, target->choice.targetName);
        BIO_puts(out, "\n");
        break;
    case (TGT_TARGET_GROUP):
        BIO_printf(out, "%*sTarget Group: ", indent, "");
        GENERAL_NAME_print(out, target->choice.targetGroup);
        BIO_puts(out, "\n");
        break;
    case (TGT_TARGET_CERT):
        BIO_printf(out, "%*sTarget Cert:\n", indent, "");
        i2r_TARGET_CERT(method, target->choice.targetCert, out, indent + 2);
        break;
    }
    return 1;
}

static int i2r_TARGETS(X509V3_EXT_METHOD *method,
                      TARGETS *targets,
                      BIO *out, int indent)
{
    int i;
    TARGET *target;
    for (i = 0; i < sk_TARGET_num(targets); i++) {
        BIO_printf(out, "%*sTarget:\n", indent, "");
        target = sk_TARGET_value(targets, i);
        i2r_TARGET(method, target, out, indent + 2);
    }
    return 1;
}

static int i2r_TARGETING_INFORMATION(X509V3_EXT_METHOD *method,
                                     TARGETING_INFORMATION *tinfo,
                                     BIO *out, int indent)
{
    int i;
    TARGETS *targets;
    for (i = 0; i < sk_TARGETS_num(tinfo); i++) {
        BIO_printf(out, "%*sTargets:\n", indent, "");
        targets = sk_TARGETS_value(tinfo, i);
        i2r_TARGETS(method, targets, out, indent + 2);
    }
    return 1;
}

const X509V3_EXT_METHOD ossl_v3_targeting_information = {
    NID_target_information, 0, ASN1_ITEM_ref(TARGETING_INFORMATION),
    0, 0, 0, 0,
    0,
    0,
    0, 0,
    (X509V3_EXT_I2R)i2r_TARGETING_INFORMATION,
    0,
    NULL
};