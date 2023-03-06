/*
 * Copyright 1995-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <limits.h>

#include "crypto/ctype.h"
#include "internal/cryptlib.h"
#include <openssl/crypto.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/core_names.h>
#include "internal/dane.h"
#include "crypto/x509.h"
#include "x509_local.h"
#include "x509_acert.h"

/*-
 * Check attribute certificate validity times.
 */
int ossl_x509_check_acert_time(X509_STORE_CTX *ctx, X509_ACERT *acert)
{
    time_t *ptime;
    int i;

    if ((ctx->param->flags & X509_V_FLAG_USE_CHECK_TIME) != 0)
        ptime = &ctx->param->check_time;
    else if ((ctx->param->flags & X509_V_FLAG_NO_CHECK_TIME) != 0)
        return X509_V_OK;
    else
        ptime = NULL;

    i = X509_cmp_time(X509_ACERT_get0_notBefore(acert), ptime);
    if (i == 0)
        return X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD;
    if (i > 0)
        return X509_V_ERR_CERT_NOT_YET_VALID;

    i = X509_cmp_time(X509_ACERT_get0_notAfter(acert), ptime);
    if (i == 0)
        return X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD;
    if (i < 0)
        return X509_V_ERR_CERT_HAS_EXPIRED;

    return X509_V_OK;
}

int ossl_x509_check_acert_exts(X509_ACERT *acert)
{
    int i;
    X509_EXTENSION *time_spec_ext;
    TIME_SPEC *time_spec;

    i = X509_acert_get_ext_by_NID(acert, NID_time_specification, -1);
    if (i >= 0) {
        time_spec_ext = X509_acert_get_ext(acert, i);
        if (time_spec_ext != NULL) {
            time_spec = X509V3_EXT_d2i(time_spec_ext);
            if (time_spec == NULL)
                return X509_V_ERR_INVALID_EXTENSION;
            // TODO: Verify time specification
        }
    }

    return X509_V_OK;
}

int X509_attr_cert_verify(X509_STORE_CTX *ctx, X509_ACERT *acert)
{
    int rc;
    int pki_depth;
    EVP_PKEY *pkey;
    X509 *subj_pkc;


    if (X509_ALGOR_cmp(&acert->sig_alg, &acert->signature) != 0)
        return 0;
    rc = X509_STORE_CTX_verify(ctx);
    if (rc != X509_V_OK)
        return rc;
    pki_depth = sk_X509_num(ctx->chain);
    if (sk_X509_num(ctx->chain) <= 0)
        return 0;
    subj_pkc = sk_X509_value(ctx->chain, 0);
    if ((pkey = X509_get0_pubkey(subj_pkc)) == NULL)
        return X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY;
    rc = ASN1_item_verify(ASN1_ITEM_rptr(X509_ACERT), &acert->sig_alg,
                           &acert->signature, &acert->acinfo, pkey);
    if (rc != 1)
        return X509_V_ERR_CERT_SIGNATURE_FAILURE;

    rc = ossl_x509_check_acert_time(ctx, acert);
    if (rc != X509_V_OK)
        return rc;

    rc = ossl_x509_check_acert_exts(acert);
    if (rc != X509_V_OK)
        return rc;

    return X509_V_OK;
}

// /*-
//  * Check certificate validity times.
//  * If depth >= 0, invoke verification callbacks on error, otherwise just return
//  * the validation status.
//  *
//  * Return 1 on success, d0 otherwise.
//  * Sadly, returns 0 also on internal error in ctx->verify_cb().
//  */
// int ossl_x509_check_cert_time(X509_STORE_CTX *ctx, X509 *x, int depth)
// {
//     time_t *ptime;
//     int i;

//     if ((ctx->param->flags & X509_V_FLAG_USE_CHECK_TIME) != 0)
//         ptime = &ctx->param->check_time;
//     else if ((ctx->param->flags & X509_V_FLAG_NO_CHECK_TIME) != 0)
//         return 1;
//     else
//         ptime = NULL;

//     i = X509_cmp_time(X509_get0_notBefore(x), ptime);
//     if (i >= 0 && depth < 0)
//         return 0;
//     CB_FAIL_IF(i == 0, ctx, x, depth, X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD);
//     CB_FAIL_IF(i > 0, ctx, x, depth, X509_V_ERR_CERT_NOT_YET_VALID);

//     i = X509_cmp_time(X509_get0_notAfter(x), ptime);
//     if (i <= 0 && depth < 0)
//         return 0;
//     CB_FAIL_IF(i == 0, ctx, x, depth, X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD);
//     CB_FAIL_IF(i < 0, ctx, x, depth, X509_V_ERR_CERT_HAS_EXPIRED);
//     return 1;
// }

// int X509_cmp_current_time(const ASN1_TIME *ctm)
// {
//     return X509_cmp_time(ctm, NULL);
// }

// /* returns 0 on error, otherwise 1 if ctm > cmp_time, else -1 */
// int X509_cmp_time(const ASN1_TIME *ctm, time_t *cmp_time)
// {
//     static const size_t utctime_length = sizeof("YYMMDDHHMMSSZ") - 1;
//     static const size_t generalizedtime_length = sizeof("YYYYMMDDHHMMSSZ") - 1;
//     ASN1_TIME *asn1_cmp_time = NULL;
//     int i, day, sec, ret = 0;
// #ifdef CHARSET_EBCDIC
//     const char upper_z = 0x5A;
// #else
//     const char upper_z = 'Z';
// #endif

//     /*-
//      * Note that ASN.1 allows much more slack in the time format than RFC5280.
//      * In RFC5280, the representation is fixed:
//      * UTCTime: YYMMDDHHMMSSZ
//      * GeneralizedTime: YYYYMMDDHHMMSSZ
//      *
//      * We do NOT currently enforce the following RFC 5280 requirement:
//      * "CAs conforming to this profile MUST always encode certificate
//      *  validity dates through the year 2049 as UTCTime; certificate validity
//      *  dates in 2050 or later MUST be encoded as GeneralizedTime."
//      */
//     switch (ctm->type) {
//     case V_ASN1_UTCTIME:
//         if (ctm->length != (int)(utctime_length))
//             return 0;
//         break;
//     case V_ASN1_GENERALIZEDTIME:
//         if (ctm->length != (int)(generalizedtime_length))
//             return 0;
//         break;
//     default:
//         return 0;
//     }

//     /**
//      * Verify the format: the ASN.1 functions we use below allow a more
//      * flexible format than what's mandated by RFC 5280.
//      * Digit and date ranges will be verified in the conversion methods.
//      */
//     for (i = 0; i < ctm->length - 1; i++) {
//         if (!ossl_ascii_isdigit(ctm->data[i]))
//             return 0;
//     }
//     if (ctm->data[ctm->length - 1] != upper_z)
//         return 0;

//     /*
//      * There is ASN1_UTCTIME_cmp_time_t but no
//      * ASN1_GENERALIZEDTIME_cmp_time_t or ASN1_TIME_cmp_time_t,
//      * so we go through ASN.1
//      */
//     asn1_cmp_time = X509_time_adj(NULL, 0, cmp_time);
//     if (asn1_cmp_time == NULL)
//         goto err;
//     if (ASN1_TIME_diff(&day, &sec, ctm, asn1_cmp_time) == 0)
//         goto err;

//     /*
//      * X509_cmp_time comparison is <=.
//      * The return value 0 is reserved for errors.
//      */
//     ret = (day >= 0 && sec >= 0) ? -1 : 1;

//  err:
//     ASN1_TIME_free(asn1_cmp_time);
//     return ret;
// }

// /*
//  * Return 0 if time should not be checked or reference time is in range,
//  * or else 1 if it is past the end, or -1 if it is before the start
//  */
// int X509_cmp_timeframe(const X509_VERIFY_PARAM *vpm,
//                        const ASN1_TIME *start, const ASN1_TIME *end)
// {
//     time_t ref_time;
//     time_t *time = NULL;
//     unsigned long flags = vpm == NULL ? 0 : X509_VERIFY_PARAM_get_flags(vpm);

//     if ((flags & X509_V_FLAG_USE_CHECK_TIME) != 0) {
//         ref_time = X509_VERIFY_PARAM_get_time(vpm);
//         time = &ref_time;
//     } else if ((flags & X509_V_FLAG_NO_CHECK_TIME) != 0) {
//         return 0; /* this means ok */
//     } /* else reference time is the current time */

//     if (end != NULL && X509_cmp_time(end, time) < 0)
//         return 1;
//     if (start != NULL && X509_cmp_time(start, time) > 0)
//         return -1;
//     return 0;
// }
