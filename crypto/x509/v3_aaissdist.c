/*
 * Copyright 1999-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/conf.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/x509v3.h>

#include "crypto/x509.h"
#include "ext_dat.h"
#include "x509_local.h"

ASN1_SEQUENCE(AA_DIST_POINT) = {
    ASN1_EXP_OPT(AA_DIST_POINT, distpoint, DIST_POINT_NAME, 0),
    ASN1_IMP_OPT(AA_DIST_POINT, reasons, ASN1_BIT_STRING, 1),
    ASN1_IMP_OPT(AA_DIST_POINT, indirectCRL, ASN1_FBOOLEAN, 2),
    ASN1_IMP_OPT(AA_DIST_POINT, containsUserAttributeCerts, ASN1_TBOOLEAN, 3),
    ASN1_IMP_OPT(AA_DIST_POINT, containsAACerts, ASN1_TBOOLEAN, 4),
    ASN1_IMP_OPT(AA_DIST_POINT, containsSOAPublicKeyCerts, ASN1_TBOOLEAN, 5)
} ASN1_SEQUENCE_END(AA_DIST_POINT)

IMPLEMENT_ASN1_FUNCTIONS(AA_DIST_POINT)

static int print_boolean (BIO *out, ASN1_BOOLEAN b) {
    if (b) {
        BIO_puts(out, "TRUE");
    } else {
        BIO_puts(out, "FALSE");
    }
}

static STACK_OF(GENERAL_NAME) *gnames_from_sectname(X509V3_CTX *ctx,
                                                    char *sect)
{
    STACK_OF(CONF_VALUE) *gnsect;
    STACK_OF(GENERAL_NAME) *gens;
    if (*sect == '@')
        gnsect = X509V3_get_section(ctx, sect + 1);
    else
        gnsect = X509V3_parse_list(sect);
    if (!gnsect) {
        ERR_raise(ERR_LIB_X509V3, X509V3_R_SECTION_NOT_FOUND);
        return NULL;
    }
    gens = v2i_GENERAL_NAMES(NULL, ctx, gnsect);
    if (*sect == '@')
        X509V3_section_free(ctx, gnsect);
    else
        sk_CONF_VALUE_pop_free(gnsect, X509V3_conf_free);
    return gens;
}

static int set_dist_point_name(DIST_POINT_NAME **pdp, X509V3_CTX *ctx,
                               CONF_VALUE *cnf)
{
    STACK_OF(GENERAL_NAME) *fnm = NULL;
    STACK_OF(X509_NAME_ENTRY) *rnm = NULL;

    if (HAS_PREFIX(cnf->name, "fullname")) {
        fnm = gnames_from_sectname(ctx, cnf->value);
        if (!fnm)
            goto err;
    } else if (strcmp(cnf->name, "relativename") == 0) {
        int ret;
        STACK_OF(CONF_VALUE) *dnsect;
        X509_NAME *nm;
        nm = X509_NAME_new();
        if (nm == NULL)
            return -1;
        dnsect = X509V3_get_section(ctx, cnf->value);
        if (!dnsect) {
            X509_NAME_free(nm);
            ERR_raise(ERR_LIB_X509V3, X509V3_R_SECTION_NOT_FOUND);
            return -1;
        }
        ret = X509V3_NAME_from_section(nm, dnsect, MBSTRING_ASC);
        X509V3_section_free(ctx, dnsect);
        rnm = nm->entries;
        nm->entries = NULL;
        X509_NAME_free(nm);
        if (!ret || sk_X509_NAME_ENTRY_num(rnm) <= 0)
            goto err;
        /*
         * Since its a name fragment can't have more than one RDNSequence
         */
        if (sk_X509_NAME_ENTRY_value(rnm,
                                     sk_X509_NAME_ENTRY_num(rnm) - 1)->set) {
            ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_MULTIPLE_RDNS);
            goto err;
        }
    } else
        return 0;

    if (*pdp) {
        ERR_raise(ERR_LIB_X509V3, X509V3_R_DISTPOINT_ALREADY_SET);
        goto err;
    }

    *pdp = DIST_POINT_NAME_new();
    if (*pdp == NULL)
        goto err;
    if (fnm) {
        (*pdp)->type = 0;
        (*pdp)->name.fullname = fnm;
    } else {
        (*pdp)->type = 1;
        (*pdp)->name.relativename = rnm;
    }

    return 1;

 err:
    sk_GENERAL_NAME_pop_free(fnm, GENERAL_NAME_free);
    sk_X509_NAME_ENTRY_pop_free(rnm, X509_NAME_ENTRY_free);
    return -1;
}

static const BIT_STRING_BITNAME reason_flags[] = {
    {0, "Unused", "unused"},
    {1, "Key Compromise", "keyCompromise"},
    {2, "CA Compromise", "CACompromise"},
    {3, "Affiliation Changed", "affiliationChanged"},
    {4, "Superseded", "superseded"},
    {5, "Cessation Of Operation", "cessationOfOperation"},
    {6, "Certificate Hold", "certificateHold"},
    {7, "Privilege Withdrawn", "privilegeWithdrawn"},
    {8, "AA Compromise", "AACompromise"},
    {-1, NULL, NULL}
};

static int set_reasons(ASN1_BIT_STRING **preas, char *value)
{
    STACK_OF(CONF_VALUE) *rsk = NULL;
    const BIT_STRING_BITNAME *pbn;
    const char *bnam;
    int i, ret = 0;
    rsk = X509V3_parse_list(value);
    if (rsk == NULL)
        return 0;
    if (*preas != NULL)
        goto err;
    for (i = 0; i < sk_CONF_VALUE_num(rsk); i++) {
        bnam = sk_CONF_VALUE_value(rsk, i)->name;
        if (*preas == NULL) {
            *preas = ASN1_BIT_STRING_new();
            if (*preas == NULL)
                goto err;
        }
        for (pbn = reason_flags; pbn->lname; pbn++) {
            if (strcmp(pbn->sname, bnam) == 0) {
                if (!ASN1_BIT_STRING_set_bit(*preas, pbn->bitnum, 1))
                    goto err;
                break;
            }
        }
        if (pbn->lname == NULL)
            goto err;
    }
    ret = 1;

 err:
    sk_CONF_VALUE_pop_free(rsk, X509V3_conf_free);
    return ret;
}

static int print_reasons(BIO *out, const char *rname,
                         ASN1_BIT_STRING *rflags, int indent)
{
    int first = 1;
    const BIT_STRING_BITNAME *pbn;
    BIO_printf(out, "%*s%s:\n%*s", indent, "", rname, indent + 4, "");
    for (pbn = reason_flags; pbn->lname; pbn++) {
        if (ASN1_BIT_STRING_get_bit(rflags, pbn->bitnum)) {
            if (first)
                first = 0;
            else
                BIO_puts(out, ", ");
            BIO_puts(out, pbn->lname);
        }
    }
    if (first)
        BIO_puts(out, "<EMPTY>\n");
    else
        BIO_puts(out, "\n");
    return 1;
}

static AA_DIST_POINT *aaidp_from_section(X509V3_CTX *ctx,
                                      STACK_OF(CONF_VALUE) *nval)
{
    int i;
    CONF_VALUE *cnf;
    AA_DIST_POINT *point = AA_DIST_POINT_new();

    if (point == NULL)
        goto err;
    for (i = 0; i < sk_CONF_VALUE_num(nval); i++) {
        int ret;
        cnf = sk_CONF_VALUE_value(nval, i);
        ret = set_dist_point_name(&point->distpoint, ctx, cnf);
        if (ret > 0)
            continue;
        if (ret < 0)
            goto err;
        if (strcmp(cnf->name, "reasons") == 0) {
            if (!set_reasons(&point->reasons, cnf->value))
                goto err;
        } else if (strcmp(cnf->name, "indirectCRL") == 0) {
            if (!X509V3_get_value_bool(cnf, &point->indirectCRL))
                goto err;
        } else if (strcmp(cnf->name, "containsUserAttributeCerts") == 0) {
            if (!X509V3_get_value_bool(cnf, &point->containsUserAttributeCerts))
                goto err;
        } else if (strcmp(cnf->name, "containsAACerts") == 0) {
            if (!X509V3_get_value_bool(cnf, &point->containsAACerts))
                goto err;
        } else if (strcmp(cnf->name, "containsSOAPublicKeyCerts") == 0) {
            if (!X509V3_get_value_bool(cnf, &point->containsSOAPublicKeyCerts))
                goto err;
        }
    }

    return point;

 err:
    AA_DIST_POINT_free(point);
    return NULL;
}

static void *v2i_aaidp(const X509V3_EXT_METHOD *method,
                      X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *nval)
{
    GENERAL_NAMES *gens = NULL;
    GENERAL_NAME *gen = NULL;
    CONF_VALUE *cnf;
    const int num = sk_CONF_VALUE_num(nval);
    int i;
    AA_DIST_POINT *point;

    cnf = sk_CONF_VALUE_value(nval, i);
    if (cnf->value == NULL) {
        STACK_OF(CONF_VALUE) *dpsect;
        dpsect = X509V3_get_section(ctx, cnf->name);
        if (!dpsect)
            goto err;
        point = aaidp_from_section(ctx, dpsect);
        X509V3_section_free(ctx, dpsect);
        if (point == NULL)
            goto err;
    } else {
        if ((gen = v2i_GENERAL_NAME(method, ctx, cnf)) == NULL)
            goto err;
        if ((gens = GENERAL_NAMES_new()) == NULL) {
            ERR_raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB);
            goto err;
        }
        if (!sk_GENERAL_NAME_push(gens, gen)) {
            ERR_raise(ERR_LIB_X509V3, ERR_R_CRYPTO_LIB);
            goto err;
        }
        gen = NULL;
        if ((point = DIST_POINT_new()) == NULL) {
            ERR_raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB);
            goto err;
        }
        if ((point->distpoint = DIST_POINT_NAME_new()) == NULL) {
            ERR_raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB);
            goto err;
        }
        point->distpoint->name.fullname = gens;
        point->distpoint->type = 0;
        gens = NULL;
    }
    return point;

 err:
    GENERAL_NAME_free(gen);
    GENERAL_NAMES_free(gens);
    AA_DIST_POINT_free(point);
    return NULL;
}

static int print_distpoint(BIO *out, DIST_POINT_NAME *dpn, int indent)
{
    if (dpn->type == 0) {
        BIO_printf(out, "%*sFull Name:\n", indent, "");
        ossl_print_gens(out, dpn->name.fullname, indent);
        BIO_puts(out, "\n");
    } else {
        X509_NAME ntmp;
        ntmp.entries = dpn->name.relativename;
        BIO_printf(out, "%*sRelative Name:\n%*s", indent, "", indent + 4, "");
        X509_NAME_print_ex(out, &ntmp, 0, XN_FLAG_ONELINE);
        BIO_puts(out, "\n");
    }
    return 1;
}

static int i2r_aaidp(const X509V3_EXT_METHOD *method, AA_DIST_POINT *dp, BIO *out,
                     int indent)
{
    if (dp->distpoint)
        print_distpoint(out, dp->distpoint, indent);
    if (dp->reasons)
        print_reasons(out, "Reasons", dp->reasons, indent);
    if (dp->indirectCRL) {
        BIO_printf(out, "%*sIndirect CRL: ", indent, "");
        print_boolean(out, dp->indirectCRL);
        BIO_puts(out, "\n");
    }
    if (dp->containsUserAttributeCerts) {
        BIO_printf(out, "%*sContains User Attribute Certificates: ", indent, "");
        print_boolean(out, dp->containsUserAttributeCerts);
        BIO_puts(out, "\n");
    }
    if (dp->containsAACerts) {
        BIO_printf(out, "%*sContains Attribute Authority (AA) Certificates: ", indent, "");
        print_boolean(out, dp->containsAACerts);
        BIO_puts(out, "\n");
    }
    if (dp->containsSOAPublicKeyCerts) {
        BIO_printf(out, "%*sContains Source Of Authority (SOA) Public Key Certificates: ", indent, "");
        print_boolean(out, dp->containsSOAPublicKeyCerts);
        BIO_puts(out, "\n");
    }
    return 1;
}

// // TODO: Refactor into separate module, because this came from `v3_crld.c`.
// /* Append any nameRelativeToCRLIssuer in dpn to iname, set in dpn->dpname */
// static int DIST_POINT_set_dpname(DIST_POINT_NAME *dpn, const X509_NAME *iname)
// {
//     int i;
//     STACK_OF(X509_NAME_ENTRY) *frag;
//     X509_NAME_ENTRY *ne;

//     if (dpn == NULL || dpn->type != 1)
//         return 1;
//     frag = dpn->name.relativename;
//     X509_NAME_free(dpn->dpname); /* just in case it was already set */
//     dpn->dpname = X509_NAME_dup(iname);
//     if (dpn->dpname == NULL)
//         return 0;
//     for (i = 0; i < sk_X509_NAME_ENTRY_num(frag); i++) {
//         ne = sk_X509_NAME_ENTRY_value(frag, i);
//         if (!X509_NAME_add_entry(dpn->dpname, ne, -1, i ? 0 : 1))
//             goto err;
//     }
//     /* generate cached encoding of name */
//     if (i2d_X509_NAME(dpn->dpname, NULL) >= 0)
//         return 1;

//  err:
//     X509_NAME_free(dpn->dpname);
//     dpn->dpname = NULL;
//     return 0;
// }

const X509V3_EXT_METHOD ossl_v3_aa_issuing_dist_point = {
    NID_id_aa_issuing_distribution_point, 0, ASN1_ITEM_ref(AA_DIST_POINT),
    0, 0, 0, 0,
    0, 0,
    0,
    v2i_aaidp,
    i2r_aaidp, 0,
    NULL
};