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

ASN1_SEQUENCE(HASH) = {
    ASN1_SIMPLE(HASH, algorithmIdentifier, X509_ALGOR),
    ASN1_OPT(HASH, hashValue, ASN1_BIT_STRING),
} ASN1_SEQUENCE_END(HASH)

ASN1_SEQUENCE(INFO_SYNTAX_POINTER) = {
    ASN1_SIMPLE(INFO_SYNTAX_POINTER, name, GENERAL_NAMES),
    ASN1_OPT(INFO_SYNTAX_POINTER, hash, HASH),
} ASN1_SEQUENCE_END(INFO_SYNTAX_POINTER)

ASN1_CHOICE(INFO_SYNTAX) = {
    ASN1_SIMPLE(INFO_SYNTAX, choice.content, DIRECTORYSTRING),
    ASN1_SIMPLE(INFO_SYNTAX, choice.pointer, INFO_SYNTAX_POINTER)
} ASN1_CHOICE_END(INFO_SYNTAX)

ASN1_SEQUENCE(PRIVILEGE_POLICY_ID) = {
    ASN1_SIMPLE(PRIVILEGE_POLICY_ID, privilegePolicy, ASN1_OBJECT),
    ASN1_SIMPLE(PRIVILEGE_POLICY_ID, privPolSyntax, INFO_SYNTAX),
} ASN1_SEQUENCE_END(PRIVILEGE_POLICY_ID)

ASN1_SEQUENCE(ATTRIBUTE_DESCRIPTOR) = {
    ASN1_SIMPLE(ATTRIBUTE_DESCRIPTOR, identifier, ASN1_OBJECT),
    ASN1_SIMPLE(ATTRIBUTE_DESCRIPTOR, attributeSyntax, ASN1_OCTET_STRING),
    ASN1_IMP_OPT(ATTRIBUTE_DESCRIPTOR, name, ASN1_UTF8STRING, 0),
    ASN1_IMP_OPT(ATTRIBUTE_DESCRIPTOR, description, ASN1_UTF8STRING, 1),
    ASN1_SIMPLE(ATTRIBUTE_DESCRIPTOR, dominationRule, PRIVILEGE_POLICY_ID),
} ASN1_SEQUENCE_END(ATTRIBUTE_DESCRIPTOR)

IMPLEMENT_ASN1_FUNCTIONS(ATTRIBUTE_DESCRIPTOR)

static int i2r_HASH(X509V3_EXT_METHOD *method,
                    HASH *hash,
                    BIO *out, int indent)
{
    BIO_printf(out, "%*sAlgorithm: ", indent, "");
    i2a_ASN1_OBJECT(out, hash->algorithmIdentifier->algorithm);
    BIO_puts(out, "\n");
    if (hash->algorithmIdentifier->parameter) {
        BIO_printf(out, "%*sParameter: ", indent, "");
        print_attribute_value(out, 0, hash->algorithmIdentifier->parameter);
        BIO_puts(out, "\n");
    }
    BIO_printf(out, "%*sHash Value: ", indent, "");
    print_hex(out, hash->hashValue->data, hash->hashValue->length);
    return 1;
}

static int i2r_INFO_SYNTAX_POINTER(X509V3_EXT_METHOD *method,
                                   INFO_SYNTAX_POINTER *pointer,
                                   BIO *out, int indent)
{
    BIO_printf(out, "%*sNames:\n", indent, "");
    ossl_print_gens(out, pointer->name, indent);
    BIO_puts(out, "\n");
    if (pointer->hash != NULL) {
        BIO_printf(out, "%*sHash:\n", indent, "");
        i2r_HASH(method, pointer->hash, out, indent + 4);
    }
    return 1;
}

static int i2r_INFO_SYNTAX(X509V3_EXT_METHOD *method,
                           INFO_SYNTAX *info,
                           BIO *out, int indent)
{
    switch (info->type) {
    case (INFO_SYNTAX_TYPE_CONTENT): {
        BIO_printf(out, "%*sContent: ", indent, "");
        BIO_printf(out, "%.*s", info->choice.content->length, info->choice.content->data);
        BIO_puts(out, "\n");
        return 1;
    }
    case (INFO_SYNTAX_TYPE_POINTER): {
        BIO_printf(out, "%*sPointer:\n", indent, "");
        return i2r_INFO_SYNTAX_POINTER(method, info->choice.pointer, out, indent + 4);
    }
    default: return 0;
    }
    return 0;
}

static int i2r_PRIVILEGE_POLICY_ID(X509V3_EXT_METHOD *method,
                                   PRIVILEGE_POLICY_ID *ppid,
                                   BIO *out, int indent)
{
    char buf[80];

    /* Intentionally display the numeric OID, rather than the textual name. */
    if (OBJ_obj2txt(buf, sizeof(buf), ppid->privilegePolicy, 1) <= 0) {
        return 0;
    }
    BIO_printf(out, "%*sIdentifier: %s\n", indent, "", buf);
    BIO_printf(out, "%*sSyntax:\n", indent, "");
    i2r_INFO_SYNTAX(method, ppid->privPolSyntax, out, indent + 4);
    return 1;
}

static int i2r_ATTRIBUTE_DESCRIPTOR(X509V3_EXT_METHOD *method,
                                    ATTRIBUTE_DESCRIPTOR *ad,
                                    BIO *out, int indent)
{
    char buf[80];

    /* Intentionally display the numeric OID, rather than the textual name. */
    if (OBJ_obj2txt(buf, sizeof(buf), ad->identifier, 1) <= 0) {
        return 0;
    }
    BIO_printf(out, "%*sIdentifier: %s\n", indent, "", buf);
    BIO_printf(out, "%*sSyntax:\n", indent, "");
    BIO_printf(out, "%*s%.*s", indent + 4, "", ad->attributeSyntax->length, ad->attributeSyntax->data);
    BIO_puts(out, "\n\n");
    if (ad->name != NULL) {
        BIO_printf(out, "%*sName: ", indent, "");
        BIO_printf(out, "%.*s", ad->name->length, ad->name->data);
        BIO_puts(out, "\n");
    }
    if (ad->description != NULL) {
        BIO_printf(out, "%*sDescription: ", indent, "");
        BIO_printf(out, "%.*s", ad->description->length, ad->description->data);
        BIO_puts(out, "\n");
    }
    BIO_printf(out, "%*sDomination Rule:\n", indent, "");
    i2r_PRIVILEGE_POLICY_ID(method, ad->dominationRule, out, indent + 4);
    return 1;
}

const X509V3_EXT_METHOD ossl_v3_attribute_descriptor = {
    NID_attribute_descriptor, X509V3_EXT_MULTILINE,
    ASN1_ITEM_ref(ATTRIBUTE_DESCRIPTOR),
    0, 0, 0, 0,
    0, 0,
    0,
    0,
    (X509V3_EXT_I2R)i2r_ATTRIBUTE_DESCRIPTOR,
    NULL,
    NULL
};