/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/objects.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include "x509_local.h"

/*-
 * X509_ATTRIBUTE: this has the following form:
 *
 * typedef struct x509_attributes_st
 *      {
 *      ASN1_OBJECT *object;
 *      STACK_OF(ASN1_TYPE) *set;
 *      } X509_ATTRIBUTE;
 *
 */

ASN1_SEQUENCE(X509_ATTRIBUTE) = {
        ASN1_SIMPLE(X509_ATTRIBUTE, object, ASN1_OBJECT),
        ASN1_SET_OF(X509_ATTRIBUTE, set, ASN1_ANY)
} ASN1_SEQUENCE_END(X509_ATTRIBUTE)

IMPLEMENT_ASN1_FUNCTIONS(X509_ATTRIBUTE)
IMPLEMENT_ASN1_DUP_FUNCTION(X509_ATTRIBUTE)

X509_ATTRIBUTE *X509_ATTRIBUTE_create(int nid, int atrtype, void *value)
{
    X509_ATTRIBUTE *ret = NULL;
    ASN1_TYPE *val = NULL;
    ASN1_OBJECT *oid;

    if ((oid = OBJ_nid2obj(nid)) == NULL)
        return NULL;
    if ((ret = X509_ATTRIBUTE_new()) == NULL)
        return NULL;
    ret->object = oid;
    if ((val = ASN1_TYPE_new()) == NULL)
        goto err;
    if (!sk_ASN1_TYPE_push(ret->set, val))
        goto err;

    ASN1_TYPE_set(val, atrtype, value);
    return ret;
 err:
    X509_ATTRIBUTE_free(ret);
    ASN1_TYPE_free(val);
    return NULL;
}

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

int print_hex(BIO *out, unsigned char *buf, int len)
{
    int i;
    for (i = 0; i < len; i++) {
        if (BIO_printf(out, "%02X ", buf[i]) <= 0) {
            return 0;
        }
    }
    return 1;
}

int print_attribute_value(BIO *out, int obj_nid, const ASN1_TYPE *av)
{
    const char *ln;
    char objbuf[80];
    ASN1_STRING *str;
    char *value;
    X509_NAME *xn = NULL;

    // This switch-case is only for syntaxes that are not encoded as a single
    // primitively-constructed value universal ASN.1 type.
    switch (obj_nid) {
    case NID_undef: break; // Unrecognized OID.
    // Attribute types with DN syntax.
    case NID_member:
    case NID_roleOccupant:
    case NID_seeAlso:
    case NID_manager:
    case NID_documentAuthor:
    case NID_secretary:
    case NID_associatedName:
    case NID_dITRedirect:
    case NID_owner:
        value = av->value.sequence->data;
        if ((xn = d2i_X509_NAME(NULL, (const unsigned char**)&(av->value.sequence->data), av->value.sequence->length)) == NULL) {
            if (BIO_puts(out, "(COULD NOT DECODE DISTINGUISHED NAME)") <= 0) {
                return 0;
            }
            break;
        }
        // d2i_ functions increment the ppin pointer. See doc/man3/d2i_X509.pod.
        // This resets the pointer. We don't want to corrupt this value.
        av->value.sequence->data = value;
        if (X509_NAME_print_ex(out, xn, 0, 0) <= 0) {
            return 0;
        }
        X509_NAME_free(xn);
        return 1;
    default: break;
    }

    switch (av->type) {
    case V_ASN1_BOOLEAN:
        if (av->value.boolean) {
            return BIO_puts(out, "TRUE");
        } else {
            return BIO_puts(out, "FALSE");
        }

    case V_ASN1_INTEGER:
    case V_ASN1_ENUMERATED:
        str = av->value.integer;
        return ASN1_INTEGER_print_bio(out, str);

    case V_ASN1_BIT_STRING:
        return print_hex(out, av->value.bit_string->data,
                 av->value.bit_string->length);

    case V_ASN1_OCTET_STRING:
    case V_ASN1_VIDEOTEXSTRING:
        return print_hex(out, av->value.octet_string->data,
                 av->value.octet_string->length);

    case V_ASN1_NULL:
        return BIO_puts(out, "NULL");

    case V_ASN1_OBJECT:
        /* Does this need to be freed? */
        ln = OBJ_nid2ln(OBJ_obj2nid(av->value.object));
        if (!ln)
            ln = "";
        if (OBJ_obj2txt(objbuf, sizeof(objbuf), av->value.object, 1) <= 0) {
            return 0;
        }
        return BIO_printf(out, "%s (%s)", ln, objbuf);
    
    /* ObjectDescriptor is an IMPLICIT GraphicString, but GeneralString is a
    superset supported by OpenSSL, so we will use that anywhere a GraphicString
    is needed here. */
    case V_ASN1_GENERALSTRING:
    case V_ASN1_GRAPHICSTRING:
    case V_ASN1_OBJECT_DESCRIPTOR:
        return BIO_printf(out, "%.*s", av->value.generalstring->length,
                av->value.generalstring->data);

    /* EXTERNAL */
    /* EMBEDDED PDV */

    case V_ASN1_UTF8STRING:
        return BIO_printf(out, "%.*s", av->value.utf8string->length,
                   av->value.utf8string->data);

    case V_ASN1_REAL:
        return BIO_puts(out, "REAL");

    /* RELATIVE-OID */
    /* TIME */

    case V_ASN1_SEQUENCE:
        return ASN1_parse_dump(out, av->value.sequence->data,
                        av->value.sequence->length, 0, 1);

    case V_ASN1_SET:
        return ASN1_parse_dump(out, av->value.set->data,
                av->value.set->length, 0, 1);

    /*
        UTCTime ::= [UNIVERSAL 23] IMPLICIT VisibleString
        GeneralizedTime ::= [UNIVERSAL 24] IMPLICIT VisibleString
        VisibleString is a superset for NumericString, so it will work for that.
    */
    case V_ASN1_VISIBLESTRING:
    case V_ASN1_UTCTIME:
    case V_ASN1_GENERALIZEDTIME:
    case V_ASN1_NUMERICSTRING:
        return BIO_printf(out, "%.*s", av->value.visiblestring->length,
                   av->value.visiblestring->data);

    case V_ASN1_PRINTABLESTRING:
        return BIO_printf(out, "%.*s", av->value.printablestring->length,
            av->value.printablestring->data);

    case V_ASN1_T61STRING:
        return BIO_printf(out, "%.*s", av->value.t61string->length,
            av->value.t61string->data);

    case V_ASN1_IA5STRING:
        return BIO_printf(out, "%.*s", av->value.ia5string->length,
            av->value.ia5string->data);

    /* UniversalString */
    /* CHARACTER STRING */

    case V_ASN1_BMPSTRING:
        value = OPENSSL_uni2asc(av->value.bmpstring->data,
                                av->value.bmpstring->length);
        int ret = BIO_printf(out, "%s", value);
        OPENSSL_free(value);
        return ret;

    /* DATE */
    /* TIME-OF-DAY */
    /* DATE-TIME */
    /* DURATION */
    /* OID-IRI */
    /* RELATIVE-OID-IRI */

    /* Would it be approriate to just hexdump? */
    default:
        return BIO_printf(out, "<Unsupported tag %d>", av->type);
    }
}
