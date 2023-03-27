#include "crypto/evp.h"
#include "crypto/x509_acert.h"
#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include <crypto/x509.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include "openssl/x509_vfy.h"
#include "openssl/types.h"
#include "internal/cryptlib.h"
#include "crypto/types.h"
#include "crypto/asn1.h"
#include <openssl/asn1t.h>

int create_platform_specification (X509_ATTRIBUTE **pattr) {
    X509_ATTRIBUTE *attr;
    unsigned char *der = NULL;
    ASN1_STRING *seq = NULL;

    ASN1_INTEGER *majorVersion = ASN1_INTEGER_new();
    ASN1_INTEGER *minorVersion = ASN1_INTEGER_new();
    ASN1_INTEGER *revision = ASN1_INTEGER_new();
    if (ASN1_INTEGER_set(majorVersion, 1) <= 0) {
        return -1;
    }
    if (ASN1_INTEGER_set(minorVersion, 2) <= 0) {
        return -2;
    }
    if (ASN1_INTEGER_set(revision, 3) <= 0) {
        return -3;
    }
    TCG_SPEC_VERSION *specver = TCG_SPEC_VERSION_new();
    specver->majorVersion = majorVersion;
    specver->minorVersion = minorVersion;
    specver->revision = revision;
    ASN1_OCTET_STRING *plat_class = ASN1_OCTET_STRING_new();
    if (!ASN1_STRING_set(plat_class, "lool", -1))
        return -31;
    TCG_PLATFORM_SPEC *platspec = TCG_PLATFORM_SPEC_new();
    platspec->version = specver;
    platspec->platformClass = plat_class;

    if ((seq = ASN1_STRING_new()) == NULL) {
        return -32;
    }
    seq->length = i2d_TCG_PLATFORM_SPEC(platspec, &der);
    if (seq->length <= 0) {
        return -4;
    }
    seq->data = der;
    attr = X509_ATTRIBUTE_create(NID_tcg_at_tcgPlatformSpecification, V_ASN1_SEQUENCE, seq);
    if (attr == NULL) {
        return -5;
    }
    (*pattr) = attr;
    return 0;
}

int create_credential_type (X509_ATTRIBUTE **pattr) {
    X509_ATTRIBUTE *attr;
    unsigned char *der = NULL;
    ASN1_STRING *seq = NULL;

    TCG_CRED_TYPE *credtype = TCG_CRED_TYPE_new();
    credtype->certificateType = OBJ_nid2obj(NID_tcg_kp_PlatformAttributeCertificate);

    if ((seq = ASN1_STRING_new()) == NULL) {
        return -32;
    }
    seq->length = i2d_TCG_CRED_TYPE(credtype, &der);
    if (seq->length <= 0) {
        return -4;
    }
    seq->data = der;
    attr = X509_ATTRIBUTE_create(NID_tcg_at_tcgCredentialType, V_ASN1_SEQUENCE, seq);
    if (attr == NULL) {
        return -2;
    }
    (*pattr) = attr;
    return 0;
}

int create_platform_manufacturer_string (X509_ATTRIBUTE **pattr) {
    X509_ATTRIBUTE *attr;
    ASN1_UTF8STRING *text = ASN1_UTF8STRING_new();
    if (!ASN1_STRING_set(text, "Wildboar Software", -1))
        return -1;
    attr = X509_ATTRIBUTE_create(NID_tcg_at_platformManufacturerStr, V_ASN1_UTF8STRING, text);
    if (attr == NULL) {
        return -2;
    }
    (*pattr) = attr;
    return 0;
}

int create_platform_model (X509_ATTRIBUTE **pattr) {
    X509_ATTRIBUTE *attr;
    ASN1_UTF8STRING *text = ASN1_UTF8STRING_new();
    if (!ASN1_STRING_set(text, "Infiniti", -1))
        return -1;
    attr = X509_ATTRIBUTE_create(NID_tcg_at_platformModel, V_ASN1_UTF8STRING, text);
    if (attr == NULL) {
        return -2;
    }
    (*pattr) = attr;
    return 0;
}

int create_platform_version (X509_ATTRIBUTE **pattr) {
    X509_ATTRIBUTE *attr;
    ASN1_UTF8STRING *text = ASN1_UTF8STRING_new();
    if (!ASN1_STRING_set(text, "QX-80", -1))
        return -1;
    attr = X509_ATTRIBUTE_create(NID_tcg_at_platformVersion, V_ASN1_UTF8STRING, text);
    if (attr == NULL) {
        return -2;
    }
    (*pattr) = attr;
    return 0;
}

int create_platform_serial (X509_ATTRIBUTE **pattr) {
    X509_ATTRIBUTE *attr;
    ASN1_UTF8STRING *text = ASN1_UTF8STRING_new();
    if (!ASN1_STRING_set(text, "103794AEDF", -1))
        return -1;
    attr = X509_ATTRIBUTE_create(NID_tcg_at_platformSerial, V_ASN1_UTF8STRING, text);
    if (attr == NULL) {
        return -2;
    }
    (*pattr) = attr;
    return 0;
}

int create_manufacturer_id (X509_ATTRIBUTE **pattr) {
    X509_ATTRIBUTE *attr;
    unsigned char *der = NULL;
    ASN1_STRING *seq = NULL;

    MANUFACTURER_ID *mid = MANUFACTURER_ID_new();
    /* Your organization might not have an NID assigned within the OpenSSL
    codebase, in which case, you'll have to construct an object identifier. */
    mid->manufacturerIdentifier = OBJ_nid2obj(NID_tcg);
    if ((seq = ASN1_STRING_new()) == NULL) {
        return -32;
    }
    seq->length = i2d_MANUFACTURER_ID(mid, &der);
    if (seq->length <= 0) {
        return -4;
    }
    seq->data = der;
    attr = X509_ATTRIBUTE_create(NID_tcg_at_platformManufacturerId, V_ASN1_SEQUENCE, seq);
    if (attr == NULL) {
        return -2;
    }
    (*pattr) = attr;
    return 0;
}

int create_platform_config_uri (X509_ATTRIBUTE **pattr) {
    X509_ATTRIBUTE *attr;
    unsigned char *der = NULL;
    ASN1_STRING *seq = NULL;
    char hash_bytes[32];

    const unsigned char *uri = "https://wildboarsoftware.com";
    ASN1_IA5STRING *uri_str = ASN1_IA5STRING_new();
    if (!ASN1_STRING_set(uri_str, uri, -1))
        return -1;
    URI_REFERENCE *ref = URI_REFERENCE_new();
    ASN1_BIT_STRING *hash = ASN1_BIT_STRING_new();
    if (!ASN1_BIT_STRING_set(hash, &hash_bytes[0], sizeof(hash_bytes))) {
        return -2;
    }
    ref->uniformResourceIdentifier = uri_str;
    ref->hashAlgorithm = X509_ALGOR_new();
    if (!X509_ALGOR_set0(ref->hashAlgorithm, OBJ_nid2obj(NID_sha256), V_ASN1_UNDEF, NULL))
        return -2;
    ref->hashValue = hash;

    if ((seq = ASN1_STRING_new()) == NULL) {
        return -32;
    }
    seq->length = i2d_URI_REFERENCE(ref, &der);
    if (seq->length <= 0) {
        return -4;
    }
    seq->data = der;
    attr = X509_ATTRIBUTE_create(NID_tcg_at_platformManufacturerId, V_ASN1_SEQUENCE, seq);
    if (attr == NULL) {
        return -4;
    }
    (*pattr) = attr;
    return 0;
}

int create_tbb_sec_assertions (X509_ATTRIBUTE **pattr) {
    X509_ATTRIBUTE *attr;
    unsigned char *der = NULL;
    ASN1_STRING *seq = NULL;

    COMMON_CRITERIA_MEASURES *ccm = COMMON_CRITERIA_MEASURES_new();
    FIPS_LEVEL *fips = FIPS_LEVEL_new();
    ASN1_ENUMERATED *mrt = ASN1_ENUMERATED_new();
    ASN1_IA5STRING *iso_uri = ASN1_IA5STRING_new();
    ASN1_IA5STRING *fips_version = ASN1_IA5STRING_new();
    ASN1_ENUMERATED *fips_sec_level = ASN1_ENUMERATED_new();

    ASN1_IA5STRING *ccm_version = ASN1_IA5STRING_new();
    ASN1_ENUMERATED *assurance = ASN1_ENUMERATED_new();
    ASN1_ENUMERATED *eval_status = ASN1_ENUMERATED_new();
    ASN1_ENUMERATED *sof = ASN1_ENUMERATED_new();
    URI_REFERENCE *profile_uri = URI_REFERENCE_new();
    URI_REFERENCE *target_uri = URI_REFERENCE_new();
    ASN1_IA5STRING *profile_uri_str = ASN1_IA5STRING_new();
    ASN1_IA5STRING *target_uri_str = ASN1_IA5STRING_new();

    if (!ASN1_ENUMERATED_set(mrt, MEASUREMENT_ROOT_TYPE_VIRTUAL)) {
        return -1;
    }
    if (!ASN1_STRING_set(iso_uri, "https://wildboarsoftware.com/iso9000uri", -1)) {
        return -2;
    }
    if (!ASN1_STRING_set(fips_version, "140-2", -1)) {
        return -3;
    }
    if (!ASN1_ENUMERATED_set(fips_sec_level, SECURITY_LEVEL_3)) {
        return -4;
    }
    if (!ASN1_STRING_set(ccm_version, "3.1", -1)) {
        return -5;
    }
    if (!ASN1_ENUMERATED_set(assurance, EVALUATION_ASSURANCE_LEVEL_6)) {
        return -6;
    }
    if (!ASN1_ENUMERATED_set(eval_status, EVALUATION_STATUS_EVAL_IN_PROGRESS)) {
        return -7;
    }
    if (!ASN1_ENUMERATED_set(sof, STRENGTH_OF_FUNCTION_MEDIUM)) {
        return -8;
    }
    if (!ASN1_STRING_set(profile_uri_str, "https://wildboarsoftware.com/profile_uri", -1)) {
        return -9;
    }
    if (!ASN1_STRING_set(target_uri_str, "https://wildboarsoftware.com/target_uri", -1)) {
        return -10;
    }
    profile_uri->uniformResourceIdentifier = profile_uri_str;
    target_uri->uniformResourceIdentifier = target_uri_str;

    ccm->version = ccm_version;
    ccm->assurancelevel = assurance;
    ccm->evaluationStatus = eval_status;
    ccm->plus = 1;
    ccm->strengthOfFunction = sof;
    ccm->profileOid = OBJ_nid2obj(NID_cades);
    ccm->profileUri = profile_uri;
    ccm->targetOid = OBJ_nid2obj(NID_cades);
    ccm->targetUri = target_uri;

    fips->version = fips_version;
    fips->level = fips_sec_level;
    fips->plus = 1;
    TBB_SECURITY_ASSERTIONS *tbb = TBB_SECURITY_ASSERTIONS_new();
    tbb->ccInfo = ccm;
    tbb->fipsLevel = fips;
    tbb->rtmType = mrt;
    tbb->iso9000Certified = 1;
    tbb->iso9000Uri = iso_uri;
    if ((seq = ASN1_STRING_new()) == NULL) {
        return -32;
    }
    seq->length = i2d_TBB_SECURITY_ASSERTIONS(tbb, &der);
    if (seq->length <= 0) {
        return -4;
    }
    seq->data = der;
    attr = X509_ATTRIBUTE_create(NID_tcg_at_tbbSecurityAssertions, V_ASN1_SEQUENCE, seq);
    if (attr == NULL) {
        return -4;
    }
    (*pattr) = attr;
    return 0;
}

int create_platform_config (X509_ATTRIBUTE **pattr) {
    X509_ATTRIBUTE *attr;
    unsigned char *der = NULL;
    ASN1_STRING *seq = NULL;

    STACK_OF(COMPONENT_IDENTIFIER) *componentIdentifiers = sk_COMPONENT_IDENTIFIER_new(NULL);
    STACK_OF(PLATFORM_PROPERTY) *platformProperties = sk_PLATFORM_PROPERTY_new(NULL);
    URI_REFERENCE *componentIdentifiersUri = URI_REFERENCE_new();
    URI_REFERENCE *platformPropertiesUri = URI_REFERENCE_new();
    ASN1_IA5STRING *ci_uri_str = ASN1_IA5STRING_new();
    ASN1_IA5STRING *pp_uri_str = ASN1_IA5STRING_new();


    if (!ASN1_STRING_set(ci_uri_str, "https://wildboarsoftware.com/component_identifiers_uri", -1)) {
        return -1;
    }
    if (!ASN1_STRING_set(pp_uri_str, "https://wildboarsoftware.com/platform_properties_uri", -1)) {
        return -2;
    }
    componentIdentifiersUri->uniformResourceIdentifier = ci_uri_str;
    platformPropertiesUri->uniformResourceIdentifier = pp_uri_str;

    COMPONENT_IDENTIFIER *ci1 = COMPONENT_IDENTIFIER_new();
    COMPONENT_CLASS *cc1 = COMPONENT_CLASS_new();
    ASN1_OCTET_STRING *ccv1 = ASN1_OCTET_STRING_new();
    cc1->componentClassRegistry = OBJ_nid2obj(NID_tcg_registry_componentClass_tcg);
    cc1->componentClassValue = ccv1;
    ASN1_UTF8STRING *comp_manufacturer_1 = ASN1_UTF8STRING_new();
    ASN1_UTF8STRING *comp_model_1 = ASN1_UTF8STRING_new();
    ASN1_UTF8STRING *comp_serial_1 = ASN1_UTF8STRING_new();
    ASN1_UTF8STRING *comp_revision_1 = ASN1_UTF8STRING_new();
    if (!ASN1_STRING_set(ccv1, "asdf", -1))                             return -3;
    if (!ASN1_STRING_set(comp_manufacturer_1, "Wildboar Software", -1)) return -4;
    if (!ASN1_STRING_set(comp_model_1, "Infiniti", -1))                 return -5;
    if (!ASN1_STRING_set(comp_serial_1, "QX-80", -1))                   return -6;
    if (!ASN1_STRING_set(comp_revision_1, "5-beta", -1))                return -7;
    // CERTIFICATE_IDENTIFIER *cert_id = CERTIFICATE_IDENTIFIER_new();
    // cert_id->genericCertIdentifier = X509_get_issuer_serial()
    URI_REFERENCE *cpci1 = URI_REFERENCE_new();
    ASN1_IA5STRING *cpci1_str = ASN1_IA5STRING_new();
    if (!ASN1_STRING_set(cpci1_str, "https://wildboarsoftware.com/component_platform_cert_uri", -1)) {
        return -3;
    }
    ASN1_ENUMERATED *status1 = ASN1_ENUMERATED_new();
    if (!ASN1_ENUMERATED_set(status1, ATTRIBUTE_STATUS_ADDED)) {
        return -4;
    }

    STACK_OF(COMPONENT_ADDRESS) *caddrs1 = sk_COMPONENT_ADDRESS_new(NULL);

    COMPONENT_ADDRESS *caddr1_1 = COMPONENT_ADDRESS_new();
    ASN1_OCTET_STRING *caddr1_1_value = ASN1_OCTET_STRING_new();
    if (!ASN1_STRING_set(caddr1_1_value, "zxcvqwer", -1)) return -8;
    caddr1_1->addressType = OBJ_nid2obj(NID_tcg_address_ethernetmac);
    caddr1_1->addressValue = caddr1_1_value;

    COMPONENT_ADDRESS *caddr1_2 = COMPONENT_ADDRESS_new();
    ASN1_OCTET_STRING *caddr1_2_value = ASN1_OCTET_STRING_new();
    if (!ASN1_STRING_set(caddr1_2_value, "qwerty", -1)) return -8;
    caddr1_2->addressType = OBJ_nid2obj(NID_tcg_address_bluetoothmac);
    caddr1_2->addressValue = caddr1_2_value;

    sk_COMPONENT_ADDRESS_push(caddrs1, caddr1_1);
    sk_COMPONENT_ADDRESS_push(caddrs1, caddr1_2);

    ci1->componentClass = cc1;
    ci1->componentManufacturer = comp_manufacturer_1;
    ci1->componentModel = comp_model_1;
    ci1->componentSerial = comp_serial_1;
    ci1->componentRevision = comp_revision_1;
    ci1->componentManufacturerId = OBJ_nid2obj(NID_netscape);
    ci1->fieldReplaceable = 1;
    ci1->componentAddresses = caddrs1;
    // TODO: ci1->componentPlatformCert = NULL;
    ci1->componentPlatformCertUri = cpci1;
    ci1->status = status1;

    COMPONENT_IDENTIFIER *ci2 = COMPONENT_IDENTIFIER_new();
    COMPONENT_CLASS *cc2 = COMPONENT_CLASS_new();
    ASN1_OCTET_STRING *ccv2 = ASN1_OCTET_STRING_new();
    cc2->componentClassRegistry = OBJ_nid2obj(NID_tcg_registry_componentClass_ietf);
    cc2->componentClassValue = ccv2;
    ASN1_UTF8STRING *comp_manufacturer_2 = ASN1_UTF8STRING_new();
    ASN1_UTF8STRING *comp_model_2 = ASN1_UTF8STRING_new();
    ASN1_UTF8STRING *comp_serial_2 = ASN1_UTF8STRING_new();
    ASN1_UTF8STRING *comp_revision_2 = ASN1_UTF8STRING_new();
    if (!ASN1_STRING_set(ccv2, "zxcv", -1))                             return -3;
    if (!ASN1_STRING_set(comp_manufacturer_2, "Wildboar Software", -1)) return -4;
    if (!ASN1_STRING_set(comp_model_2, "Infiniti", -1))                 return -5;
    if (!ASN1_STRING_set(comp_serial_2, "QX-90", -1))                   return -6;
    if (!ASN1_STRING_set(comp_revision_2, "8-beta", -1))                return -7;
    // CERTIFICATE_IDENTIFIER *cert_id = CERTIFICATE_IDENTIFIER_new();
    // cert_id->genericCertIdentifier = X509_get_issuer_serial()
    URI_REFERENCE *cpci2 = URI_REFERENCE_new();
    ASN1_IA5STRING *cpci2_str = ASN1_IA5STRING_new();
    if (!ASN1_STRING_set(cpci2_str, "https://wildboarsoftware.com/cpc_uri_2", -1)) {
        return -3;
    }
    ASN1_ENUMERATED *status2 = ASN1_ENUMERATED_new();
    if (!ASN1_ENUMERATED_set(status2, ATTRIBUTE_STATUS_ADDED)) {
        return -4;
    }

    STACK_OF(COMPONENT_ADDRESS) *caddrs2 = sk_COMPONENT_ADDRESS_new(NULL);

    COMPONENT_ADDRESS *caddr2_1 = COMPONENT_ADDRESS_new();
    ASN1_OCTET_STRING *caddr2_1_value = ASN1_OCTET_STRING_new();
    if (!ASN1_STRING_set(caddr2_1_value, "fhklfu", -1)) return -8;
    caddr2_1->addressType = OBJ_nid2obj(NID_tcg_address_wlanmac);
    caddr2_1->addressValue = caddr2_1_value;

    COMPONENT_ADDRESS *caddr2_2 = COMPONENT_ADDRESS_new();
    ASN1_OCTET_STRING *caddr2_2_value = ASN1_OCTET_STRING_new();
    if (!ASN1_STRING_set(caddr2_2_value, "tuitl", -1)) return -8;
    caddr2_2->addressType = OBJ_nid2obj(NID_tcg_address_bluetoothmac);
    caddr2_2->addressValue = caddr2_2_value;

    sk_COMPONENT_ADDRESS_push(caddrs2, caddr2_1);
    sk_COMPONENT_ADDRESS_push(caddrs2, caddr2_2);

    ci2->componentClass = cc2;
    ci2->componentManufacturer = comp_manufacturer_2;
    ci2->componentModel = comp_model_2;
    ci2->componentSerial = comp_serial_2;
    ci2->componentRevision = comp_revision_2;
    ci2->componentManufacturerId = OBJ_nid2obj(NID_itu_t);
    ci2->fieldReplaceable = 0;
    ci2->componentAddresses = caddrs2;
    // TODO: ci2->componentPlatformCert = NULL;
    ci2->componentPlatformCertUri = cpci2;
    ci2->status = status2;

    PLATFORM_PROPERTY *pp1 = PLATFORM_PROPERTY_new();
    ASN1_UTF8STRING *pn1 = ASN1_UTF8STRING_new();
    ASN1_UTF8STRING *pv1 = ASN1_UTF8STRING_new();
    ASN1_ENUMERATED *ps1 = ASN1_ENUMERATED_new();
    if (!ASN1_STRING_set(pn1, "PCIe Slots", -1)) return -3;
    if (!ASN1_STRING_set(pv1, "5", -1)) return -3;
    if (!ASN1_ENUMERATED_set(ps1, ATTRIBUTE_STATUS_MODIFIED)) return -3;
    PLATFORM_PROPERTY *pp2 = PLATFORM_PROPERTY_new();
    ASN1_UTF8STRING *pn2 = ASN1_UTF8STRING_new();
    ASN1_UTF8STRING *pv2 = ASN1_UTF8STRING_new();
    ASN1_ENUMERATED *ps2 = ASN1_ENUMERATED_new();
    if (!ASN1_STRING_set(pn2, "USB Ports", -1)) return -3;
    if (!ASN1_STRING_set(pv2, "459", -1)) return -3;
    if (!ASN1_ENUMERATED_set(ps2, ATTRIBUTE_STATUS_REMOVED)) return -3;
    sk_COMPONENT_IDENTIFIER_push(componentIdentifiers, ci1);
    sk_COMPONENT_IDENTIFIER_push(componentIdentifiers, ci2);
    sk_PLATFORM_PROPERTY_push(platformProperties, pp1);
    sk_PLATFORM_PROPERTY_push(platformProperties, pp2);

    PLATFORM_CONFIG *config = PLATFORM_CONFIG_new();
    config->componentIdentifiers = componentIdentifiers;
    config->componentIdentifiersUri = componentIdentifiersUri;
    config->platformProperties = platformProperties;
    config->platformPropertiesUri = platformPropertiesUri;

    if ((seq = ASN1_STRING_new()) == NULL) {
        return -32;
    }
    seq->length = i2d_PLATFORM_CONFIG(config, &der);
    if (seq->length <= 0) {
        return -4;
    }
    seq->data = der;
    attr = X509_ATTRIBUTE_create(NID_tcg_at_platformConfiguration_v2, V_ASN1_SEQUENCE, seq);
    if (attr == NULL) {
        return -2;
    }
    (*pattr) = attr;
    return 0;
}


int add_tcg_attributes (STACK_OF(X509_ATTRIBUTE) *attributes, BIO *outbio) {
    X509_ATTRIBUTE *attr;
    int rc = 0;

    if (create_platform_specification(&attr) != 0)          return -1;
    sk_X509_ATTRIBUTE_push(attributes, attr);
    if (create_credential_type(&attr) != 0)                 return -2;
    sk_X509_ATTRIBUTE_push(attributes, attr);
    if (create_platform_manufacturer_string(&attr) != 0)    return -3;
    sk_X509_ATTRIBUTE_push(attributes, attr);
    if (create_platform_model(&attr) != 0)                  return -4;
    sk_X509_ATTRIBUTE_push(attributes, attr);
    if (create_platform_version(&attr) != 0)                return -5;
    sk_X509_ATTRIBUTE_push(attributes, attr);
    if (create_platform_serial(&attr) != 0)                 return -6;
    sk_X509_ATTRIBUTE_push(attributes, attr);
    if (create_manufacturer_id(&attr) != 0)                 return -7;
    sk_X509_ATTRIBUTE_push(attributes, attr);
    if (create_platform_config_uri(&attr) != 0)             return -8;
    sk_X509_ATTRIBUTE_push(attributes, attr);
    if (create_tbb_sec_assertions(&attr) != 0)              return -9;
    sk_X509_ATTRIBUTE_push(attributes, attr);
    if (create_platform_config(&attr) != 0)                 return -10;
    sk_X509_ATTRIBUTE_push(attributes, attr);
    // TODO: TCG Certificate Specification?
    return 0;
}

// Compile with gcc -g3 -o pccreate examples/plat_cert_create.c -L./ -lssl -lcrypto -Iinclude
/*

NOTE: ./cert-file.pem, ./key.pem, and ./acert.der MUST exist before you run this
function. It does not create these files or ensure that they are present
before attempting to use them.

*/
int main () {
    const char cert_filestr[] = "./cert-file.pem";
    const char key_filestr[] = "./key.pem";
    char outfile_name[] = "./acert.der";
    BIO *certbio;
    BIO *keybio;
    BIO *outbio;
    BIO *acertbio;
    X509 *error_cert;
    X509 *cert;
    X509_NAME *certsubject;
    X509_STORE *store;
    X509_STORE_CTX *ctx;
    int ret;

    OpenSSL_add_all_algorithms();
    certbio = BIO_new(BIO_s_file());
    keybio = BIO_new(BIO_s_file());
    outbio = BIO_new_fp(stdout, BIO_NOCLOSE);
    acertbio = BIO_new(BIO_s_file());

    if ((store = X509_STORE_new()) == NULL) {
        BIO_printf(outbio, "Error creating X509_STORE object\n");
        return 1;
    }
    if ((ctx = X509_STORE_CTX_new()) == NULL) {
        return 1;
    }

    ret = BIO_read_filename(certbio, cert_filestr);
    if (!(cert = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
        BIO_printf(outbio, "Error loading cert into memory\n");
        return 3;
    }

    ret = X509_STORE_load_locations(store, cert_filestr, NULL);
    if (ret != 1) {
        BIO_printf(outbio, "Error loading CA cert or chain file\n");
        return 2;
    }

    ret = BIO_read_filename(keybio, key_filestr);
    if (ret != 1) {
        BIO_printf(outbio, "Error loading key\n");
        return 3;
    }
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(keybio, NULL, NULL, NULL);
    if (pkey == NULL) {
        BIO_printf(outbio, "Not a key\n");
        return -3;
    }

    X509_STORE_CTX_init(ctx, store, cert, NULL);
    ret = X509_verify_cert(ctx);
    if (ret == 0 || ret == 1) {
        BIO_printf(outbio, "Verification result text: %s\n",
            X509_verify_cert_error_string(ctx->error));
    }
    if (ret == 0) {
        error_cert = X509_STORE_CTX_get_current_cert(ctx);
        certsubject = X509_get_subject_name(error_cert);
        BIO_printf(outbio, "Verification failed cert:\n");
        X509_NAME_print_ex(outbio, certsubject, 0, XN_FLAG_MULTILINE);
        BIO_printf(outbio, "\n");
        return 6;
    }

    // ret = X509_STORE_CTX_get1_issuer(&issuer_cert, ctx, cert);
    // if (ret != 1) {
    //     return 5;
    // }
    
    // These would come from the subject's public-key certificate.
    OSSL_ISSUER_SERIAL *holder_base_cert_id = X509_get_issuer_serial(cert);
    if (holder_base_cert_id == NULL) {
        BIO_puts(outbio, "No IssuerSerial\n");
    }
    /* From the platform certificate spec: "The BaseCertificateID choice MUST be used." */
    X509_HOLDER *holder = X509_HOLDER_new();
    holder->baseCertificateID = holder_base_cert_id;
    holder->entityName = NULL;
    holder->objectDigestInfo = NULL;
    // "This field contains the distinguished name of the entity that issued this Platform Certificate."
    // ^That implies that we are using the `issuerName` field.
    X509_ACERT_ISSUER_V2FORM *v2_issuer = X509_ACERT_ISSUER_V2FORM_new();
    v2_issuer->baseCertificateId = holder_base_cert_id;
    v2_issuer->issuerName = NULL;
    v2_issuer->objectDigestInfo = NULL;
    X509_ACERT_ISSUER *issuer = X509_ACERT_ISSUER_new();
    issuer->type = 1;
    issuer->u.v2Form = v2_issuer;
    X509_ALGOR *sig_alg = X509_ALGOR_new();
    if (sig_alg == NULL)
        return -5;
    if (!X509_ALGOR_set0(sig_alg, OBJ_nid2obj(NID_sha256WithRSAEncryption), V_ASN1_NULL, NULL))
        return 5;
    
    ASN1_INTEGER *serialNumber = ASN1_INTEGER_new();
    if (ASN1_INTEGER_set(serialNumber, 1234) <= 0) {
        return 6;
    }

    ASN1_TIME *notBefore = ASN1_TIME_new();
    ASN1_TIME *notAfter = ASN1_TIME_new();
    if (ASN1_TIME_set_string(notBefore, "20230321000000Z") <= 0) {
        return 8;
    }

    if (ASN1_TIME_set_string(notAfter, "20330321000000Z") <= 0) {
        return 8;
    }

    X509_VAL *validityPeriod = X509_VAL_new();
    validityPeriod->notBefore = notBefore;
    validityPeriod->notAfter = notAfter;
    STACK_OF(X509_ATTRIBUTE) *attributes = sk_X509_ATTRIBUTE_new(NULL);
    ASN1_BIT_STRING *issuerUID = NULL;
    X509_EXTENSIONS *extensions = sk_X509_EXTENSION_new(NULL);

    if (add_tcg_attributes(attributes, outbio) != 0) {
        return 9;
    }

    X509_ACERT_INFO *acinfo = X509_ACERT_INFO_new();
    acinfo->version = *ASN1_INTEGER_new(); // TODO: How do you make this NULL?
    acinfo->holder = *holder;
    acinfo->issuer = *issuer;
    acinfo->signature = *sig_alg;
    acinfo->serialNumber = *serialNumber;
    acinfo->validityPeriod = *validityPeriod;
    acinfo->attributes = attributes;
    acinfo->issuerUID = issuerUID;
    acinfo->extensions = extensions;
    if (!ASN1_INTEGER_set_int64(&acinfo->version, 1)) {
        return 1001;
    }

    X509_ACERT *acert = X509_ACERT_new();
    acert->acinfo = acinfo;
    // Leave the other fields null for the sign function to fill in.

    EVP_MD_CTX *mdctx = NULL;
    if(!(mdctx = EVP_MD_CTX_create())) {
        return 100;
    }
    
    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        return 101;
    }
    ret = X509_ACERT_sign_ctx(acert, mdctx);
    if (ret <= 0) {
        ERR_print_errors(outbio);
        return ret;
    }

    unsigned char *der = NULL;
    int acert_len = i2d_X509_ACERT(acert, &der);
    if (acert_len <= 0) {
        return 103;
    }
    ret = BIO_write_filename(acertbio, outfile_name);
    if (ret != 1) {
        BIO_printf(outbio, "Error writing result to file\n");
        return 105;
    }
    if (BIO_write(acertbio, der, acert_len) <= 0) {
        return 104;
    }
    EVP_MD_CTX_destroy(mdctx);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(cert);
    BIO_free_all(certbio);
    BIO_free_all(outbio);
    return 0;
}