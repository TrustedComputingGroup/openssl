#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/x509v3.h>

void print_notice(BIO *out, USERNOTICE *notice, int indent)
{
    int i;
    if (notice->noticeref) {
        NOTICEREF *ref;
        ref = notice->noticeref;
        BIO_printf(out, "%*sOrganization: %.*s\n", indent, "",
                   ref->organization->length,
                   ref->organization->data);
        BIO_printf(out, "%*sNumber%s: ", indent, "",
                   sk_ASN1_INTEGER_num(ref->noticenos) > 1 ? "s" : "");
        for (i = 0; i < sk_ASN1_INTEGER_num(ref->noticenos); i++) {
            ASN1_INTEGER *num;
            char *tmp;
            num = sk_ASN1_INTEGER_value(ref->noticenos, i);
            if (i)
                BIO_puts(out, ", ");
            if (num == NULL)
                BIO_puts(out, "(null)");
            else {
                tmp = i2s_ASN1_INTEGER(NULL, num);
                if (tmp == NULL)
                    return;
                BIO_puts(out, tmp);
                OPENSSL_free(tmp);
            }
        }
        if (notice->exptext)
            BIO_puts(out, "\n");
    }
    if (notice->exptext)
        BIO_printf(out, "%*sExplicit Text: %.*s", indent, "",
                   notice->exptext->length,
                   notice->exptext->data);
}
