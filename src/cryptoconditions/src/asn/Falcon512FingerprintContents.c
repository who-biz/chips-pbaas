

#include "Falcon512FingerprintContents.h"

static int
memb_publicKey_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	const OCTET_STRING_t *st = (const OCTET_STRING_t *)sptr;
	size_t size;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	size = st->size;
	
	if((size == 896)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_TYPE_member_t asn_MBR_Falcon512FingerprintContents_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct Falcon512FingerprintContents, publicKey),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_OCTET_STRING,
		memb_publicKey_constraint_1,
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"publicKey"
		},
};
static const ber_tlv_tag_t asn_DEF_Falcon512FingerprintContents_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)) /* monkins: not sure agin what the masks do*/
};
static const asn_TYPE_tag2member_t asn_MAP_Falcon512FingerprintContents_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* publicKey */
};
static asn_SEQUENCE_specifics_t asn_SPC_Falcon512FingerprintContents_specs_1 = {
	sizeof(struct Falcon512FingerprintContents),
	offsetof(struct Falcon512FingerprintContents, _asn_ctx),
	asn_MAP_Falcon512FingerprintContents_tag2el_1,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_Falcon512FingerprintContents = {
	"Falcon512FingerprintContents",
	"Falcon512FingerprintContents",
	SEQUENCE_free,
	SEQUENCE_print,
	SEQUENCE_constraint,
	SEQUENCE_decode_ber,
	SEQUENCE_encode_der,
	SEQUENCE_decode_xer,
	SEQUENCE_encode_xer,
	0, 0,	/* No PER support, use "-gen-PER" to enable */
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_Falcon512FingerprintContents_tags_1,
	sizeof(asn_DEF_Falcon512FingerprintContents_tags_1)
		/sizeof(asn_DEF_Falcon512FingerprintContents_tags_1[0]), /* 1 */
	asn_DEF_Falcon512FingerprintContents_tags_1,	/* Same as above */
	sizeof(asn_DEF_Falcon512FingerprintContents_tags_1)
		/sizeof(asn_DEF_Falcon512FingerprintContents_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_Falcon512FingerprintContents_1,
	1,	/* Elements count */
	&asn_SPC_Falcon512FingerprintContents_specs_1	/* Additional specs */
};
