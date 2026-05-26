#ifndef HYPERION_EMV_H
#define HYPERION_EMV_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KRN_ABI_VERSION 2u
#define KRN_MAX_APDU_RESPONSE_LEN 258u
#define KRN_MAX_ONLINE_AUTH_DATA_LEN 1024u
#define KRN_MAX_HOST_RESPONSE_LEN 1024u
#define KRN_PROFILE_SHA256_LEN 32u
#define KRN_INTERFACE_CONTACT 1u
#define KRN_INTERFACE_CONTACTLESS 2u

typedef struct KrnContext KrnContext;
typedef int32_t (*KrnTransmitApduCallback)(const uint8_t *cmd, size_t cmd_len, uint8_t *resp, size_t *resp_len, int32_t timeout_ms, void *user_data);
typedef int32_t (*KrnGetUnpredictableNumberCallback)(uint8_t *out, size_t out_len, void *user_data);

typedef struct KrnConfigBlob {
    uint32_t abi_version;
    uint32_t struct_size;
    const uint8_t *bytes;
    size_t len;
} KrnConfigBlob;

typedef struct KrnRuntime {
    uint32_t abi_version;
    uint32_t struct_size;
    KrnTransmitApduCallback transmit_apdu;
    KrnGetUnpredictableNumberCallback get_unpredictable_number;
    void *contactless_outcome;
    void *user_data;
} KrnRuntime;

typedef struct KrnTxnParams {
    uint32_t struct_size;
    uint64_t amount_authorised_minor;
    uint64_t amount_other_minor;
    uint16_t currency_code;
    uint8_t currency_exponent;
    uint16_t terminal_country_code;
    uint8_t transaction_type;
    uint8_t terminal_type;
    uint8_t merchant_category_code[2];
    uint8_t interface_preference;
    const uint8_t *merchant_name_location;
    size_t merchant_name_location_len;
} KrnTxnParams;

KrnContext *krn_context_new(void);
int32_t krn_init(KrnContext *ctx, const KrnConfigBlob *config, const KrnRuntime *runtime);
void krn_context_free(KrnContext *ctx);
int32_t krn_reset(KrnContext *ctx);
int32_t krn_get_last_error(const KrnContext *ctx);
uint32_t krn_abi_version(void);
int32_t krn_set_transaction_params(KrnContext *ctx, const KrnTxnParams *params);
int32_t krn_load_profiles_verified(KrnContext *ctx, const uint8_t *profile_json, size_t profile_json_len);
int32_t krn_load_certification_bundle_verified(KrnContext *ctx, const uint8_t *bundle_json, size_t bundle_json_len, const uint8_t *trust_anchor_json, size_t trust_anchor_json_len);
int32_t krn_run_transaction(KrnContext *ctx);
int32_t krn_build_select_environment(KrnContext *ctx, uint8_t *out, size_t *out_len);
int32_t krn_build_generate_ac(KrnContext *ctx, uint8_t cryptogram_type, uint8_t *out, size_t *out_len);
int32_t krn_get_online_authorization_data(KrnContext *ctx, uint8_t *out, size_t *out_len);
int32_t krn_apply_host_response(KrnContext *ctx, const uint8_t *response, size_t response_len);
int32_t krn_process_issuer_authentication(KrnContext *ctx);
int32_t krn_process_issuer_scripts(KrnContext *ctx);
int32_t krn_process_final_generate_ac(KrnContext *ctx);
int32_t krn_get_final_outcome(const KrnContext *ctx);
int32_t krn_get_profile_sha256(const KrnContext *ctx, uint8_t *out, size_t out_len);
int32_t krn_mask_apdu_command_json(const uint8_t *cmd, size_t cmd_len, uint8_t *out, size_t *out_len);
int32_t krn_mask_apdu_response_json(const uint8_t *resp, size_t resp_len, uint8_t *out, size_t *out_len);
int32_t krn_get_conformance_statement_json(uint8_t *out, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif
