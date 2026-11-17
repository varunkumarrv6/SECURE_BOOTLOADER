#ifndef FWAUTH_H
#define FWAUTH_H
#include <stdint.h>
#include <stddef.h>

#define FW_META_ADDR     0x08020000U
#define FW_CM7_ADDR      0x08020400U
#define FW_CM4_ADDR      0x08100000U
#define FW_MAGIC         0x46574D41U
#define FW_CM7_MAX_SIZE  (FW_CM4_ADDR - FW_CM7_ADDR)   /* 0xDFC00 */
#define FW_CM4_MAX_SIZE  0x00100000U
#define FW_SIGNED_LEN    128U

typedef struct {
    uint32_t fw_magic;
    uint32_t fw_cm7_size;
    uint32_t fw_cm4_size;
    uint32_t fw_version;
    uint8_t  fw_cm7_tag[32];
    uint8_t  fw_cm4_tag[32];
    uint8_t  reserved[48];
    uint8_t  meta_tag[32];     /* not trusted; we recompute it */
    uint8_t  meta_sig[64];     /* raw r||s */
} FW_Meta_t;

_Static_assert(sizeof(FW_Meta_t) == 224, "FW_Meta_t size");
_Static_assert(offsetof(FW_Meta_t, meta_tag) == FW_SIGNED_LEN, "signed block must be 128 bytes");
#endif
