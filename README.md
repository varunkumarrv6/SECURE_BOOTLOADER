# ELE304 Lab 5: Secure bootloader (STM32H755, CM7 + CM4)

A bootloader at `0x08000000` that verifies an ECDSA (P-256) signature and the
SHA-256 digests of both the CM7 and CM4 application images before it jumps to
the application. If any check fails, it prints the reason and does not boot.

## Memory map

| Region | Address | Content |
|---|---|---|
| Bootloader (CM7) | `0x08000000` | this project, `CM7/` (128 KB sector) |
| Metadata header | `0x08020000` | 0x400 bytes, written by `tools/ele304_postbuild.py` |
| CM7 application | `0x08020400` | linked with `FLASH ORIGIN = 0x08020400`, `VECT_TAB_OFFSET = 0x20400` |
| CM4 application | `0x08100000` | unchanged |

## Metadata header (little-endian)

| Offset | Field |
|---|---|
| 0x00 | magic `0x46574D41` |
| 0x04 | CM7 size |
| 0x08 | CM4 size |
| 0x0C | version |
| 0x10 | SHA-256 of CM7 image (32 B) |
| 0x30 | SHA-256 of CM4 image (32 B) |
| 0x50 | reserved, 48 B (bytes 0x00..0x7F are the signed block) |
| 0x80 | SHA-256 of the signed block (not trusted; the bootloader recomputes it) |
| 0xA0 | ECDSA signature, raw r\|\|s, 64 B |

Layout is also in `CM7/Core/Inc/fwauth.h`.

## Boot flow

1. Check magic and size limits, so no read goes outside the allowed regions.
2. Hash the 128-byte signed block and verify the signature with the public key
   in `ecc_pub_key.h` (`CMOX_ECC_SECP256R1_LOWMEM`).
3. Hash the CM7 image in flash and compare with the signed CM7 digest.
4. Hash the CM4 image and compare with the signed CM4 digest.
5. Jump to the application only if all checks pass.

## Build and flash

Dependencies that are not in this repository:
- ST **STM32Cube Expansion Crypto V4.0.0** (STM32_Cryptographic). Copy it to
  `CM7/STM32_Cryptographic` and link `libSTM32Cryptographic_CM7.a` (see
  `CM7/.cproject`, whose include and library paths are from the original machine).
  `Core/Src/cmox_low_level.c` is the low-level layer taken from the library template.
- The course's Host_Tools (openssl, `PreBuild.bat`).

Steps:
1. Generate a P-256 key: `openssl ecparam -name prime256v1 -genkey -out ecc.key`.
   **Keep `ecc.key` private and out of git.**
2. Run `PreBuild.bat` to write `ecc_pub_key.h` into `CM7/Core/Inc`, and build the bootloader.
3. Build the CM7 and CM4 applications to `.bin`, then:
   `python tools/ele304_postbuild.py --cm7 app_cm7.bin --cm4 app_cm4.bin --key ecc.key --version 1 --out out --check-header CM7/Core/Inc/ecc_pub_key.h`
4. Flash with STM32CubeProgrammer: bootloader at `0x08000000`,
   `out/out_app_meta.bin` at `0x08020000`, CM4 `.bin` at `0x08100000`.

## Tests done on the board

| Test | Result |
|---|---|
| Valid signed image | signature OK, CM7 OK, CM4 OK, jumps to application |
| One byte of CM7 code changed | `signature OK`, `FAIL: CM7 digest`, no boot |
| One byte of the signed header changed | `FAIL: signature`, no boot |
| One byte of CM4 code changed | `signature OK`, `CM7 digest OK`, `FAIL: CM4 digest`, no boot |

## Limitations

- The bootloader itself is not write-protected (no WRP/RDP in this lab), so the
  bootloader or the public key could be overwritten with debug access.
- The CM4 may start before verification finishes, depending on boot
  configuration and the D2 domain clock. Not verified on this board.
