/* test_aes_xts.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#if !defined(WOLFSSL_USER_SETTINGS) && !defined(WOLFSSL_NO_OPTIONS_H)
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/port/caam/wolfcaam.h>
#include <tests/unit.h>
#include <tests/api/api.h>
#include <tests/api/test_aes_xts.h>

/*******************************************************************************
 * AES-XTS
 ******************************************************************************/

/*
 * Testing function for wc_AesXtsSetKey().
 */
int test_wc_AesXtsSetKey(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_AES_XTS
    XtsAes aes;
    byte key32[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
    byte key64[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
    byte badKey[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65
    };

    /* Initialize */
    ExpectIntEQ(wc_AesXtsInit(&aes, NULL, INVALID_DEVID), 0);

    /* Test key sizes */
    ExpectIntEQ(wc_AesXtsSetKey(&aes, key32, sizeof(key32), AES_ENCRYPTION, 
                               NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_AesXtsSetKey(&aes, key64, sizeof(key64), AES_ENCRYPTION, 
                               NULL, INVALID_DEVID), 0);

    /* Test bad args */
    ExpectIntEQ(wc_AesXtsSetKey(NULL, key32, sizeof(key32), AES_ENCRYPTION, 
                               NULL, INVALID_DEVID), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesXtsSetKey(&aes, NULL, sizeof(key32), AES_ENCRYPTION, 
                               NULL, INVALID_DEVID), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* For bad key size, the error is BAD_LENGTH_E not BAD_FUNC_ARG */
    ExpectIntEQ(wc_AesXtsSetKey(&aes, badKey, sizeof(badKey), AES_ENCRYPTION, 
                               NULL, INVALID_DEVID), 
                WC_NO_ERR_TRACE(BAD_LENGTH_E));
    ExpectIntEQ(wc_AesXtsSetKey(&aes, key32, sizeof(key32), -1, 
                               NULL, INVALID_DEVID), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_AesXtsFree(&aes);
#endif
    return EXPECT_RESULT();
}

/*
 * Testing function for wc_AesXtsEncrypt() and wc_AesXtsDecrypt()
 */
int test_wc_AesXtsEncryptDecrypt(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_AES_XTS
    XtsAes aes;
    byte key32[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
    byte tweak[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
    byte plaintext[32] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
    };
    byte ciphertext[32];
    byte decrypted[32];

    /* Initialize */
    XMEMSET(ciphertext, 0, sizeof(ciphertext));
    XMEMSET(decrypted, 0, sizeof(decrypted));
    
    ExpectIntEQ(wc_AesXtsInit(&aes, NULL, INVALID_DEVID), 0);

    /* Test encryption */
    ExpectIntEQ(wc_AesXtsSetKey(&aes, key32, sizeof(key32), AES_ENCRYPTION, 
                               NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_AesXtsEncrypt(&aes, ciphertext, plaintext, sizeof(plaintext), 
                                tweak, sizeof(tweak)), 0);

    /* Test decryption */
    ExpectIntEQ(wc_AesXtsSetKey(&aes, key32, sizeof(key32), AES_DECRYPTION, 
                               NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_AesXtsDecrypt(&aes, decrypted, ciphertext, sizeof(ciphertext), 
                                tweak, sizeof(tweak)), 0);
    
    /* Verify decryption */
    ExpectIntEQ(XMEMCMP(plaintext, decrypted, sizeof(plaintext)), 0);

    /* Test bad args */
    ExpectIntEQ(wc_AesXtsEncrypt(NULL, ciphertext, plaintext, sizeof(plaintext), 
                                tweak, sizeof(tweak)), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesXtsEncrypt(&aes, NULL, plaintext, sizeof(plaintext), 
                                tweak, sizeof(tweak)), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesXtsEncrypt(&aes, ciphertext, NULL, sizeof(plaintext), 
                                tweak, sizeof(tweak)), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesXtsEncrypt(&aes, ciphertext, plaintext, 0, 
                                tweak, sizeof(tweak)), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesXtsEncrypt(&aes, ciphertext, plaintext, sizeof(plaintext), 
                                NULL, sizeof(tweak)), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test bad args for decrypt */
    ExpectIntEQ(wc_AesXtsDecrypt(NULL, decrypted, ciphertext, sizeof(ciphertext), 
                                tweak, sizeof(tweak)), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesXtsDecrypt(&aes, NULL, ciphertext, sizeof(ciphertext), 
                                tweak, sizeof(tweak)), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesXtsDecrypt(&aes, decrypted, NULL, sizeof(ciphertext), 
                                tweak, sizeof(tweak)), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesXtsDecrypt(&aes, decrypted, ciphertext, 0, 
                                tweak, sizeof(tweak)), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesXtsDecrypt(&aes, decrypted, ciphertext, sizeof(ciphertext), 
                                NULL, sizeof(tweak)), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_AesXtsFree(&aes);
#endif
    return EXPECT_RESULT();
}

/*
 * Testing function for wc_AesXtsEncryptSector() and wc_AesXtsDecryptSector()
 */
int test_wc_AesXtsSectorEncryptDecrypt(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_AES_XTS
    XtsAes aes;
    byte key32[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
    byte plaintext[512];
    byte ciphertext[512];
    byte decrypted[512];
    word64 sector = 0x1234567890ABCDEF;
    int i;

    /* Fill plaintext with pattern */
    for (i = 0; i < (int)sizeof(plaintext); i++) {
        plaintext[i] = (byte)i;
    }

    /* Initialize */
    XMEMSET(ciphertext, 0, sizeof(ciphertext));
    XMEMSET(decrypted, 0, sizeof(decrypted));
    
    ExpectIntEQ(wc_AesXtsInit(&aes, NULL, INVALID_DEVID), 0);

    /* Test encryption */
    ExpectIntEQ(wc_AesXtsSetKey(&aes, key32, sizeof(key32), AES_ENCRYPTION, 
                               NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_AesXtsEncryptSector(&aes, ciphertext, plaintext, 
                                      sizeof(plaintext), sector), 0);

    /* Test decryption */
    ExpectIntEQ(wc_AesXtsSetKey(&aes, key32, sizeof(key32), AES_DECRYPTION, 
                               NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_AesXtsDecryptSector(&aes, decrypted, ciphertext, 
                                      sizeof(ciphertext), sector), 0);
    
    /* Verify decryption */
    ExpectIntEQ(XMEMCMP(plaintext, decrypted, sizeof(plaintext)), 0);

    /* Test bad args */
    ExpectIntEQ(wc_AesXtsEncryptSector(NULL, ciphertext, plaintext, 
                                      sizeof(plaintext), sector), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesXtsEncryptSector(&aes, NULL, plaintext, 
                                      sizeof(plaintext), sector), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesXtsEncryptSector(&aes, ciphertext, NULL, 
                                      sizeof(plaintext), sector), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesXtsEncryptSector(&aes, ciphertext, plaintext, 
                                      0, sector), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test bad args for decrypt */
    ExpectIntEQ(wc_AesXtsDecryptSector(NULL, decrypted, ciphertext, 
                                      sizeof(ciphertext), sector), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesXtsDecryptSector(&aes, NULL, ciphertext, 
                                      sizeof(ciphertext), sector), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesXtsDecryptSector(&aes, decrypted, NULL, 
                                      sizeof(ciphertext), sector), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesXtsDecryptSector(&aes, decrypted, ciphertext, 
                                      0, sector), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_AesXtsFree(&aes);
#endif
    return EXPECT_RESULT();
}

#if defined(WOLFSSL_AESXTS_STREAM)
/*
 * Testing function for AES-XTS streaming API
 */
int test_wc_AesXtsStreamEncryptDecrypt(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_AES_XTS) && defined(WOLFSSL_AESXTS_STREAM)
    XtsAes aes;
    byte key32[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
    byte tweak[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
    byte plaintext[WC_AES_BLOCK_SIZE * 2];
    byte ciphertext[WC_AES_BLOCK_SIZE * 2];
    byte decrypted[WC_AES_BLOCK_SIZE * 2];
    XtsAesStreamData stream;
    int i;

    /* Fill plaintext with pattern */
    for (i = 0; i < (int)sizeof(plaintext); i++) {
        plaintext[i] = (byte)i;
    }

    /* Initialize */
    XMEMSET(ciphertext, 0, sizeof(ciphertext));
    XMEMSET(decrypted, 0, sizeof(decrypted));
    
    ExpectIntEQ(wc_AesXtsInit(&aes, NULL, INVALID_DEVID), 0);

    /* Test encryption */
    ExpectIntEQ(wc_AesXtsSetKey(&aes, key32, sizeof(key32), AES_ENCRYPTION, 
                               NULL, INVALID_DEVID), 0);
    
    /* Initialize encryption stream */
    XMEMSET(&stream, 0, sizeof(stream));
    ExpectIntEQ(wc_AesXtsEncryptInit(&aes, tweak, sizeof(tweak), &stream), 0);
    
    /* Process first block */
    ExpectIntEQ(wc_AesXtsEncryptUpdate(&aes, ciphertext, plaintext, 
                                      WC_AES_BLOCK_SIZE, &stream), 0);
    
    /* Process second block and finalize */
    ExpectIntEQ(wc_AesXtsEncryptFinal(&aes, ciphertext + WC_AES_BLOCK_SIZE, 
                                     plaintext + WC_AES_BLOCK_SIZE, 
                                     WC_AES_BLOCK_SIZE, &stream), 0);

    /* Test decryption */
    ExpectIntEQ(wc_AesXtsSetKey(&aes, key32, sizeof(key32), AES_DECRYPTION, 
                               NULL, INVALID_DEVID), 0);
    
    /* Initialize decryption stream */
    XMEMSET(&stream, 0, sizeof(stream));
    ExpectIntEQ(wc_AesXtsDecryptInit(&aes, tweak, sizeof(tweak), &stream), 0);
    
    /* Process first block */
    ExpectIntEQ(wc_AesXtsDecryptUpdate(&aes, decrypted, ciphertext, 
                                      WC_AES_BLOCK_SIZE, &stream), 0);
    
    /* Process second block and finalize */
    ExpectIntEQ(wc_AesXtsDecryptFinal(&aes, decrypted + WC_AES_BLOCK_SIZE, 
                                     ciphertext + WC_AES_BLOCK_SIZE, 
                                     WC_AES_BLOCK_SIZE, &stream), 0);
    
    /* Verify decryption */
    ExpectIntEQ(XMEMCMP(plaintext, decrypted, sizeof(plaintext)), 0);

    /* Test bad args for encrypt */
    ExpectIntEQ(wc_AesXtsEncryptInit(NULL, tweak, sizeof(tweak), &stream), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesXtsEncryptInit(&aes, NULL, sizeof(tweak), &stream), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesXtsEncryptInit(&aes, tweak, 0, &stream), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesXtsEncryptInit(&aes, tweak, sizeof(tweak), NULL), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    
    ExpectIntEQ(wc_AesXtsEncryptUpdate(NULL, ciphertext, plaintext, 
                                      WC_AES_BLOCK_SIZE, &stream), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesXtsEncryptUpdate(&aes, NULL, plaintext, 
                                      WC_AES_BLOCK_SIZE, &stream), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesXtsEncryptUpdate(&aes, ciphertext, NULL, 
                                      WC_AES_BLOCK_SIZE, &stream), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesXtsEncryptUpdate(&aes, ciphertext, plaintext, 
                                      WC_AES_BLOCK_SIZE, NULL), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    
    ExpectIntEQ(wc_AesXtsEncryptFinal(NULL, ciphertext, plaintext, 
                                     WC_AES_BLOCK_SIZE, &stream), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesXtsEncryptFinal(&aes, NULL, plaintext, 
                                     WC_AES_BLOCK_SIZE, &stream), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesXtsEncryptFinal(&aes, ciphertext, NULL, 
                                     WC_AES_BLOCK_SIZE, &stream), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesXtsEncryptFinal(&aes, ciphertext, plaintext, 
                                     WC_AES_BLOCK_SIZE, NULL), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test bad args for decrypt */
    ExpectIntEQ(wc_AesXtsDecryptInit(NULL, tweak, sizeof(tweak), &stream), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesXtsDecryptInit(&aes, NULL, sizeof(tweak), &stream), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesXtsDecryptInit(&aes, tweak, 0, &stream), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesXtsDecryptInit(&aes, tweak, sizeof(tweak), NULL), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    
    ExpectIntEQ(wc_AesXtsDecryptUpdate(NULL, decrypted, ciphertext, 
                                      WC_AES_BLOCK_SIZE, &stream), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesXtsDecryptUpdate(&aes, NULL, ciphertext, 
                                      WC_AES_BLOCK_SIZE, &stream), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesXtsDecryptUpdate(&aes, decrypted, NULL, 
                                      WC_AES_BLOCK_SIZE, &stream), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesXtsDecryptUpdate(&aes, decrypted, ciphertext, 
                                      WC_AES_BLOCK_SIZE, NULL), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    
    ExpectIntEQ(wc_AesXtsDecryptFinal(NULL, decrypted, ciphertext, 
                                     WC_AES_BLOCK_SIZE, &stream), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesXtsDecryptFinal(&aes, NULL, ciphertext, 
                                     WC_AES_BLOCK_SIZE, &stream), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesXtsDecryptFinal(&aes, decrypted, NULL, 
                                     WC_AES_BLOCK_SIZE, &stream), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AesXtsDecryptFinal(&aes, decrypted, ciphertext, 
                                     WC_AES_BLOCK_SIZE, NULL), 
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_AesXtsFree(&aes);
    return EXPECT_RESULT();
}
#endif /* WOLFSSL_AESXTS_STREAM */

#endif /* WOLFSSL_AES_XTS */
