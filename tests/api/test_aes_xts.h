/* test_aes_xts.h
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

#ifndef WOLFCRYPT_TEST_AES_XTS_H
#define WOLFCRYPT_TEST_AES_XTS_H

#ifdef WOLFSSL_AES_XTS
int test_wc_AesXtsSetKey(void);
int test_wc_AesXtsEncryptDecrypt(void);
int test_wc_AesXtsSectorEncryptDecrypt(void);
#if defined(WOLFSSL_AESXTS_STREAM)
int test_wc_AesXtsStreamEncryptDecrypt(void);
#endif
#endif /* WOLFSSL_AES_XTS */

#endif /* WOLFCRYPT_TEST_AES_XTS_H */
