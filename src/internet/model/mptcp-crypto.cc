/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2007 Georgia Tech Research Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Matthieu Coudron <matthieu.coudron@lip6.fr>
 */




#include <gcrypt.h>
//#include <openssl/sha.h>

//https://www.gnupg.org/documentation/manuals/gcrypt/Working-with-hash-algorithms.html#Working-with-hash-algorithms

void
MpTcpSocketBase::GenerateTokenForKey( mptcp_crypto_t alg, uint64_t key, uint32_t& token, uint64_t& idsn)
{
  NS_ASSERT_MSG(alg == MPTCP_SHA1, "Only sha1 hmac currently supported (and standardised !)");

  NS_LOG_UNCOND("Generating token/key from key=" << key);
  const int DIGEST_SIZE_IN_BYTES = SHA_DIGEST_LENGTH; //20

  const int KEY_SIZE_IN_BYTES = 8;
//  const int TOKEN_SIZE_IN_BYTES = 4;
  Buffer keyBuff, digestBuf;
  keyBuff.AddAtStart(KEY_SIZE_IN_BYTES);
  digestBuf.AddAtStart(DIGEST_SIZE_IN_BYTES);

  Buffer::Iterator it = keyBuff.Begin();
  it.WriteHtonU64(key);

//  uint32_t result = 0;
//  unsigned char *SHA1(const unsigned char *d, size_t n, unsigned char *md);
  uint8_t digest[DIGEST_SIZE_IN_BYTES];
//  const uint8_t* test = (const uint8_t*)&key;
  // Convert to network order
  // computes hash of KEY_SIZE_IN_BYTES bytes in keyBuff
// TODO according to openssl doc (https://www.openssl.org/docs/crypto/EVP_DigestInit.html#)
// we should use  EVP_MD_CTX *mdctx; instead of sha1
	SHA1( keyBuff.PeekData(), KEY_SIZE_IN_BYTES, digest);

	Buffer::Iterator it_digest = digestBuf.Begin();
	it_digest.Write( digest , DIGEST_SIZE_IN_BYTES ); // strlen( (const char*)digest)
	it_digest = digestBuf.Begin();
  token = it_digest.ReadNtohU32();
  it_digest.Next( 8 );

  idsn = it_digest.ReadNtohU64();

  NS_LOG_UNCOND("Resulting token=" << token << " and idsn=" << idsn);
}
