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

#include <stdint.h>
#include "ns3/mptcp-crypto.h"
#include "ns3/log.h"
#include "ns3/node.h"
#include "ns3/buffer.h"
#include "ns3/assert.h"
#include <cstddef> // for size_t

#ifdef HAVE_CRYPTO
    #include <gcrypt.h> // for the sha1 hash
#else
    #include <functional> // to emulate some hash function
    #include <iostream>
    #include <string>
//    #include "ns3/hash.h"
//    Create<Hash::Function::Fnv1a> ()
#endif

NS_LOG_COMPONENT_DEFINE ("MpTcpCrypto");

namespace ns3 {

//#ifdef HAVE_CRYPTO
//static gcry_md_algos
//map_ns_to_gcrypt_alg(mptcp_crypto_alg_t alg)
//{
//    return GCRY_MD_SHA1;
//}
//
//#endif


//https://www.gnupg.org/documentation/manuals/gcrypt/Working-with-hash-algorithms.html#Working-with-hash-algorithms
void
GenerateTokenForKey( mptcp_crypto_alg_t ns_alg, uint64_t key, uint32_t& token, uint64_t& idsn)
{

  NS_LOG_LOGIC("Generating token/key from key=" << key);


//  uint8_t digest[DIGEST_SIZE_IN_BYTES];
  #ifdef HAVE_CRYPTO
//  gcry_md_algos gcry_algo = map_ns_to_gcrypt_alg(ns_alg);
  gcry_md_algos gcry_algo = GCRY_MD_SHA1;
//  NS_LOG_UNCOND("Used algorithm [" << gcry_md_algo_name(alg) << "]");

  static const int KEY_SIZE_IN_BYTES = sizeof(key);
  /* converts the key into a buffer */
  Buffer keyBuff;

  keyBuff.AddAtStart(KEY_SIZE_IN_BYTES);
  Buffer::Iterator it = keyBuff.Begin();
  it.WriteHtonU64(key);


    NS_LOG_DEBUG("Used algorithm [" << gcry_md_algo_name(gcry_algo) << "]");
    int hash_length = gcry_md_get_algo_dlen( gcry_algo );
//    unsigned char digest[ hash_length ];
    unsigned char digest[ 20 ];

    NS_LOG_DEBUG("Key length=" <<KEY_SIZE_IN_BYTES << " and hash_len=" << hash_length);

    Buffer digestBuf; /* to store the generated hash */
    digestBuf.AddAtStart(hash_length);

    /*
    gcry_md_hash_buffer (int algo, void *digest, const void *buffer, size_t length);
    gcry_md_hash_buffer is a shortcut function to calculate a message digest of a buffer.
    This function does not require a context and immediately returns the message digest
    of the length bytes at buffer. digest must be allocated by the caller,
    large enough to hold the message digest yielded by the the specified algorithm algo.
    This required size may be obtained by using the function gcry_md_get_algo_dlen.
    */
    gcry_md_hash_buffer( GCRY_MD_SHA1, digest, keyBuff.PeekData(), KEY_SIZE_IN_BYTES );

    Buffer::Iterator it_digest = digestBuf.Begin();
    it_digest.Write( digest , hash_length ); // strlen( (const char*)digest)
    it_digest = digestBuf.Begin();
    token = it_digest.ReadNtohU32();
    it_digest.Next( 8 );
    idsn = it_digest.ReadNtohU64();
  #else
    /* the cryptographic library is not available so we rely on a ns3 specific implementation
    that does not comply with the standard.
    In the following, the idsn = the key (could be 0) and the token a truncated key

    */
    idsn = key;
    token = (uint32_t)key;

//     Hasher hasher = Hasher ( Create<Hash::Function::Fnv1a> () );
//uint32_t hash = Hasher.GetHash32 (data);
//     Create<Hash::Function::Fnv1a> ();
  #endif // HAVE_CRYPTO

  NS_LOG_DEBUG("Resulting token=" << token << " and idsn=" << idsn);
}


} // end of 'ns3'
