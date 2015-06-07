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


//#include "ns3/tcp-option-mptcp.h"
#include <stdint.h>
#include "ns3/mptcp-crypto.h"
#include "ns3/log.h"
#include "ns3/node.h"
#include "ns3/assert.h"
#include <cstddef> // for size_t

#ifdef ENABLE_CRYPTO
    #include <gcrypt.h> // for the sha1 hash
#else
    #include <functional> // to emulate some hash function
    #include <iostream>
    #include <string>
    #include "ns3/hash.h"
//    Create<Hash::Function::Fnv1a> ()
#endif

namespace ns3 {

//#include <openssl/sha.h>

//https://www.gnupg.org/documentation/manuals/gcrypt/Working-with-hash-algorithms.html#Working-with-hash-algorithms

void
GenerateTokenForKey( mptcp_crypto_alg_t alg, uint64_t key, uint32_t& token, uint64_t& idsn)
{

  NS_LOG_UNCOND("Generating token/key from key=" << key);


//  uint8_t digest[DIGEST_SIZE_IN_BYTES];
  #ifdef ENABLE_CRYPTO
  NS_LOG_UNCOND("Used algorithm [" << gcry_md_algo_name(alg) << "]");


  /* converts the key into a buffer */
  Buffer keyBuff;

  keyBuff.AddAtStart(KEY_SIZE_IN_BYTES);
  Buffer::Iterator it = keyBuff.Begin();
  it.WriteHtonU64(key);



  Buffer digestBuf; /* to store the generated hash */
  digestBuf.AddAtStart(DIGEST_SIZE_IN_BYTES);


  switch(alg)
  {
    case HMAC_SHA1:
        {

            int hash_len = gcry_md_get_algo_dlen( GCRY_MD_SHA1 );
            unsigned char digest[ hash_length ];



            /*
            gcry_md_hash_buffer (int algo, void *digest, const void *buffer, size_t length);
            */
            gcry_md_hash_buffer( GCRY_MD_SHA1, digest, keyBuff.PeekData(), hash_length );

            Buffer::Iterator it_digest = digestBuf.Begin();
            it_digest.Write( digest , DIGEST_SIZE_IN_BYTES ); // strlen( (const char*)digest)
            it_digest = digestBuf.Begin();
            token = it_digest.ReadNtohU32();
            it_digest.Next( 8 );

            idsn = it_digest.ReadNtohU64();
        }
        break;

    default:
        NS_FATAL_ERROR("Only sha1 hmac currently supported (and standardised !)");
        break;
  };
  #else
    /* the cryptographic library is not available so we rely on a ns3 specific implementation
    that does not comply with the standard.
    In the following, the idsn = the key (could be 0) and the token a truncated key

    */
    idsn = 0;
    token = key >> 32;
//    std::hash<std::string> hash_fn;
    // every hash_fn should return a size_t
//    std::hash<uint64_t> hash_fn;
//     Hasher hasher = Hasher ( Create<Hash::Function::Fnv1a> () );
//uint32_t hash = Hasher.GetHash32 (data);

     // GetHash32 / 64
//     Create<Hash::Function::Fnv1a> ();

//    std::size_t digest = hash_fn(key);
  #endif // ENABLE_CRYPTO

#if 0
  const int DIGEST_SIZE_IN_BYTES = SHA_DIGEST_LENGTH; //20
  const int KEY_SIZE_IN_BYTES = 8;


//  const int TOKEN_SIZE_IN_BYTES = 4;


//  uint32_t result = 0;
//  unsigned char *SHA1(const unsigned char *d, size_t n, unsigned char *md);
  uint8_t digest[DIGEST_SIZE_IN_BYTES];

    /*
    This is the Openssl code
    */
//  const uint8_t* test = (const uint8_t*)&key;
  // Convert to network order
  // computes hash of KEY_SIZE_IN_BYTES bytes in keyBuff
// TODO according to openssl doc (https://www.openssl.org/docs/crypto/EVP_DigestInit.html#)
// we should use  EVP_MD_CTX *mdctx; instead of sha1
	SHA1( keyBuff.PeekData(), KEY_SIZE_IN_BYTES, digest);
    #endif



  NS_LOG_UNCOND("Resulting token=" << token << " and idsn=" << idsn);
}


} // end of 'ns3'
