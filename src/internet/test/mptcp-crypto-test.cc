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

#include "ns3/log.h"
#include "ns3/test.h"
#include "ns3/mptcp-crypto.h"

NS_LOG_COMPONENT_DEFINE ("MpTcpCryptoTest");




namespace ns3 {

/* client initiates connection => SYN */
typedef struct _crypto_material {
uint64_t keyClient;
uint64_t keyServer;
uint32_t expectedTokenClient;
uint32_t expectedTokenServer;
/* it makes little sense to test these but just in case */
uint32_t nonceSyn;
uint32_t nonceSynAck;
uint64_t expectedHmacSynAck;
uint32_t expectedHmacAck;
uint64_t expectedIdsnClient;
uint64_t expectedIdsnServer;
} crypto_materials_t;


/**
Used to test key/token generation
**/
class MpTcpCryptoTest : public TestCase
{
public:

  MpTcpCryptoTest(crypto_materials_t t) : TestCase("MPTCP crypto test with values ..."),m_c(t)
  {
    //!
    NS_LOG_FUNCTION(this);
  }

  virtual ~MpTcpCryptoTest()
  {
      NS_LOG_FUNCTION(this);
  }

  virtual void DoRun(void)
  {
    const mptcp_crypto_alg_t algo = HMAC_SHA1;
    uint32_t tokenClient = 0, tokenServer = 0;
    uint64_t idsnClient = 0, idsnServer = 0;

    GenerateTokenForKey( algo, m_c.keyServer, tokenServer, idsnServer);
    GenerateTokenForKey( algo, m_c.keyClient, tokenClient, idsnClient);
    NS_LOG_INFO( "Client: Generated token "<< tokenClient << ". Expected "<< m_c.expectedTokenClient);
    NS_LOG_INFO( "Client: Generated idsn "<< idsnClient << ". Expected "<< m_c.expectedIdsnClient);

    NS_LOG_INFO( "Server: Generated token " << tokenServer << ". Expected "<< m_c.expectedTokenServer);
    NS_LOG_INFO( "Server: Generated idsn " << idsnServer << ". Expected "<< m_c.expectedIdsnServer);
    NS_TEST_EXPECT_MSG_EQ( m_c.expectedTokenClient, tokenClient, "Token generated does not match key (Client)");
    NS_TEST_EXPECT_MSG_EQ( m_c.expectedIdsnClient, idsnClient, "Token generated does not match key (Client)");

    NS_TEST_EXPECT_MSG_EQ( m_c.expectedTokenServer, tokenServer, "Token generated does not match key (Server)");
    NS_TEST_EXPECT_MSG_EQ( m_c.expectedIdsnServer, idsnServer, "Token generated does not match key (Server)");

  }

protected:
  crypto_materials_t m_c;
};


static class TcpOptionMpTcpTestSuite : public TestSuite
{
public:
 TcpOptionMpTcpTestSuite ()
 : TestSuite ("mptcp-crypto", UNIT)
 {

    const uint64_t keyClient = 17578475652852252522U;
    const uint64_t keyServer = 4250710109353306436U;
    // Notice the 'U' suffix at the end of the number . By default compiler
    // considers int as signed, thus triggering a warning
    crypto_materials_t c = {
      .keyClient = keyClient,
      .keyServer = keyServer,
      /*expectedTokenClient computed from SynAck key */
      #ifdef HAVE_CRYPTO
      .expectedTokenClient = 781076417,
      .expectedTokenServer = 109896498,
      #else
      .expectedTokenClient = (uint32_t)keyClient,
      .expectedTokenServer = (uint32_t)keyServer,
      #endif
      .nonceSyn = 4179070691,
      .nonceSynAck = 786372555,
      .expectedHmacSynAck = 17675966670101668951U,
      .expectedHmacAck = 0,
      #ifdef HAVE_CRYPTO
      .expectedIdsnClient =2027218329290435821U,
      .expectedIdsnServer  = 14296996231892742347U
      #else
      .expectedIdsnClient = keyClient,
      .expectedIdsnServer  = keyServer
      #endif
    };

    AddTestCase( new MpTcpCryptoTest(c), QUICK );


 }




} g_TcpCryptoTestSuite;

}
