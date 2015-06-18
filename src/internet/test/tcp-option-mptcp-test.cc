/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2015 Matthieu Coudron
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

#include "ns3/test.h"
#include "ns3/drop-tail-queue.h"
#include "ns3/config.h"
#include "ns3/uinteger.h"
#include "ns3/log.h"
#include "ns3/sequence-number.h"

#include "ns3/tcp-option-mptcp.h"
#include <string>

NS_LOG_COMPONENT_DEFINE ("MpTcpOptionsTestSuite");

using namespace ns3;


template<class T>
class TcpOptionMpTcpTestCase : public TestCase
{
public:
  TcpOptionMpTcpTestCase (Ptr<T> configuredOption,std::string desc) : TestCase (desc)
  {
    NS_LOG_FUNCTION (this);
    m_option = configuredOption;
  }

  virtual ~TcpOptionMpTcpTestCase ()
  {
    NS_LOG_FUNCTION (this);
  }

  virtual void TestSerialize (void)
  {
    NS_LOG_INFO ( "option.GetSerializedSize ():" << m_option->GetSerializedSize () );
    m_buffer.AddAtStart ( m_option->GetSerializedSize ());
    m_option->Serialize ( m_buffer.Begin () );


  }

  virtual void TestDeserialize (void)
  {
    T option;
    Buffer::Iterator start = m_buffer.Begin ();
    uint8_t kind = start.PeekU8 ();

    NS_TEST_EXPECT_MSG_EQ (kind, TcpOption::MPTCP, "Option number does not match MPTCP sequence number");

    uint32_t read = option.Deserialize ( start );

    NS_LOG_INFO ("original LEN = " << option.GetSerializedSize () );
    NS_TEST_EXPECT_MSG_EQ ( read, option.GetSerializedSize (), "");

    bool res = (*m_option == option);
    NS_TEST_EXPECT_MSG_EQ ( res,true, "Option loaded after serializing/deserializing are not equal. you should investigate ");
  }


  virtual void DoRun (void)
  {
    TestSerialize ();
    TestDeserialize ();
  }

protected:
  Ptr<T> m_option;
  Buffer m_buffer;
};



static class TcpOptionMpTcpTestSuite : public TestSuite
{
public:
  TcpOptionMpTcpTestSuite ()
    : TestSuite ("tcp-option-mptcp", UNIT)
  {

    ////////////////////////////////////////////////
    //// MP CAPABLE
    ////
    Ptr<TcpOptionMpTcpCapable> mpc = CreateObject<TcpOptionMpTcpCapable> (),
                               mpc2 = CreateObject<TcpOptionMpTcpCapable> ();
    mpc->SetPeerKey (42);
    mpc->SetSenderKey (232323);
    AddTestCase (
      new TcpOptionMpTcpTestCase<TcpOptionMpTcpCapable> (mpc,"MP_CAPABLE with Sender & Peer keys both set"),
      QUICK
      );

    mpc2->SetSenderKey (3);
    AddTestCase (
      new TcpOptionMpTcpTestCase<TcpOptionMpTcpCapable> (mpc2,"MP_CAPABLE with only sender Key set"),
      QUICK
      );



    ////////////////////////////////////////////////
    //// MP PRIORITY
    ////
    Ptr<TcpOptionMpTcpChangePriority> prio = CreateObject<TcpOptionMpTcpChangePriority> (),
                                      prio2 = CreateObject<TcpOptionMpTcpChangePriority> ();

    prio->SetAddressId (3);
    AddTestCase (
      new TcpOptionMpTcpTestCase<TcpOptionMpTcpChangePriority> (prio,"Change priority for a different address"),
      QUICK
      );


    ////////////////////////////////////////////////
    //// MP REMOVE_ADDRESS
    ////
    Ptr<TcpOptionMpTcpRemoveAddress> rem = CreateObject<TcpOptionMpTcpRemoveAddress> ();
    for (uint8_t i = 0; i < 4; ++i)
      {
        Ptr<TcpOptionMpTcpRemoveAddress> rem2 = CreateObject<TcpOptionMpTcpRemoveAddress> ();

        rem->AddAddressId (i);
        rem2->AddAddressId (i);

        AddTestCase (
          new TcpOptionMpTcpTestCase<TcpOptionMpTcpRemoveAddress> (rem,"With X addresses"),
          QUICK
          );

        AddTestCase (
          new TcpOptionMpTcpTestCase<TcpOptionMpTcpRemoveAddress> (rem2,"With 1 address"),
          QUICK
          );

      }


    ////////////////////////////////////////////////
    //// MP ADD_ADDRESS
    ////
    Ptr<TcpOptionMpTcpAddAddress> add = CreateObject<TcpOptionMpTcpAddAddress> ();
    add->SetAddress ( InetSocketAddress ( "123.24.23.32"), 8 );

    AddTestCase (
      new TcpOptionMpTcpTestCase<TcpOptionMpTcpAddAddress> (add,"AddAddress IPv4"),
      QUICK
      );


    ////////////////////////////////////////////////
    //// MP_DSS
    ////
    uint16_t checksum = 32321;

    for (int i = 0; i < 2; ++i)
      {

        Ptr<TcpOptionMpTcpDSS> dss1 = CreateObject<TcpOptionMpTcpDSS> (),
                               dss2 = CreateObject<TcpOptionMpTcpDSS> (),
                               dss3 = CreateObject<TcpOptionMpTcpDSS> (),
                               dss4 = CreateObject<TcpOptionMpTcpDSS> ()
        ;
        if (i > 0)
          {
            dss1->SetChecksum (checksum);
            dss2->SetChecksum (checksum);
            dss3->SetChecksum (checksum);
            dss4->SetChecksum (checksum);
          }



//          MpTcpMapping mapping;
        uint16_t dataLvlLen = 32;
        uint64_t dsn = 54;
        uint32_t ssn = 40;
//          mapping.SetHeadDSN( SequenceNumber32(dsn));
//          mapping.SetMappingSize(dataLvlLen);
//          mapping.MapToSSN( SequenceNumber32(ssn));


        dss1->SetMapping (dsn,ssn,dataLvlLen);


        AddTestCase (
          new TcpOptionMpTcpTestCase<TcpOptionMpTcpDSS> (dss1,"DSN mapping only"),
          QUICK
          );

        dss1->AddDataFin ( (dsn + dataLvlLen + 1), true);
        AddTestCase (
          new TcpOptionMpTcpTestCase<TcpOptionMpTcpDSS> (dss1,"DSN mapping + DFIN"),
          QUICK
          );

        dss1->SetDataAck (45000);
        AddTestCase (
          new TcpOptionMpTcpTestCase<TcpOptionMpTcpDSS> (dss1, "DataAck + DSN mapping + DFIN"),
          QUICK
          );

        dss2->SetDataAck (3210);
        AddTestCase (
          new TcpOptionMpTcpTestCase<TcpOptionMpTcpDSS> (dss2, "DataAck only"),
          QUICK
          );


        dss3->AddDataFin ( 45 );
        AddTestCase (
          new TcpOptionMpTcpTestCase<TcpOptionMpTcpDSS> (dss3, "DataFin only"),
          QUICK
          );

        dss4->AddDataFin ( 32 );
        dss4->SetDataAck (45000);
        AddTestCase (
          new TcpOptionMpTcpTestCase<TcpOptionMpTcpDSS> (dss4, "DataAck + DSN mapping + Datafin"),
          QUICK
          );

      }
    ////////////////////////////////////////////////
    //// MP_JOIN Initial syn
    ////
    Ptr<TcpOptionMpTcpJoin> syn = CreateObject<TcpOptionMpTcpJoin> (),
                            syn2 = CreateObject<TcpOptionMpTcpJoin> ();
//                    TcpOptionMpTcpMain::CreateMpTcpOption(TcpOptionMpTcpMain::MP_JOIN);
//                     CreateObject<TcpOptionMpTcpJoin>();
    syn->SetMode (TcpOptionMpTcpJoin::Syn);
    syn->SetAddressId (4);
    syn->SetPeerToken (5323);
    AddTestCase (
      new TcpOptionMpTcpTestCase<TcpOptionMpTcpJoin> ( syn, "MP_JOIN Syn"),
      QUICK
      );


    ////////////////////////////////////////////////
    //// MP_JOIN synRcvd
    ////
    Ptr<TcpOptionMpTcpJoin> jsr = CreateObject<TcpOptionMpTcpJoin> (),
                            jsr2 = CreateObject<TcpOptionMpTcpJoin> ();
    jsr->SetMode (TcpOptionMpTcpJoin::SynAck);
    jsr->SetAddressId (4);
    jsr->SetTruncatedHmac ( 522323 );
    AddTestCase (
      new TcpOptionMpTcpTestCase<TcpOptionMpTcpJoin> ( jsr, "MP_JOIN Syn Received"),
      QUICK
      );



    ////////////////////////////////////////////////
    //// MP_JOIN SynAck
    ////
    Ptr<TcpOptionMpTcpJoin> jsar = CreateObject<TcpOptionMpTcpJoin> ();
    uint8_t hmac[20] = {3,0};
    jsar->SetMode (TcpOptionMpTcpJoin::Ack);
    jsar->SetHmac ( hmac  );
    AddTestCase (
      new TcpOptionMpTcpTestCase<TcpOptionMpTcpJoin> ( jsar, "MP_JOIN SynAck Received"),
      QUICK
      );


    ////////////////////////////////////////////////
    //// MP_FASTCLOSE
    ////
    Ptr<TcpOptionMpTcpFastClose> close = CreateObject<TcpOptionMpTcpFastClose> ();
    close->SetPeerKey (3232);

    AddTestCase (
      new TcpOptionMpTcpTestCase<TcpOptionMpTcpFastClose> ( close, "MP_Fastclose"),
      QUICK
      );

  }




} g_TcpOptionTestSuite;
