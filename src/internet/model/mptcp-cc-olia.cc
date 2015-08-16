/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2015 Université Pierre et Marie Curie (UPMC)
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
#include "ns3/mptcp-olia.h"
#include "ns3/log.h"
#include "ns3/object.h"

NS_LOG_COMPONENT_DEFINE("MpTcpCCOlia");


namespace ns3 {



NS_OBJECT_ENSURE_REGISTERED (MpTcpCCOlia);

TypeId
MpTcpCCOlia::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::MpTcpCCOlia")
    .SetParent<TcpCongestionOps> ()
    .AddConstructor<MpTcpCCOlia> ()
//    .AddAttribute ("ReTxThreshold", "Threshold for fast retransmit",
//                    UintegerValue (3),
//                    MakeUintegerAccessor (&TcpNewReno::m_retxThresh),
//                    MakeUintegerChecker<uint32_t> ())
//    .AddAttribute ("LimitedTransmit", "Enable limited transmit",
//		    BooleanValue (false),
//		    MakeBooleanAccessor (&TcpNewReno::m_limitedTx),
//		    MakeBooleanChecker ())
//    .AddTraceSource ("CongestionWindow",
//                     "The TCP connection's congestion window",
//                     MakeTraceSourceAccessor (&MpTcpCCOlia::m_cWnd))
  ;
  return tid;
}


//TypeId
//MpTcpCCOlia::GetInstanceTypeId(void) const
//{
//  return GetTypeId();
//}
std::string
MpTcpCCOlia::GetName(void) const {
    return "OLIA";
};

MpTcpCCOlia::MpTcpCCOlia(void) :
  TcpCongestionOps()
{
  NS_LOG_FUNCTION (this);
}

MpTcpCCOlia::MpTcpCCOlia(const MpTcpCCOlia& sock) :
  TcpCongestionOps(sock)
{
  NS_LOG_FUNCTION (this);
  NS_LOG_LOGIC ("Invoked the copy constructor");
}

MpTcpCCOlia::~MpTcpCCOlia()
{
  NS_LOG_FUNCTION (this);
}


//uint32_t
//MpTcpCCOlia::OpenCWND(uint32_t cwnd, uint32_t ackedBytes) {
//
//  return 1;
//}
//
//uint32_t
//MpTcpCCOlia::ReduceCWND(uint32_t cwnd)
//{
//  return cwnd/2;
//}
//
//  // inherited function, no need to doc.
//TypeId
//MpTcpCCOlia::GetInstanceTypeId (void) const
//{
//  return GetTypeId();
//}

Ptr<MpTcpSocketBase>
MpTcpCCOlia::ForkAsMeta(void)
{
  NS_LOG_UNCOND ("Fork as meta" << this->GetInstanceTypeId() << " to " << GetTypeId());
//  Ptr<MpTcpCCOlia> p =

  return CopyObject<MpTcpCCOlia>(this);
}

uint32_t
MpTcpCCOlia::GetSSThresh(void) const
{
  return 2;
}

virtual Ptr<TcpCongestionOps>
uint32_t MpTcpCCOlia::Fork ()
{
  //!
  return CreateObject<MpTcpCCOlia>(*this);
}

} //end of ns3
