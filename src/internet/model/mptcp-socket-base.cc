/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2015 University of Sussex
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
 * Author:  Matthieu Coudron <matthieu.coudron@lip6.fr>
 *          Morteza Kheirkhah <m.kheirkhah@sussex.ac.uk>
 */
#undef NS_LOG_APPEND_CONTEXT
#define NS_LOG_APPEND_CONTEXT \
  if (m_node) { std::clog << Simulator::Now ().GetSeconds () << " [node " << m_node->GetId () << "] "; }

#include <algorithm>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <map>
#include "ns3/abort.h"
#include "ns3/log.h"
#include "ns3/string.h"
#include "ns3/mptcp-socket-base.h"
#include "ns3/tcp-l4-protocol.h"
#include "ns3/ipv4-l3-protocol.h"
#include "ns3/error-model.h"
#include "ns3/point-to-point-channel.h"
#include "ns3/point-to-point-net-device.h"
#include "ns3/pointer.h"
#include "ns3/drop-tail-queue.h"
#include "ns3/object-vector.h"
#include "ns3/mptcp-scheduler-round-robin.h"
#include "ns3/mptcp-id-manager.h"
#include "ns3/mptcp-id-manager-impl.h"
#include "ns3/mptcp-subflow.h"
#include "ns3/tcp-option-mptcp.h"
#include "ns3/callback.h"
#include "ns3/trace-helper.h"
#include <openssl/sha.h>

NS_LOG_COMPONENT_DEFINE("MpTcpSocketBase");

#define LOOP_THROUGH_SUBFLOWS(sflow)  for(SubflowList::iterator sflow = 0; sflow != m_subflows.end(); ++sflow)




using namespace std;


namespace ns3
{

NS_OBJECT_ENSURE_REGISTERED(MpTcpSocketBase);


static inline
SequenceNumber32 SEQ64TO32(SequenceNumber64 seq)
{
    //!
    return SequenceNumber32( seq.GetValue());
}

static inline
SequenceNumber64 SEQ32TO64(SequenceNumber32 seq)
{
    //!
    return SequenceNumber64( seq.GetValue());
}


//
//  void GetMapping (uint64_t& dsn, uint32_t& ssn, uint16_t& length) const;
//
//  /**
//   * \brief
//   * \param trunc_to_32bits Set to true to send a 32bit DSN
//   * \warn Mapping can be set only once, otherwise it will crash ns3
//   */

//! wrapper function
static inline
MpTcpMapping
GetMapping(Ptr<TcpOptionMpTcpDSS> dss)
{
    MpTcpMapping mapping;
    uint64_t dsn;
    uint32_t ssn;
    uint16_t length;

    dss->GetMapping (dsn, ssn, length);
    mapping.SetHeadDSN( SequenceNumber64(dsn));
    mapping.SetMappingSize(length);
    mapping.MapToSSN( SequenceNumber32(ssn));
    return mapping;
}



TypeId
MpTcpSocketBase::GetTypeId(void)
{
  static TypeId tid = TypeId("ns3::MpTcpSocketBase")
      .SetParent<TcpSocketBase>()
//      .AddConstructor<MpTcpSocketBase>()
// TODO rehabilitate
//      .AddAttribute("SchedulingAlgorithm", "Algorithm for data distribution between m_subflows", EnumValue(Round_Robin),
//          MakeEnumAccessor(&MpTcpSocketBase::SetDataDistribAlgo),
//          MakeEnumChecker(Round_Robin, "Round_Robin"))
//      .AddAttribute("Subflows", "The list of subflows associated to this protocol.",
//          ObjectVectorValue(),
//          MakeObjectVectorAccessor(&MpTcpSocketBase::m_subflows),
//          MakeObjectVectorChecker<MpTcpSocketBase>())
//        )


    ;
  return tid;
}


static const std::string containerNames[MpTcpSocketBase::Maximum] = {
  "Established",
  "Others",
  "Closing"
//  ,
//  "Maximum"

};


// TODO unused for now
MpTcpSocketBase::MpTcpSocketBase(const TcpSocketBase& sock) :
  TcpSocketBase(sock),
  m_tracePrefix("default"),
  m_prefixCounter(1),
  m_server(true), // TODO remove or use it
  m_localKey(0),
  m_localToken(0),
  m_peerKey(0),
  m_peerToken(0),
  m_doChecksum(false),
  m_receivedDSS(false)
//    MpTcpSocketBase()   //! delegatin constructors only available in C++11
{
    //
    NS_LOG_FUNCTION(this);
    NS_LOG_LOGIC("Copying from TcpSocketBase");
    m_remotePathIdManager = Create<MpTcpPathIdManagerImpl>();
    m_scheduler = Create<MpTcpSchedulerRoundRobin>();
    m_scheduler->SetMeta(this);
}


MpTcpSocketBase::MpTcpSocketBase(const MpTcpSocketBase& sock) :
  TcpSocketBase(sock),
  m_tracePrefix(sock.m_tracePrefix),
  m_prefixCounter(1), //!< Start at one
  m_server(sock.m_server), //! true, if I am forked
  m_localKey(sock.m_localKey),
  m_localToken(sock.m_localToken),
  m_peerKey(sock.m_peerKey),
  m_peerToken(sock.m_peerToken),
  m_doChecksum(sock.m_doChecksum),
  m_subflowConnectionSucceeded(sock.m_subflowConnectionSucceeded),
  m_subflowConnectionFailure(sock.m_subflowConnectionFailure),
  m_joinRequest(sock.m_joinRequest),
  m_subflowCreated(sock.m_subflowCreated)

{
  NS_LOG_FUNCTION(this);
  NS_LOG_LOGIC ("Invoked the copy constructor");
  //! Scheduler may have some states, thus generate a new one
  m_remotePathIdManager = Create<MpTcpPathIdManagerImpl>();
  m_scheduler = Create<MpTcpSchedulerRoundRobin>();
  m_scheduler->SetMeta(this);


  //! TODO here I should generate a new Key
}


// TODO implement a copy constructor
MpTcpSocketBase::MpTcpSocketBase() :
  TcpSocketBase(),
  m_tracePrefix("default"),
  m_prefixCounter(1),
  m_server(true),
  m_localKey(0),
  m_localToken(0),
  m_peerKey(0),
  m_peerToken(0),
  m_doChecksum(false),
  m_receivedDSS(false)
{
  NS_LOG_FUNCTION(this);

  //not considered as an Object
  m_remotePathIdManager = Create<MpTcpPathIdManagerImpl>();
  m_scheduler = Create<MpTcpSchedulerRoundRobin>();
  m_scheduler->SetMeta(this);

  m_subflowConnectionSucceeded  = MakeNullCallback<void, Ptr<MpTcpSubflow> >();
  m_subflowConnectionFailure    = MakeNullCallback<void, Ptr<MpTcpSubflow> >();
}


MpTcpSocketBase::~MpTcpSocketBase(void)
{
  NS_LOG_FUNCTION(this);
  m_node = 0;

  if( m_scheduler )
  {

  }
  /*
   * Upon Bind, an Ipv4Endpoint is allocated and set to m_endPoint, and
   * DestroyCallback is set to TcpSocketBase::Destroy. If we called
   * m_tcp->DeAllocate, it will destroy its Ipv4EndpointDemux::DeAllocate,
   * which in turn destroys my m_endPoint, and in turn invokes
   * TcpSocketBase::Destroy to nullify m_node, m_endPoint, and m_tcp.
   */
//  if (m_endPoint != 0)
//    {
//      NS_ASSERT(m_tcp != 0);
//      m_tcp->DeAllocate(m_endPoint);
//      NS_ASSERT(m_endPoint == 0);
//    }
//  m_tcp = 0;
//  CancelAllSubflowTimers();
//  NS_LOG_INFO(Simulator::Now().GetSeconds() << " ["<< this << "] ~MpTcpSocketBase ->" << m_tcp );

  m_subflowConnectionSucceeded = MakeNullCallback<void, Ptr<MpTcpSubflow> >();
  m_subflowCreated = MakeNullCallback<void, Ptr<MpTcpSubflow> >();
  m_subflowConnectionSucceeded = MakeNullCallback<void, Ptr<MpTcpSubflow> >();
}



int
MpTcpSocketBase::ConnectNewSubflow(const Address &local, const Address &remote)
{
  NS_ASSERT_MSG(InetSocketAddress::IsMatchingType(local) && InetSocketAddress::IsMatchingType(remote), "only support ipv4");

  //!
  NS_LOG_LOGIC("Trying to add a new subflow " << InetSocketAddress::ConvertFrom(local).GetIpv4() << "->" << InetSocketAddress::ConvertFrom(remote).GetIpv4());



  // false => not master (this is silly I know)
  Ptr<MpTcpSubflow> sf = CreateSubflow(false);

  NS_ASSERT(sf->Bind(local) == 0);
  NS_ASSERT(sf->Connect(remote) == 0);

//  SetupSubflowTracing(sf);
  return 0;
}

uint64_t
MpTcpSocketBase::GetLocalKey() const
{
  return m_localKey;
}

uint64_t
MpTcpSocketBase::GetPeerKey() const
{
  return m_peerKey;
}


//MpTcpAddressInfo info
// Address info
void
MpTcpSocketBase::NotifyRemoteAddAddr(Address address)
{

  if (!m_onRemoteAddAddr.IsNull())
  {
    // TODO user should not have to deal with MpTcpAddressInfo , info.second
    m_onRemoteAddAddr (this, address, 0);
  }
}


bool
MpTcpSocketBase::DoChecksum() const
{
  return false;
}



MpTcpSocketBase::SubflowList::size_type
MpTcpSocketBase::GetNActiveSubflows() const
{
  return m_subflows[Established].size();
}

  //std::vector<MpTcpSubflow>::size_ uint8
Ptr<MpTcpSubflow>
MpTcpSocketBase::GetSubflow(uint8_t id) const
{
  NS_ASSERT_MSG(id < m_subflows[Established].size(), "Trying to get an unexisting subflow");
  return m_subflows[Established][id];
}



//
//void
//MpTcpSocketBase::EstimateRtt(const TcpHeader& TcpHeader)
//{
//  NS_LOG_FUNCTION(this);
//}


void
MpTcpSocketBase::SetPeerKey(uint64_t remoteKey)
{
//  NS_ASSERT( m_peerKey == 0);
//  NS_ASSERT( m_state != CLOSED);
  uint64_t idsn = 0;
  m_peerKey = remoteKey;

  // not  sure yet. Wait to see if SYN/ACK is acked
  NS_LOG_DEBUG("Peer key set to " << m_peerKey);


  //! TODO generate remote token/IDSN
//  MpTcpSocketBase::GenerateTokenForKey

// TODO use the one  from mptcp-crypo.h
  GenerateTokenForKey(HMAC_SHA1, m_peerKey, m_peerToken, idsn);

  NS_LOG_DEBUG("Peer token set to " << m_peerToken);

  //! TODO Set in TcpSocketBase an attribute to enable idsn random
  // motivation is that it's clearer to plot from 0
  if(m_nullIsn)
  {
    idsn = 0;
  }
  // + 1 ?
  NS_LOG_DEBUG("test");
//  m_rxBuffer->SetNextRxSequence(SequenceNumber32( (uint32_t)idsn ));
}



// TODO this should get reestablished and process the option depending on the state ?
//int
//MpTcpSocketBase::ProcessOptionMpTcp(const Ptr<const TcpOption> opt)
//{
//   NS_FATAL_ERROR("disabled .");
//}



void
MpTcpSocketBase::ProcessListen(Ptr<Packet> packet, const TcpHeader& mptcpHeader, const Address& fromAddress, const Address& toAddress)
{
  // TODO removed
  NS_FATAL_ERROR("disabled");
}


/**
TODO if without option create a NewReno
TODO remove
**/
void
MpTcpSocketBase::CompleteFork(
  Ptr<Packet> p,
  const TcpHeader& mptcpHeader,
  const Address& fromAddress,
  const Address& toAddress
)
{
  NS_LOG_FUNCTION(this);
  NS_FATAL_ERROR("Disabled");
  #if 0
  // Get port and address from peer (connecting host)

  // That should not be the case
//  NS_ASSERT(InetSocketAddress::ConvertFrom(toAddress).GetIpv4() == m_endPoint->GetLocalAddress());
//  NS_ASSERT(InetSocketAddress::ConvertFrom(toAddress).GetPort() == m_endPoint->GetLocalPort());
//
//  NS_ASSERT(InetSocketAddress::ConvertFrom(fromAddress).GetIpv4() == m_endPoint->GetPeerAddress());
//  NS_ASSERT(InetSocketAddress::ConvertFrom(fromAddress).GetPort() == m_endPoint->GetPeerPort());
  Ptr<const TcpOptionMpTcpCapable> mpc;
  NS_ASSERT( GetTcpOption(mptcpHeader, mpc) );

  m_server = true;

  NS_LOG_INFO("peer key " << mpc->GetSenderKey() );
  SetPeerKey( mpc->GetSenderKey() );

  // got moved to constructor
  // TODO generate unique key
//  m_localKey = GenerateKey();

  // We only setup destroy callback for MPTCP connection's endPoints, not on subflows endpoints.
  SetupCallback();

  // Otherwise when looking for the token on an MP_JOIN it is not found
  // TODO this is wrong, TcpL4Protocol now gives CreateSocket etc...
//  m_tcp->m_sockets.push_back(this);
  m_tcp->AddSocket ( this) ;
  // TODO move out to an helper
//  SetupMetaTracing(m_tracePrefix);

  // Create new master subflow (master subsock) and assign its endpoint to the connection endpoint
//  Ptr<MpTcpSubflow> sFlow = CreateSubflowAndCompleteFork(true, mptcpHeader, fromAddress, toAddress);

//  ComputeTotalCWND();

  m_state = SYN_RCVD; // Think of updating it
  NS_LOG_INFO(this << " LISTEN -> SYN_RCVD");
//  NS_ASSERT_MSG(sFlow,"Contact ns3 team");

  // TODO remove that, it should be done by the subflow complete fork
  m_connected = true;

  NotifyNewConnectionCreated(this, fromAddress);

  // As this connection is established, the socket is available to send data now
  if (GetTxAvailable() > 0)
  {
    NotifySend(GetTxAvailable());
  }

  NS_LOG_INFO(this << "MPTCP connection is initiated (Receiver): ");
  #endif
}


 // in fact it just calls SendPendingData()
int
MpTcpSocketBase::Send(Ptr<Packet> p, uint32_t flags)
{
  NS_LOG_FUNCTION(this);

  //! This will check for established state
  return TcpSocketBase::Send(p,flags);
}


// Receipt of new packet, put into Rx buffer
// TODO should be called from subflows only
void
MpTcpSocketBase::ReceivedData(Ptr<Packet> p, const TcpHeader& mptcpHeader)
{
  // Just override parent's
  // Does nothing
  NS_FATAL_ERROR("Disabled");
}

bool
MpTcpSocketBase::UpdateWindowSize(const TcpHeader& header)
{
  //!
  NS_LOG_FUNCTION(this);
  m_rWnd = header.GetWindowSize();
  NS_LOG_DEBUG("Meta Receiver window=" << m_rWnd);
  return true;
}


/*
A receiver MUST NOT shrink the right edge of the receive window (i.e.,
DATA_ACK + receive window)
   */
//void
//MpTcpSocketBase::SetRemoteWindow(uint32_t win_size)
//{
//  //No checks are done here
//  NS_LOG_FUNCTION(" Updating remote window. New m_rWnd=" << win_size );
//  m_rWnd = win_size;
//
//  // Go through all containers
//  for(int i = 0; i < Maximum; ++i) {
//
////    Established
////    NS_LOG_INFO("Closing all subflows in state [" << containerNames [i] << "]");
//    for( SubflowList::const_iterator it = m_subflows[i].begin(); it != m_subflows[i].end(); it++ )
//    {
//      (*it)->m_rWnd = m_rWnd;
//    }
//
//  }
//
//}

//void
//MpTcpSocketBase::DupAck( SequenceNumber32 dack,Ptr<MpTcpSubflow> sf, uint32_t count)
//{
//  //!
//  NS_LOG_ERROR("TODO Duplicate ACK " << dack);
//
////  NS_LOG_WARN("TODO DupAck " << count);
//  /*
//  As discussed earlier, however, an MPTCP
//   implementation MUST NOT treat duplicate ACKs with any MPTCP option,
//   with the exception of the DSS option, as indications of congestion
//
//  and an MPTCP implementation SHOULD NOT send more than two
//   duplicate ACKs
//   */
//}


void
MpTcpSocketBase::ReceivedAck(Ptr<Packet> packet, const TcpHeader& mptcpHeader)
{
  NS_FATAL_ERROR("Disabled");
}

uint32_t
MpTcpSocketBase::SendDataPacket(SequenceNumber32 seq, uint32_t maxSize, bool withAck)
{
//  NS_LOG_FUNCTION (this << "Should do nothing" << maxSize << withAck);
  NS_FATAL_ERROR("Disabled");
  // Disabled
  return 0;
}




/** Cut cwnd and enter fast recovery mode upon triple dupack TODO ?*/
//void
//MpTcpSocketBase::DupAck(const TcpHeader& t, uint32_t count)
//{
//  NS_ASSERT_MSG(false,"Should never be called. Use overloeaded dupack instead");
//
////  NS_LOG_LOGIC("DupAck " << count);
////  NS_LOG_WARN("TODO DupAck " << count);
////  if( count > 3)
////  GetMeta()->OnSubflowDupAck(this);
//
//  //! Regerenate mappings for that
//  //! Reset the m_nextTxSequence to the dupacked value
//
//
////  NS_LOG_FUNCTION (this << "t " << count);
////  if (count == m_retxThresh && !m_inFastRec)
////    { // triple duplicate ack triggers fast retransmit (RFC2581, sec.3.2)
////      m_ssThresh = std::max (2 * m_segmentSize, BytesInFlight () / 2);
////      m_cWnd = m_ssThresh + 3 * m_segmentSize;
////      m_inFastRec = true;
////      NS_LOG_INFO ("Triple dupack. Entering fast recovery. Reset cwnd to " << m_cWnd << ", ssthresh to " << m_ssThresh);
////      DoRetransmit ();
////    }
////  else if (m_inFastRec)
////    { // In fast recovery, inc cwnd for every additional dupack (RFC2581, sec.3.2)
////      m_cWnd += m_segmentSize;
////      NS_LOG_INFO ("In fast recovery. Increased cwnd to " << m_cWnd);
////      SendPendingData (m_connected);
////    };
//}
////...........................................................................................
//

/** Inherit from Socket class: Get the max number of bytes an app can read */
uint32_t
MpTcpSocketBase::GetRxAvailable(void) const
{
  NS_LOG_FUNCTION (this);
  return m_rxBuffer->Available();
}


//void
//MpTcpSocketBase::OnSubflowReset( Ptr<MpTcpSubflow> sf)
//{
//
//}

void
MpTcpSocketBase::OnSubflowClosed(Ptr<MpTcpSubflow> subflow, bool reset)
{
  NS_LOG_LOGIC("Subflow " << subflow  << " definitely closed");
  //! TODO it should remove itself from the list of subflows and when 0 are active
  // it should call CloseAndNotify ?
  if(reset)
  {
    NS_FATAL_ERROR("Case not handled yet.");
  }

//  SubflowList::iterator it = std::find(m_subflows[Closing].begin(), m_subflows[Closing].end(), subflow);
// m_containers[Closing].erase(it);
//NS_ASSERT(it != m_subflows[Closing].end());
  SubflowList::iterator it = std::remove(m_subflows[Closing].begin(), m_subflows[Closing].end(), subflow);
}

void
MpTcpSocketBase::DumpRxBuffers(Ptr<MpTcpSubflow> sf) const
{
  NS_LOG_INFO("=> Dumping meta RxBuffer ");
  m_rxBuffer->Dump();

  // TODO parcourir les sous flots

  for(int i = 0; i < (int)GetNActiveSubflows(); ++i)
  {
    Ptr<MpTcpSubflow> sf = GetSubflow(i);
    NS_LOG_INFO("=> Rx Buffer of subflow=" << sf);
    sf->m_rxBuffer->Dump();
  }
}

//Ptr<Socket> sock
//SequenceNumber32 dataSeq,
/**
TODO the decision to ack is unclear with this structure.
May return a bool to let subflow know if it should return a ack ?
it would leave the possibility for meta to send ack on another subflow

We have to extract data from subflows on a per mapping basis because mappings
may not necessarily be contiguous
**/
void
MpTcpSocketBase::OnSubflowRecv(Ptr<MpTcpSubflow> sf)
{
  NS_LOG_FUNCTION(this << "Received data from subflow=" << sf);
  NS_LOG_INFO("=> Dumping meta RxBuffer before extraction");
  DumpRxBuffers(sf);

//  NS_ASSERT(IsConnected());

  SequenceNumber32 expectedDSN = m_rxBuffer->NextRxSequence();

  /* Extract one by one mappings from subflow */
  while(true)
  {

    Ptr<Packet> p;
    SequenceNumber64 dsn;
    uint32_t canRead = m_rxBuffer->MaxBufferSize() - m_rxBuffer->Size();

    if(canRead <= 0)
    {
      NS_LOG_LOGIC("No free space in meta Rx Buffer");
      break;
    }

    /* Todo tell if we stop to extract only between mapping boundaries or if
    Extract
    */
    p = sf->ExtractAtMostOneMapping(canRead, true, dsn);

    if (p->GetSize() == 0)
    {
      NS_LOG_DEBUG("packet extracted empty.");
      break;
    }

    // THIS MUST WORK. else we removed the data from subflow buffer so it would be lost
    // Pb here, htis will be extracted but will not be saved into the main buffer
    // TODO use an assert instead
//    NS_LOG_INFO( "Meta  << "next Rx" << m_rxBuffer->NextRxSequence() );
    // Notify app to receive if necessary
    NS_LOG_DEBUG( "Before adding to metaRx: RxBufferHead=" << m_rxBuffer->HeadSequence() << " NextRxSequence=" << m_rxBuffer->NextRxSequence());

    if(!m_rxBuffer->Add(p, SEQ64TO32(dsn)))
    {

      NS_FATAL_ERROR("Data might have been lost");
    }

//    NS_ASSERT_MSG(m_rxBuffer->Add(p, dsn), "Data got LOST");
//    NS_ASSERT_MSG(m_rxBuffer->Add(p, dsn), "Data got LOST");
    NS_LOG_DEBUG( "After adding to metaRx: RxBufferHead=" << m_rxBuffer->HeadSequence() << " NextRxSequence=" << m_rxBuffer->NextRxSequence());
  } // end of the while

  // TODO should restablish delayed acks ?
  NS_LOG_UNCOND("=> Dumping RxBuffers after extraction");


//  NS_LOG_INFO("=> After extraction Dumping Rx Buffer of subflow " << sf);
  DumpRxBuffers(sf);
//  sf->m_rxBuffer->Dump();

  if (expectedDSN < m_rxBuffer->NextRxSequence())
    {
      NS_LOG_LOGIC("The Rxbuffer advanced");

      // NextRxSeq advanced, we have something to send to the app
      if (!m_shutdownRecv)
        {
          //<< m_receivedData
          NS_LOG_LOGIC("Notify data Rcvd" );
          NotifyDataRecv();

        }
      // Handle exceptions
      if (m_closeNotified)
        {
          NS_LOG_WARN ("Why TCP " << this << " got data after close notification?");
        }
      // If we received FIN before and now completed all "holes" in rx buffer,
      // invoke peer close procedure
      // TODO this should be handled cautiously. TO reenable later with the correct
      // MPTCP syntax
//      if (m_rxBuffer->Finished() && (tcpHeader.GetFlags() & TcpHeader::FIN) == 0)
//        {
//          DoPeerClose();
//        }
    }

}

/**
TODO check that it autodisconnects when we destroy the object ?
**/
//void
//MpTcpSocketBase::OnSubflowNewCwnd(std::string context, uint32_t oldCwnd, uint32_t newCwnd)
//{
//  NS_LOG_LOGIC("Subflow updated window from " << oldCwnd << " to " << newCwnd
////        << " (context=" << context << ")"
//        );
//
//  //
////  m_cWnd = ComputeTotalCWND();
//}


/**
TODO add a MakeBoundCallback that accepts a member function as first input
**/
static void
onSubflowNewState(
//  std::string context,
  Ptr<MpTcpSocketBase> meta,
  Ptr<MpTcpSubflow> sf,
  TcpSocket::TcpStates_t  oldState,
  TcpSocket::TcpStates_t newState
  )
{
  NS_LOG_UNCOND("onSubflowNewState wrapper");
    meta->OnSubflowNewState(
      "context", sf, oldState, newState);
}

/**
TODO use it to Notify user of
We need a MakeBoundCallback
*/
void
MpTcpSocketBase::OnSubflowNewState(std::string context,
  Ptr<MpTcpSubflow> sf,
  TcpSocket::TcpStates_t  oldState,
  TcpSocket::TcpStates_t newState
)
{
  NS_LOG_LOGIC("subflow " << sf << " state changed from " << TcpStateName[oldState] << " to " << TcpStateName[newState]);
  NS_LOG_LOGIC("Current rWnd=" << m_rWnd);

  ComputeTotalCWND();

  if(sf->IsMaster() && newState == SYN_RCVD)
  {
      //!
      NS_LOG_LOGIC("moving meta to SYN_RCVD");
      m_server = true;
      m_state = SYN_RCVD;
      m_rWnd = sf->m_rWnd;
  }

  // Only react when it gets established
  if(newState == ESTABLISHED)
  {
    //!
    MoveSubflow(sf, Others, Established);

    // subflow did SYN_RCVD -> ESTABLISHED
    if(oldState == SYN_RCVD)
    {
      NS_LOG_LOGIC("Subflow created");
//      Simulator::ScheduleNow(&MpTcpSocketBase::OnSubflowEstablished, this, sf);
      // TODO schedule it else it sends nothing ?
      OnSubflowEstablished(sf);
    }
    // subflow did SYN_SENT -> ESTABLISHED
    else if(oldState == SYN_SENT)
    {
      // TODO schedule it else it sends nothing ?
//      Simulator::ScheduleNow(&MpTcpSocketBase::OnSubflowEstablishment, this, sf);
      OnSubflowEstablishment(sf);
    }
    else
    {
      NS_FATAL_ERROR("Unhandled case");
    }
  }

}

/*
Create in SYN/RCVD mode
*/
//  CompleteFork(Ptr<Packet> p, const TcpHeader& h, const Address& fromAddress, const Address& toAddress);
// TODO remove
#if 0
Ptr<MpTcpSubflow>
MpTcpSocketBase::CreateSubflowAndCompleteFork(
  bool masterSocket,
//  Ptr<Packet> p,
 const TcpHeader& mptcpHeader, const Address& fromAddress, const Address& toAddress
)
{
  NS_LOG_FUNCTION(this);

  Ptr<MpTcpSubflow> sFlow = CreateSubflow(masterSocket);

  Ptr<Packet> p = Create<Packet>();


//
//  Simulator::ScheduleNow(
//      &MpTcpSubflow::CompleteFork,
//      sFlow,
//      p,
//      mptcpHeader,
//      fromAddress,
//      toAddress
//    );
  sFlow->CompleteFork(p, mptcpHeader, fromAddress,toAddress);
//  SetupSubflowTracing(sFlow);

  //! TODO steal endpoint ?
  if(sFlow->IsMaster())
  {
    m_endPoint = sFlow->m_endPoint;
  }

  return sFlow;
}
#endif
/*
TODO it should block subflow creation until it received a DSS on a new subflow
TODO rename ? CreateAndAdd? Add ? Start ? Initiate
TODO do it so that it does not return the subflow. Should make for fewer mistakes

C'est là qu'il faut activer le socket tracing
*/

Ptr<MpTcpSubflow>
MpTcpSocketBase::CreateSubflow(
                               bool masterSocket
                               )
{
  NS_LOG_FUNCTION(this);
//  NS_ASSERT_MSG(
//  InetSocketAddress::IsMatchingType(_srcAddr),
//  InetSocketAddress srcAddr = InetSocketAddress::ConvertFrom(_srcAddr);

  // TODO could replaced that by the number of established subflows
  // rename getSubflow by
  if( IsConnected() )
  {

    //! Before allowing more subflows, we need to check if we already received a DSS ! (cf standard)
//    if(!IsMpTcpEnabled())
//    {
//      NS_LOG_ERROR("Remote host does not seem MPTCP compliant so impossible to create additionnal subflows");
////      return -ERROR_INVAL;
//      return 0;
//    }
  }
  //else if( GetNActiveSubflows() > 0 )
  else if( m_state == SYN_SENT || m_state == SYN_RCVD)
  {
    // throw an assert here instead ?
    NS_LOG_ERROR("Already attempting to establish a connection");
    return 0;
  }
  // TODO remove CLOSEWAIT right ?
  else if(m_state == TIME_WAIT || m_state == CLOSE_WAIT || m_state == CLOSING)
  {
    NS_LOG_ERROR("Not allowed to  create new subflow ");
    return 0;
  }

// Subflow got no endpoint yet
  // TODO pass CC
//  m_congestionControl->GetInstanceTypeId()
//GetMpTcpSubflowTypeId
  Ptr<Socket> sock = m_tcp->CreateSocket();

  Ptr<MpTcpSubflow> sFlow = DynamicCast<MpTcpSubflow>(sock);
  // So that we know when the connection gets established
  //sFlow->SetConnectCallback( MakeCallback (&MpTcpSocketBase::OnSubflowEstablishment, Ptr<MpTcpSocketBase>(this) ) );
  sFlow->SetMeta(this);

  // TODO Maybe useless, master could be recognized based on endpoint  or mptcp state
  sFlow->m_masterSocket = masterSocket;


  /**
  We need to update MPTCP level cwin every time a subflow window is updated,
  thus we resort to the tracing system to track subflows cwin
  **/
  NS_ASSERT_MSG( sFlow, "Contact ns3 team");
  m_subflows[Others].push_back( sFlow );
  NS_LOG_INFO ( "subflow " << sFlow << " associated with node " << sFlow->m_node);
  return sFlow;
}


void
MpTcpSocketBase::OnSubflowCreated (Ptr<Socket> socket, const Address &from)
{
    NS_LOG_LOGIC(this);
    Ptr<MpTcpSubflow> sf = DynamicCast<MpTcpSubflow>(socket);

    NotifySubflowCreated(sf);
}

void
MpTcpSocketBase::OnSubflowConnectionSuccess (Ptr<Socket> socket)
{

    NS_LOG_LOGIC(this);
    Ptr<MpTcpSubflow> sf = DynamicCast<MpTcpSubflow>(socket);
    NotifySubflowConnected(sf);
}

void
MpTcpSocketBase::OnSubflowConnectionFailure (Ptr<Socket> socket)
{
    NS_LOG_LOGIC(this);
    Ptr<MpTcpSubflow> sf = DynamicCast<MpTcpSubflow>(socket);
    if(sf->IsMaster())
    {
        TcpSocketBase::NotifyConnectionFailed();
    }
    else
    {
        // use a specific callback
        NS_FATAL_ERROR("TODO");
    }
}

//
//  Ptr<MpTcpSubflow>
//Ptr<MpTcpSubflow>
void
MpTcpSocketBase::AddSubflow(Ptr<MpTcpSubflow> sflow)
{
  NS_LOG_FUNCTION(sflow);

//  Ptr<MpTcpSubflow> sf = DynamicCast<MpTcpSubflow>(sflow);
  Ptr<MpTcpSubflow> sf = sflow;
  bool ok;
// ok = sf->TraceConnect ("CongestionWindow", "CongestionWindow", MakeCallback(&MpTcpSocketBase::OnSubflowNewCwnd, this));
//  NS_ASSERT_MSG(ok, "Tracing mandatory to update the MPTCP global congestion window");

  //! We need to act on certain subflow state transitions according to doc "There is not a version with bound arguments."
    //  NS_ASSERT(sFlow->TraceConnect ("State", "State", MakeCallback(&MpTcpSocketBase::OnSubflowNewState, this)) );
  ok = sf->TraceConnectWithoutContext ("State", MakeBoundCallback(&onSubflowNewState, this, sf));
  NS_ASSERT_MSG(ok, "Tracing mandatory to update the MPTCP socket state");

  if(sf->IsMaster())
  {
      //! then we update
      m_state = sf->GetState();
      m_mptcpLocalKey = sf->m_mptcpLocalKey;
      m_mptcpLocalToken = sf->m_mptcpLocalToken;

      // Those may be overriden later
      m_endPoint = sf->m_endPoint;
      m_endPoint6 = sf->m_endPoint6;
  }

  //!
  sf->SetMeta(this);

  /* We override here callbacks so that subflows
  don't communicate with the applications directly. The meta socket will
  */
//  sf->SetSendCallback ( MakeCallback);
  sf->SetConnectCallback (MakeCallback (&MpTcpSocketBase::OnSubflowConnectionSuccess,this),
                          MakeCallback (&MpTcpSocketBase::OnSubflowConnectionFailure,this));   // Ok
  sf->SetAcceptCallback (
                         MakeNullCallback<bool, Ptr<Socket>, const Address &>(),
//                         MakeCallback (&MpTcpSocketBase::NotifyConnectionRequest,this)
                         MakeCallback (&MpTcpSocketBase::OnSubflowCreated,this));
  // Il y a aussi les!
//  sf->SetCloseCallbacks
//  sf->SetDataSentCallback (  );
//  sf->RecvCallback (cbRcv);




  m_subflows[Others].push_back( sf );


}



/**
I ended up duplicating this code to update the meta r_Wnd,
which would have been hackish otherwise

**/
//void
//MpTcpSocketBase::DoForwardUp(Ptr<Packet> packet, Ipv4Header header, uint16_t port, Ptr<Ipv4Interface> incomingInterface)
//{
//  NS_LOG_FUNCTION(this);
//  TcpSocketBase::DoForwardUp(packet,header,port,incomingInterface);
//
//}
void
MpTcpSocketBase::ForwardUp (Ptr<Packet> packet, Ipv4Header header, uint16_t port, Ptr<Ipv4Interface> incomingInterface)
{
    NS_LOG_DEBUG(this << " called with endpoint " << m_endPoint);
    NS_FATAL_ERROR("This socket should never receive any packet");
//    TcpSocketBase::ForwardUp(packet, header, port, incomingInterface);
}

uint32_t
MpTcpSocketBase::GetToken() const
{
//  NS_ASSERT(m_state != SYN);
  return m_localToken;
}


Ipv4EndPoint*
MpTcpSocketBase::NewSubflowRequest(
//Ptr<Packet> p,
const TcpHeader & header,
const Address & fromAddress,
const Address & toAddress,
Ptr<const TcpOptionMpTcpJoin> join
)
{
  NS_LOG_LOGIC("Received request for a new subflow while in state " << TcpStateName[m_state]);
  NS_LOG_WARN("TODO check if destination exists here");
  NS_ASSERT(InetSocketAddress::IsMatchingType(fromAddress) && InetSocketAddress::IsMatchingType(toAddress));
  //join->GetState() == TcpOptionMpTcpJoin::Syn &&
  NS_ASSERT(join->GetPeerToken() == m_localToken);

  //! TODO check we can accept the creation of a new subflow (did we receive a DSS already ?)
//  NS_ASSERT(m_state == ESTABLISHED);

  //! TODO here we should trigger a callback to say if we accept the connection or not
  // (and create a helper that acts as a path manager)
  // TODO use m_receivedDSS
  bool accept_connection = true;
  if(!accept_connection)
  {
    NS_LOG_LOGIC("Refusing establishement of a new subflow");
    return 0;
  }
  Ptr<MpTcpSubflow> subflow ;
  //! accepted subflow false => not master
  // TODO move part of the code here really
#if 0
  Ptr<MpTcpSubflow> subflow = CreateSubflowAndCompleteFork(
      false,
// TODO pass the packet
      header,
      fromAddress,
      toAddress
      );
#endif
//  NS_ASSERT_MSG(subflow->Bind(toAddress) == 0, "TODO we didn't check that dest ip belonged to the same node, hence this error; subflow should never have been created !!");

//  subflow->Listen();


//  Schedule()
  return subflow->m_endPoint;
}


/**
Need to override parent's otherwise it allocates an endpoint to the meta socket
and upon connection , the tcp subflow can't allocate
TODO remove
*/
int
MpTcpSocketBase::Connect(const Address & toAddress)
{
  NS_LOG_FUNCTION(this);

  // TODO may have to set m_server to false here
  NS_FATAL_ERROR("TODO rmeove");
  return -1;
#if 0
// generated either on connect or fork
//  m_localKey = GenerateKey();
  m_localKey = 42;


  if( IsConnected() )
  {
    NS_LOG_WARN("Trying to connect meta while already connected");
    return -ERROR_ISCONN; // INVAL ?
  }

  //! TODO should generate a key
  if (m_state == CLOSED || m_state == LISTEN || m_state == SYN_SENT || m_state == LAST_ACK || m_state == CLOSE_WAIT)
    {
      m_server = false;

      Ptr<MpTcpSubflow> sFlow = CreateSubflow(true);

      // This function will allocate a new one
      int ret = sFlow->Connect(toAddress);
//      SetupSubflowTracing(sFlow);

      if(ret != 0)
      {
        NS_LOG_ERROR("Could not connect but why ? TODO destroy subflow");
        // TODO destroy
        return ret;
      }
      // NS_LOG_INFO ("looks like successful connection");

      /**
      * We need to copy the m_endPoint and prevent it from being unallocated otherwise
      a 2nd socket could be created again and *overrides* this one .
      */
      if(sFlow->IsMaster())
      {
        m_endPoint = sFlow->m_endPoint;
      }


//      m_endPoint6 = sFlow->m_endPoint6;

//      m_subflows[Others].push_back( sFlow );

//      NS_ASSERT( );
//      SendEmptyPacket(TcpHeader::SYN);
      NS_LOG_INFO (TcpStateName[m_state] << " -> SYN_SENT");
      m_state = SYN_SENT;

      return ret;
    }
  else if (m_state != TIME_WAIT)
    { // In states SYN_RCVD, ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, and CLOSING, an connection
      // exists. We send RST, tear down everything, and close this socket.
      // TODO
//      SendRST();
//      CloseAndNotify();
      NS_LOG_UNCOND("Time wait");
      return -ERROR_ADDRINUSE;
    }

  return DoConnect();
#endif
}

/** This function closes the endpoint completely. Called upon RST_TX action. */
void
MpTcpSocketBase::SendRST(void)
{
  NS_FATAL_ERROR("TO REMOVE, use SendFastClose instead");
}

void
MpTcpSocketBase::SendFastClose(Ptr<MpTcpSubflow> sf)
{
  NS_LOG_LOGIC ("Sending MP_FASTCLOSE");
//  NS_FATAL_ERROR("TODO");
  // TODO: send an MPTCP_fail
   TcpHeader header;
//   Ptr<MpTcpSubflow> sf = GetSubflow(0);
  sf->GenerateEmptyPacketHeader(header, TcpHeader::RST);
  Ptr<TcpOptionMpTcpFastClose> opt = Create<TcpOptionMpTcpFastClose>();

  opt->SetPeerKey( GetPeerKey() );

  sf->SendEmptyPacket(header);

  //! Enter TimeWait ?
//  NotifyErrorClose();
  TimeWait();
//  DeallocateEndPoint();
}


int
MpTcpSocketBase::DoConnect(void)
{
  NS_LOG_FUNCTION (this << "Disabled");
//DeAllocate
//  if(IsConnected()) {
//    NS_LOG_WARN(this << " is already connected");
//    return -1;
//  }
  return 0;
}

void
MpTcpSocketBase::ConnectionSucceeded(void)
{
  NS_LOG_FUNCTION(this);
   m_connected = true;
   TcpSocketBase::ConnectionSucceeded();
}

// TODO move to TcpSocketBase
bool
MpTcpSocketBase::IsConnected() const
{
  return m_connected;
}



//int
//MpTcpSocketBase::Connect(const Address &address)
//{
//  NS_LOG_FUNCTION ( this << address );
//  // this should call our own DoConnect
//  return TcpSocketBase::Connect(address);
//}


/** Inherited from Socket class: Bind socket to an end-point in MpTcpL4Protocol
TODO convert to noop
*/
int
MpTcpSocketBase::Bind()
{
  NS_LOG_FUNCTION (this);
  NS_FATAL_ERROR("TO remove");
  m_server = true;
  m_endPoint = m_tcp->Allocate();  // Create endPoint with ephemeralPort
  if (0 == m_endPoint)
    {
      m_errno = ERROR_ADDRNOTAVAIL;
      return -1;
    }
  //m_tcp->m_sockets.push_back(this); // We don't need it for now
  return SetupCallback();
}

/** Clean up after Bind operation. Set up callback function in the end-point */
int
MpTcpSocketBase::SetupCallback()
{
  NS_LOG_FUNCTION(this);
  return TcpSocketBase::SetupCallback();
}

/** Inherit from socket class: Bind socket (with specific address) to an end-point in TcpL4Protocol
cconvert to noop
*/
int
MpTcpSocketBase::Bind(const Address &address)
{
  NS_LOG_FUNCTION (this<<address);
  NS_FATAL_ERROR("TO remove");

  return TcpSocketBase::Bind(address);
}



// CAREFUL, note that here it's SequenceNumber64
//void
//MpTcpSocketBase::NewAck(SequenceNumber64 const& dataLevelSeq)
//{
//  //!
//
//}

/*
Notably, it is only DATA_ACKed once all
data has been successfully received at the connection level.  Note,
therefore, that a DATA_FIN is decoupled from a subflow FIN.  It is
only permissible to combine these signals on one subflow if there is
no data outstanding on other subflows.
*/
void
MpTcpSocketBase::PeerClose( SequenceNumber32 dsn, Ptr<MpTcpSubflow> sf)
{
  NS_LOG_LOGIC("Datafin with seq=" << dsn);


//  SequenceNumber32 dsn = SequenceNumber32 (dss->GetDataFinDSN() );
  // TODO the range check should be generalized somewhere else
  if( dsn < m_rxBuffer->NextRxSequence() || m_rxBuffer->MaxRxSequence() < dsn)
  {

    NS_LOG_INFO("dsn " << dsn << " out of expected range [ " << m_rxBuffer->NextRxSequence()  << " - " << m_rxBuffer->MaxRxSequence() << " ]" );
    return ;
  }


  // For any case, remember the FIN position in rx buffer first
  //! +1 because the datafin doesn't count as payload
  // TODO rename mapping into GetDataMapping
//  NS_LOG_LOGIC("Setting FIN sequence to " << dss->GetMapping().TailDSN());
  m_rxBuffer->SetFinSequence(dsn);
  NS_LOG_LOGIC ("Accepted MPTCP FIN at seq " << dsn);

  // Return if FIN is out of sequence, otherwise move to CLOSE_WAIT state by DoPeerClose
  if (!m_rxBuffer->Finished())
  {
    NS_LOG_WARN("Out of range");
    return;
  }

//  NS_LOG_LOGIC ("Accepted DATA FIN at seq " << tcpHeader.GetSequenceNumber () + SequenceNumber32 (p->GetSize ()));

  // Simultaneous close: Application invoked Close() when we are processing this FIN packet
  TcpStates_t old_state = m_state;
  switch(m_state)
  {
    case FIN_WAIT_1:
      m_state = CLOSING;
      break;

    case FIN_WAIT_2:
      // will go into timewait later
      TimeWait();
      break;

    case ESTABLISHED:
      m_state = CLOSE_WAIT;
      break;

    default:
      NS_FATAL_ERROR("Should not be here");
      break;
  };

  NS_LOG_INFO(TcpStateName[old_state] << " -> " << TcpStateName[m_state]);


//  if (m_state == FIN_WAIT_1 || m_state == FIN_WAIT_2 || m_state == ESTABLISHED)
//    {
//      NS_LOG_INFO ("FIN_WAIT_1 -> CLOSING");
//      m_state = CLOSING;

      // TODO should send dataACK
      TcpHeader header;
      sf->GenerateEmptyPacketHeader(header,TcpHeader::ACK);
      sf->AppendDSSAck();
      sf->SendEmptyPacket(header);
//      return;
//    }


//   DoPeerClose();
}

void
MpTcpSocketBase::OnInfiniteMapping(Ptr<TcpOptionMpTcpDSS> dss, Ptr<MpTcpSubflow> sf)
{
  NS_FATAL_ERROR("Infinite mapping not implemented");
}



/**
this function supposes that
TODO is  never called apparently
**/
void
MpTcpSocketBase::OnSubflowNewAck(Ptr<MpTcpSubflow> subflow)
{
  NS_LOG_LOGIC("new subflow ack " );
//  SyncTxBuffers(subflow);
  SyncTxBuffers();
}


void
MpTcpSocketBase::SyncTxBuffers()
{
  NS_LOG_LOGIC("Syncing Tx buffer with all subflows");
  for(int i = 0; i < Maximum; ++i) {

//    Established
//    NS_LOG_INFO("Closing all subflows in state [" << containerNames [i] << "]");
    for( SubflowList::const_iterator it = m_subflows[i].begin(); it != m_subflows[i].end(); it++ )
    {

//      SubflowList::iterator it = std::find(m_subflows[i].begin(), m_subflows[i].end(), subflow);
//      NS_ASSERT(it != m_subflows[from].end() ); //! the subflow must exist
//      if(it != m_subflows[i].end()) {
      SyncTxBuffers(*it);
    }
  }


  ComputeTotalCWND();


  // TODO remove it maybe (check) ?
  // TODO I should go through all
  // TODO that should be triggered !!! it should ask the meta for data rather !
  if (GetTxAvailable() > 0)
    {
      NS_LOG_INFO("Tx available" << GetTxAvailable());
      NotifySend(GetTxAvailable());
    }



  // if no more data and socket closing
  if (m_txBuffer->Size() == 0 && m_state != FIN_WAIT_1 && m_state != CLOSING)
    { // No retransmit timer if no data to retransmit
      NS_LOG_WARN (this << " Cancelled ReTxTimeout event which was set to expire at " <<
          (Simulator::Now () + Simulator::GetDelayLeft (m_retxEvent)).GetSeconds ());
      m_retxEvent.Cancel();
      return;
    }

  // Partie que j'ai ajoutée to help closing the connection
  // maybe remove some of it
  if (m_txBuffer->Size() == 0)
    {
      // In case we m_RxBuffer m_rxBuffer->Finished()
      // m_highTxMark + SequenceNumber32(1)
      // TODO maybe
//      if(m_state == FIN_WAIT_1 && m_txBuffer->Size() == 0 &&  (dsn == m_txBuffer->HeadSequence() + SequenceNumber32(1) ) ) {
      if(m_state == FIN_WAIT_1 && m_txBuffer->Size() == 0
      &&  (FirstUnackedSeq() ==  m_txBuffer->HeadSequence() + SequenceNumber32(1) ) ) {

        NS_LOG_LOGIC("FIN_WAIT_1 -> FIN_WAIT_2 ");
        m_state=FIN_WAIT_2;
        TcpHeader header;

        Ptr<MpTcpSubflow> sf = GetSubflow(0);
        sf->GenerateEmptyPacketHeader(header, TcpHeader::ACK);
        sf->AppendDSSAck();
        sf->SendEmptyPacket(header);
        //!

      }
//      else if (m_state == FIN_WAIT_2) {
////        Send DACK for DFIN
//        NS_LOG_INFO("FIN_WAIT_2 test");
//        CloseAllSubflows();
//      }
//      else if (m_state == FIN_WAIT_1) {
//        //!
//      }


      return;
    }
  // in case it freed some space in cwnd, try to send more data
  SendPendingData(m_connected);
}


// TODO maybe add a bool to ask for
//SequenceNumber32 const& ack,
void
MpTcpSocketBase::SyncTxBuffers(Ptr<MpTcpSubflow> subflow)
{

  NS_LOG_LOGIC("Syncing TxBuffer between meta " << this << " and subflow " << subflow);

  while(true)
  {
//    SequenceNumber32 dack = 0;
    MpTcpMapping mapping;

    if(!subflow->DiscardAtMostOneTxMapping( SEQ32TO64(FirstUnackedSeq()), mapping ))
    {
      NS_LOG_DEBUG("Nothing discarded");
      break;
    }

    /**
    returned mapping discarded because we don't support NR sack right now
    **/
    NS_LOG_DEBUG("subflow Tx mapping " << mapping << " discarded");

    /*
    DiscardUpTo  Discard data up to but not including this sequence number.
    */
    m_txBuffer->DiscardUpTo( SEQ64TO32(mapping.TailDSN()) + SequenceNumber32(1));
  }
}


/**
TODO call 64bits  version ?
It should know from which subflow it comes from
TODO update the r_Wnd here


This is not really possible until we change the buffer system:
"The sender MUST keep data in its send buffer as long as the data has
not been acknowledged at both connection level and on all subflows on
which it has been sent."

TODO:


**/

void
MpTcpSocketBase::UpdateTxBuffer()
{
    NS_LOG_LOGIC("Synchronizing buffers");

    SyncTxBuffers();
}


void
MpTcpSocketBase::NewAck(SequenceNumber32 const& dsn)
{
  NS_LOG_FUNCTION(this << " new dataack=[" <<  dsn << "]");

  TcpSocketBase::NewAck(dsn);

  #if 0

  // update tx buffer
  // TODO if I call this, it crashes because on the MpTcpBase client, there is no endpoint configured
  // so it tries to connect to IPv6 node
//  TcpSocketBase::NewAck( seq  );

  // Retrieve the highest m_txBuffer

  // Is done at subflow lvl alread
  // should be done from here for all subflows since
  // a same mapping could have been attributed to for allo
  // BUT can't be discarded if not acklowdged at subflow level so...
//  sf->DiscardTxMappingsUpToDSN( m_txBuffer->HeadSequence() );
//    in that fct
//  discard

//  NS_LOG_FUNCTION (this << dsn);

// TODO reestablish
  if (m_state != SYN_RCVD)
    { // Set RTO unless the ACK is received in SYN_RCVD state
      NS_LOG_LOGIC (this << " Cancelled ReTxTimeout event which was set to expire at " <<
          (Simulator::Now () + Simulator::GetDelayLeft (m_retxEvent)).GetSeconds ());
      m_retxEvent.Cancel();
      // On recieving a "New" ack we restart retransmission timer .. RFC 2988
      m_rto = ComputeRTO();
      NS_LOG_LOGIC (this << " Schedule ReTxTimeout at time " <<
          Simulator::Now ().GetSeconds () << " to expire at time " <<
          (Simulator::Now () + m_rto.Get ()).GetSeconds ());
      m_retxEvent = Simulator::Schedule(m_rto, &MpTcpSocketBase::ReTxTimeout, this);
    }

  // TODO update m_rWnd
  if (m_rWnd.Get() == 0 && m_persistEvent.IsExpired())
    { // Zero window: Enter persist state to send 1 byte to probe
      NS_LOG_LOGIC (this << "Enter zerowindow persist state");NS_LOG_LOGIC (this << "Cancelled ReTxTimeout event which was set to expire at " <<
          (Simulator::Now () + Simulator::GetDelayLeft (m_retxEvent)).GetSeconds ());
      m_retxEvent.Cancel();
      NS_LOG_LOGIC ("Schedule persist timeout at time " <<
          Simulator::Now ().GetSeconds () << " to expire at time " <<
          (Simulator::Now () + m_persistTimeout).GetSeconds ());
      m_persistEvent = Simulator::Schedule(m_persistTimeout, &MpTcpSocketBase::PersistTimeout, this);
      NS_ASSERT(m_persistTimeout == Simulator::GetDelayLeft (m_persistEvent));
    }
//    #endif
  // Note the highest ACK and tell app to send more
  NS_LOG_LOGIC ("TCP " << this << " NewAck " << dsn <<
      " nbAckedBytes " << (dsn - FirstUnackedSeq())); // Number bytes ack'ed


  /**
  This is possible because packets were copied int osubflows buffers, and that there is no intent to
  reinject them on other paths
//  m_txBuffer->DiscardUpTo(dsn);
  TODO here I should
  **/
  m_firstTxUnack = std::min(dsn, m_txBuffer->TailSequence());;



  // TODO wrong. what happens with NR-SACK ?
  if (m_firstTxUnack > m_nextTxSequence)
    {
      m_nextTxSequence = m_firstTxUnack; // If advanced
    }



  #endif
}

bool
MpTcpSocketBase::IsInfiniteMappingEnabled() const
{
    return false;
}

// Send 1-byte data to probe for the window size at the receiver when
// the local knowledge tells that the receiver has zero window size
// C.f.: RFC793 p.42, RFC1112 sec.4.2.2.17
void
MpTcpSocketBase::PersistTimeout()
{
  NS_LOG_LOGIC ("PersistTimeout expired at " << Simulator::Now ().GetSeconds ());
  NS_FATAL_ERROR("TODO");
}

/**
 * Sending data via subflows with available window size.
 * Todo somehow rename to dispatch
 * we should not care about IsInfiniteMapping()
 */

bool
MpTcpSocketBase::SendPendingData(bool withAck)
{
  NS_LOG_FUNCTION(this << "Sending data" << TcpStateName[m_state]);

//  MappingList mappings;
  if (m_txBuffer->Size () == 0)
    {
      NS_LOG_DEBUG("Nothing to send");
      return false;                           // Nothing to send
    }
  //start/size
  int nbMappingsDispatched = 0; // mimic nbPackets in TcpSocketBase::SendPendingData

  MappingVector mappings;
  SequenceNumber32 dsnHead;
  SequenceNumber32 ssn;
  int subflowArrayId;
  uint16_t length;

  //mappings.reserve( GetNActiveSubflows() );
  // the MapToSsn will be done,
  // dsn, size, and path instead of a unmapped mapping
  // GenerateMapping( sf, );

  while(m_scheduler->GenerateMapping(subflowArrayId, dsnHead, length))
  {
      bool ok = GetSubflow(subflowArrayId)->AddLooseMapping(dsnHead, length);
      NS_ASSERT(ok);
  }




  // Then we loop through subflows to see if the dsn was mapped to the subflow
  // this allows to send the same data over different subflows
    for(int i = 0; i < (int)GetNActiveSubflows() ; i++ )
    {
        Ptr<MpTcpSubflow> sf = GetSubflow(i);

        std::vector<> temp;
        sf->GetMappedButMissingData(temp);

        // go through the unsent meta Tx buffer
        // and check if any part of it is mapped in a subflow
        for(it = temp.begin(); it != temp.end(); ++it)
//        while(sf->CanMapDSN2SSN(dsnHead, len))
        {
            // Extract the mapped part
            // temp
            Ptr<Packet> p = m_txBuffer->CopyFromSequence(mapping.GetLength(), SEQ64TO32(mapping.HeadDSN()));
            sf->Send(p, 0);

            //TODO update m_nextTx / txmark
        }
    }


  // Just dump the generated mappings
//  NS_LOG_UNCOND("=================\nGenerated " << mappings.size() << " mappings for node=" << (int)GetNode()->GetId());
//  for(MappingVector::iterator it(mappings.begin()); it  != mappings.end(); it++ )
//  {
//    MpTcpMapping& mapping = it->second;
//    NS_LOG_UNCOND("Send " << it->second << " on sf id=" << (int)it->first);
//  }
//  NS_LOG_UNCOND("=================");
//
////  NS_ASSERT_MSG( mappings.size() == GetNActiveSubflows(), "The number of mappings should be equal to the nb of already established subflows" );
//
//  NS_LOG_DEBUG("generated [" << mappings.size() << "] mappings");
//  // TODO dump mappings ?
//  // Loop through mappings and send Data
////  for(int i = 0; i < (int)GetNActiveSubflows() ; i++ )
//  for(MappingVector::iterator it(mappings.begin()); it  != mappings.end(); it++ )
//  {
//
//
//    Ptr<MpTcpSubflow> sf = GetSubflow(it->first);
//    MpTcpMapping& mapping = it->second;
////    Retrieve data  Rename SendMappedData
//    //SequenceNumber32 dataSeq = mappings[i].first;
//    //uint16_t mappingSize = mappings[i].second;
//
//    NS_LOG_DEBUG("Sending mapping "<< mapping << " on subflow #" << (int)it->first);
//
//    //sf->AddMapping();
//    Ptr<Packet> p = m_txBuffer->CopyFromSequence(mapping.GetLength(), SEQ64TO32(mapping.HeadDSN()));
//    NS_ASSERT(p->GetSize() == mapping.GetLength());
//
//    /// Recently replaced by the following
////    int ret = sf->SendMapping(p, mapping);
//    /// here the mapping should be already mapped set
//    int ret = sf->AddMapping(mapping);
//
//
//    if( ret < 0)
//    {
//      // TODO dump the mappings ?
//      NS_FATAL_ERROR("Could not send mapping. The generated mappings");
//    }
//
//
//
//
//
//    // if successfully sent,
//    nbMappingsDispatched++;
//
////    bool sentPacket =
//    sf->SendPendingData();
////    NS_LOG_DEBUG("Packet sent ? boolean=s" << sentPacket );
//
//  // TODO here update the m_nextTxSequence only if it is in order
//      // Maybe the max is unneeded; I put it here
//    if( SEQ64TO32(mapping.HeadDSN()) <= m_nextTxSequence && SEQ64TO32(mapping.TailDSN()) >= m_nextTxSequence)
//    {
//      m_nextTxSequence = SEQ64TO32(mapping.TailDSN()) + 1;
//    }
//
//    m_highTxMark = std::max( m_highTxMark.Get(), SEQ64TO32(mapping.TailDSN()));
////      m_nextTxSequence = std::max(m_nextTxSequence.Get(), mapping.TailDSN() + 1);
//    NS_LOG_LOGIC("m_nextTxSequence=" << m_nextTxSequence << " m_highTxMark=" << m_highTxMark);
//  }



  // TODO here send for all



  uint32_t remainingData = m_txBuffer->SizeFromSequence(m_nextTxSequence );

  if (m_closeOnEmpty && (remainingData == 0))
    {
      TcpHeader header;

      ClosingOnEmpty(header);

    }

//  NS_LOG_LOGIC ("Dispatched " << nPacketsSent << " mappings");
  return nbMappingsDispatched > 0;
}

#if 0
bool
MpTcpSocketBase::SendPendingData(bool withAck)
{
  NS_LOG_FUNCTION(this << "Sending data" << TcpStateName[m_state]);

//  MappingList mappings;
  if (m_txBuffer->Size () == 0)
    {
      NS_LOG_DEBUG("Nothing to send");
      return false;                           // Nothing to send
    }
  //start/size
  int nbMappingsDispatched = 0; // mimic nbPackets in TcpSocketBase::SendPendingData

  MappingVector mappings;
  //mappings.reserve( GetNActiveSubflows() );
  // the MapToSsn will be done,
  // dsn, size, and path instead of a unmapped mapping
  // GenerateMapping( sf, );
  m_scheduler->GenerateMappings(mappings);


  // Just dump the generated mappings
  NS_LOG_UNCOND("=================\nGenerated " << mappings.size() << " mappings for node=" << (int)GetNode()->GetId());
  for(MappingVector::iterator it(mappings.begin()); it  != mappings.end(); it++ )
  {
    MpTcpMapping& mapping = it->second;
    NS_LOG_UNCOND("Send " << it->second << " on sf id=" << (int)it->first);
  }
  NS_LOG_UNCOND("=================");

//  NS_ASSERT_MSG( mappings.size() == GetNActiveSubflows(), "The number of mappings should be equal to the nb of already established subflows" );

  NS_LOG_DEBUG("generated [" << mappings.size() << "] mappings");
  // TODO dump mappings ?
  // Loop through mappings and send Data
//  for(int i = 0; i < (int)GetNActiveSubflows() ; i++ )
  for(MappingVector::iterator it(mappings.begin()); it  != mappings.end(); it++ )
  {


    Ptr<MpTcpSubflow> sf = GetSubflow(it->first);
    MpTcpMapping& mapping = it->second;
//    Retrieve data  Rename SendMappedData
    //SequenceNumber32 dataSeq = mappings[i].first;
    //uint16_t mappingSize = mappings[i].second;

    NS_LOG_DEBUG("Sending mapping "<< mapping << " on subflow #" << (int)it->first);

    //sf->AddMapping();
    Ptr<Packet> p = m_txBuffer->CopyFromSequence(mapping.GetLength(), SEQ64TO32(mapping.HeadDSN()));
    NS_ASSERT(p->GetSize() == mapping.GetLength());

    /// Recently replaced by the following
//    int ret = sf->SendMapping(p, mapping);
    /// here the mapping should be already mapped set
    int ret = sf->AddMapping(mapping);


    if( ret < 0)
    {
      // TODO dump the mappings ?
      NS_FATAL_ERROR("Could not send mapping. The generated mappings");
    }





    // if successfully sent,
    nbMappingsDispatched++;

//    bool sentPacket =
    sf->SendPendingData();
//    NS_LOG_DEBUG("Packet sent ? boolean=s" << sentPacket );

  // TODO here update the m_nextTxSequence only if it is in order
      // Maybe the max is unneeded; I put it here
    if( SEQ64TO32(mapping.HeadDSN()) <= m_nextTxSequence && SEQ64TO32(mapping.TailDSN()) >= m_nextTxSequence)
    {
      m_nextTxSequence = SEQ64TO32(mapping.TailDSN()) + 1;
    }

    m_highTxMark = std::max( m_highTxMark.Get(), SEQ64TO32(mapping.TailDSN()));
//      m_nextTxSequence = std::max(m_nextTxSequence.Get(), mapping.TailDSN() + 1);
    NS_LOG_LOGIC("m_nextTxSequence=" << m_nextTxSequence << " m_highTxMark=" << m_highTxMark);
  }



  // TODO here send for all



  uint32_t remainingData = m_txBuffer->SizeFromSequence(m_nextTxSequence );

  if (m_closeOnEmpty && (remainingData == 0))
    {
      TcpHeader header;

      ClosingOnEmpty(header);

    }

//  NS_LOG_LOGIC ("Dispatched " << nPacketsSent << " mappings");
  return nbMappingsDispatched > 0;
}
#endif

int
MpTcpSocketBase::Listen(void)
{
  NS_LOG_FUNCTION (this);
  NS_FATAL_ERROR("Disabled");
  return 0;

}

/**
 TCP: Upon RTO:
 1) GetSSThresh() is set to half of flight size
 2) cwnd is set to 1*MSS
 3) retransmit the lost packet
 4) Tcp back to slow start
 */
//
//void
//MpTcpSocketBase::ReTxTimeout(uint8_t sFlowIdx)
//{ // Retransmit timeout
//  NS_LOG_FUNCTION (this);
////  NS_ASSERT_MSG(client, "ReTxTimeout is not implemented for server side yet");
//  Ptr<MpTcpSubflow> sFlow = m_subflows[sFlowIdx];
//
//  NS_LOG_INFO ("Subflow ("<<(int)sFlowIdx<<") ReTxTimeout Expired at time "
//        << Simulator::Now ().GetSeconds()<< " unacked packets count is "<<sFlow->m_mapDSN.size()
//        << " sFlow->state: " << TcpStateName[sFlow->m_state]
//        ); //
//  //NS_LOG_INFO("TxSeqNb: " << sFlow->TxSeqNumber << " HighestAck: " << sFlow->highestAck);
//  // If erroneous timeout in closed/timed-wait state, just return
//  if (sFlow->m_state == CLOSED || sFlow->m_state  == TIME_WAIT)
//    {
//      NS_LOG_INFO("RETURN");
//      NS_ASSERT(3!=3);
//      return;
//    }
//  // If all data are received (non-closing socket and nothing to send), just return
//  // if (m_state <= ESTABLISHED && m_txBuffer->HeadSequence() >= m_highTxMark)
//  if (sFlow->m_state  <= ESTABLISHED && sFlow->m_mapDSN.size() == 0)
//    {
//      NS_LOG_INFO("RETURN");
//      NS_ASSERT(3!=3);
//      return;
//    }
//  Retransmit(sFlowIdx); // Retransmit the packet
//}

void
MpTcpSocketBase::OnSubflowDupAck(Ptr<MpTcpSubflow> sf)
{
  NS_LOG_DEBUG("Dup ack signaled by subflow " << sf );

}


// TODO move that away a t'on besoin de passer le mapping ?
// OnRetransmit()
// OnLoss
#if 0
void
MpTcpSocketBase::ReduceCWND(uint8_t sFlowIdx)
{

  NS_ASSERT(m_algoCC);

//  Ptr<MpTcpSubflow> sFlow = m_subflows[sFlowIdx];
//  uint32_t m_segmentSize = sFlow->GetSegSize();
//  int cwnd_tmp = 0;

  // TODO

//  m_algoCC->OnRetransmit( );

  switch (m_algoCC)
    {
  case Uncoupled_TCPs:
    sFlow->SetSSThresh( std::max(2 * m_segmentSize, BytesInFlight(sFlowIdx) / 2) );
    sFlow->cwnd = sFlow->GetSSThresh() + 3 * m_segmentSize;
    break;
  case Linked_Increases:
    sFlow->SetSSThresh( std::max(2 * m_segmentSize, BytesInFlight(sFlowIdx) / 2) );
    sFlow->cwnd = sFlow->GetSSThresh() + 3 * m_segmentSize;
    break;
  case RTT_Compensator:
    sFlow->SetSSThresh( std::max(2 * m_segmentSize, BytesInFlight(sFlowIdx) / 2) );
    sFlow->cwnd = sFlow->GetSSThresh() + 3 * m_segmentSize;
    break;
  case Fully_Coupled:
    cwnd_tmp = sFlow->cwnd - m_totalCwnd / 2;
    if (cwnd_tmp < 0)
      cwnd_tmp = 0;
    sFlow->SetSSThresh( std::max((uint32_t) cwnd_tmp, 2 * m_segmentSize) );
    sFlow->cwnd = sFlow->GetSSThresh() + 3 * m_segmentSize;
    break;
  default:
    NS_ASSERT(3!=3);
    break;
    }

  // update
//  sFlow->m_recover = SequenceNumber32(sFlow->maxSeqNb + 1);
//  sFlow->m_inFastRec = true;
//
//  // Retrasnmit a specific packet (lost segment)
//  DoRetransmit(sFlowIdx, ptrDSN);
//
//  // plotting
//  reTxTrack.push_back(make_pair(Simulator::Now().GetSeconds(), sFlow->cwnd));
//  sFlow->ssthreshtrack.push_back(make_pair(Simulator::Now().GetSeconds(), sFlow->GetSSThresh()));
}
    #endif

/**
Retransmit timeout

This function should be very interesting because one may
adopt different strategies here, like reinjecting on other subflows etc...
Maybe allow for a callback to be set here.
*/
void
MpTcpSocketBase::Retransmit()
{
  NS_LOG_LOGIC(this);
//  NS_FATAL_ERROR("TODO reestablish retransmit ?");
//  NS_LOG_ERROR("TODO");
  m_nextTxSequence = FirstUnackedSeq(); // Start from highest Ack
//  m_rtt->IncreaseMultiplier(); // Double the timeout value for next retx timer
  m_dupAckCount = 0;
  DoRetransmit(); // Retransmit the packet
//  TcpSocketBase::Retransmit();
}



void
MpTcpSocketBase::DoRetransmit()
{
  NS_LOG_FUNCTION (this);


  // Retransmit SYN packet
  if (m_state == SYN_SENT)
    {
      if (m_cnCount > 0)
        {
          // TODO
          NS_FATAL_ERROR("TODO, first syn didn't reach it should be resent. Maybe this shoudl be let to the subflow");
//          SendEmptyPacket(TcpHeader::SYN);
        }
      else
        {
          NotifyConnectionFailed();
        }
      return;
    }

  // Retransmit non-data packet: Only if in FIN_WAIT_1 or CLOSING state
  if (m_txBuffer->Size() == 0)
    {
      if (m_state == FIN_WAIT_1 || m_state == CLOSING)
        {
          // Must have lost FIN, re-send
//          SendEmptyPacket(TcpHeader::FIN);
          TcpHeader header;
        Ptr<MpTcpSubflow> subflow = GetSubflow(0);
//          m_state = FIN_WAIT_1;
//          subflow->GenerateEmptyPacketHeader(header,);
    //      SendEmptyPacket(header);
          subflow->AppendDSSFin();
          subflow->SendEmptyPacket(TcpHeader::ACK);

        }
      return;
    }
  // Retransmit a data packet: Call SendDataPacket
  NS_LOG_LOGIC ("TcpSocketBase " << this << " retxing seq " << FirstUnackedSeq ());

//  m_rxBuffer->Dump();

  DumpRxBuffers(0);

  NS_FATAL_ERROR("TODO later, but for the tests only, it should not be necesssary ?! Check for anything suspicious");
//
//  m_nextTxSequence = FirstUnackedSeq();
//  SendPendingData(true);
//

  // normally here m_nextTxSequence has been set to firstUna
//  uint32_t sz = SendDataPacket(, m_segmentSize, true);
//  // In case of RTO, advance m_nextTxSequence
//  m_nextTxSequence = std::max(m_nextTxSequence.Get(), FirstUnackedSeq() + sz);
  //reTxTrack.push_back(std::make_pair(Simulator::Now().GetSeconds(), ns3::TcpNewReno::cWnd));
}


void
MpTcpSocketBase::ReTxTimeout()
{
  NS_LOG_FUNCTION(this);
  return TcpSocketBase::ReTxTimeout();
}


// I moved it to mptcp-crypto.h
// TODO remove
#if 0
uint64_t
MpTcpSocketBase::GenerateKey()
{
  // TODO rather use NS3 random generator
  NS_ASSERT_MSG( m_localKey == 0, "Key already generated");

  //! arbitrary function, TODO replace with ns3 random gneerator
  m_localKey = (rand() % 1000 + 1);

  uint64_t idsn = 0;
  GenerateTokenForKey( HMAC_SHA1, m_localKey, m_localToken, idsn );

  /**

  /!\ seq nb must be 64 bits for mptcp but that would mean rewriting lots of code so

  TODO add a SetInitialSeqNb member into TcpSocketBase
  **/
  if(m_nullIsn)
  {
    m_nextTxSequence = (uint32_t)0;
  }
  else
  {
    m_nextTxSequence = (uint32_t)idsn;
  }

//  SetTxHead(m_nextTxSequence);
  m_firstTxUnack = m_nextTxSequence;
  m_highTxMark = m_nextTxSequence;


  // TODO update m_endPoint
//  m_endPoint->m_mptcpLocalKey = m_localKey;
//  m_endPoint->m_mptcpToken = m_localToken;

  return m_localKey;
}
#endif


//void
//MpTcpSocketBase::GetIdManager()
//{
//  NS_ASSERT(m_remotePathIdManager);
//  return m_remotePathIdManager;
//}

void
MpTcpSocketBase::GetAllAdvertisedDestinations(std::vector<InetSocketAddress>& cont)
{
  NS_ASSERT(m_remotePathIdManager);
  m_remotePathIdManager->GetAllAdvertisedDestinations(cont);
}


void
MpTcpSocketBase::SetNewAddrCallback(Callback<bool, Ptr<Socket>, Address, uint8_t> remoteAddAddrCb,
                          Callback<void, uint8_t> remoteRemAddrCb)

{
  //
  m_onRemoteAddAddr = remoteAddAddrCb;
  m_onAddrDeletion = remoteRemAddrCb;
}


void
MpTcpSocketBase::MoveSubflow(Ptr<MpTcpSubflow> subflow, mptcp_container_t from, mptcp_container_t to)
{

  NS_LOG_DEBUG("Moving subflow " << subflow << " from " << containerNames[from] << " to " << containerNames[to]);
  NS_ASSERT(from != to);
  SubflowList::iterator it = std::find(m_subflows[from].begin(), m_subflows[from].end(), subflow);

  if(it == m_subflows[from].end())
  {
    NS_LOG_ERROR("Could not find subflow in *from* container. It may have already been moved by another callback ");
    DumpSubflows();
    return;
  }

  m_subflows[to].push_back(*it);
  m_subflows[from].erase(it);
}


void
MpTcpSocketBase::DumpSubflows() const
{
  NS_LOG_FUNCTION(this << "\n");
  for(int i = 0; i < Maximum; ++i)
  {

    NS_LOG_UNCOND("===== container [" << containerNames[i] << "]");
//    Established
//    NS_LOG_INFO("Closing all subflows in state [" << containerNames [i] << "]");
    for( SubflowList::const_iterator it = m_subflows[i].begin(); it != m_subflows[i].end(); it++ )
    {
      NS_LOG_UNCOND("- subflow [" << *it  << "]");

    }

  }
}
/*
We shouldn't need the from container, it could be found
*/
void
MpTcpSocketBase::MoveSubflow(Ptr<MpTcpSubflow> subflow, mptcp_container_t to)
{
  NS_LOG_DEBUG("Moving subflow " << subflow << " to " << containerNames[to]);

  for(int i = 0; i < Maximum; ++i)
  {

      SubflowList::iterator it = std::find(m_subflows[i].begin(), m_subflows[i].end(), subflow);
      if(it != m_subflows[i].end())
      {
          NS_LOG_DEBUG("Found sf in container [" << containerNames[i] << "]");
          MoveSubflow(subflow, static_cast<mptcp_container_t>(i), to);
          return;
      }

  }

  NS_FATAL_ERROR("Subflow not found in any container");

  //! TODO it should call the meta
  //! SetSendCallback (Callback<void, Ptr<Socket>, uint32_t> sendCb)
//  subflow->SetSendCallback();


}


/*
TODO rename into subflow created
*/
void
MpTcpSocketBase::OnSubflowEstablished(Ptr<MpTcpSubflow> subflow)
{


  //! TODO We should try to steal the endpoint
  if(subflow->IsMaster())
  {
    NS_LOG_LOGIC("Master subflow created, copying its endpoint");
    m_endPoint = subflow->m_endPoint;
    SetTcp(subflow->m_tcp);
    SetNode(subflow->GetNode());

    if(m_state == SYN_SENT || m_state == SYN_RCVD)
    {
      NS_LOG_LOGIC("Meta " << TcpStateName[m_state] << " -> ESTABLISHED");
      m_state = ESTABLISHED;
    }
    else
    {
      NS_FATAL_ERROR("Unhandled case where subflow got established while meta in " << TcpStateName[m_state] );
    }
  // from
    InetSocketAddress addr(subflow->m_endPoint->GetPeerAddress(), subflow->m_endPoint->GetPeerPort());
//    NotifyNewConnectionCreated(subflow, addr);
    NotifyNewConnectionCreated(this, addr);
  }
//  else
//  {
  ComputeTotalCWND();
//  Simulator::ScheduleNow(&MpTcpSocketBase::NotifySubflowCreated, this, subflow );
//  }
}

// TODO this could be done when tracking the subflow m_state
void
MpTcpSocketBase::OnSubflowEstablishment(Ptr<MpTcpSubflow> subflow)
{
  NS_LOG_LOGIC(this << " (=meta) New subflow " << subflow << " established");
  //Ptr<MpTcpSubflow> subflow = DynamicCast<MpTcpSubflow>(sock);

  NS_ASSERT_MSG(subflow, "Contact ns3 team");

  ComputeTotalCWND();

  if(subflow->IsMaster())
  {
    NS_LOG_LOGIC("Master subflow established, moving meta(server:" << m_server << ") from " << TcpStateName[m_state] << " to ESTABLISHED state");
    if(m_state == SYN_SENT || m_state == SYN_RCVD)
    {
      NS_LOG_LOGIC("Meta " << TcpStateName[m_state] << " -> ESTABLISHED");
      m_state = ESTABLISHED;
    }
    else
    {
      NS_LOG_WARN("Unhandled case where subflow got established while meta in " << TcpStateName[m_state] );
    }

    Simulator::ScheduleNow(&MpTcpSocketBase::ConnectionSucceeded, this);
  }

//  Simulator::ScheduleNow(&MpTcpSocketBase::NotifySubflowConnected, this, subflow);
}


void
MpTcpSocketBase::NotifySubflowCreated(Ptr<MpTcpSubflow> sf)
{
  NS_LOG_FUNCTION(this << sf);
  if (!m_subflowCreated.IsNull ())
  {
      m_subflowCreated (sf);
  }
}

void
MpTcpSocketBase::NotifySubflowConnected(Ptr<MpTcpSubflow> sf)
{
  NS_LOG_FUNCTION(this << sf);
  if (!m_subflowConnectionSucceeded.IsNull ())
    {
      m_subflowConnectionSucceeded (sf);
    }
}

//
void
MpTcpSocketBase::SetSubflowAcceptCallback(
//  Callback<void, Ptr<MpTcpSubflow> > connectionRequest,
  Callback<bool, Ptr<MpTcpSubflow>, const Address &, const Address & > joinRequest,
  Callback<void, Ptr<MpTcpSubflow> > connectionCreated
)
{
  NS_LOG_FUNCTION(this << &joinRequest << " " << &connectionCreated);
//  NS_LOG_WARN("TODO not implemented yet");
//  m_subflowConnectionSucceeded = connectionCreated;
  m_joinRequest = joinRequest;
  m_subflowCreated = connectionCreated;
}

void
MpTcpSocketBase::SetSubflowConnectCallback(
  Callback<void, Ptr<MpTcpSubflow> > connectionSucceeded,
  Callback<void, Ptr<MpTcpSubflow> > connectionFailure
  )
{
  NS_LOG_FUNCTION(this << &connectionSucceeded);
  m_subflowConnectionSucceeded = connectionSucceeded;
  m_subflowConnectionFailure = connectionFailure;
}

//void
//MpTcpSocketBase::SetJoinCreatedCallback(
//  Callback<void, Ptr<MpTcpSubflow> > connectionCreated)
//{
//  NS_LOG_FUNCTION(this << &connectionCreated);
//  m_subflowCreated = connectionCreated;
//}



TypeId
MpTcpSocketBase::GetInstanceTypeId(void) const
{
  return MpTcpSocketBase::GetTypeId();
}



void
MpTcpSocketBase::OnSubflowClosing(Ptr<MpTcpSubflow> sf)
{
  NS_LOG_LOGIC("Subflow has gone into state ["
//               << TcpStateName[sf->m_state]
               );

//
//  /* if this is the last active subflow
//
//  */
//  //FIN_WAIT_1
//  switch( sf->m_state)
//  {
//    case FIN_WAIT_1:
//    case CLOSE_WAIT:
//    case LAST_ACK:
//    default:
//      break;
//  };


  MoveSubflow(sf, Established, Closing);
  //      #TODO I need to Ack the DataFin in (DoPeerCLose)
}


void
MpTcpSocketBase::OnSubflowDupack(Ptr<MpTcpSubflow> sf, MpTcpMapping mapping)
{
  NS_LOG_LOGIC("Subflow Dupack TODO.Nothing done by meta");
}

void
MpTcpSocketBase::OnSubflowRetransmit(Ptr<MpTcpSubflow> sf)
{
  NS_LOG_INFO("Subflow retransmit. Nothing done by meta");
}


// renvoie m_highTxMark.Get() - m_txBuffer->HeadSequence(); should be ok even
// if bytes may not really be in flight but rather in subflows buffer
uint32_t
MpTcpSocketBase::BytesInFlight()
{
  NS_LOG_FUNCTION(this);
  return TcpSocketBase::BytesInFlight();

  #if 0
  uint32_t total = 0;

  for( SubflowList::const_iterator it = m_subflows[Established].begin(); it != m_subflows[Established].end(); it++ )
  {
    total += (*it)->BytesInFlight();
  }
  #endif
}

//uint32_t
//TcpSocketBase::UnAckDataCount()
// TODO buggy ?
uint16_t
MpTcpSocketBase::AdvertisedWindowSize()
{
  NS_LOG_FUNCTION(this);
  return TcpSocketBase::AdvertisedWindowSize();
//  NS_LOG_DEBUG("Advertised Window size of " << value );
//  return value;
}

uint32_t
MpTcpSocketBase::Window()
{
  NS_LOG_FUNCTION (this);
  return TcpSocketBase::Window();
}


uint32_t
MpTcpSocketBase::AvailableWindow()
{
  NS_LOG_FUNCTION (this);
  uint32_t unack = UnAckDataCount(); // Number of outstanding bytes
  uint32_t win = Window(); // Number of bytes allowed to be outstanding
  NS_LOG_LOGIC ("UnAckCount=" << unack << ", Win=" << win);
  return (win < unack) ? 0 : (win - unack);
}


/**
This does not change much for now
**/
//Time
//MpTcpSocketBase::ComputeReTxTimeoutForSubflow( Ptr<MpTcpSubflow> sf)
//{
//  NS_ASSERT(sf);
//    //ReTxTimeout
//  return sf->
////  m_rtt->RetransmitTimeout();
//}





void
MpTcpSocketBase::ClosingOnEmpty(TcpHeader& header)
{
  /* TODO the question is: is that ever called ?
  */
  NS_LOG_INFO("closing on empty called");
  //      GenerateEmptyPacketHeader(header);
// sets the datafin
//    header.SetFlags( header.GetFlags() | TcpHeader::FIN);
//    // flags |= TcpHeader::FIN;
//    if (m_state == ESTABLISHED)
//    { // On active close: I am the first one to send FIN
//      NS_LOG_INFO ("ESTABLISHED -> FIN_WAIT_1");
//      m_state = FIN_WAIT_1;
//      // TODO get DSS, if none
//      Ptr<TcpOptionMpTcpDSS> dss;
//
//      //! TODO add GetOrCreate member
//      if(!GetMpTcpOption(header, dss))
//      {
//        // !
//        dss = Create<TcpOptionMpTcpDSS>();
//
//      }
//      dss->SetDataFin(true);
//      header.AppendOption(dss);
//
//    }
//    else if (m_state == CLOSE_WAIT)
//    { // On passive close: Peer sent me FIN already
//      NS_LOG_INFO ("CLOSE_WAIT -> LAST_ACK");
//      m_state = LAST_ACK;
//    }
}


/** Inherit from Socket class: Kill this socket and signal the peer (if any) */
int
MpTcpSocketBase::Close(void)
{
  NS_LOG_FUNCTION (this);
  return TcpSocketBase::Close();
  #if 0
  // First we check to see if there is any unread rx data
  // Bug number 426 claims we should send reset in this case.
// TODO reestablish ?
//  if (m_rxBuffer->Size() != 0)
  if (GetRxAvailable() != 0)
  {
    NS_FATAL_ERROR("TODO rxbuffer != 0");
      SendRST();
      return 0;
  }

  uint32_t remainingData = m_txBuffer->SizeFromSequence(m_nextTxSequence);
//  uint32_t remainingData = GetTxAvailable();


  NS_LOG_UNCOND("Call to close: data =" << remainingData );

  if (remainingData > 0)
  {

    // App close with pending data must wait until all data transmitted
    if (m_closeOnEmpty == false)
    {
      m_closeOnEmpty = true;
      NS_LOG_INFO ("Socket " << this << " deferring close, state " << TcpStateName[m_state]);
    }
    return 0;
  }

  //!
  return DoClose();
  #endif
}

void
MpTcpSocketBase::CloseAllSubflows()
{
  NS_LOG_FUNCTION(this << "Closing all subflows");
  NS_ASSERT( m_state == FIN_WAIT_2 || m_state == CLOSING || m_state == CLOSE_WAIT || m_state == LAST_ACK);

  for(int i = 0; i < Closing; ++i)
  {
//    Established
    NS_LOG_INFO("Closing all subflows in state [" << containerNames [i] << "]");
//    std::for_each( );
    for( SubflowList::const_iterator it = m_subflows[i].begin(); it != m_subflows[i].end(); it++ )
    {
        Ptr<MpTcpSubflow> sf = *it;
        //   TODO trigger events in path manager
          NS_LOG_LOGIC("Closing sf " << sf);

          int ret = sf->Close();
//        }
        NS_ASSERT_MSG(ret == 0, "Can't close subflow");
    }

    m_subflows[Closing].insert( m_subflows[Closing].end(), m_subflows[i].begin(), m_subflows[i].end());
    m_subflows[i].clear();
    //! Once subflow of current container were closed, we move everything to
    //!
//    MoveSubflow(sf, Closing);
  }
}



void
MpTcpSocketBase::ReceivedAck(
  SequenceNumber32 dack
  , Ptr<MpTcpSubflow> sf
  , bool count_dupacks
  )
{
//    NS_FATAL_ERROR("Received DACK " << dack << "from subflow" << sf << "(Enable dupacks:" << count_dupacks << " )");
  NS_LOG_FUNCTION("Received DACK " << dack << "from subflow" << sf << "(Enable dupacks:" << count_dupacks << " )");
//  NS_ASSERT( dss->GetFlags() & TcpOptionMpTcpDSS::DataAckPresent);

//  SequenceNumber32 dack = SequenceNumber32(dss->GetDataAck());

  TcpSocketBase::ReceivedAck(dack);
#if 0
  if (dack < FirstUnackedSeq())
    { // Case 1: Old ACK, ignored.
      NS_LOG_LOGIC ("Old ack Ignored " << dack  );
    }
  else if (dack  == FirstUnackedSeq())
    { // Case 2: Potentially a duplicated ACK
      if (dack  < m_nextTxSequence && count_dupacks)
        {
        /* TODO dupackcount shall only be increased if there is only a DSS option ! */
//          NS_LOG_WARN ("TODO Dupack of " << dack << " not handled yet." );
          // TODO add new prototpye ?

            DupAck(dack, sf, ++m_dupAckCount);
        }
      // otherwise, the ACK is precisely equal to the nextTxSequence
      NS_ASSERT( dack  <= m_nextTxSequence);
    }
  else if (dack  > FirstUnackedSeq())
    { // Case 3: New ACK, reset m_dupAckCount and update m_txBuffer
      NS_LOG_LOGIC ("New DataAck [" << dack  << "]");

      NewAck( dack );
      m_dupAckCount = 0;
    }

#endif
}






/** Received a packet upon CLOSE_WAIT, FIN_WAIT_1, or FIN_WAIT_2 states */
//void
//MpTcpSocketBase::ProcessWait(Ptr<Packet> packet, const TcpHeader& tcpHeader)
//{
//  NS_LOG_FUNCTION (this << tcpHeader);
//
//  NS_FATAL_ERROR("TO remove");
//
//}


/** Peacefully close the socket by notifying the upper layer and deallocate end point */
//void
//MpTcpSocketBase::CloseAndNotify(void)
//{
//  NS_LOG_FUNCTION (this);
//
//  if (!m_closeNotified)
//    {
//      NotifyNormalClose();
//    }
//  if (m_state != TIME_WAIT)
//    {
//      DeallocateEndPoint();
//    }
//  m_closeNotified = true;
//  NS_LOG_INFO (TcpStateName[m_state] << " -> CLOSED");
//  CancelAllTimers();
//  m_state = CLOSED;
//
//}

/** Move TCP to Time_Wait state and schedule a transition to Closed state */
void
MpTcpSocketBase::TimeWait()
{
  Time timewait_duration = Seconds(2 * m_msl);
  NS_LOG_INFO (TcpStateName[m_state] << " -> TIME_WAIT "
              << "with duration of " << timewait_duration
              << "; m_msl=" << m_msl);
//  TcpSocketBase::TimeWait();
  CloseAllSubflows();
  m_state = TIME_WAIT;
  CancelAllTimers();
//  // Move from TIME_WAIT to CLOSED after 2*MSL. Max segment lifetime is 2 min
//  // according to RFC793, p.28
  m_timewaitEvent = Simulator::Schedule(timewait_duration, &MpTcpSocketBase::OnTimeWaitTimeOut, this);
}

void
MpTcpSocketBase::OnTimeWaitTimeOut(void)
{
  // Would normally call CloseAndNotify
  NS_LOG_LOGIC("Timewait timeout expired");
  NS_LOG_UNCOND("after timewait timeout, there are still " << m_subflows[Closing].size() << " subflows pending");

  CloseAndNotify();
}

/** Peacefully close the socket by notifying the upper layer and deallocate end point */
void
MpTcpSocketBase::CloseAndNotify(void)
{
  NS_LOG_FUNCTION (this);

  // TODO check the number of open subflows
  if (!m_closeNotified)
    {
      NotifyNormalClose();
    }
  if (m_state != TIME_WAIT)
    {
      DeallocateEndPoint();
    }
  m_closeNotified = true;
  NS_LOG_INFO (TcpStateName[m_state] << " -> CLOSED");
  CancelAllTimers();
  m_state = CLOSED;

}

/* Peer sent me a DATA FIN. Remember its sequence in rx buffer.
It means there won't be any mapping above that dataseq
*/

void
MpTcpSocketBase::PeerClose(Ptr<Packet> p, const TcpHeader& tcpHeader)
{
  NS_LOG_FUNCTION(this << " PEEER CLOSE CALLED !" << tcpHeader);

  NS_FATAL_ERROR("TO REMOVE. Function overriden by PeerClose(subflow)");

//  Ptr<TcpOptionMpTcpDSS> dss;
//  NS_ASSERT_MSG( GetMpTcpOption(tcpHeader,dss), "If this function was called, it must be because a dss had been found" );
//  NS_ASSERT( dss->GetFlags() & TcpOptionMpTcpDSS::DataFin);
//
//  /* */
//  SequenceNumber32 dsn = SequenceNumber32 (dss->GetDataFinDSN() );
//  if( dsn < m_rxBuffer->NextRxSequence() || m_rxBuffer->MaxRxSequence() < dsn) {
//      //!
//    NS_LOG_INFO("dsn " << dsn << " out of expected range [ " << m_rxBuffer->NextRxSequence()  << " - " << m_rxBuffer->MaxRxSequence() << " ]" );
//    return ;
//  }
//  /*
// Notably, it is only DATA_ACKed once all
//   data has been successfully received at the connection level.  Note,
//   therefore, that a DATA_FIN is decoupled from a subflow FIN.  It is
//   only permissible to combine these signals on one subflow if there is
//   no data outstanding on other subflows. */
//
//  // Copier/coller de
//
//  // Ignore all out of range packets
////  if (tcpHeader.GetSequenceNumber() < m_rxBuffer->NextRxSequence() || tcpHeader.GetSequenceNumber() > m_rxBuffer->MaxRxSequence())
////    {
////      return;
////    }
//
//  // For any case, remember the FIN position in rx buffer first
//  //! +1 because the datafin doesn't count as payload
//  // TODO rename mapping into GetDataMapping
//  NS_LOG_LOGIC("Setting FIN sequence to " << dss->GetMapping().TailDSN());
//  m_rxBuffer->SetFinSequence(
//                            dss->GetMapping().TailDSN()
//                            );
//
//  // Return if FIN is out of sequence, otherwise move to CLOSE_WAIT state by DoPeerClose
//  if (!m_rxBuffer->Finished())
//  {
//    NS_LOG_WARN("Out of range");
//    return;
//  }
//
//  // For any case, remember the FIN position in rx buffer first
////  #error TODO
//
//
//
//
//  NS_LOG_LOGIC ("Accepted DATA FIN at seq " << tcpHeader.GetSequenceNumber () + SequenceNumber32 (p->GetSize ()));
//
////  NS_LOG_LOGIC ("State " << m_state );
////  m_state == FIN_WAIT_1;
//
//  // Simultaneous close: Application invoked Close() when we are processing this FIN packet
//  if (m_state == FIN_WAIT_1)
//    {
//      NS_LOG_INFO ("FIN_WAIT_1 -> CLOSING");
//      m_state = CLOSING;
//
//      // TODO should send dataACK
//      TcpHeader header;
//      AppendDataAck(header);
//      GenerateEmptyPacketHeader(header,TcpHeader::ACK);
//      //!
//      GetSubflow(0)->SendEmptyPacket(header);
//      return;
//    }
//  DoPeerClose();
}

/** Received a in-sequence FIN. Close down this socket. */
// FIN is in sequence, notify app and respond with a FIN
void
MpTcpSocketBase::DoPeerClose(void)
{
  NS_FATAL_ERROR("To remove");
//  NS_ASSERT(m_state == ESTABLISHED || m_state == SYN_RCVD);

  // Move the state to CLOSE_WAIT
  NS_LOG_INFO (TcpStateName[m_state] << " -> CLOSE_WAIT");
  m_state = CLOSE_WAIT;

  if (!m_closeNotified)
    {
      // The normal behaviour for an application is that, when the peer sent a in-sequence
      // FIN, the app should prepare to close. The app has two choices at this point: either
      // respond with ShutdownSend() call to declare that it has nothing more to send and
      // the socket can be closed immediately; or remember the peer's close request, wait
      // until all its existing data are pushed into the TCP socket, then call Close()
      // explicitly.
      NS_LOG_LOGIC ("TCP " << this << " calling NotifyNormalClose");
      NotifyNormalClose();
      m_closeNotified = true;
    }
  if (m_shutdownSend)
    { // The application declares that it would not sent any more, close this socket
      Close();
    }
    else
    { // Need to ack, the application will close later
//    #error TODO send Dataack
      TcpHeader header;

      GenerateEmptyPacketHeader(header, TcpHeader::ACK);
      //!
      Ptr<MpTcpSubflow> sf = GetSubflow(0);
      sf->AppendDSSAck();
      sf->SendEmptyPacket(header);
    }

  if (m_state == LAST_ACK)
  {
      NS_LOG_LOGIC ("TcpSocketBase " << this << " scheduling Last Ack timeout 01 (LATO1)");
      NS_FATAL_ERROR("TODO");
//      m_lastAckEvent = Simulator::Schedule(m_rtt->RetransmitTimeout(), &TcpSocketBase::LastAckTimeout, this);
    }
}


// TODO this could be reimplemented via choosing
void
MpTcpSocketBase::SendEmptyPacket(TcpHeader& header)
{
  NS_FATAL_ERROR("Disabled. Should call subflow member");
}


/** Do the action to close the socket. Usually send a packet with appropriate
 flags depended on the current m_state.

 TODO use a closeAndNotify in more situations
 */
int
MpTcpSocketBase::DoClose()
{
  NS_LOG_FUNCTION(this << " in state " << TcpStateName[m_state]);

  // TODO close all subflows
  // TODO send a data fin
  // TODO ideally we should be able to work without any subflows and
  // retransmit as soon as we get a subflow up !
  // TODO we should ask the scheduler on what subflow to send the messages
  TcpHeader header;




  switch (m_state)
  {
  case SYN_RCVD:
  case ESTABLISHED:
// send FIN to close the peer
      {
      NS_LOG_INFO ("ESTABLISHED -> FIN_WAIT_1");


      m_state = FIN_WAIT_1;
      Ptr<MpTcpSubflow> subflow = GetSubflow(0);
      subflow->GenerateEmptyPacketHeader(header,TcpHeader::ACK);
//      SendEmptyPacket(header);
      subflow->AppendDSSFin();
      subflow->SendEmptyPacket(header);
      }
      break;

  case CLOSE_WAIT:
      {
// send ACK to close the peer
      NS_LOG_INFO ("CLOSE_WAIT -> LAST_ACK");
      Ptr<MpTcpSubflow> subflow = GetSubflow(0);
      m_state = LAST_ACK;

      subflow->GenerateEmptyPacketHeader(header, TcpHeader::ACK);
      subflow->AppendDSSAck();
      subflow->SendEmptyPacket(header);
//      SendEmptyPacket(TcpHeader::FIN | TcpHeader::ACK);
      }

      break;

  case SYN_SENT:
//      SendRST();
//      CloseAndNotify();

  case CLOSING:
// Send RST if application closes in SYN_SENT and CLOSING
// TODO deallocate all childrne
      NS_LOG_WARN("trying to close while closing..");
//      NS_LOG_INFO ("CLOSING -> LAST_ACK");
//      m_state = TIME_WAIT;
//        NotifyErrorClose();
//      DeallocateEndPoint();

      break;
  case LISTEN:
      CloseAndNotify();
      break;
  case LAST_ACK:
      TimeWait();
      break;
  case CLOSED:
  case FIN_WAIT_1:
  case FIN_WAIT_2:
    break;
  case TIME_WAIT:
//      CloseAndNotify();
      break;

  default: /* mute compiler */
// Do nothing in these four states
      break;
  }
  return 0;
}





Ptr<Packet>
MpTcpSocketBase::Recv(uint32_t maxSize, uint32_t flags)
{
  NS_LOG_FUNCTION(this);
  return TcpSocketBase::Recv(maxSize,flags);
  // TODO here I could choose to discard mappings
}



uint32_t
MpTcpSocketBase::GetTxAvailable(void) const
{
  NS_LOG_FUNCTION (this);
  uint32_t value = m_txBuffer->Available();
  NS_LOG_DEBUG("Tx available " << value);
  return value;
}

//this would not accomodate with google option that proposes to add payload in
// syn packets MPTCP
/**
This function should be overridable since it may depend on the CC, cf RFC:

   To compute cwnd_total, it is an easy mistake to sum up cwnd_i across
   all subflows: when a flow is in fast retransmit, its cwnd is
   typically inflated and no longer represents the real congestion
   window.  The correct behavior is to use the ssthresh (slow start
   threshold) value for flows in fast retransmit when computing
   cwnd_total.  To cater to connections that are app limited, the
   computation should consider the minimum between flight_size_i and
   cwnd_i, and flight_size_i and ssthresh_i, where appropriate.

TODO fix this to handle fast recovery
**/
uint32_t
MpTcpSocketBase::ComputeTotalCWND()
{
  NS_LOG_DEBUG("Cwnd before update=" << Window()
//               m_tcb->m_cWnd.Get()
               );

  uint32_t totalCwnd = 0;

  for (uint32_t i = 0; i < Maximum; i++)
  {
    for( SubflowList::const_iterator it = m_subflows[i].begin(); it != m_subflows[i].end(); it++ )
    {
  //      Ptr<MpTcpSubflow> sf = m_subflows[Established][i];
        Ptr<MpTcpSubflow> sf = *it;

        // TODO handle fast recovery
        // fast recovery
  //      if ( sf->m_inFastRec) {
  //        NS_LOG_DEBUG("Is in Fast recovery");
  //        totalCwnd += sf->GetSSThresh();
  //      }
  //      else
        {
//          NS_LOG_WARN("Don't consider Fast recovery yet");
//          totalCwnd += sf->m_cWnd.Get();          // Should be this all the time ?!
          totalCwnd += sf->Window();          // Should be this all the time ?!
        }
    }
  }
  m_tcb->m_cWnd = totalCwnd;
  NS_LOG_DEBUG("Cwnd after computation=" << m_tcb->m_cWnd.Get());
  return totalCwnd;
}






/** Kill this socket. This is a callback function configured to m_endpoint in
 SetupCallback(), invoked when the endpoint is destroyed. */
void
MpTcpSocketBase::Destroy(void)
{
  NS_LOG_FUNCTION(this);
  NS_LOG_INFO("Enter Destroy(" << this << ") m_sockets: )");

  NS_LOG_ERROR("Before unsetting endpoint, check it's not used by subflow ?");
  m_endPoint = 0;
  // TODO loop through subflows and Destroy them too ?
//  if (m_tcp != 0)
//    {
//      std::vector<Ptr<TcpSocketBase> >::iterator it = std::find(m_tcp->m_sockets.begin(), m_tcp->m_sockets.end(), this);
//      if (it != m_tcp->m_sockets.end())
//        {
//          m_tcp->m_sockets.erase(it);
//        }
//    }
//  CancelAllSubflowTimers();
//  NS_LOG_INFO("Leave Destroy(" << this << ") m_sockets:  " << m_tcp->m_sockets.size()<< ")");
}




}  //namespace ns3
