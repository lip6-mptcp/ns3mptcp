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
  if (m_node) { std::clog << Simulator::Now ().GetSeconds () << " [node " << m_node->GetId () << ": ] "; }
//<< TcpStateName[m_node->GetTcp()->GetState()] <<

#include <iostream>
#include <cmath>
#include "ns3/mptcp-mapping.h"
#include "ns3/simulator.h"
#include "ns3/log.h"
#include "ns3/abort.h"
#include "ns3/mptcp-subflow.h"
#include "ns3/mptcp-socket-base.h"
#include "ns3/tcp-l4-protocol.h"
#include "ns3/ipv4-address.h"
#include "ns3/ipv4-end-point.h"
#include "ipv6-end-point.h" // it is not exported in ns3.19
#include "ns3/node.h"
#include "ns3/ptr.h"
#include "ns3/tcp-option-mptcp.h"
#include "ns3/mptcp-id-manager.h"
//#include "ns3/ipv4-address.h"
#include "ns3/trace-helper.h"
#include <algorithm>
#include <openssl/sha.h>

NS_LOG_COMPONENT_DEFINE("MpTcpSubflow");

/*
#define DISABLE_MEMBER(retType,member) retType \
                                        MpTcpSubflow::member(void) {\
                                            NS_FATAL_ERROR("This should never be called. The meta will make the subflow pass from LISTEN to ESTABLISHED."); \
                                        }
*/

namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED(MpTcpSubflow);


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



TypeId
MpTcpSubflow::GetTypeId(void)
{
  static TypeId tid = TypeId("ns3::MpTcpSubflow")
      .SetParent<TcpSocketBase>()
//      .AddConstructor<MpTcpSubflow>()
      // TODO should be inherited
//      .AddTraceSource("CongestionWindow",
//          "The congestion control window to trace.",
//           MakeTraceSourceAccessor(&MpTcpSubflow::m_cWnd))
//      .AddTraceSource("SSThreshold",
//          "The Slow Start Threshold.",
//           MakeTraceSourceAccessor(&MpTcpSubflow::m_ssThresh))
    ;
  return tid;
}



//! wrapper function
static inline
MpTcpMapping
GetMapping(const Ptr<const TcpOptionMpTcpDSS> dss)
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
MpTcpSubflow::GetInstanceTypeId(void) const
{
  return GetTypeId();
}

//bool
void
MpTcpSubflow::SetMeta(Ptr<MpTcpSocketBase> metaSocket)
{
  NS_ASSERT(metaSocket);
//  NS_ASSERT(m_state == CLOSED);
  NS_LOG_FUNCTION(this);
  m_metaSocket = metaSocket;

  // kinda hackish
//  m_TxMappings.m_txBuffer = &m_txBuffer;
//  m_RxMappings.m_rxBuffer = &m_rxBuffer;

//  return true;
}

void
MpTcpSubflow::DumpInfo() const
{
      NS_LOG_LOGIC ("MpTcpSubflow " << this << " SendPendingData" <<
//          " w " << w <<
          " rxwin " << m_rWnd <<
//          " segsize " << GetSegSize() <<
          " nextTxSeq " << m_nextTxSequence <<
          " highestRxAck " << FirstUnackedSeq() <<
//          " pd->Size " << m_txBuffer->Size () <<
          " pd->SFS " << m_txBuffer->SizeFromSequence (m_nextTxSequence)
          );
}

//Ptr<TcpSocketBase>
//MpTcpSubflow::Fork(void)
//{
//  // Call CopyObject<> to clone me
////  NS_LOG_ERROR("Not implemented");
//
//
//  return ForkAsSubflow();
//}

//Ptr<MpTcpSubflow>
//MpTcpSubflow::ForkAsSubflow(void)
//{
//  return CopyObject<MpTcpSubflow> (this);
//}

/*
DupAck
RFC 6824
"As discussed earlier, however, an MPTCP
   implementation MUST NOT treat duplicate ACKs with any MPTCP option,
   with the exception of the DSS option, as indications of congestion
   [12], and an MPTCP implementation SHOULD NOT send more than two
   duplicate ACKs in a row for signaling purposes."
*/
//void
//MpTcpSubflow::DupAck(const TcpHeader& t, uint32_t count)


// TODO check with parent's
void
MpTcpSubflow::CancelAllTimers()
{
  NS_LOG_FUNCTION(this);
  //(int) sFlowIdx
  m_retxEvent.Cancel();
  m_lastAckEvent.Cancel();
  m_timewaitEvent.Cancel();
  NS_LOG_LOGIC( "CancelAllTimers");
}

// TODO remove in favor
int
MpTcpSubflow::DoConnect()
{
  NS_LOG_FUNCTION (this);
  return TcpSocketBase::DoConnect();

//  InitializeCwnd ();
//
//  // A new connection is allowed only if this socket does not have a connection
//  if (m_state == CLOSED || m_state == LISTEN || m_state == SYN_SENT || m_state == LAST_ACK || m_state == CLOSE_WAIT)
//    { // send a SYN packet and change state into SYN_SENT
//      TcpHeader header;
//      GenerateEmptyPacketHeader(header,TcpHeader::SYN);
//
//      // code moved inside SendEmptyPacket
//
//      AddOptionMpTcp3WHS(header);
//
//      TcpSocketBase::SendEmptyPacket(header);
////      NS_ASSERT( header.)
//      NS_LOG_INFO (TcpStateName[m_state] << " -> SYN_SENT");
//      m_state = SYN_SENT;
//    }
//  else if (m_state != TIME_WAIT)
//  { // In states SYN_RCVD, ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, and CLOSING, an connection
//    // exists. We send RST, tear down everything, and close this socket.
//    SendRST();
//    CloseAndNotify();
//  }
//  return 0;
}


/** Inherit from Socket class: Kill this socket and signal the peer (if any) */
int
MpTcpSubflow::Close(void)
{
  NS_LOG_FUNCTION (this);
  // First we check to see if there is any unread rx data
  // Bug number 426 claims we should send reset in this case.

//  if (m_rxBuffer->Size() != 0)
//    {
//      SendRST();
//      return 0;
//    }
//
//  //
////  if( GetMeta()->GetNClosingSubflows() )
////  {
////
////  }
//
//
//  if (m_txBuffer->SizeFromSequence(m_nextTxSequence) > 0)
//    { // App close with pending data must wait until all data transmitted
//      if (m_closeOnEmpty == false)
//        {
//          m_closeOnEmpty = true;
//          NS_LOG_INFO ("Socket " << this << " deferring close, state " << TcpStateName[m_state]);
//        }
//      return 0;
//    }
//  return DoClose();

    return TcpSocketBase::Close();
}



/*
If copied from a legacy socket, then it's a master socket
*/
MpTcpSubflow::MpTcpSubflow(const TcpSocketBase& sock)
    : TcpSocketBase(sock),
    m_masterSocket(true),
    m_dssFlags(0)

{
    NS_LOG_FUNCTION (this << &sock);
      NS_LOG_LOGIC ("Copying from TcpSocketBase. endPoint=" << sock.m_endPoint);
//      if(sFlow->IsMaster())
//  {
//    m_endPoint = sock.m_endPoint;
//  }

    // We need to update the endpoint callbnacks so that packets come to this socket
    // instead of the abstract meta
    // this is necessary for the client socket
    NS_LOG_UNCOND("Cb=" << m_sendCb.IsNull () << " endPoint=" << m_endPoint);
    m_endPoint = (sock.m_endPoint);
    m_endPoint6 = (sock.m_endPoint6);
    SetupCallback();
//    NS_ASSERT(res == 0);
}


// Does this constructor even make sense ? no ? to remove ?
MpTcpSubflow::MpTcpSubflow(const MpTcpSubflow& sock)
  : TcpSocketBase(sock),
  m_masterSocket(sock.m_masterSocket),  //!false
  m_localNonce(sock.m_localNonce),
  m_dssFlags(0)
{
  NS_LOG_FUNCTION (this << &sock);
  NS_LOG_LOGIC ("Invoked the copy constructor");
}

MpTcpSubflow::MpTcpSubflow(
//Ptr<MpTcpSocketBase> metaSocket
) :
    TcpSocketBase(),
    m_routeId(0),
    m_metaSocket(0),
    m_backupSubflow(false),
    m_masterSocket(false),
    m_localNonce(0)
{
  NS_LOG_FUNCTION(this);
}

MpTcpSubflow::~MpTcpSubflow()
{
  NS_LOG_FUNCTION(this);
}


/**
TODO maybe override that not to have the callbacks
**/
void
MpTcpSubflow::CloseAndNotify(void)
{
  //TODO
  NS_LOG_FUNCTION_NOARGS();
  TcpSocketBase::CloseAndNotify();
  GetMeta()->OnSubflowClosed( this, false );
}


/**
Mapping should already exist when sending the packet
**/
int
MpTcpSubflow::Send(Ptr<Packet> p, uint32_t flags)
{
  // TODO use TcpSocketBase
//  NS_FATAL_ERROR("Use SendMapping instead");
  NS_LOG_FUNCTION(this);

  // TO
  int ret = TcpSocketBase::Send(p, flags);


  if(ret > 0)
  {
//      // Check that the packet is covered by mapping
//      // compute ssnHead and tail
//      SequenceNumber32 ssnTail = m_txBuffer->TailSequence();
      MpTcpMapping temp;
      SequenceNumber32 ssnHead = m_txBuffer->TailSequence() - p->GetSize();
      NS_ASSERT(m_TxMappings.GetMappingForSSN(ssnHead, temp));
//      return ret;
  }

  return ret;
}

//, uint32_t maxSize
// rename globalSeqNb ?

void
MpTcpSubflow::SendEmptyPacket(uint8_t flags)
{
  NS_LOG_FUNCTION_NOARGS();
  TcpSocketBase::SendEmptyPacket(flags);
}


void
MpTcpSubflow::SendEmptyPacket(TcpHeader& header)
{
  NS_LOG_FUNCTION(this << header);


  TcpSocketBase::SendEmptyPacket(header);
}

//bool
//MpTcpSubflow::HasMappingForDSNRange(SequenceNumber64 dsn, uint16_t len)
//{
//    NS_LOG_FUNCTION(dsn << len);
//
//}
//

// Return the dsn range
//uint32_t
//MpTcpSubflow::AddMapping(SequenceNumber32 dsn, uint16_t len)
//{
//    NS_LOG_LOGIC("Register mapping");
//    MpTcpMapping mapping;
//    mapping.SetHeadDSN();
//    mapping.SetMappingSize();
//    mapping.MapToSSN( m_txBuffer->TailSequence() );
//    NS_LOG_DEBUG("Generated mapping=" << mapping );
//
//    bool ok = m_TxMappings.AddMapping( mapping  );
//    NS_ASSERT_MSG( ok, "Can't add mapping: 2 mappings overlap");
//}

/**
//! GetLength()
this fct asserts when the mapping length is 0 but in fact it can be possible
when there is an infinite mapping

Probleme ici c si j'essaye
**/
#if 0
int
MpTcpSubflow::SendMapping(Ptr<Packet> p, MpTcpMapping& mapping)
{
  NS_LOG_FUNCTION (this << p << mapping);
  NS_ASSERT(p);

  NS_ASSERT_MSG(mapping.GetLength() != 0,"Mapping should not be empty" );
  NS_ASSERT_MSG(mapping.GetLength() == p->GetSize(), "You should fill the mapping" );
  // backup its value because send will change it
  //SequenceNumber32 nextTxSeq = m_nextTxSequence;

  // Check m_txBuffer can handle it otherwise it will get refused

    // Everything went fine
  //if(res >= 0)
  //{*
  // TODO in fact there could be an overlap between recorded mappings and the current one
  // so the following check is not enough. To change later

//  if(m_txBuffer->Available() < mapping.GetLength())
//  {
//    NS_LOG_ERROR("Too much data to send");
//    return -ERROR_MSGSIZE;
//  }
//  NS_LOG_FUNCTION (this << p);
//  NS_ABORT_MSG_IF(flags, "use of flags is not supported in TcpSocketBase::Send()");
  //! & !m_closeOnEmpty
  if (m_state == ESTABLISHED || m_state == SYN_SENT || m_state == CLOSE_WAIT)
    {

      SequenceNumber32 savedTail = m_txBuffer->TailSequence();
      // Store the packet into Tx buffer
      if (!m_txBuffer->Add(p))
        { // TxBuffer overflow, send failed
          NS_LOG_WARN("TX buffer overflow");

          m_errno = ERROR_MSGSIZE;
          return -1;
        }

      //! add succeeded
      NS_LOG_DEBUG(mapping << "Mapped to SSN=" << savedTail);
      mapping.MapToSSN( savedTail );
      NS_ASSERT_MSG(m_TxMappings.AddMapping( mapping  ) == true, "2 mappings overlap");

      // Submit the data to lower layers
      NS_LOG_LOGIC ("txBufSize=" << m_txBuffer->Size () << " state " << TcpStateName[m_state]);
      if (m_state == ESTABLISHED || m_state == CLOSE_WAIT)
        {
          NS_LOG_DEBUG("m_nextTxSequence [" << m_nextTxSequence << "]");
          // Try to send the data out
          SendPendingData(m_connected);
        }
      return p->GetSize();
    }
  else
    { // Connection not established yet
      m_errno = ERROR_NOTCONN;
      return -1; // Send failure
    }

    return 0;
}
#endif

//uint32_t
//MpTcpSubflow::SendDataPacket(TcpHeader& header, const SequenceNumber32& ssn, uint32_t maxSize)
//{
//
//}

bool
MpTcpSubflow::AddLooseMapping(SequenceNumber64 dsnHead, uint16_t length)
{
    NS_LOG_LOGIC("Adding mapping with dsn=" << dsnHead << " len=" << length);
    MpTcpMapping mapping;

    mapping.MapToSSN(FirstUnmappedSSN());
    mapping.SetMappingSize(length);
    mapping.SetHeadDSN(dsnHead);

    bool ok = m_TxMappings.AddMapping( mapping  );
    NS_ASSERT_MSG( ok, "Can't add mapping: 2 mappings overlap");
    return ok;
}

SequenceNumber32
MpTcpSubflow::FirstUnmappedSSN()
{
    NS_LOG_FUNCTION(this);
    SequenceNumber32 ssn;
    if(!m_TxMappings.FirstUnmappedSSN(ssn))
    {
        ssn = m_txBuffer->TailSequence();
    }
    return ssn;
}

// Fills the vector with all the pieces of data it can accept
// but not in TxBuffer
//                SequenceNumber64 headDsn,
//                std::vector< std::pair<SequenceNumber64, uint16_t> >& missing
void
MpTcpSubflow::GetMappedButMissingData(
                std::set< MpTcpMapping >& missing
                )
{
    //!
    NS_LOG_FUNCTION(this);
//    missing.clear();

    SequenceNumber32 startingSsn = m_txBuffer->TailSequence();

    m_TxMappings.GetMappingsStartingFromSSN(startingSsn, missing);
}

#if 0
bool
MpTcpSubflow::CheckRangeIsCoveredByMapping(SequenceNumber32 ssnHead, SequenceNumber32 ssnTail)
{
  NS_LOG_FUNCTION(this << ssnHead << ssnTail);
  if(IsInfiniteMappingEnabled())
    {
        NS_LOG_DEBUG("Infinite mapping");
        return true;
    }

  /**
  In this loop, we make sure we don't send data for which there is no
  Tx mapping. A packet may be spanned over
   Packets may contain data described by several mappings
  */
  while(ssnHead < ssnTail)
  {
    NS_LOG_DEBUG("Looking for mapping that overlaps with ssn " << ssnHead);

    // TODO je viens de le changer
//    NS_ASSERT_MSG(m_TxMappings.FindOverlappingMapping(ssnHead, ssnTail - ssnHead, mapping), "Sent data not covered by mappings");
    NS_ASSERT_MSG( m_TxMappings.GetMappingForSSN(ssnHead, mapping), "Sent data not covered by mappings");
//    ssnTail =
//    NS_ASSERT_MSG(mapping.HeadSSN() <= ssnHead, "Mapping can only start");

    ssnHead = mapping.TailSSN() + SequenceNumber32(1);
    NS_LOG_DEBUG("mapping " << mapping << " covers it");

  }
}
#endif

  /* We don't automatically embed mappings since we want the possibility to create mapping spanning over several segments
//   here, it should already have been put in the packet, we just check
//  that the

*/

// pass as const ref
void
MpTcpSubflow::SendPacket(TcpHeader header, Ptr<Packet> p)
{
  NS_LOG_FUNCTION (this << header <<  p);
  // TODO here we should decide if we call AppendMapping or not and with which value


  //! if we send data...
  if(p->GetSize() && !IsInfiniteMappingEnabled())
  {
    //... we must decide to send a mapping or not
    // For now we always append the mapping but we could have mappings spanning over several packets.
    // and thus not add the mapping for several packets
    /// TODO : just moved from SendDataPacket.
    ///============================
      SequenceNumber32 ssnHead = header.GetSequenceNumber();
//      SequenceNumber32 ssnTail = ssnHead + SequenceNumber32(p->GetSize())-1;

      MpTcpMapping mapping;
      // TODO
      bool result = m_TxMappings.GetMappingForSSN(ssnHead, mapping);
      if(!result)
      {
        m_TxMappings.Dump();
        NS_FATAL_ERROR("Could not find mapping associated to ssn");
      }
      NS_ASSERT_MSG(mapping.TailSSN() >= ssnHead +p->GetSize() -1, "mapping should cover the whole packet" );

      AppendDSSMapping(mapping);
    ///============================

  }



  // we append hte ack everytime
//  AppendDSSAck();
  TcpSocketBase::SendPacket(header, p);

  m_dssFlags = 0; // reset for next packet
}

/**
 *
 */
uint32_t
MpTcpSubflow::SendDataPacket(TcpHeader& header, SequenceNumber32 ssnHead, uint32_t maxSize)
{
  NS_LOG_FUNCTION(this << "Sending packet starting at SSN [" << ssnHead.GetValue() << "] with len=" << maxSize);
  //! if we send data...
//  if(p->GetSize() && !IsInfiniteMappingEnabled())
//  {

      MpTcpMapping mapping;
      // TODO
      bool result = m_TxMappings.GetMappingForSSN(ssnHead, mapping);
      if(!result)
      {
        m_TxMappings.Dump();
        NS_FATAL_ERROR("Could not find mapping associated to ssn");
      }
//      NS_ASSERT_MSG(mapping.TailSSN() >= ssnHead +p->GetSize() -1, "mapping should cover the whole packet" );

      AppendDSSMapping(mapping);
    ///============================

//  }
//  #error TODO copy some commands from TcpSocketBase

  // Here we set the maxsize to the size of the mapping
  return TcpSocketBase::SendDataPacket(header, ssnHead, std::min( (int)maxSize,mapping.TailSSN()-ssnHead+1));
}


bool
MpTcpSubflow::IsInfiniteMappingEnabled() const
{
    return GetMeta()->IsInfiniteMappingEnabled();
}

/*
behavior should be the same as in TcpSocketBase
TODO check if m_cWnd is

*/
void
MpTcpSubflow::Retransmit(void)
{
  NS_LOG_FUNCTION (this);

//  TcpSocketBase::Retransmit();
#if 0
  NS_LOG_LOGIC (this << " ReTxTimeout Expired at time " << Simulator::Now ().GetSeconds ()
  << "Exiting Fast recovery  (previously set to " << m_inFastRec << ")");
  m_inFastRec = false;

  // If erroneous timeout in closed/timed-wait state, just return
  if (m_state == CLOSED || m_state == TIME_WAIT) {
    NS_LOG_WARN("erroneous timeout");
    return;
  }
  // If all data are received (non-closing socket and nothing to send), just return
  if (m_state <= ESTABLISHED && m_txBuffer->HeadSequence () >= m_highTxMark) {
    NS_FATAL_ERROR("May be removed");
    return;
  }

  // According to RFC2581 sec.3.1, upon RTO, ssthresh is set to half of flight
  // size and cwnd is set to 1*MSS, then the lost packet is retransmitted and
  // TCP back to slow start
  m_ssThresh = std::max (2 * GetSegSize(), BytesInFlight () / 2);
  m_cWnd = GetSegSize();
  m_nextTxSequence = m_txBuffer->HeadSequence (); // Restart from highest Ack
  NS_LOG_INFO ("RTO. "
//               << m_rtt->RetransmitTimeout()
               << " Reset cwnd to " << m_cWnd
//               ", ssthresh to " << GetSSThresh()
               << ", restart from seqnum " << m_nextTxSequence
               );



// Care
//  m_rtt->IncreaseMultiplier ();             // Double the next RTO
  DoRetransmit ();                          // Retransmit the packet

//  TcpSocketBase::Retransmit();

//  NS_FATAL_ERROR("TODO retransmit");
  // pass on mapping
#endif

}


// TODO this could be replaced
void
MpTcpSubflow::DoRetransmit()
{
  NS_LOG_FUNCTION(this);

  GetMeta()->OnSubflowRetransmit(this);

  TcpSocketBase::DoRetransmit();
  #if 0
//  NS_LOG_FUNCTION (this);
  // Retransmit SYN packet
  if (m_state == SYN_SENT)
    {
      if (m_cnCount > 0)
        {
          NS_FATAL_ERROR("Not implemented yet");
          SendEmptyPacket(TcpHeader::SYN);
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
          NS_FATAL_ERROR("Not implemented yet");
          // Must have lost FIN, re-send
          SendEmptyPacket(TcpHeader::FIN);
        }
      return;
    }
  // Retransmit a data packet: Call SendDataPacket
  NS_LOG_LOGIC ("TcpSocketBase " << this << " retxing seq " << FirstUnackedSeq());


  /**
  We want to send mappings only
  **/
  MpTcpMapping mapping;
  if(!m_TxMappings.GetMappingForSSN(FirstUnackedSeq(), mapping))
//  if(!m_RxMappings.TranslateSSNtoDSN(headSSN, dsn))
  {
    NS_LOG_UNCOND("Rx mappings");
    m_TxMappings.Dump();
    NS_FATAL_ERROR("Could not associate a mapping to ssn [" << FirstUnackedSeq() << "]. Should be impossible");
  }

  // TODO maybe we could set an option to tell SendDataPacket to trim the packet
  // normally here m_nextTxSequence has been set to firstUna
  uint32_t sz = SendDataPacket(FirstUnackedSeq(), mapping.GetLength(), true);
  // In case of RTO, advance m_nextTxSequence
  m_nextTxSequence = std::max(m_nextTxSequence.Get(), FirstUnackedSeq() + sz);
  //reTxTrack.push_back(std::make_pair(Simulator::Now().GetSeconds(), ns3::TcpNewReno::cWnd));
  #endif
}

/**
Received a packet upon LISTEN state.
En fait il n'y a pas vraiment de ProcessListen :s si ?
TODO remove that one, it should never be called ?
*/
void
MpTcpSubflow::ProcessListen(Ptr<Packet> packet, const TcpHeader& tcpHeader, const Address& fromAddress, const Address& toAddress)
{
  NS_LOG_FUNCTION (this << tcpHeader);

  NS_FATAL_ERROR("This function should never be called, shoud it ?!");

  // Extract the flags. PSH and URG are not honoured.
  uint8_t tcpflags = tcpHeader.GetFlags() & ~(TcpHeader::PSH | TcpHeader::URG);

  // Fork a socket if received a SYN. Do nothing otherwise.
  // C.f.: the LISTEN part in tcp_v4_do_rcv() in tcp_ipv4.c in Linux kernel
  if (tcpflags != TcpHeader::SYN)
    {
      return;
    }

  // Call socket's notify function to let the server app know we got a SYN
  // If the server app refuses the connection, do nothing
  // TODO should be moved to
  if (!NotifyConnectionRequest(fromAddress))
    {
      return;
    }

  NS_LOG_LOGIC("Updating receive window" << tcpHeader.GetWindowSize());
//  GetMeta()->SetRemoteWindow(tcpHeader.GetWindowSize());

  // Clone the socket, simulate fork
//  Ptr<MpTcpSubflow> newSock = Fork();
  Ptr<MpTcpSubflow> newSock = DynamicCast<MpTcpSubflow>(Fork());
  NS_LOG_LOGIC ("Cloned a TcpSocketBase " << newSock);
  // TODO TcpSocketBase::
  Simulator::ScheduleNow(
      &MpTcpSubflow::CompleteFork,
      newSock,
      packet,
      tcpHeader,
      fromAddress,
      toAddress
      );
}

Ptr<MpTcpSocketBase>
MpTcpSubflow::GetMeta() const
{
  NS_ASSERT(m_metaSocket);
  return m_metaSocket;
}

/*
It is also encouraged to
   reduce the timeouts (Maximum Segment Life) on subflows at end hosts.
Move TCP to Time_Wait state and schedule a transition to Closed state
*/
void
MpTcpSubflow::TimeWait()
{
  NS_LOG_INFO (TcpStateName[m_state] << " -> TIME_WAIT");
  m_state = TIME_WAIT;
  CancelAllTimers();
  // Move from TIME_WAIT to CLOSED after 2*MSL. Max segment lifetime is 2 min
  // according to RFC793, p.28
  m_timewaitEvent = Simulator::Schedule(Seconds( m_msl), &MpTcpSubflow::CloseAndNotify, this);
}

//void
//MpTcpSubflow::ProcessEstablished(Ptr<Packet> packet, const TcpHeader& header)
//{
//  NS_LOG_FUNCTION (this);
//  TcpSocketBase::ProcessEstablished(packet,header);
//}

//int
//MpTcpSubflow::ProcessTcpOptionsLastAck(const TcpHeader& header)
//{
//  NS_LOG_FUNCTION (this << header);
//  TcpSocketBase::ProcessTcpOptionsLastAck(header);
//}
//
//int
//MpTcpSubflow::ProcessTcpOptionsClosing(const TcpHeader& header)
//{
//  NS_LOG_FUNCTION (this << header);
//  TcpSocketBase::ProcessTcpOptionsClosing(tcpHeader);
//}

void
MpTcpSubflow::AddMpTcpOptionDSS(TcpHeader& header)
{
  NS_LOG_FUNCTION(this);
  Ptr<TcpOptionMpTcpDSS> dss = Create<TcpOptionMpTcpDSS>();
  const bool sendDataFin = m_dssFlags &  TcpOptionMpTcpDSS::DataFin;
  const bool sendDataAck = m_dssFlags & TcpOptionMpTcpDSS::DataAckPresent;

  if(sendDataAck)
  {
      // TODO replace with member function to keep isolation
      uint32_t dack = GetMeta()->GetRxBuffer()->NextRxSequence().GetValue();
      dss->SetDataAck( dack );
  }

  // If no mapping set but datafin set , we have to create the mapping from scratch
  if( sendDataFin && !(m_dssFlags & TcpOptionMpTcpDSS::DSNMappingPresent))
  {
    // TODO replace with member function to keep isolation

    // TODO map to ssn
    m_dssMapping.MapToSSN(SequenceNumber32(0));
    m_dssMapping.SetHeadDSN(SEQ64TO32(GetMeta()->m_txBuffer->TailSequence() ));
    m_dssMapping.SetMappingSize(1);

    m_dssFlags |= TcpOptionMpTcpDSS::DSNMappingPresent;
  }

  // if there is a mapping to send
  if(m_dssFlags & TcpOptionMpTcpDSS::DSNMappingPresent)
  {


      // TODO don't send  mapping for every subsequent packet
      // New prototype
      //SetMapping (uint64_t& headDsn, uint32_t& headSsn, uint16_t& length, const bool& trunc_to_32bits = true);
      dss->SetMapping(m_dssMapping.HeadDSN().GetValue(), m_dssMapping.HeadSSN().GetValue(),
                            m_dssMapping.GetLength(), sendDataFin);
   }
  header.AppendOption(dss);
}


void
MpTcpSubflow::AddMpTcpOptions (TcpHeader& header)
{
    NS_LOG_FUNCTION(this);
    // TODO look for the mapping
    if((header.GetFlags () & TcpHeader::SYN))
    {
//         if token not generated yet
//        if(m_mptcpLocalKey == 0)
//        {
//            !
//            m_mptcpLocalKey = GenerateUniqueMpTcpKey();
//        }
        // Append the MPTCP capable option
//        Ptr<TcpOptionMpTcpCapable> mpc = CreateObject<TcpOptionMpTcpCapable>();
//        mpc->SetSenderKey( m_mptcpLocalKey );
//        header.AppendOption(mpc);
        //!
        // TODO assert on the state ?
        AddOptionMpTcp3WHS(header);
//        break;
    }
    // as long as we've not received an ack from the peer we
    // send an MP_CAPABLE with both keys
    // TODO create a member function that returns if multipath is available
    else if(!GetMeta()->m_receivedDSS)
    {
        AddOptionMpTcp3WHS(header);
    }


  /// Constructs DSS if necessary
  /////////////////////////////////////////
    if(m_dssFlags)
    {
        AddMpTcpOptionDSS(header);
    }

}

/**
I ended up duplicating this code to update the meta r_Wnd, which would have been hackish otherwise
TODO to remove
**/
#if 0
void
MpTcpSubflow::DoForwardUp(Ptr<Packet> packet, Ipv4Header header, uint16_t port, Ptr<Ipv4Interface> incomingInterface)
{
  NS_LOG_FUNCTION(this);
  //m_rWnd = tcpHeader.GetWindowSize();


  NS_LOG_FUNCTION(this);

  NS_LOG_LOGIC ("Socket " << this << " forward up " <<
      m_endPoint->GetPeerAddress () <<
      ":" << m_endPoint->GetPeerPort () <<
      " to " << m_endPoint->GetLocalAddress () <<
      ":" << m_endPoint->GetLocalPort ());
  Address fromAddress = InetSocketAddress(header.GetSource(), port);
  Address toAddress = InetSocketAddress(header.GetDestination(), m_endPoint->GetLocalPort());

  //NS_LOG_INFO("Before: " << packet->GetSize());
  // Peel off TCP header and do validity checking
  TcpHeader tcpHeader;
  packet->RemoveHeader(tcpHeader);
  if (tcpHeader.GetFlags() & TcpHeader::ACK)
  {
    EstimateRtt(tcpHeader);
  }
//  ReadOptions(tcpHeader);

  GetMeta()->ProcessMpTcpOptions(tcpHeader, this);

  //NS_LOG_INFO("After cuttingHeader: " << packet->GetSize());
  // Update Rx window size, i.e. the flow control window
//  TODO this will be done in meta
//  if (m_rWnd.Get() == 0 && tcpHeader.GetWindowSize() != 0)
//    { // persist probes end
//      NS_LOG_LOGIC (this << " Leaving zerowindow persist state");
//      m_persistEvent.Cancel();
//    }

//  m_rWnd = tcpHeader.GetWindowSize();
//  GetMeta()->m_rWnd = tcpHeader.GetWindowSize();

  /*  Update of receive window:

  If we are in master socket, in SYN_SENT or SYN_RCVD state then the connection should not be qualified
  as an mptcp connection yet, so we are allowed to save the receive window.
  When the connection qualifies as MPTCP, we copy the receive window value into the meta.

  As soon as the connection qualifies as an MPTCP connection, then there is only one possible way to update
  the receiver window, as explained in http://www.rfc-editor.org/rfc/rfc6824.txt :
      "The sender remembers receiver window advertisements from the
     receiver.  It should only update its local receive window values when
     the largest sequence number allowed (i.e., DATA_ACK + receive window)
     increases, on the receipt of a DATA_ACK. "
  */
  if(IsMaster() && (m_state == SYN_SENT || m_state == SYN_RCVD) ) {
      NS_LOG_LOGIC("Connection does not qualify as MPTCP yet so we can update receive window");
//      GetMeta()->SetRemoteWindow(tcpHeader.GetWindowSize());
        m_rWnd = tcpHeader.GetWindowSize();
  }



  // Discard fully out of range data packets
  if (packet->GetSize() && OutOfRange(tcpHeader.GetSequenceNumber(), tcpHeader.GetSequenceNumber() + packet->GetSize()))
    {
      NS_LOG_LOGIC ("At state " << TcpStateName[m_state] <<
          " received packet of seq [" << tcpHeader.GetSequenceNumber () <<
          ":" << tcpHeader.GetSequenceNumber () + packet->GetSize () <<
          ") out of range [" << m_rxBuffer->NextRxSequence () << ":" <<
          m_rxBuffer->MaxRxSequence () << ")");
      // Acknowledgement should be sent for all unacceptable packets (RFC793, p.69)
      if (m_state == ESTABLISHED && !(tcpHeader.GetFlags() & TcpHeader::RST))
        {
          SendEmptyPacket(TcpHeader::ACK);
        }
      return;
    }

  // TCP state machine code in different process functions
  // C.f.: tcp_rcv_state_process() in tcp_input.c in Linux kernel
  switch (m_state)
    {
  case ESTABLISHED:
    ProcessEstablished(packet, tcpHeader);
    break;
  case LISTEN:
    ProcessListen(packet, tcpHeader, fromAddress, toAddress);
    break;
  case TIME_WAIT:
    // Do nothing
    break;
  case CLOSED:
    // Send RST if the incoming packet is not a RST
    if ((tcpHeader.GetFlags() & ~(TcpHeader::PSH | TcpHeader::URG)) != TcpHeader::RST)
      { // Since m_endPoint is not configured yet, we cannot use SendRST here
        TcpHeader h;
        h.SetFlags(TcpHeader::RST);
        h.SetSequenceNumber(m_nextTxSequence);
        h.SetAckNumber(m_rxBuffer->NextRxSequence());
        h.SetSourcePort(tcpHeader.GetDestinationPort());
        h.SetDestinationPort(tcpHeader.GetSourcePort());
        h.SetWindowSize(AdvertisedWindowSize());
        AddOptions(h);
        m_tcp->SendPacket(Create<Packet>(), h, header.GetDestination(), header.GetSource(), m_boundnetdevice);
      }
    break;
  case SYN_SENT:
    ProcessSynSent(packet, tcpHeader);
    break;
  case SYN_RCVD:
    ProcessSynRcvd(packet, tcpHeader, fromAddress, toAddress);
    break;
  case FIN_WAIT_1:
  case FIN_WAIT_2:
  case CLOSE_WAIT:
    ProcessWait(packet, tcpHeader);
    break;
  case CLOSING:
    ProcessClosing(packet, tcpHeader);
    break;
  case LAST_ACK:
    ProcessLastAck(packet, tcpHeader);
    break;
  default: // mute compiler
    break;
    }

}
#endif // 0

void
MpTcpSubflow::ProcessClosing(Ptr<Packet> packet, const TcpHeader& tcpHeader)
{
  NS_LOG_FUNCTION (this << tcpHeader);

//  ProcessOptions()

  return TcpSocketBase::ProcessClosing(packet,tcpHeader);
}

/** Received a packet upon CLOSE_WAIT, FIN_WAIT_1, or FIN_WAIT_2 states */
void
MpTcpSubflow::ProcessWait(Ptr<Packet> packet, const TcpHeader& tcpHeader)
{
  NS_LOG_FUNCTION (this << tcpHeader);


  TcpSocketBase::ProcessWait(packet,tcpHeader);
}

/** Deallocate the end point and cancel all the timers */
void
MpTcpSubflow::DeallocateEndPoint(void)
{
    NS_LOG_FUNCTION(this);
    TcpSocketBase::DeallocateEndPoint();
}


void
MpTcpSubflow::CompleteFork(Ptr<Packet> p, const TcpHeader& h, const Address& fromAddress, const Address& toAddress)
{
  NS_LOG_INFO( this << "Completing fork of MPTCP subflow");
  // Get port and address from peer (connecting host)
  // TODO upstream ns3 should assert that to and from Address are of the same kind
  TcpSocketBase::CompleteFork(p, h, fromAddress, toAddress);
//   NS_FATAL_ERROR("TODO: endpoint never set. be careful to set it for meta too");
//   GetMeta()->AddSubflow(this);
  NS_LOG_INFO( this << " Endpoint="  << m_endPoint);
    if(IsMaster())
    {
       NS_LOG_LOGIC("Setting meta endpoint to " << m_endPoint
                    << " (old endpoint=" << GetMeta()->m_endPoint << " )");
       GetMeta()->m_endPoint = m_endPoint;
    }
}

Ptr<MpTcpPathIdManager>
MpTcpSubflow::GetIdManager()
{
  return GetMeta()->m_remotePathIdManager;
}


//void
//MpTcpSubflow::InitializeCwnd (void)
//{
//  NS_LOG_LOGIC(this << "InitialCWnd:" << m_initialCWnd << " SegmentSize:" << GetSegSize());
//  /*
//   * Initialize congestion window, default to 1 MSS (RFC2001, sec.1) and must
//   * not be larger than 2 MSS (RFC2581, sec.3.1). Both m_initiaCWnd and
//   * m_segmentSize are set by the attribute system in ns3::TcpSocket.
//   */
//  m_cWnd = GetInitialCwnd() * GetSegSize();
//  NS_LOG_DEBUG("m_cWnd set to " << m_cWnd);
//}


/**
Apparently this function is never called for now
**/
void
MpTcpSubflow::ConnectionSucceeded(void)
{
  NS_LOG_LOGIC(this << "Connection succeeded");
  m_connected = true;
//  if(IsMaster())
//  GetMeta()->ConnectionS
//  GetMeta()->OnSubflowEstablishment(this);
//  TcpSocketBase::ConnectionSucceeded();
}

/** Received a packet upon SYN_SENT */
void
MpTcpSubflow::ProcessSynSent(Ptr<Packet> packet, const TcpHeader& tcpHeader)
{
  NS_LOG_FUNCTION (this << tcpHeader);
  NS_ASSERT(m_state == SYN_SENT);

  NS_LOG_DEBUG("endp=" << m_endPoint);
  TcpSocketBase::ProcessSynSent(packet, tcpHeader);
  #if 0
  // Extract the flags. PSH and URG are not honoured.
  uint8_t tcpflags = tcpHeader.GetFlags() & ~(TcpHeader::PSH | TcpHeader::URG);

  if (tcpflags == 0)
    { // Bare data, accept it and move to ESTABLISHED state. This is not a normal behaviour. Remove this?
      NS_ASSERT(false);
//      NS_LOG_INFO ("SYN_SENT -> ESTABLISHED");
//      m_state = ESTABLISHED;
//      m_connected = true;
//      m_retxEvent.Cancel();
//      m_delAckCount = m_delAckMaxCount;
//      ReceivedData(packet, tcpHeader);
//      Simulator::ScheduleNow(&TcpSocketBase::ConnectionSucceeded, this);
    }
  else if (tcpflags == TcpHeader::ACK)
    { // Ignore ACK in SYN_SENT
    }
  else if (tcpflags == TcpHeader::SYN)
    {
      NS_FATAL_ERROR("Not supported at the moment");
      // Received SYN, move to SYN_RCVD state and respond with SYN+ACK
      // TODO
//      NS_LOG_INFO ("SYN_SENT -> SYN_RCVD");
//      m_state = SYN_RCVD;
//      m_cnCount = m_cnRetries;  //reset
//      m_rxBuffer->SetNextRxSequence(tcpHeader.GetSequenceNumber() + SequenceNumber32(1));
//      SendEmptyPacket(TcpHeader::SYN | TcpHeader::ACK);
    }
    else if (tcpflags == (TcpHeader::SYN | TcpHeader::ACK) &&
             (m_nextTxSequence + SequenceNumber32(1) == tcpHeader.GetAckNumber()))
    {

      NS_LOG_INFO("Received a SYN/ACK as answer");

//      Simulator::ScheduleNow(&MpTcpSubflow::ConnectionSucceeded, this);

      uint8_t addressId = 0;

      // TODO move that to MpTcpSubflow
      // Check cryptographic materials
      if( IsMaster())
      {
        /**
        * Here is how the MPTCP 3WHS works:
        *  o  SYN (A->B): A's Key for this connection.
        *  o  SYN/ACK (B->A): B's Key for this connection.
        *  o  ACK (A->B): A's Key followed by B's Key.
        *
        */

        // Expect an MP_CAPABLE option
        Ptr<TcpOptionMpTcpCapable> mpcRcvd;
        NS_ASSERT_MSG( GetTcpOption(tcpHeader, mpcRcvd), "There must be an MP_CAPABLE option in the SYN Packet" );

        GetMeta()->SetPeerKey( mpcRcvd->GetSenderKey() );

      }
      else
      {
        /**
               |             |   SYN + MP_JOIN(Token-B, R-A)  |
               |             |------------------------------->|
               |             |<-------------------------------|
               |             | SYN/ACK + MP_JOIN(HMAC-B, R-B) |
               |             |                                |
               |             |     ACK + MP_JOIN(HMAC-A)      |
               |             |------------------------------->|
               |             |<-------------------------------|
               |             |             ACK                |

         HMAC-A = HMAC(Key=(Key-A+Key-B), Msg=(R-A+R-B))
         HMAC-B = HMAC(Key=(Key-B+Key-A), Msg=(R-B+R-A))
          */

        Ptr<TcpOptionMpTcpJoin> join;
        // TODO should be less restrictive in case there is a loss

        NS_ASSERT_MSG( GetTcpOption(tcpHeader, join), "There must be an MP_JOIN option in the SYN Packet" );
        NS_ASSERT_MSG( join && join->GetMode() == TcpOptionMpTcpJoin::SynAck, "the MPTCP join option received is not of the expected 1 out of 3 MP_JOIN types." );

        addressId = join->GetAddressId();
        // TODO Here we should check the tokens
//        uint8_t buf[20] =
//        opt3->GetTruncatedHmac();
      }

      m_retxEvent.Cancel();
      m_rxBuffer->SetNextRxSequence(tcpHeader.GetSequenceNumber() + SequenceNumber32(1));
      m_highTxMark = ++m_nextTxSequence;
//      SetTxHead(m_nextTxSequence);
      m_firstTxUnack = m_nextTxSequence;

      // TODO support IPv6
      GetIdManager()->AddRemoteAddr(addressId, m_endPoint->GetPeerAddress(), m_endPoint->GetPeerPort() );

      TcpHeader answerHeader;
      GenerateEmptyPacketHeader(answerHeader, TcpHeader::ACK);
      AddOptionMpTcp3WHS(answerHeader);

      NS_LOG_INFO ("SYN_SENT -> ESTABLISHED");
      m_state = ESTABLISHED;

      // TODO send ConnectionSucceeded or
//      GetMeta()->OnSubflowEstablishment(this);
//      m_connected = true;


//      NS_LOG_LOGIC("Updating receive window");
//      GetMeta()->SetRemoteWindow(tcpHeader.GetWindowSize());



      // TODO here we send a packet  with wrong seq number
      // and another ack will be emitted just after
      SendEmptyPacket(answerHeader);

//      NS_LOG_UNCOND("m_nextTxSequence [" << m_nextTxSequence << "]");

      // TODO check we can send rightaway data ?
      SendPendingData(m_connected);

//      NS_LOG_UNCOND("m_nextTxSequence [" << m_nextTxSequence << "]");

      // Always respond to first data packet to speed up the connection.
      // Remove to get the behaviour of old NS-3 code.
      m_delAckCount = m_delAckMaxCount;
//      initialSeqNb = tcpHeader.GetAckNumber().GetValue();
//      NS_LOG_INFO("initialSeqNb: " << initialSeqNb);
    }
  else
    {
      NS_LOG_WARN("Unexpected case");

      // Other in-sequence input
      if (tcpflags != TcpHeader::RST)
        { // When (1) rx of FIN+ACK; (2) rx of FIN; (3) rx of bad flags
          NS_LOG_LOGIC ("Illegal flag " << TcpHeader::FlagsToString (tcpflags) << " received. Reset packet is sent.");
          SendRST();
        }
      CloseAndNotify();
    }
    #endif
}


//void
//MpTcpSubflow::SendEmptyPacket(TcpHeader& header)
//{
//  // Automatically append DSS
//  if(header.GetFlags() & TcpHeader::ACK)
//  {
//
//  }
//}



int
MpTcpSubflow::ProcessOptionMpTcpCapable(const Ptr<const TcpOptionMpTcpMain> option)
{
    NS_LOG_LOGIC(this << option);
    NS_ASSERT_MSG(IsMaster(), "You can receive MP_CAPABLE only on the master subflow");

    /**
    * Here is how the MPTCP 3WHS works:
    *  o  SYN (A->B): A's Key for this connection.
    *  o  SYN/ACK (B->A): B's Key for this connection.
    *  o  ACK (A->B): A's Key followed by B's Key.
    *
    */
    // Expect an MP_CAPABLE option
    Ptr<const TcpOptionMpTcpCapable> mpcRcvd = DynamicCast<const TcpOptionMpTcpCapable>(option);
    NS_ASSERT_MSG(mpcRcvd, "There must be a MP_CAPABLE option");
//        if(mpcRcvd) {
//            return 2;
//        }
//        NS_ASSERT_MSG( GetTcpOption(tcpHeader, mpcRcvd), "There must be an MP_CAPABLE option in the SYN Packet" );

    // TODO depending on the state
    GetMeta()->SetPeerKey( mpcRcvd->GetSenderKey() );

    // TODO add it to the manager too
    return 0;
}


/**
       |             |   SYN + MP_JOIN(Token-B, R-A)  |
       |             |------------------------------->|
       |             |<-------------------------------|
       |             | SYN/ACK + MP_JOIN(HMAC-B, R-B) |
       |             |                                |
       |             |     ACK + MP_JOIN(HMAC-A)      |
       |             |------------------------------->|
       |             |<-------------------------------|
       |             |             ACK                |

 HMAC-A = HMAC(Key=(Key-A+Key-B), Msg=(R-A+R-B))
 HMAC-B = HMAC(Key=(Key-B+Key-A), Msg=(R-B+R-A))
  */

int
MpTcpSubflow::ProcessOptionMpTcpJoin(const Ptr<const TcpOptionMpTcpMain> option)
{
   NS_LOG_FUNCTION(this << option);

   uint8_t addressId = 0; //!< each mptcp subflow has a uid assigned

    NS_LOG_DEBUG("Expecting MP_JOIN...");

    Ptr<const TcpOptionMpTcpJoin> join = DynamicCast<const TcpOptionMpTcpJoin>(option);
    // TODO should be less restrictive in case there is a loss

    NS_ASSERT_MSG( join, "There must be an MP_JOIN option in the SYN Packet" );
    NS_ASSERT_MSG( join && join->GetMode() == TcpOptionMpTcpJoin::SynAck, "the MPTCP join option received is not of the expected 1 out of 3 MP_JOIN types." );

    addressId = join->GetAddressId();
    // TODO Here we should check the tokens
//        uint8_t buf[20] =
//        opt3->GetTruncatedHmac();
  NS_LOG_DEBUG("Id manager");
  GetIdManager()->AddRemoteAddr(addressId, m_endPoint->GetPeerAddress(), m_endPoint->GetPeerPort() );
  return 0;
}


int
MpTcpSubflow::ProcessOptionMpTcp (const Ptr<const TcpOption> option)
{
    //! adds the header
    NS_LOG_FUNCTION(option);
    // TODO
    Ptr<const TcpOptionMpTcpMain> main = DynamicCast<const TcpOptionMpTcpMain>(option);
    switch(main->GetSubType())
    {
        case TcpOptionMpTcpMain::MP_CAPABLE:
            return ProcessOptionMpTcpCapable(main);

        case TcpOptionMpTcpMain::MP_JOIN:
            return ProcessOptionMpTcpJoin(main);

        case TcpOptionMpTcpMain::MP_DSS:
            {
                Ptr<const TcpOptionMpTcpDSS> dss = DynamicCast<const TcpOptionMpTcpDSS>(option);
                NS_ASSERT(dss);
                // Update later on
                ProcessOptionMpTcpDSSEstablished(dss);
            }
            break;

        case TcpOptionMpTcpMain::MP_FASTCLOSE:
        case TcpOptionMpTcpMain::MP_FAIL:
        default:
            NS_FATAL_ERROR("Unsupported yet");
            break;


    };

    return 0;
}

//TcpOptionMpTcpJoin::State
// TODO move to meta and adapt meta state
void
MpTcpSubflow::AddOptionMpTcp3WHS(TcpHeader& hdr) const
{
  //NS_ASSERT(m_state == SYN_SENT || m_state == SYN_RCVD);
  NS_LOG_FUNCTION(this << hdr << hdr.FlagsToString(hdr.GetFlags()));

  if( IsMaster() )
  {
    //! Use an MP_CAPABLE option
    Ptr<TcpOptionMpTcpCapable> mpc =  CreateObject<TcpOptionMpTcpCapable>();
    switch(hdr.GetFlags())
    {
      case TcpHeader::SYN:
      case (TcpHeader::SYN | TcpHeader::ACK):
        mpc->SetSenderKey( GetMeta()->GetLocalKey() );
        break;
      case TcpHeader::ACK:
        mpc->SetSenderKey( GetMeta()->GetLocalKey() );
        mpc->SetPeerKey( GetMeta()->GetPeerKey() );
        break;
      default:
        NS_FATAL_ERROR("Should never happen");
        break;
    };
    NS_LOG_INFO("Appended option" << mpc);
    hdr.AppendOption( mpc );
  }
  else
  {
    Ptr<TcpOptionMpTcpJoin> join =  CreateObject<TcpOptionMpTcpJoin>();

    switch(hdr.GetFlags())
    {
      case TcpHeader::SYN:
        {
          join->SetMode(TcpOptionMpTcpJoin::Syn);
//          uint32_t token = 0;
//          uint64_t idsn = 0;
//          int result = 0;
//          result =
//          MpTcpSocketBase::GenerateTokenForKey( MPTCP_SHA1, GetMeta()->GetRemoteKey(), token, idsn );

          join->SetPeerToken(GetMeta()->m_peerToken);
          join->SetNonce(0);
        }
        break;

      case TcpHeader::ACK:
        {
          uint8_t hmac[20];

          join->SetMode(TcpOptionMpTcpJoin::Ack);
          join->SetHmac( hmac );
        }
        break;

      case (TcpHeader::SYN | TcpHeader::ACK):
        {
          join->SetMode(TcpOptionMpTcpJoin::SynAck);
          //! TODO request from idmanager an id
          static uint8_t id = 0;
          // TODO
          NS_LOG_WARN("IDs are incremental, there is no real logic behind it yet");
  //        id = GetIdManager()->GetLocalAddrId( InetSocketAddress(m_endPoint->GetLocalAddress(),m_endPoint->GetLocalPort()) );
          join->SetAddressId( id++ );
          join->SetTruncatedHmac(424242); // who cares
          join->SetNonce(4242); //! truly random :)
        }
        break;

      default:
        NS_FATAL_ERROR("Should never happen");
        break;
    }

    NS_LOG_INFO("Appended option" << join);
    hdr.AppendOption( join );
  }

  //!
//  if()
}


//DISABLE_MEMBER(int, Listen)
int
MpTcpSubflow::Listen(void)
{
  NS_FATAL_ERROR("This should never be called. The meta will make the subflow pass from LISTEN to ESTABLISHED.");
}

void
MpTcpSubflow::NotifySend (uint32_t spaceAvailable)
{
  GetMeta()->NotifySend(spaceAvailable);
}


/*
if one looks at the linux kernel, tcp_synack_options
*/


void
MpTcpSubflow::ProcessSynRcvd(Ptr<Packet> packet, const TcpHeader& tcpHeader, const Address& fromAddress,
    const Address& toAddress)
{
  //!
  NS_LOG_FUNCTION (this << tcpHeader);
  TcpSocketBase::ProcessSynRcvd(packet, tcpHeader, fromAddress, toAddress);
}

// TODO and normally I should wait for a fourth ack
#if 0
void
MpTcpSubflow::ProcessSynRcvd(Ptr<Packet> packet, const TcpHeader& tcpHeader, const Address& fromAddress,
    const Address& toAddress)
{
  //!
  NS_LOG_FUNCTION (this << tcpHeader);




  // Extract the flags. PSH and URG are not honoured.
  uint8_t tcpflags = tcpHeader.GetFlags() & ~(TcpHeader::PSH | TcpHeader::URG);

  //! TODO replace by FirstUnack
  if (tcpflags == 0 || (tcpflags == TcpHeader::ACK && m_nextTxSequence + SequenceNumber32(1) == tcpHeader.GetAckNumber()))
    { // If it is bare data, accept it and move to ESTABLISHED state. This is
      // possibly due to ACK lost in 3WHS. If in-sequence ACK is received, the
      // handshake is completed nicely.

      m_connected = true;
      m_retxEvent.Cancel();
      m_highTxMark = ++m_nextTxSequence;
//      SetTxHead(m_nextTxSequence);
      m_txBuffer->SetHeadSequence (m_nextTxSequence);
      m_firstTxUnack = m_nextTxSequence;
//      NS_LOG_LOGIC("Updating receive window");
//      GetMeta()->SetRemoteWindow(tcpHeader.GetWindowSize());

//0.07s 0 0.07 [node 0: ] MpTcpSubflow:ProcessSynRcvd(0x1f1cc20, 4420 > 50000 [ ACK ] Seq=1 Ack=1 Win=65535
//ns3::TcpOptionMpTcpMain(MP_JOIN: [Ack] with hash [TODO]) ns3::TcpOptionMpTcpMain( MP_DSS: Acknowledges [1680] ))
      // Expecting ack
      Ptr<TcpOptionMpTcpCapable> mp_capable;
      Ptr<TcpOptionMpTcpJoin>    mp_join;
      if(GetMpTcpOption(tcpHeader, mp_capable))
      {
        NS_LOG_INFO("Received a MP_CAPABLE");
        NS_ASSERT_MSG( IsMaster(), "Makes no sense to receive an MP_CAPABLE if we are not the master subflow");
      }
      else if(GetMpTcpOption(tcpHeader, mp_join))
      {
        NS_LOG_INFO("Received a MP_JOIN");
        NS_ASSERT_MSG( !IsMaster(), "Makes no sense to receive an MP_JOIN if we are the master");

      }
      else
      {
        NS_FATAL_ERROR("We should have received either an MP_JOIN or MP_CAPABLE. Fallback to TCP is not supported.");
      }
//      NS_LOG_INFO ( "Should contain both keys" );



      // I think it's already set sooner. To check
      if (m_endPoint)
        {
          m_endPoint->SetPeer(InetSocketAddress::ConvertFrom(fromAddress).GetIpv4(),
              InetSocketAddress::ConvertFrom(fromAddress).GetPort());
        }
      else if (m_endPoint6)
        {
          m_endPoint6->SetPeer(Inet6SocketAddress::ConvertFrom(fromAddress).GetIpv6(),
              Inet6SocketAddress::ConvertFrom(fromAddress).GetPort());
        }

      NS_LOG_INFO ( "SYN_RCVD -> ESTABLISHED");
      // TODO we should check for the mptcp capable option
      m_state = ESTABLISHED;

      // Always respond to first data packet to speed up the connection.
      // Remove to get the behaviour of old NS-3 code.
      m_delAckCount = m_delAckMaxCount;
      ReceivedAck(packet, tcpHeader);

      // TODO this may be remvoed otherwise it will be
//      GetMeta()->OnSubflowEstablishment(this);

//      NotifyNewConnectionCreated(this, fromAddress);
      // As this connection is established, the socket is available to send data now
      if (GetTxAvailable() > 0)
        {
          NotifySend(GetTxAvailable());
        }
    }
  else if (tcpflags == TcpHeader::SYN)
    { // Probably the peer lost my SYN+ACK
      m_rxBuffer->SetNextRxSequence(tcpHeader.GetSequenceNumber() + SequenceNumber32(1));
      SendEmptyPacket(TcpHeader::SYN | TcpHeader::ACK);
    }
  else if (tcpflags == (TcpHeader::FIN | TcpHeader::ACK))
    {
      if (tcpHeader.GetSequenceNumber() == m_rxBuffer->NextRxSequence())
        { // In-sequence FIN before connection complete. Set up connection and close.
          m_connected = true;
          m_retxEvent.Cancel();
          m_highTxMark = ++m_nextTxSequence;
//          SetTxHead(m_nextTxSequence);
          m_txBuffer->SetHeadSequence (m_nextTxSequence);
          m_firstTxUnack = m_nextTxSequence;
          if (m_endPoint)
            {
              m_endPoint->SetPeer(InetSocketAddress::ConvertFrom(fromAddress).GetIpv4(),
                  InetSocketAddress::ConvertFrom(fromAddress).GetPort());
            }
          else if (m_endPoint6)
            {
              m_endPoint6->SetPeer(Inet6SocketAddress::ConvertFrom(fromAddress).GetIpv6(),
                  Inet6SocketAddress::ConvertFrom(fromAddress).GetPort());
            }
          PeerClose(packet, tcpHeader);
        }
    }
  else
    { // Other in-sequence input
      if (tcpflags != TcpHeader::RST)
        { // When (1) rx of SYN+ACK; (2) rx of FIN; (3) rx of bad flags
          NS_LOG_LOGIC ("Illegal flag " << tcpflags << " received. Reset packet is sent.");
          if (m_endPoint)
            {
              m_endPoint->SetPeer(InetSocketAddress::ConvertFrom(fromAddress).GetIpv4(),
                  InetSocketAddress::ConvertFrom(fromAddress).GetPort());
            }
          else if (m_endPoint6)
            {
              m_endPoint6->SetPeer(Inet6SocketAddress::ConvertFrom(fromAddress).GetIpv6(),
                  Inet6SocketAddress::ConvertFrom(fromAddress).GetPort());
            }
          SendRST();
        }
      CloseAndNotify();
    }


  // In case our syn/ack got lost
//  if (tcpflags == TcpHeader::SYN)
//    {
//      NS_FATAL_ERROR("Not implemented yet");
//      // TODO check for MP_CAPABLE
//      // factorize with code from Listen( that sends options !!
//
//      // Probably the peer lost my SYN+ACK
//      // So we need to resend it with the MPTCP option
//      // This could be a join case too
//      Ptr<TcpOptionMpTcpCapable> mpc;
//      TcpHeader answerHeader;
//      GenerateEmptyPacketHeader(answerHeader,TcpHeader::SYN | TcpHeader::ACK);
//      mpc->SetSenderKey( GetMeta()->GetLocalKey() );
//      m_rxBuffer->SetNextRxSequence(tcpHeader.GetSequenceNumber() + SequenceNumber32(1));
//
//      answerHeader.AppendOption(mpc);
//      SendEmptyPacket(answerHeader);
//      return;
//    }

  //
//  TcpSocketBase::ProcessSynRcvd( packet, tcpHeader, fromAddress, toAddress);

}
#endif
bool
MpTcpSubflow::SendPendingData(bool withAck)
{
  //!
  NS_LOG_FUNCTION(this);
  return TcpSocketBase::SendPendingData(withAck);
}


/**
TODO m_masterSocket should not be necessary
*/
bool
MpTcpSubflow::IsMaster() const
{
//  NS_ASSERT(GetMeta());

  return m_masterSocket;
  // TODO it will never return true
//  TcpStates_t metaState = GetMeta()->GetState();
//  return (metaState == SYN_RCVD
//      || metaState == SYN_SENT
//    || m_endPoint == GetMeta()->m_endPoint
//); // This is master subsock, its endpoint is the same as connection endpoint.
  // is that enough ?
//  return (m_metaSocket->m_subflows.size() == 1);
}


bool
MpTcpSubflow::BackupSubflow() const
{
  return m_backupSubflow;
}


/**
should be able to advertise several in one packet if enough space
It is possible
http://tools.ietf.org/html/rfc6824#section-3.4.1
   A host can send an ADD_ADDR message with an already assigned Address
   ID, but the Address MUST be the same as previously assigned to this
   Address ID, and the Port MUST be different from one already in use
   for this Address ID.  If these conditions are not met, the receiver
   SHOULD silently ignore the ADD_ADDR.  A host wishing to replace an
   existing Address ID MUST first remove the existing one
   (Section 3.4.2).

   A host that receives an ADD_ADDR but finds a connection set up to
   that IP address and port number is unsuccessful SHOULD NOT perform
   further connection attempts to this address/port combination for this
   connection.  A sender that wants to trigger a new incoming connection
   attempt on a previously advertised address/port combination can
   therefore refresh ADD_ADDR information by sending the option again.

**/
void
MpTcpSubflow::AdvertiseAddress(Ipv4Address addr, uint16_t port)
{
  NS_LOG_FUNCTION("Started advertising address");
//  NS_ASSERT( );
#if 0
//      IPv4Address;;ConvertFrom ( addr );
  Ptr<TcpOptionMpTcpAddAddress> addAddrOption = CreateObject<TcpOptionMpTcpAddAddress>();
  addAddrOption->SetAddress( InetSocketAddress( m_endPoint->GetLocalAddress(),0), addrId );


//      this->SendPacket(pkt, header, m_localAddress, m_remoteAddress, FindOutputNetDevice(m_localAddress) );
  NS_LOG_INFO("Advertise  Addresses-> "<< header);
  #endif
}


bool
MpTcpSubflow::StopAdvertisingAddress(Ipv4Address address)
{
  return true;
}


void
MpTcpSubflow::ReTxTimeout()
{
  NS_LOG_LOGIC("MpTcpSubflow ReTxTimeout expired !");
  TcpSocketBase::ReTxTimeout();
}

/*
   The sender MUST keep data in its send buffer as long as the data has
   not been acknowledged at both connection level and on all subflows on
   which it has been sent.

For now assume
Called from NewAck, this
SequenceNumber32 const& ack,
*/
bool
MpTcpSubflow::DiscardAtMostOneTxMapping(SequenceNumber64 const& firstUnackedMeta, MpTcpMapping& mapping)
//MpTcpSubflow::DiscardTxMappingsUpTo(SequenceNumber32 const& dack, SequenceNumber32 const& ack)
{
  NS_LOG_DEBUG("Removing mappings with DSN <" << firstUnackedMeta
          << " and SSN <" << FirstUnackedSeq()
          );

  SequenceNumber32 headSSN = m_txBuffer->HeadSequence();


  //  MpTcpMapping mapping;
  // m_state == FIN_WAIT_1 &&
  if(headSSN >= FirstUnackedSeq())
  {
    NS_LOG_DEBUG("Subflow tx Buffer already empty");
    return false;
  }
  else if(!m_TxMappings.GetMappingForSSN(headSSN, mapping))
  {
    m_TxMappings.Dump();
    NS_LOG_ERROR("Could not associate a tx mapping to ssn [" << headSSN << "]. Should be impossible");
//    NS_FATAL_ERROR("Could not associate a tx mapping to ssn [" << headSSN << "]. Should be impossible");
    return false;
  }

  if(mapping.TailDSN() < firstUnackedMeta && mapping.TailSSN() < FirstUnackedSeq())
  {
    NS_LOG_DEBUG("mapping can be discarded");
    bool ok = m_TxMappings.DiscardMapping(mapping);
    NS_ASSERT(ok);
    m_txBuffer->DiscardUpTo(mapping.TailSSN() + SequenceNumber32(1));
    return true;
  }

  return false;
}


bool
MpTcpSubflow::UpdateWindowSize(const TcpHeader& header)
{
    bool updated = TcpSocketBase::UpdateWindowSize(header);
    if(updated)
    {
        GetMeta()->UpdateWindowSize(header);
    }
    return updated;
}

uint32_t
MpTcpSubflow::GetTxAvailable() const
{
  //!
  return TcpSocketBase::GetTxAvailable();
}


void
MpTcpSubflow::UpdateTxBuffer()
{
  NS_LOG_FUNCTION(this);
  GetMeta()->SyncTxBuffers();
}

/**
TODO check with its parent equivalent, may miss a few features
Receipt of new packet, put into Rx buffer

SlowStart and fast recovery remains untouched in MPTCP.
The reaction should be different depending on if we handle NR-SACK or not
*/

void
MpTcpSubflow::NewAck(SequenceNumber32 const& ack)
{
  NS_LOG_FUNCTION (this << ack);

  TcpSocketBase::NewAck(ack);
#if 0
  MpTcpMapping mapping;

  // TODO move elsewhere on rece
//  if(!m_TxMappings.GetMappingForSegment( ack-1, mapping) )
//  {
//    NS_LOG_DEBUG("Could not find an adequate Tx mapping for ack " << ack);
//    return;
//  }

  NS_LOG_FUNCTION (this << ack);
  NS_LOG_LOGIC ("Subflow receieved ACK for seq " << ack <<
                " cwnd " << m_cWnd <<
                " ssthresh " << m_ssThresh
              );



  // Check for exit condition of fast recovery
  if (m_inFastRec)
    { // RFC2001, sec.4; RFC2581, sec.3.2
      // First new ACK after fast recovery: reset cwnd
      m_cWnd = m_ssThresh;
      m_inFastRec = false;
      NS_LOG_INFO ("Exiting fast recovery. Reset cwnd to " << m_cWnd);
    };


  // Increase of cwnd based on current phase (slow start or congestion avoidance)
  if (m_cWnd < m_ssThresh)
    { // Slow start mode, add one segSize to cWnd. Default m_ssThresh is 65535. (RFC2001, sec.1)
      m_cWnd += GetSegSize();
      NS_LOG_INFO ("In SlowStart, updated to cwnd " << m_cWnd << " ssthresh " << m_ssThresh);
    }
  else
    {
      /** TODO in the future, there should be a way to easily override this in future releases
      **/

      // Congestion avoidance mode, increase by (segSize*segSize)/cwnd. (RFC2581, sec.3.1)
//
//      OpenCwndInCA(0);

      // To increase cwnd for one segSize per RTT, it should be (ackBytes*segSize)/cwnd
//      double adder = static_cast<double> (m_segmentSize * m_segmentSize) / m_cWnd.Get ();
//      adder = std::max (1.0, adder);
//      m_cWnd += static_cast<uint32_t> (adder);
      NS_LOG_INFO ("In CongAvoid, updated to cwnd " << m_cWnd << " ssthresh " << m_ssThresh);
    }




  if (m_state != SYN_RCVD)
    { // Set RTO unless the ACK is received in SYN_RCVD state
      NS_LOG_LOGIC (this << " Cancelled ReTxTimeout event which was set to expire at " <<
          (Simulator::Now () + Simulator::GetDelayLeft (m_retxEvent)).GetSeconds ());
      m_retxEvent.Cancel();
      // On recieving a "New" ack we restart retransmission timer .. RFC 2988
      // TODO
//      m_rto = m_rtt->RetransmitTimeout();
//      NS_LOG_LOGIC (this << " Schedule ReTxTimeout at time " <<
//          Simulator::Now ().GetSeconds () << " to expire at time " <<
//          (Simulator::Now () + m_rto.Get ()).GetSeconds ());
//      m_retxEvent = Simulator::Schedule(m_rto, &MpTcpSubflow::ReTxTimeout, this);
    }

  if (m_rWnd.Get() == 0 && m_persistEvent.IsExpired())
    { // Zero window: Enter persist state to send 1 byte to probe
      NS_LOG_LOGIC (this << "Enter zerowindow persist state");NS_LOG_LOGIC (this << "Cancelled ReTxTimeout event which was set to expire at " <<
          (Simulator::Now () + Simulator::GetDelayLeft (m_retxEvent)).GetSeconds ());
      m_retxEvent.Cancel();
      NS_LOG_LOGIC ("Schedule persist timeout at time " <<
          Simulator::Now ().GetSeconds () << " to expire at time " <<
          (Simulator::Now () + m_persistTimeout).GetSeconds ());
      m_persistEvent = Simulator::Schedule(m_persistTimeout, &MpTcpSubflow::PersistTimeout, this);
      NS_ASSERT(m_persistTimeout == Simulator::GetDelayLeft (m_persistEvent));
    }

  // Note the highest ACK and tell app to send more
  NS_LOG_LOGIC ("TCP " << this << " NewAck " << ack <<
      " numberAck " << (ack - FirstUnackedSeq())); // Number bytes ack'ed


  m_firstTxUnack = std::min(ack, m_txBuffer->TailSequence());

  // TODO: get mapping associated with that Ack and
  // TODO could && m_state != FIN_WAIT_1
  // TODO I believe we could change that into something else
  if(!m_TxMappings.GetMappingForSSN( SequenceNumber32(ack-1), mapping) ) {

    NS_LOG_WARN("Late ack ! Mapping likely to have been discared already. Dumping Tx Mappings:");
    m_TxMappings.Dump();
  }
  else {
    // TODO check if all mappings below that are acked before removing them
    //    m_txBuffer->DiscardUpTo(ack);

    /** TODO here we have to update the nextTxBuffer
    but we can discard only if the full mapping was acknowledged
    la c completement con. A corriger
    */
//    if(m_nextTxSequence > mapping.TailSSN()) {
//
//      m_txBuffer->DiscardUpTo(m_nextTxSequence);
//    }
//      std::distance(s.begin(), s.lower_bound(x))
    // #error

    /**
    Before removing data from txbuffer, it must have been acked at both subflow
    and connection level.
    Here we go through the list of TxMappings
    min(ack,dataack
    **/
//    m_TxMappings.DiscardMappingsUpToDSN()


  }

  // Call it before to free window
  GetMeta()->OnSubflowNewAck(this);
// TODO I should call


  if (GetTxAvailable() > 0)
    {
      // Ok, va appeler la meta
      NotifySend(GetTxAvailable());
    }

  if (ack > m_nextTxSequence)
    {
//      if(m_state == FIN_WAIT_1 || m_state == CLOSING) {
//
//      }
//      NS_LOG_DEBUG("Advancing m_nextTxSequence from " << m_nextTxSequence  << " to " << ack);
      m_nextTxSequence = std::min(ack, m_txBuffer->TailSequence()); // If advanced
    }

  if (m_txBuffer->Size() == 0 && m_state != FIN_WAIT_1 && m_state != CLOSING)
    {
      // No retransmit timer if no data to retransmit
      NS_LOG_WARN (this << "TxBuffer empty. Cancelled ReTxTimeout event which was set to expire at " <<
          (Simulator::Now () + Simulator::GetDelayLeft (m_retxEvent)).GetSeconds ());
      m_retxEvent.Cancel();
      return;
    }

  if (m_txBuffer->Size() == 0)
    {
      NS_LOG_DEBUG("No tx buffer");
//      throughput = 10000000 * 8 / (Simulator::Now().GetSeconds() - fLowStartTime);
//      NS_LOG_UNCOND("goodput -> " << throughput / 1000000 << " Mbps {Tx Buffer is now empty}  P-AckHits:" << pAckHit);
      return;
    }
  // Try to send more data
  SendPendingData(m_connected);

//  TcpSocketBase::NewAck( ack );
  // WRONG  they can be sparse. This should be done by meta
  // DiscardTxMappingsUpToDSN( ack );
  //  Je peux pas le discard tant que
  //  m_txBuffer->DiscardUpTo( ack );
  // TODO check the full mapping is reachable
//  if( m_txBuffer->Available(mapping.HeadDSN(), mapping.MaxSequence()))
//  {
//    Packet pkt = m_rxBuffer->Extract(mapping.HeadDSN(), mapping.GetLength() );
//
//    //! pass on data
//    GetMeta()->ReceivedData( pkt, mapping );
//
//  }
#endif
}



Ptr<Packet>
MpTcpSubflow::RecvFrom(uint32_t maxSize, uint32_t flags, Address &fromAddress)
{
  NS_FATAL_ERROR("Disabled in MPTCP. Use ");
  return 0;
}

Ptr<Packet>
MpTcpSubflow::Recv(uint32_t maxSize, uint32_t flags)
{
  //!
  NS_FATAL_ERROR("Disabled in MPTCP. Use ");
  return 0;
}

Ptr<Packet>
MpTcpSubflow::Recv(void)
{
  //!
  NS_FATAL_ERROR("Disabled in MPTCP. Use ");
  return 0;
}


//bool
//MpTcpSubflow::TranslateSSNtoDSN(SequenceNumber32 ssn,SequenceNumber32 &dsn)
//{
//  // first find if a mapping exists
//  MpTcpMapping mapping;
//  if(!GetMappingForSegment( m_RxMappings, ssn, mapping) )
//  {
//    //!
//    return false;
//  }
//
//  return mapping.TranslateSSNToDSN(ssn,dsn);
//}



/**
this is private
**/
Ptr<Packet>
MpTcpSubflow::ExtractAtMostOneMapping(uint32_t maxSize, bool only_full_mapping, SequenceNumber64& headDSN)
{
  NS_LOG_DEBUG(this << " maxSize="<< maxSize);
  MpTcpMapping mapping;
  Ptr<Packet> p = Create<Packet>();

  uint32_t rxAvailable = GetRxAvailable();
  if(rxAvailable == 0)
  {
    NS_LOG_LOGIC("Nothing to extract");
    return p;
  }
  else
  {
    NS_LOG_LOGIC(rxAvailable  << " Rx available");
  }

  // as in linux, we extract in order
  SequenceNumber32 headSSN = m_rxBuffer->HeadSequence();

//  NS_LOG_LOGIC("Extracting from SSN [" << headSSN << "]");
  //SequenceNumber32 headDSN;


   if(!m_RxMappings.GetMappingForSSN(headSSN, mapping))
//  if(!m_RxMappings.TranslateSSNtoDSN(headSSN, dsn))
  {
//      NS_LOG_DEBUG("Could not find a mapping for headSSN=" << headSSN );

      m_RxMappings.Dump();
      NS_FATAL_ERROR("Could not associate a mapping to ssn [" << headSSN << "]. Should be impossible");
//    NS_FATAL_ERROR("Could not associate a mapping to ssn [" << headSSN << "]. Should be impossible");
  }
  NS_LOG_DEBUG("Extracting mapping " << mapping);

  headDSN = mapping.HeadDSN();

  if(only_full_mapping) {

    if(mapping.GetLength() > maxSize)
    {
      NS_LOG_DEBUG("Not enough space available to extract the full mapping");
      return p;
    }

    if(m_rxBuffer->Available() < mapping.GetLength())
    {
      NS_LOG_DEBUG("Mapping not fully received yet");
      return p;
    }
  }

  // Extract at most one mapping
  maxSize = std::min(maxSize, (uint32_t)mapping.GetLength());

  NS_LOG_DEBUG("Extracting at most " << maxSize << " bytes ");
  p = m_rxBuffer->Extract( maxSize );

//  m_RxMappings.DiscardMappingsUpToDSN( headDSN);
  // Not included

  // TODO seulement supprimer ce que l'on a extrait !
  SequenceNumber32 extractedTail = headSSN + p->GetSize() - 1;

  NS_LOG_DEBUG("ExtractedTail=" << extractedTail << " to compare with " << mapping.TailSSN());

  NS_ASSERT_MSG( extractedTail <= mapping.TailSSN(), "Can not extract more than the size of the mapping");

  if(extractedTail < mapping.TailSSN() )
  {
    NS_ASSERT_MSG(!only_full_mapping, "The only extracted size possible should be the one of the mapping");
    // only if data extracted covers full mapping we can remove the mapping
  }
  else
  {
    m_RxMappings.DiscardMapping(mapping);
  }
//  m_RxMappings.DiscardMappingsUpToSN( mapping.TailDSN() + SequenceNumber32(1), mapping.TailSSN());
  return p;
}


void
MpTcpSubflow::AppendDSSMapping(const MpTcpMapping& mapping)
{
    NS_LOG_FUNCTION(this << mapping);
    m_dssFlags |= TcpOptionMpTcpDSS::DSNMappingPresent;
    m_dssMapping = mapping;
}

void
MpTcpSubflow::AppendDSSAck()
{
    NS_LOG_FUNCTION(this);
    m_dssFlags |= TcpOptionMpTcpDSS::DataAckPresent;
}

void
MpTcpSubflow::AppendDSSFin()
{
    NS_LOG_FUNCTION(this);
    m_dssFlags |= TcpOptionMpTcpDSS::DataFin;
}

/**
TODO here I should look for an associated mapping.

ProcessEstablished

If there is not, then I discard the stuff
std::ostream& ns3::operator<<(std::ostream&,const ns3::TcpOptionMptcpMain&)

TODO I should also notify the meta, maybe with an enum saying if it's new data/old etc...

TODO merge with TcpSocketBase
*/
void
MpTcpSubflow::ReceivedData(Ptr<Packet> p, const TcpHeader& tcpHeader)
{
  NS_LOG_FUNCTION (this << tcpHeader);
//  NS_LOG_FUNCTION (this << tcpHeader);NS_LOG_LOGIC ("seq " << tcpHeader.GetSequenceNumber () <<
//      " ack " << tcpHeader.GetAckNumber () <<
//      " pkt size " << p->GetSize ()
//      );
  // Following was moved to ReceivedAck sincethis is from there that ReceivedData can
  // be called

  MpTcpMapping mapping;
  bool sendAck = false;


//  OutOfRange
  // If cannot find an adequate mapping, then it should [check RFC]
  if(!m_RxMappings.GetMappingForSSN(tcpHeader.GetSequenceNumber(), mapping) )
  {

    m_RxMappings.Dump();
    NS_FATAL_ERROR("Could not find mapping associated ");
    return;
  }

  // Put into Rx buffer
  SequenceNumber32 expectedSSN = m_rxBuffer->NextRxSequence();
//  NS_LOG_DEBUG("adding packet " << p->ToString());
  if (!m_rxBuffer->Add(p, tcpHeader.GetSequenceNumber()))
    { // Insert failed: No data or RX buffer full
      NS_LOG_WARN("Insert failed, No data (" << p->GetSize() << ") ?"
          // Size() returns the actual buffer occupancy
//          << "or RX buffer full (Available:" << m_rxBuffer->Available()
//          << " Occupancy=" << m_rxBuffer->Size()
//          << " OOOSize=" << m_rxBuffer->OutOfOrder ()
//          << " Maxbuffsize=" << m_rxBuffer->MaxBufferSize() << ")"
//          << " or already buffered"
          );
      m_rxBuffer->Dump();

      AppendDSSAck();
      SendEmptyPacket(TcpHeader::ACK);
      return;
    }

  // Size() = Get the actual buffer occupancy
  if (m_rxBuffer->Size() > m_rxBuffer->Available() /* Out of order packets exist in buffer */
    || m_rxBuffer->NextRxSequence() > expectedSSN + p->GetSize() /* or we filled a gap */
    )
    { // A gap exists in the buffer, or we filled a gap: Always ACK
      sendAck = true;
    }
  else
    { // In-sequĶence packet: ACK if delayed ack count allows
      // TODO i removed delayed ack. may reestablish later
//      if (++m_delAckCount >= m_delAckMaxCount)
//        {
//          m_delAckEvent.Cancel();
//          m_delAckCount = 0;
          sendAck = true;
//            dss->SetDataAck(GetMeta()->m_rxBuffer->NextRxSequence().GetValue());
//            SendEmptyPacket(answerHeader);
//        }
//      else if (m_delAckEvent.IsExpired())
//        {
//          m_delAckEvent = Simulator::Schedule(m_delAckTimeout, &TcpSocketBase::DelAckTimeout, this);
//          NS_LOG_LOGIC (this << " scheduled delayed ACK at " << (Simulator::Now () + Simulator::GetDelayLeft (m_delAckEvent)).GetSeconds ());
//        }
    }




  // Notify app to receive if necessary
  if (expectedSSN < m_rxBuffer->NextRxSequence())
    { // NextRxSeq advanced, we have something to send to the app
      if (!m_shutdownRecv)
        {
          // todo maybe retrieve return valu: should we send an ack ?
           GetMeta()->OnSubflowRecv( this );
           sendAck = true;
        }
      // Handle exceptions
      if (m_closeNotified)
        {
          NS_LOG_WARN ("Why TCP " << this << " got data after close notification?");
        }
      // If we received FIN before and now completed all "holes" in rx buffer,
      // invoke peer close procedure
      if (m_rxBuffer->Finished() && (tcpHeader.GetFlags() & TcpHeader::FIN) == 0)
        {
          DoPeerClose();
        }
    }

    // For now we always sent an ack

    // should be always true hack to allow compilation
    if(sendAck)
    {
        // This should be done automatically
//      TcpHeader answerHeader;
//      GenerateEmptyPacketHeader(answerHeader, TcpHeader::ACK);
//      GetMeta()->AppendDataAck(answerHeader);
//      SendEmptyPacket(answerHeader);
      SendEmptyPacket(TcpHeader::ACK);
    }

  // TODO handle out of order case look at parent's member.
  // TODO pass subflow id to the function
  // TODO if that acknowledges a full mapping then transfer it to  the metasock
}

/* TODO unsure ?

*/
uint32_t
MpTcpSubflow::UnAckDataCount()
{
  NS_LOG_FUNCTION (this);
//  return GetMeta()->UnAckDataCount();
  return TcpSocketBase::UnAckDataCount();
}

// TODO unsure ?
uint32_t
MpTcpSubflow::BytesInFlight()
{
  NS_LOG_FUNCTION (this);
  return TcpSocketBase::BytesInFlight();
}

/* TODO unsure ?
*/
uint32_t
MpTcpSubflow::AvailableWindow()
{
  NS_LOG_FUNCTION (this);

  return TcpSocketBase::AvailableWindow();
//  GetMeta()->AvailableWindow();
}

/* this should be ok
*/
uint32_t
MpTcpSubflow::Window (void)
{
  NS_LOG_FUNCTION (this);
  return TcpSocketBase::Window();
//  return GetMeta()->Window();
}

//uint32_t
//MpTcpSubflow::RemoteWindow()
//{
//  NS_LOG_FUNCTION (this);
//  return GetMeta()->RemoteWindow();
//}

// Ok
uint16_t
MpTcpSubflow::AdvertisedWindowSize(void)
{
  NS_LOG_DEBUG(this);
  return GetMeta()->AdvertisedWindowSize();
}

/*
   Receive Window:  The receive window in the TCP header indicates the
      amount of free buffer space for the whole data-level connection
      (as opposed to for this subflow) that is available at the
      receiver.  This is the same semantics as regular TCP, but to
      maintain these semantics the receive window must be interpreted at
      the sender as relative to the sequence number given in the
      DATA_ACK rather than the subflow ACK in the TCP header.  In this
      way, the original flow control role is preserved.  Note that some
      middleboxes may change the receive window, and so a host SHOULD
      use the maximum value of those recently seen on the constituent
      subflows for the connection-level receive window, and also needs
      to maintain a subflow-level window for subflow-level processing.



Because of this, an implementation MUST NOT use the RCV.WND
   field of a TCP segment at the connection level if it does not also
   carry a DSS option with a Data ACK field.
*/
//void
//MpTcpSubflow::SetRemoteWindow(uint32_t win_size)
//{
//  NS_FATAL_ERROR("This function should never be called. Only meta can update remote window");
////  NS_LOG_FUNCTION(win_size);
////  MpTcpSubflow::GetMeta()->SetRemoteWindow()
////  TcpSocketBase::SetRemoteWindow(win_size);
//}


// TODO merge with parent
void
MpTcpSubflow::ClosingOnEmpty(TcpHeader& header)
{
  /* TODO the question is: is that ever called ?
  */
  NS_LOG_FUNCTION(this << "mattator");

    header.SetFlags( header.GetFlags() | TcpHeader::FIN);
    // flags |= TcpHeader::FIN;
    if (m_state == ESTABLISHED)
    { // On active close: I am the first one to send FIN
      NS_LOG_INFO ("ESTABLISHED -> FIN_WAIT_1");
      m_state = FIN_WAIT_1;
      // TODO get DSS, if none
//      Ptr<TcpOptionMpTcpDSS> dss;
//
//      //! TODO add GetOrCreateMpTcpOption member
//      if(!GetMpTcpOption(header, dss))
//      {
//        // !
//        dss = Create<TcpOptionMpTcpDSS>();
//
//      }
//      dss->SetDataFin(true);
//      header.AppendOption(dss);

    }
    else if (m_state == CLOSE_WAIT)
    {
      // On passive close: Peer sent me FIN already
      NS_LOG_INFO ("CLOSE_WAIT -> LAST_ACK");
      m_state = LAST_ACK;

    }

    GetMeta()->OnSubflowClosing(this);
}

//! TODO call directly parent
//void
//MpTcpSubflow::ParseDSS(Ptr<Packet> p, const TcpHeader& header,Ptr<TcpOptionMpTcpDSS> dss)
//{
//  //!
////  NS_FATAL_ERROR("TO REMOVE. Use meta->ProcessDSS")
//  NS_ASSERT(dss);
//  GetMeta()->ProcessDSS(header, dss, Ptr<MpTcpSubflow>(this));
//
//}

//
//int
//MpTcpSubflow::ProcessOptionMpTcpEstablished(const Ptr<const TcpOption> option)
//{
//    NS_LOG_FUNCTION(this << option);
//    //! Just looking for DSS
////    Ptr<TcpOptionMpTcpFastClose> fastClose;
////    GetTcpOption(fastClose)
////    Ptr<const TcpOptionMpTcpFastClose> fastClose = DynamicCast<const TcpOptionMpTcpFastClose>(option);
//    Ptr<const TcpOptionMpTcpDSS> dss = DynamicCast<const TcpOptionMpTcpDSS>(option);
//    if(dss)
//    {
//        ProcessOptionMpTcpDSSEstablished(dss);
//    }
//
//}

//int
//MpTcpSubflow::ProcessOptionMpTcpClosing(const Ptr<const TcpOption> option)
//{
//    NS_LOG_FUNCTION(this << option);
//
//    // Just DSS ?
//    ProcessTcpOptionMpTcpDSS
//}
//
//int
//MpTcpSubflow::ProcessOptionTimeWait(const Ptr<const TcpOption> option)
//{
//    NS_LOG_FUNCTION(this << option);
//
//}


/*
Quote from rfc 6824:
    Because of this, an implementation MUST NOT use the RCV.WND
    field of a TCP segment at the connection level if it does not also
    carry a DSS option with a Data ACK field

    and in not established mode ?
    TODO
*/
    #if 0
int
MpTcpSubflow::ProcessTcpOptionMpTcpDSS(Ptr<const TcpOptionMpTcpDSS> dss)
{
  NS_LOG_FUNCTION ( this << "Received ack " << dss << " from subflow ");

  // might be suboptimal but should make sure it gets properly updated
//  SequenceNumber32 dfin;
//  SequenceNumber32 dack;


  // TODO maybe this should be done within an processMPTCPoption, more global. For instance during 3WHS
  /*Because of this, an implementation MUST NOT use the RCV.WND
  field of a TCP segment at the connection level if it does not also
  carry a DSS option with a Data ACK field*/
  if(dss->GetFlags() & TcpOptionMpTcpDSS::DataAckPresent)
  {

    /*
    The receive window is relative to the DATA_ACK.  As in TCP, a
    receiver MUST NOT shrink the right edge of the receive window (i.e.,
    DATA_ACK + receive window).  The receiver will use the data sequence
    number to tell if a packet should be accepted at the connection
    level.

    TODO use, OutOfRange or IsInWindow ?
    TODO readd a check
    */


    if( dss->GetDataAck() + tcpHeader.GetWindowSize() >= m_rxBuffer->NextRxSequence().GetValue() + m_rWnd)
    {
      // TODO update all r_wnd of subflows
      NS_LOG_LOGIC("Updating receive window");
//      SetRemoteWindow(tcpHeader.GetWindowSize());
    }
    else {
//      NS_LOG_DEBUG("Not advancing window");
    }

  }

  switch(m_state)
  {

    case ESTABLISHED:
      ProcessDSSEstablished(
//                            tcpHeader,
                            dss
                            );
      break;

    case LAST_ACK:
    case CLOSING:
      ProcessDSSClosing(dss
//                        ,sf
                        );
      break;
    case FIN_WAIT_1:
    case FIN_WAIT_2:
    case CLOSE_WAIT:

    case TIME_WAIT:
      // do nothing just wait for subflows to be closed
      ProcessDSSWait(dss
//                     ,sf
                     );
      break;


    case SYN_RCVD:
      NS_LOG_ERROR("Unhandled DSS but Thing is I should not receive a DSS ack right now right ?");
      break;
    case LISTEN:
    case SYN_SENT:
    default:
      NS_FATAL_ERROR("Unhandled case to process DSS" << TcpStateName[m_state]);
      break;
  };
//  #endif
  // If there is any data piggybacked, store it into m_rxBuffer
//  if (packet->GetSize() > 0)
//    {
//      ReceivedData(packet, tcpHeader);
//    }
//  #endif
}
    #endif

#if 0
/* process while in CLOSING/LAST_ACK */
void
MpTcpSocketBase::ProcessOptionMpTcpClosing( Ptr<TcpOptionMpTcpDSS> dss, Ptr<MpTcpSubflow> sf)
{

  /////////////////////////////////////////////
  ////
  //// ZIS FUNCTION IS NEVER CALLED for now
  ////
  ////
  /////////////////////////////////////////////
  //// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  NS_LOG_FUNCTION (this << dss << " from " << this);


// CLOSING state means simultaneous close, i.e. no one is sending data to
      // anyone. If anything other than ACK is received, respond with a reset.
//  if(dss->GetFlags() & TcpOptionMpTcpDSS::DataFin) {
//    if()else
//    { // CLOSING state means simultaneous close, i.e. no one is sending data to
//      // anyone. If anything other than ACK is received, respond with a reset.
//      SendFastClose(sf);
//      CloseAndNotify();
//    }
//  }

  // If there is a datafin in there, I should ack it
  if ( dss->GetFlags() & TcpOptionMpTcpDSS::DataFin) {
    //
    PeerClose( SequenceNumber32(dss->GetDataFinDSN()), this);
  }


  if(dss->GetFlags() & TcpOptionMpTcpDSS::DataAckPresent)
  {
    SequenceNumber32 dack(dss->GetDataAck());
    NS_LOG_LOGIC("Received while closing dack="<< dack);
    // TODO maybe add 1 since it acknowledges the datafin ?
    // or maybe it is already
    // I changed m_rx by m_tx here
//    if ( dack == m_txBuffer->NextRxSequence())
    if ( dack == m_nextTxSequence)
    { // This ACK corresponds to the FIN sent
      NS_LOG_LOGIC("Our datafin got acked since dack=m_nextTxSequence="<< m_nextTxSequence);
      TimeWait(); //! TimeWait starts closing the subflows
      return;
    }
  }


// CLOSING state means simultaneous close, i.e. no one is sending data to
//      // anyone. If anything other than ACK is received, respond with a reset.
//  SendFastClose(sf);
//  CloseAndNotify();
}

/** when in m_closed fin_wait etc
According to 6824
A connection is considered closed once both hosts' DATA_FINs have
been acknowledged by DATA_ACKs.
*/
void
MpTcpSubflow::ProcessDSSWait( Ptr<TcpOptionMpTcpDSS> dss)
{
  NS_LOG_FUNCTION (this << dss << " from " << sf << " while in state [" << TcpStateName[m_state] << "]");

  if(dss->GetFlags() & TcpOptionMpTcpDSS::DataFin)
  {
    NS_LOG_LOGIC("Received DFIN");
//    if(m_state == FIN_WAIT_1)
//    {
      // TODO send
      PeerClose( SequenceNumber32(dss->GetDataFinDSN() ), sf);
//      TcpHeader header;
//      sf->GenerateEmptyPacketHeader(header,TcpHeader::ACK);
//      AppendDataAck(header);
//      sf->SendEmptyPacket(header);

//      NS_LOG_INFO("FIN_WAIT_1 -> CLOSING");
//      m_state = CLOSING;

//    }
//    else {
//      SendFastClose(sf);
////      CloseAndNotify();
//    }
  }

  // TODO I should check
  // m_txBuffer->SetHeadSequence(m_nextTxSequence)
  if(dss->GetFlags() & TcpOptionMpTcpDSS::DataAckPresent)
  {
    SequenceNumber32 dack(dss->GetDataAck() );
    ReceivedAck(dack,sf,false);


    NS_LOG_INFO("dack=" << dack <<  " to compare with m_nextTxSequence=" << m_nextTxSequence);
//    if (dack == m_rxBuffer->NextRxSequence())
//    if (dack == m_nextTxSequence)
//    { // This ACK corresponds to the DATA FIN sent
//      NS_LOG_LOGIC("Ack corresponds to DFIN sent");
//      NS_LOG_DEBUG("Setting m_nextTxSequence to ");
//      m_nextTxSequence = dack;
//      SyncTxBuffers();

      if(m_state == FIN_WAIT_1 && FirstUnackedSeq() == m_txBuffer->TailSequence()) {
        NS_LOG_LOGIC(" FIN_WAIT_1 -> FIN_WAIT_2");
        m_state= FIN_WAIT_2;
        return;
      }
//      // CLOSING or LAST_ACK
//      else if(m_state == CLOSING || m_state == LAST_ACK){
//        TimeWait();
//        return;
//      }
//      else {
//        NS_LOG_ERROR("dack=" << dack << " not equal to the one expected " << m_nextTxSequence);
//      }
  // Check if the close responder sent an in-sequence FIN, if so, respond ACK


    // Finished renvoie m_gotFin && m_finSeq < m_nextRxSeq
    NS_LOG_DEBUG("Is Rx Buffer finished ?" << m_rxBuffer->Finished());
    if ((m_state == FIN_WAIT_1 || m_state == FIN_WAIT_2) && m_rxBuffer->Finished())
    {
      if (m_state == FIN_WAIT_1)
        {
          NS_LOG_INFO ("FIN_WAIT_1 -> CLOSING");
          m_state = CLOSING;
          if (m_txBuffer->Size() == 0 && FirstUnackedSeq() == m_txBuffer->TailSequence())
            { // This ACK corresponds to the FIN sent
              TimeWait();
            }
        }
      else if (m_state == FIN_WAIT_2)
        {
          TimeWait();
        }
//      SendEmptyPacket(TcpHeader::ACK);
      if (!m_shutdownRecv)
        {
          NotifyDataRecv();
        }
    }
  }


  if( (dss->GetFlags() & TcpOptionMpTcpDSS::DSNMappingPresent) && !dss->DataFinMappingOnly() )
  {
      MpTcpMapping m = GetMapping(dss);
      sf->AddPeerMapping(m);
  }

}
#endif

int
MpTcpSubflow::ProcessOptionMpTcpDSSEstablished(const Ptr<const TcpOptionMpTcpDSS> dss)
{
  NS_LOG_FUNCTION (this << dss << " from subflow ");

  if(!GetMeta()->m_receivedDSS )
  {
    NS_LOG_LOGIC("First DSS received !");
    GetMeta()->m_receivedDSS = true;

    // Wrong, one should be able to send this a lot before
    // should be called only on client side
//    GetMeta()->ConnectionSucceeded();
  }

  //! datafin case handled at the start of the function
  if( (dss->GetFlags() & TcpOptionMpTcpDSS::DSNMappingPresent) && !dss->DataFinMappingOnly() )
  {
      MpTcpMapping m;
      // TODO Get mapping n'est utilisé qu'une fois, copier le code ici
      m = GetMapping(dss);
//      AddPeerMapping(m);
      // Add peer mapping
      bool ok = m_RxMappings.AddMapping( m );
      if(!ok)
      {
        NS_LOG_WARN("Could not insert mapping: already received ?");
        NS_LOG_UNCOND("Dumping Rx mappings...");
        m_RxMappings.Dump();
//        NS_FATAL_ERROR("Insert failed");
      }
  }

//  #if 0
//  uint32_t ack = (tcpHeader.GetAckNumber()).GetValue();
//  uint32_t tmp = ((ack - initialSeqNb) / m_segmentSize) % mod;
//  ACK.push_back(std::make_pair(Simulator::Now().GetSeconds(), tmp));
  if ( dss->GetFlags() & TcpOptionMpTcpDSS::DataFin)
  {
    NS_LOG_LOGIC("DFIN detected " << dss->GetDataFinDSN());
    GetMeta()->PeerClose( SequenceNumber32(dss->GetDataFinDSN()), this);
  }


  // TOdO replace that
  if( dss->GetFlags() & TcpOptionMpTcpDSS::DataAckPresent)
  {
//    NS_LOG_DEBUG("DataAck detected");
    GetMeta()->ReceivedAck( SequenceNumber32(dss->GetDataAck()), this, false);
//    SequenceNumber32 dack = SequenceNumber32(dss->GetDataAck());
  }



  return 0;
}


/*
Upon ack receival we need to act depending on if it's new or not
-if it's new it may allow us to discard a mapping
-otherwise notify meta of duplicate

this is called
*/
void
MpTcpSubflow::ReceivedAck(Ptr<Packet> p, const TcpHeader& header)
{
  NS_LOG_FUNCTION (this << header);

  // if packet size > 0 then it will call ReceivedData
  TcpSocketBase::ReceivedAck(p, header );

  // By default we always append a DACK
  // We should consider more advanced schemes
  AppendDSSAck();
}

// TODO remove
//bool
//MpTcpSubflow::AddPeerMapping(const MpTcpMapping& mapping)
//{
//  NS_LOG_FUNCTION(this << mapping);
//
//  return true;
//}

} // end of ns3
