/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2010 University of Washington
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
 */

#include <stdint.h>
#include <string>
#include <fstream>

#include "ns3/abort.h"
#include "ns3/assert.h"
#include "ns3/log.h"
#include "ns3/ptr.h"
#include "ns3/node.h"
#include "ns3/names.h"
#include "ns3/net-device.h"
#include "ns3/pcap-file-wrapper.h"
#include "ns3/sequence-number.h"
#include "ns3/tcp-socket-base.h"
#include "ns3/mptcp-socket-base.h"
#include "ns3/mptcp-subflow.h"
//#include "ns3/mptcp-subflow.h"

#include "tcp-trace-helper.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("TcpTraceHelper");

void
dumpSequence32(Ptr<OutputStreamWrapper> stream, std::string context, SequenceNumber32 oldSeq, SequenceNumber32 newSeq)
{
  //<< context <<
//  if (context == "NextTxSequence")

  *stream->GetStream() << Simulator::Now()
                       << "," << oldSeq
                       << "," << newSeq
                       << std::endl;
}


void
dumpUint32(Ptr<OutputStreamWrapper> stream, std::string context, uint32_t oldVal, uint32_t newVal) {

//  NS_LOG_UNCOND("Context " << context << "oldVal=" << oldVal << "newVal=" << newVal);

  *stream->GetStream() << Simulator::Now()
                       << "," << oldVal
                       << "," << newVal
                       << std::endl;
}


void
dumpTcpState(Ptr<OutputStreamWrapper> stream, std::string context, TcpSocket::TcpStates_t oldVal, TcpSocket::TcpStates_t newVal) {
  // TODO rely
  *stream->GetStream() << Simulator::Now()
                      << "," << TcpSocket::TcpStateName[oldVal]
                      << "," << TcpSocket::TcpStateName[newVal]
                      << std::endl;
}

/**
TODO move that elsewhere, and plot the first line to get the initial value else it makes
for bad plots.
**/
void
TcpTraceHelper::SetupSocketTracing(Ptr<TcpSocketBase> sock, const std::string prefix)
{
  NS_LOG_UNCOND("SetupSocketTracing called with sock " << sock << " and prefix [" << prefix << "]");
  std::ios::openmode mode = std::ofstream::out | std::ofstream::trunc;

  AsciiTraceHelper asciiTraceHelper;
  Ptr<OutputStreamWrapper> streamTxNext = asciiTraceHelper.CreateFileStream (prefix+"_TxNext.csv", mode);
  Ptr<OutputStreamWrapper> streamTxHighest = asciiTraceHelper.CreateFileStream (prefix+"_TxHighest.csv", mode);
  Ptr<OutputStreamWrapper> streamRxAvailable = asciiTraceHelper.CreateFileStream (prefix+"_RxAvailable.csv", mode);
  Ptr<OutputStreamWrapper> streamRxTotal = asciiTraceHelper.CreateFileStream (prefix+"_RxTotal.csv", mode);
  Ptr<OutputStreamWrapper> streamRxNext = asciiTraceHelper.CreateFileStream (prefix+"_RxNext.csv", mode);
  Ptr<OutputStreamWrapper> streamTxUnack = asciiTraceHelper.CreateFileStream (prefix+"_TxUnack.csv", mode);
  Ptr<OutputStreamWrapper> streamStates = asciiTraceHelper.CreateFileStream (prefix+"_states.csv", mode);
  Ptr<OutputStreamWrapper> streamCwnd = asciiTraceHelper.CreateFileStream (prefix+"_cwnd.csv", mode);
  Ptr<OutputStreamWrapper> streamRwnd = asciiTraceHelper.CreateFileStream (prefix+"_rwnd.csv", mode);
  Ptr<OutputStreamWrapper> streamSSThreshold = asciiTraceHelper.CreateFileStream (prefix+"_ssThresh.csv", mode);

  Time now = Simulator::Now();
  // TODO use GetInitialCwnd, GetValue  etc...
  *streamTxNext->GetStream() << "Time,oldNextTxSequence,newNextTxSequence" << std::endl
//                             << now << ",," << sock->m_nextTxSequence << std::endl
                                ;

  *streamTxHighest->GetStream() << "Time,oldHighestSequence,newHighestSequence" << std::endl
//                              << now << ",," << sock->m_highTxMark << std::endl
                                ;

  // In fact it might be acked but as it neds to be moved on a per-mapping basis
  //
  *streamTxUnack->GetStream() << "Time,oldUnackSequence,newUnackSequence" << std::endl
                                  << now << ",," << sock->FirstUnackedSeq() << std::endl
                                  ;

  *streamRxNext->GetStream() << "Time,oldRxNext,newRxNext" << std::endl
//                             << now << ",," << sock->m_rxBuffer->NextRxSequence() << std::endl
                             ;

  *streamRxAvailable->GetStream() << "Time,oldRxAvailable,newRxAvailable" << std::endl
                                  << now << ",," << sock->GetRxAvailable() << std::endl
                                  ;

  *streamRxTotal->GetStream() << "Time,oldRxTotal,newRxTotal" << std::endl
//                                  << now << ",," << sock->m_rxBuffer->Size() << std::endl
                                  ;

  // TODO
  *streamCwnd->GetStream() << "Time,oldCwnd,newCwnd" << std::endl;
//                          << now << ",," << sock->m_cWnd.Get() << std::endl
;

//  *streamRwnd->GetStream() << "Time,oldRwnd,newRwnd" << std::endl
//                           << now << ",," << sock->RemoteWindow() << std::endl
//                           ;

  // We don't plot it, just looking at it so we don't care of the initial state
  *streamStates->GetStream() << "Time,oldState,newState" << std::endl;


//  , HighestSequence, RWND\n";

//  NS_ASSERT(f.is_open());

  // TODO je devrais etre capable de voir les CongestionWindow + tailles de buffer/ Out of order
//  CongestionWindow
//  Ptr<MpTcpSocketBase> sock(this);
//  NS_ASSERT(sock->TraceConnect ("RcvBufSize", "RcvBufSize", MakeBoundCallback(&dumpSequence32, streamTxNext)));
//  NS_ASSERT(sock->TraceConnect ("SndBufSize", "SndBufSize", MakeBoundCallback(&dumpSequence32, streamTxNext)));
  NS_ASSERT(sock->TraceConnect ("NextTxSequence", "NextTxSequence", MakeBoundCallback(&dumpSequence32, streamTxNext)));
  NS_ASSERT(sock->TraceConnect ("HighestSequence", "HighestSequence", MakeBoundCallback(&dumpSequence32, streamTxHighest)));
//  NS_ASSERT(sock->m_txBuffer->TraceConnect ("UnackSequence", "UnackSequence", MakeBoundCallback(&dumpSequence32, streamTxUnack)));
  NS_ASSERT(sock->TraceConnect ("UnackSequence", "UnackSequence", MakeBoundCallback(&dumpSequence32, streamTxUnack)));

  NS_ASSERT(sock->TraceConnect ("CongestionWindow", "CongestionWindow", MakeBoundCallback(&dumpUint32, streamCwnd)));
  NS_ASSERT(sock->TraceConnect ("State", "State", MakeBoundCallback(&dumpTcpState, streamStates) ));

//  Ptr<MpTcpSocketBase> sock2 = DynamicCast<MpTcpSocketBase>(sock);

//  Ptr<TcpTxBuffer> txBuffer( &sock->m_txBuffer);
//  NS_ASSERT(txBuffer->TraceConnect ("UnackSequence", "UnackSequence", MakeBoundCallback(&dumpSequence32, streamTx)));

//  NS_LOG_UNCOND("Starting research !!");


//  NS_ASSERT(sock->m_rxBuffer->TraceConnect ("NextRxSequence", "NextRxSequence", MakeBoundCallback(&dumpSequence32, streamRxNext) ));
//  NS_ASSERT(sock->m_rxBuffer->TraceConnect ("RxTotal", "RxTotal", MakeBoundCallback(&dumpUint32, streamRxTotal) ));
//  NS_ASSERT(sock->m_rxBuffer->TraceConnect ("RxAvailable", "RxAvailable", MakeBoundCallback(&dumpUint32, streamRxAvailable) ));

  NS_ASSERT(sock->TraceConnect ("RWND", "Remote WND", MakeBoundCallback(&dumpUint32, streamRwnd)));
  NS_ASSERT(sock->TraceConnect ("SlowStartThreshold", "SlowStartThreshold", MakeBoundCallback(&dumpUint32, streamSSThreshold)));

  /*
  This part is kinda specific to what we want to do
  */
  Ptr<MpTcpSubflow> sf = DynamicCast<MpTcpSubflow>(sock);
//  if(sock->GetInstanceTypeId() == MpTcpSubflow::GetTypeId())
  if(sf)
  {
    //!
//    *streamSSThreshold->GetStream() << "Time,oldSSThresh,newSSThresh" << std::endl
//                                  << now << ",," << sf->GetSSThresh() << std::endl;

    // TODO Trace first Cwnd
    *streamStates->GetStream() << now << ",," << TcpSocket::TcpStateName[sf->GetState()] << std::endl;


//    *streamCwnd->GetStream() << now << ",," << sf->m_cWnd.Get() << std::endl;
  }
  else if(sock->GetInstanceTypeId() == MpTcpSocketBase::GetTypeId())
  {
    //! Does nothing for now
    // could go to SetupMetaTracing
    Ptr<MpTcpSocketBase> meta = DynamicCast<MpTcpSocketBase>(sock);
    *streamStates->GetStream() << now << ",," << TcpSocket::TcpStateName[meta->GetState()] << std::endl;

  }
  else {
    NS_LOG_DEBUG("The passed sock is not related to MPTCP (which is not a problem in absolute terms)");
  }
}

//void
//MpTcpSocketBase::SetupMetaTracing(std::string prefix)
//{
////  f.open(filename, std::ofstream::out | std::ofstream::trunc);
//  m_tracePrefix = prefix + "/";
//
////  prefix = m_tracePrefix + "/meta";
//
//  // TODO move out to
//  SetupSocketTracing(this, m_tracePrefix + "/meta");
//}
//
//void
//MpTcpSocketBase::SetupSubflowTracing(Ptr<MpTcpSubflow> sf)
//{
//  NS_ASSERT_MSG(m_tracePrefix.length() != 0, "please call SetupMetaTracing before." );
//  NS_LOG_LOGIC("Meta=" << this << " Setup tracing for sf " << sf << " with prefix [" << m_tracePrefix << "]");
////  f.open(filename, std::ofstream::out | std::ofstream::trunc);
//
//  // For now, there is no subflow deletion so this should be good enough, else it will crash
//  std::stringstream os;
//  //! we start at 1 because it's nicer
//
//  os << m_tracePrefix << "subflow" <<  m_prefixCounter++;
//
//  SetupSocketTracing(sf, os.str().c_str());
//}



} // namespace ns3

