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
 * Author:  Matthieu Coudron <matthieu.coudron@lip6.fr>
 */

#ifndef TCP_TRACE_HELPER_H
#define TCP_TRACE_HELPER_H

#include "ns3/assert.h"
#include "ns3/ipv4-interface-container.h"
#include "ns3/ipv6-interface-container.h"
#include "ns3/ipv4.h"
#include "ns3/ipv6.h"
#include "ns3/trace-helper.h"

namespace ns3 {


// TODO look in TCP example for similar code
// TODO move those to a TCP helper
void
SetupSocketTracing(Ptr<TcpSocketBase> sock, const std::string prefix);

void
dumpSequence32(Ptr<OutputStreamWrapper> stream, std::string context, SequenceNumber32 oldSeq, SequenceNumber32 newSeq);

void
dumpUint32(Ptr<OutputStreamWrapper> stream, std::string context, uint32_t oldVal, uint32_t newVal);

//void
//dumpTcpState(Ptr<OutputStreamWrapper> stream, std::string context, TcpStates_t oldVal, TcpStates_t newVal);

#if 0
/**
 * @brief Base class providing common user-level pcap operations for helpers
 * representing IPv4 protocols .
 */
class PcapHelperForIpv4
{
public:
  /**
   * @brief Construct a PcapHelperForIpv4.
   */
  PcapHelperForIpv4 () {}

  /**
   * @brief Destroy a PcapHelperForIpv4.
   */
  virtual ~PcapHelperForIpv4 () {}

}
#endif

} // namespace ns3

#endif /* INTERNET_TRACE_HELPER_H */
