/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2010 Adrian Sai-wah Tam
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
 * Author: Adrian Sai-wah Tam <adrian.sw.tam@gmail.com>
 */

#include "tcp-tahoe.h"
#include "ns3/log.h"
#include "ns3/tcp-socket-base.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("TcpTahoe");

NS_OBJECT_ENSURE_REGISTERED (TcpTahoe);

TypeId
TcpTahoe::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::TcpTahoe")
    .SetParent<TcpNewReno> ()
    .SetGroupName ("Internet")
    .AddConstructor<TcpTahoe> ()
    .DeprecateAttribute ("ReTxThreshold", "TcpTahoe",
                         "The attribute ReTxThreshold is moved inside TcpSocketBase")
    .DeprecateTraceSource ("CongestionWindow", "TcpTahoe",
                           "The attribute CongestionWindow is moved inside TcpSocketBase")
    .DeprecateTraceSource ("SlowStartThreshold", "TcpTahoe",
                           "The attribute SlowStartThreshold is moved inside TcpSocketBase")
  ;
  return tid;
}

TcpTahoe::TcpTahoe (void) : TcpNewReno ()
{
  NS_LOG_FUNCTION (this);
}

TcpTahoe::TcpTahoe (const TcpTahoe& sock)
  : TcpNewReno (sock)
{
  NS_LOG_FUNCTION (this);
}

TcpTahoe::~TcpTahoe (void)
{
}

uint32_t
TcpTahoe::GetSsThresh (Ptr<const TcpSocketState> tcb)
{
  if (tcb->m_ackState == TcpSocketState::DISORDER)
    {
      // Tahoe only uses a timeout for detecting congestion
      return tcb->m_ssThresh;
    }
  else
    {
      return TcpNewReno::GetSsThresh (tcb);
    }
}

Ptr<TcpCongestionOps>
TcpTahoe::Fork()
{
  return CreateObject<TcpTahoe> (*this);
}

} // namespace ns3
