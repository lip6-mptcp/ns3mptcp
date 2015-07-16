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
#include "mptcp-id-manager.h"
#include "ns3/log.h"

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("MpTcpPathIdManager");


NS_OBJECT_ENSURE_REGISTERED(MpTcpPathIdManager);

TypeId
MpTcpPathIdManager::GetTypeId(void)
{
  static TypeId tid = TypeId("ns3::MpTcpPathIdManager")
      .SetParent<Object>()
//      .AddConstructor<MpTcpSubflow>()
      // TODO should be inherited
//      .AddTraceSource("cWindow",
//          "The congestion control window to trace.",
//           MakeTraceSourceAccessor(&MpTcpSubflow::m_cWnd))
    ;
  return tid;
}

MpTcpPathIdManager::MpTcpPathIdManager() :
  Object()
{
  NS_LOG_INFO(this);
}




} // end of ns3
