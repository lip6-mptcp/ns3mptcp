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
#ifndef MPTCP_CC_OLIA_H
#define MPTCP_CC_OLIA_H

//#include"ns3/mp-tcp-cc.h"
//#include"ns3/mp-tcp-subflow.h"
//#include"ns3/mp-tcp-socket-base.h"
#include"ns3/tcp-congestion-ops.h"
//#include"ns3/callback.h"

namespace ns3
{


/**
This is the linux struct.  We may try to get sthg close to this
http://www.nsnam.org/wiki/New_TCP_Socket_Architecture#Pluggable_Congestion_Control_in_Linux_TCP
static struct tcp_congestion_ops mptcp_olia = {
	.init		= mptcp_olia_init,
	.ssthresh	= tcp_reno_ssthresh,
	.cong_avoid	= mptcp_olia_cong_avoid,
	.set_state	= mptcp_olia_set_state,
	.min_cwnd	= tcp_reno_min_cwnd,
};

* \ingroup mptcp
*/
class MpTcpCCOlia : public TcpCongestionOps
{

public:
  static TypeId GetTypeId (void);

  MpTcpCCOlia();
  MpTcpCCOlia(const MpTcpCCOlia& sock);
  virtual ~MpTcpCCOlia();


  virtual void IncreaseWindow (Ptr<TcpSocketState> tcb);

  virtual uint32_t GetSsThresh (Ptr<const TcpSocketState> tcb);
  /**
  **/
//  virtual Ptr<TcpSocketBase> Fork(void);
  // transform into a callback ?
  // Callback<Ptr<MpTcpSubflow>, Ptr<MpTcpSocketBase>, Ptr<MpTcpCongestionControl> >
  //Ptr<MpTcpSubflow>

  // Called by SendPendingData() to get a subflow based on round robin algorithm
//  virtual int GeneratePartition(Ptr<MpTcpSocketBase> metaSock);

  virtual std::string
  GetName(void) const;

  virtual Ptr<TcpCongestionOps> Fork ();
protected:
};


}


#endif /* MPTCP_CC_OLIA_H */
