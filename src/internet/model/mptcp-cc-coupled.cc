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
#include "ns3/mptcp-cc-coupled.h"

namespace ns3
{

#if 0
void
MpTcpCongestionCoupled::CalculateAlpha()
{
  // this method is called whenever a congestion happen in order to regulate the agressivety of m_subflows
  // m_alpha = cwnd_total * MAX(cwnd_i / rtt_i^2) / {SUM(cwnd_i / rtt_i))^2}   //RFC 6356 formula (2)

  NS_LOG_FUNCTION(this);
  m_alpha = 0;
  double maxi = 0;
  double sumi = 0;

  for (uint32_t i = 0; i < m_metaSock->GetNActiveSubflows(); i++)
    {
      Ptr<MpTcpSubflow> sFlow = m_metaSock->GetSubflow(i);

      Time time = sFlow->rtt->GetCurrentEstimate();
      double rtt = time.GetSeconds();
      double tmpi = sFlow->cwnd.Get() / (rtt * rtt);
      if (maxi < tmpi)
        maxi = tmpi;

      sumi += sFlow->cwnd.Get() / rtt;
    }
  m_alpha = (m_totalCwnd * maxi) / (sumi * sumi);
}


//
uint32_t
MpTcpCongestionCoupled::OpenCWNDInCA(Ptr<MpTcpSubflow> subflow, uint32_t ackedBytes)
{
  NS_ASSERT( subflow );

  uint32_t MSS = subflow->GetSegSize();
  double inc = static_cast<double>(MSS * MSS) / m_totalCwnd;
  inc = std::max(1.0, inc);
  subflow->cwnd += static_cast<double>(inc);
//  NS_LOG_ERROR (
//      "Subflow "<<(int)sFlowIdx
//      <<" Congestion Control (Fully_Coupled) increment is "
//      << adder <<" GetSSThresh() "<< GetSSThresh() << " cwnd "<<cwnd);
  return 0;
}
#endif


}
