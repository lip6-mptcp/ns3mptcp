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
#ifndef MPTCP_CC_FULLY_COUPLED_H
#define MPTCP_CC_FULLY_COUPLED_H


#include <stdint.h>
#include "ns3/object.h"
//#include "ns3/mptcp-mapping.h"


namespace ns3
{

/**
\brief Defined in RFC 6356 (http://tools.ietf.org/html/rfc6356)

*/
#if 0
class MpTcpCongestionCoupled : public MpTcpCongestionControl
{

public:

  MpTcpCongestionCoupled(  );
  virtual ~MpTcpCongestionCoupled() {}

  virtual uint32_t
  GetInitialSSThresh(void) const = 0;

  virtual uint32_t
  GetInitialCwnd(void) const = 0;

  /**
  \brief
  \return The name of the congestion control
  **/
  virtual const char*
  GetName(void) const {
    return "Coupled";
  };

  /**
  \return Nb of
  */
  virtual void OpenCWNDInCA(Ptr<MpTcpSubflow> subflow, uint32_t ackedBytes);

protected:
  void CalculateAlpha();
  double m_alpha;
  uint32_t m_totalCwnd;

  // Put here for hte sake of simplicity
  // but should be moved to derived classes.
//  DataDistribAlgo_t m_distribAlgo; //!< Algorithm for Data Distribution
};
#endif

class MpTcpCongestionCoupled : public TcpCongestionOps
{
public:
  /**
   * \brief Get the type ID.
   * \return the object TypeId
   */
  static TypeId GetTypeId (void);

  MpTcpCongestionCoupled ();
  MpTcpCongestionCoupled (const MpTcpCongestionCoupled& sock);

  ~MpTcpCongestionCoupled ();

  std::string GetName () const;

  void IncreaseWindow (Ptr<TcpSocketState> tcb);
  uint32_t GetSsThresh (Ptr<const TcpSocketState> tcb);

  virtual Ptr<TcpCongestionOps> Fork ();
};


}


#endif /* MPTCP_CC_H */
