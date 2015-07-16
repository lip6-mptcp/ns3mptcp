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
#ifndef MPTCP_PATH_ID_MANAGER_IMPL_H
#define MPTCP_PATH_ID_MANAGER_IMPL_H

#include "ns3/callback.h"
//#include "ns3/mptcp-mapping.h"
//#include "ns3/tcp-socket-base.h"
//#include "ns3/mp-tcp-path-manager.h"
//#include "ns3/gnuplot.h"
//#include "mp-tcp-subflow.h"

#include "ns3/object.h"
#include "ns3/address.h"
#include "ns3/inet-socket-address.h"
#include "ns3/mptcp-id-manager.h"
#include <map>
#include <vector>


namespace ns3
{


/**
* TODO setup callbacks in order to know if we shall accept the addition
* \brief The MPTCP path manager tracks ADD_ADDR/REM_ADDR in case the user wants to later open new subflows.
* It is possible to use callbacks from the MPTCP metasocket to be notified in case of a new ADD_ADDR.
* Thus it is possible to immediately create the desired subflows
*
RFC6824
   The Address IDs of the subflow used in the initial SYN exchange of
   the first subflow in the connection are implicit, and have the value
   zero.  A host MUST store the mappings between Address IDs and
   addresses both for itself and the remote host.  An implementation
   will also need to know which local and remote Address IDs are
   associated with which established subflows, for when addresses are
   removed from a local or remote host.

* There should be a testsuite to
* \class MpTcpPathIdManagerImpl
**/
class MpTcpPathIdManagerImpl : public MpTcpPathIdManager
{

public:


  MpTcpPathIdManagerImpl();

  virtual ~MpTcpPathIdManagerImpl();

  static TypeId
  GetTypeId (void);

  TypeId
  GetInstanceTypeId (void) const;

  /**
  Will generate an appropriate ID
  (InetSocketAddress addr
  **/
//  virtual uint8_t GetIdForLocalAddr( Ipv4Address address );
//  virtual bool RemLocalAddr(Ipv4Address addr);

  /**
  \param addresses
  \warning Don't forget to clear the vector first !
  **/

  virtual void
  GetAllAdvertisedDestinations(std::vector<InetSocketAddress>& addresses);

  // TODO move callbacks here + local address Mgmt ?


  uint8_t
  GetLocalAddrId(const InetSocketAddress& address);
  /**
  Can force the ID with which to register
  //    const Ipv4Address& address, uint16_t port = 0
  **/
  virtual bool
  AddRemoteAddr(uint8_t addrId, const Ipv4Address& address, uint16_t port);

  /**
  * del/rem
  */
  virtual bool
  RemRemoteAddr(uint8_t addrId);

  virtual bool
  RemLocalAddr(InetSocketAddress addrId);
//  virtual bool
//  RemLocalAddr(uint8_t addrId) ;

protected:
  friend class MpTcpSocketBase;


  // MPTCP containers
  // INetSocketAddress
//  InetSocketAddress
  typedef std::pair<const Ipv4Address, std::vector<uint16_t> > MpTcpAddressInfo;  //!< Ipv4/v6 address and its port

//  typedef std::multimap<uint8_t,MpTcpAddressInfo>  MpTcpAddressContainer;
  typedef std::map<uint8_t,MpTcpAddressInfo>  MpTcpAddressContainer;

  //! Maps an Address Id to the pair  (Ipv4/v6, port)
//  std::map<uint8_t,MpTcpAddressInfo> m_localAddrs;

   //! List addresses advertised by the remote host
   //! index 0 for local, 1 for remote addr
  MpTcpAddressContainer m_addrs;


  std::map<Ipv4Address,uint8_t> m_localAddresses; //!< Associate every local IP with an unique identifier

  /**
  Need this to check if an IP has already been advertised, in which case
  the same id should be associated to the already advertised IP

  **/
//  virtual MpTcpAddressContainer::iterator FindAddrIdOfAddr(Address addr );


//  virtual uint8_t GenerateAddrId(MpTcpAddressInfo);
//  virtual uint8_t GenerateAddrId(const InetSocketAddress&);
//  virtual uint8_t GenerateAddrId(const InetSocketAddress6&);
};



}



#endif // MPTCP_PATH_ID_MANAGER_IMPL_H
