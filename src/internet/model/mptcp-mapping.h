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
#ifndef MPTCP_MAPPING_H
#define MPTCP_MAPPING_H

#include <stdint.h>
#include <vector>
#include <queue>
#include <list>
#include <set>
#include <map>
#include "ns3/object.h"
#include "ns3/uinteger.h"
#include "ns3/traced-value.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/sequence-number.h"
#include "ns3/rtt-estimator.h"
#include "ns3/event-id.h"
#include "ns3/packet.h"
#include "ns3/tcp-socket.h"
#include "ns3/ipv4-end-point.h"
#include "ns3/ipv4-address.h"
#include "ns3/tcp-tx-buffer.h"
#include "ns3/tcp-rx-buffer.h"

namespace ns3
{

/*
Only sha1 standardized for now
TODO remove and use the MPTCP option one ?
*/
//typedef enum {
//MPTCP_SHA1
//} mptcp_crypto_t;


/**
TODO rename later into MpTcpDSNMapping

=====
this should work with 64 bits seq number
======

DSN=Data Sequence Number (mptcp option level)
SSN=Subflow Sequence Number (TCP legacy seq nb)

\todo dataSeqNb should be a uint64_t but that has implications over a lot of code,
especially TCP buffers so it should be thought out with ns3 people beforehand
*/
class MpTcpMapping
{
public:
  MpTcpMapping(void);

  virtual ~MpTcpMapping(void);

  /**
  TODO maybe remove
  **/
//  void Configure( SequenceNumber32  dataSeqNb, uint16_t mappingSize);

  /**
  * \brief Set subflow sequence number
  * \param headSSN
  */
  void MapToSSN( SequenceNumber32 const& headSSN);



  /**
  \return True if mappings share DSN space
  Check if there is an overlap over DSN space or SSN space
  Decline to DSN and SSN ?
  Rename to overlap
  */
//  bool
//  Intersect(const MpTcpMapping&) const;

  /**
  TODO do the same for DSNs
  **/
  virtual bool
  OverlapRangeSSN(const SequenceNumber32& headSSN, const uint16_t& len) const;

  virtual bool
  OverlapRangeDSN(const SequenceNumber64& headDSN, const uint16_t& len) const;

  /**
   *
   */
  void
  SetHeadDSN(SequenceNumber64 const&);

  /**
   * \brief Set mapping length
   */
  virtual void
  SetMappingSize(uint16_t const&);

  /**
  * \param ssn Data seqNb
  */
  bool IsSSNInRange(SequenceNumber32 const& ssn) const;

  /**
  * \param dsn Data seqNb
  */
  bool IsDSNInRange(SequenceNumber64 const& dsn) const;

  /**
  * \param ssn Subflow sequence number
  * \param dsn Data Sequence Number
  * \return True if ssn belonged to this mapping, then a dsn would have been computed
  *
  */
  // TODO should be done by the user
  bool
  TranslateSSNToDSN(const SequenceNumber32& ssn, SequenceNumber64& dsn) const;
    /**
    **/
//    bool
//    TranslateSSNtoDSN(const SequenceNumber32& ssn,SequenceNumber32 &dsn);

  /**
   * \return The last MPTCP sequence number included in the mapping
   */
  SequenceNumber64 TailDSN (void) const;

  /**
  * \return The last subflow sequence number included in the mapping
  */
  SequenceNumber32 TailSSN (void) const;

  /**

  **/



  /**
  * Necessary for
  * std::set to sort mappings
  * Compares ssn
  * \brief Compares mapping based on their DSN number. It is required when inserting into a set
  */
  bool operator<(MpTcpMapping const& ) const;

  /**
   * \return MPTCP sequence number for the first mapped byte
   */
  virtual SequenceNumber64
  HeadDSN() const;

  // TODO rename into GetMappedSSN Head ?
  /**
   * \return subflow sequence number for the first mapped byte
   */
  virtual SequenceNumber32
  HeadSSN() const;

  /**
  * \return mapping length
  */
  virtual uint16_t
  GetLength() const ;

  /**
   * \brief Mapping are equal if everything concord, SSN/DSN and length
  */
  virtual bool operator==( const MpTcpMapping&) const;

  /**
   * \return Not ==
   */
  virtual bool operator!=( const MpTcpMapping& mapping) const;


  // TODO should be SequenceNumber64
protected:
//  SequenceNumber64 m_dataSequenceNumber;   //!< MPTCP level
  SequenceNumber64 m_dataSequenceNumber;   //!< MPTCP sequence number
  SequenceNumber32 m_subflowSequenceNumber;  //!< subflow sequence number
  uint16_t m_dataLevelLength;  //!< mapping length / size
//  bool m_send;  //!< Set to true if mapping already sent & acknowledged ?
};





/**
Depending on modifications allowed in upstream ns3, it may some day inherit from TcpTxbuffer etc ...
Meanwhile we have a pointer towards the buffers.
* \class MpTcpMappingContainer
* Mapping handling
Once a mapping has been advertised on a subflow, it must be honored. If the remote host already received the data
(because it was sent in parallel over another subflow), then the received data must be discarded.


TODO: it might be best to use a
std::lower_bound on map
Could be fun implemented as an interval tree
http://www.geeksforgeeks.org/interval-tree/
*/
class MpTcpMappingContainer
{
  public:
    MpTcpMappingContainer(void);
    virtual ~MpTcpMappingContainer(void);


    /**
    * Removes all mappings that covered dataspace seq nbs strictly lower than "dsn"
    * \param dsn
    */
//    virtual void
//    DiscardMappingsUpToDSN(const SequenceNumber32& dsn) ;


  /**
   * \brief Discard mappings which TailDSN() < maxDsn and TailSSN() < maxSSN

  This can be called only when dsn is in the meta socket Rx buffer and in order
  (since it may renegate some data when out of order).
  The mapping should also have been thoroughly fulfilled at the subflow level.


  \return Number of mappings discarded. >= 0
  Never used apparently
  **/
//  int
//  DiscardMappingsUpToSN(const SequenceNumber64& maxDsn, const SequenceNumber32& maxSsn);


  /**
  When Buffers work in non renegotiable mode,
  it should be possible to remove them one by one
  **/
  bool DiscardMapping(const MpTcpMapping& mapping);

  /**
  return lowest SSN number
  \return SSN
  Makes no sense
  */
//  SequenceNumber32 FirstMappedSSN (void) const;

  /**
   * \param firstUnmappedSsn last mapped SSN.
   * \return true if non empty
   *
   */
  bool FirstUnmappedSSN(SequenceNumber32& firstUnmappedSsn) const;

  /**
  For debug purpose. Dump all registered mappings
  **/
  virtual void Dump() const;

  /*

  */
//  bool
//  CheckIfMappingCovered(SequenceNumber32 start, uint32_t len, std::vector<MpTcpMapping>& mappings);

  /**
   * \brief one can iterate over it to find a range
   * TODO it should look for DSN and SSN overlaps
   * \param
   */
//  bool FindOverlappingMapping(
//                    const MpTcpMapping& mapping,
//                    bool ignore_identical,
//                    MpTcpMapping& ret
//                    ) const;
//  FindOverlappingMapping(SequenceNumber32 headSSN, uint32_t len, MpTcpMapping& ret) const;



  /**
  TODO this one generates disturbing logs, we should remove it
  and do it otherwise

  Will map the mapping to the first unmapped SSN
  \return Same value as for AddMappingEnforceSSN
  */
//  int
//  AddMappingLooseSSN(MpTcpMapping&);


  /**
   * \brief
   * Should do no check
   * The mapping
   * \note Check for overlap.
   * \return False if the dsn range overlaps with a registered mapping, true otherwise
   *
  **/
  bool AddMapping(const MpTcpMapping& mapping);

  /**
  * \param l list
  * \param m pass on the mapping you want to retrieve
  */
  bool
  GetMappingForSSN(const SequenceNumber32& ssn, MpTcpMapping& m) const;

  /**
   * \param dsn
   */
  virtual bool GetMappingsStartingFromSSN(SequenceNumber32 ssn, std::set<MpTcpMapping>& mappings);

protected:

    /**
    SSN/ mapping
    TODO
    Maybe use a map to recortd extra info
    we can assume that
    */

    std::set<MpTcpMapping> m_mappings;     //!< it is a set ordered by SSN
};

/**
This should be a set to prevent duplication and keep it ordered
*/

std::ostream& operator<<(std::ostream &os, const MpTcpMapping& mapping);



} //namespace ns3
#endif //MP_TCP_TYPEDEFS_H
