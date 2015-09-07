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
#include <iostream>
#include <set>
#include <iterator>
#include <algorithm>
#include "ns3/mptcp-mapping.h"
#include "ns3/simulator.h"
#include "ns3/log.h"


NS_LOG_COMPONENT_DEFINE("MpTcpMapping");

namespace ns3
{

/**
* \brief sorted on DSNs
*/
typedef std::set<MpTcpMapping> MappingList;
//typedef std::map<SequenceNumber32, MpTcpMapping> MappingList;


MpTcpMapping::MpTcpMapping() :
  m_dataSequenceNumber(0),
  m_subflowSequenceNumber(0),
  m_dataLevelLength(0)
{
  NS_LOG_FUNCTION(this);
}

MpTcpMapping::~MpTcpMapping(void)
{
  NS_LOG_FUNCTION(this);
};


void
MpTcpMapping::SetMappingSize(uint16_t const& length)
{
  NS_LOG_DEBUG(this << " length=" << length);
  m_dataLevelLength = length;
}

bool
MpTcpMapping::TranslateSSNToDSN(const SequenceNumber32& ssn, SequenceNumber64& dsn) const
{
  if(IsSSNInRange(ssn))
  {
//      dsn =
//    NS_FATAL_ERROR("TODO");
  // TODO check for seq wrapping ? PAWS
    dsn = SequenceNumber64(ssn - HeadSSN()) + HeadDSN();
    return true;
  }

  return false;
}


std::ostream&
operator<<(std::ostream& os, const MpTcpMapping& mapping)
{
  //
  os << "DSN [" << mapping.HeadDSN() << "-" << mapping.TailDSN ()
  //of size [" << mapping.GetLength() <<"] from DSN [" << mapping.HeadDSN()
    << "] mapped to SSN [" <<  mapping.HeadSSN() << "-" <<  mapping.TailSSN() << "]";
  return os;
}

void
MpTcpMapping::SetHeadDSN(SequenceNumber64 const& dsn)
{
  NS_LOG_DEBUG(this << " headDSN=" << dsn);
  m_dataSequenceNumber = dsn;
}


void
MpTcpMapping::MapToSSN( SequenceNumber32 const& seq)
{
  NS_LOG_DEBUG(this << " mapping to ssn=" << seq);
  m_subflowSequenceNumber = seq;
}

// n'est jamais utilisé en fait
//bool
//MpTcpMapping::Intersect(const MpTcpMapping& mapping) const
//{
//  //!
//  return( IsSSNInRange( mapping.HeadSSN()) || IsSSNInRange( mapping.TailSSN())
//         || IsDSNInRange( mapping.HeadDSN()) || IsDSNInRange( mapping.TailDSN()) );
//}

bool
MpTcpMapping::operator==(const MpTcpMapping& mapping) const
{
  //!
  return (
    GetLength() == mapping.GetLength()
    && HeadDSN() == mapping.HeadDSN()
    && HeadSSN() == mapping.HeadSSN()
//    && GetLength()  == GetLength()
    );
}

bool
MpTcpMapping::operator!=( const MpTcpMapping& mapping) const
{
  //!
  return !( *this == mapping);
}


SequenceNumber64
MpTcpMapping::HeadDSN() const
{
  return m_dataSequenceNumber;
}


SequenceNumber32
MpTcpMapping::HeadSSN() const
{
  return m_subflowSequenceNumber;
}

uint16_t
MpTcpMapping::GetLength() const
{
//  NS_LOG_FUNCTION(this);
  return m_dataLevelLength;
}


SequenceNumber64
MpTcpMapping::TailDSN(void) const
{
  return(HeadDSN()+GetLength()-1);
}

SequenceNumber32
MpTcpMapping::TailSSN(void) const
{
  return(HeadSSN()+GetLength()-1);
}

bool
MpTcpMapping::operator<(MpTcpMapping const& m) const
{

//  return (HeadDSN() < m.HeadDSN());
  return (HeadSSN() < m.HeadSSN());
}


bool
MpTcpMapping::IsSSNInRange(SequenceNumber32 const& ssn) const
{
//  return OverlapRangeSSN(ssn,0);
  return ( (HeadSSN() <= ssn) && (TailSSN() >= ssn) );
}

bool
MpTcpMapping::IsDSNInRange(SequenceNumber64 const& dsn) const
{
//  return OverlapRangeDSN(dsn,0);
  return ( (HeadDSN() <= dsn) && (TailDSN() >= dsn) );
}


//SequenceNumber32 subflowSeqNb
//void
//MpTcpMapping::Configure(SequenceNumber32  dataSeqNb, uint16_t mappingSize)
////  m_dataSeqNumber(dataSeqNb),
////  m_size(mappingSize)
//{
//  NS_LOG_LOGIC(this << "dsn [" << dataSeqNb << "], mappingSize [" << mappingSize << "]");
//  m_dataSequenceNumber = dataSeqNb;
//  m_dataLevelLength = mappingSize;
//}


bool
MpTcpMapping::OverlapRangeSSN(const SequenceNumber32& headSSN, const uint16_t& len) const
{
  SequenceNumber32 tailSSN = headSSN + len-1;
  //!
  if( HeadSSN() >  tailSSN || TailSSN() < headSSN)
  {
    return false;
  }
  NS_LOG_DEBUG("SSN overlap");
  return true;
}

bool
MpTcpMapping::OverlapRangeDSN(const SequenceNumber64& headDSN, const uint16_t& len) const
{
  SequenceNumber64 tailDSN = headDSN + len-1;
  //!
  if( HeadDSN() >  tailDSN || TailDSN() < headDSN)
  {
    return false;
  }

  NS_LOG_DEBUG("DSN overlap");
  return true;
}

///////////////////////////////////////////////////////////
///// MpTcpMappingContainer
/////
MpTcpMappingContainer::MpTcpMappingContainer(void)
{
  NS_LOG_LOGIC(this);
}

MpTcpMappingContainer::~MpTcpMappingContainer(void)
{
  NS_LOG_LOGIC(this);
}

void
MpTcpMappingContainer::Dump() const
{
  NS_LOG_UNCOND("\n==== Dumping list of mappings ====");
  for( MappingList::const_iterator it = m_mappings.begin(); it != m_mappings.end(); it++ )
  {
    NS_LOG_UNCOND( *it );
  }
  NS_LOG_UNCOND("==== End of dump ====\n");
}


#if 0
// This is wrong
bool
//MpTcpMappingContainer::FindOverlappingMapping(SequenceNumber32 headSSN, uint32_t len,  MpTcpMapping& ret) const
MpTcpMappingContainer::FindOverlappingMapping(const MpTcpMapping& mapping, bool ignore_identical, MpTcpMapping& ret) const
{
//  SequenceNumber32 tailSSN = headSSN + SequenceNumber32(len);
  NS_LOG_DEBUG("Looking for a mapping that overlaps with " << mapping );
  for( MappingList::const_iterator it = m_mappings.begin(); it != m_mappings.end(); it++ )
  {
    // Check if mappings overlap
//    if(it->IsSSNInRange(mapping) && mapping != *it )
  // Faux si le mapping est encore plus petit
    if(it->OverlapRangeSSN(mapping.HeadSSN(), mapping.GetLength())
      || it->OverlapRangeDSN(mapping.HeadDSN(), mapping.GetLength()) )
    {
      if( ignore_identical && (*it == mapping))
      {
        NS_LOG_DEBUG("Ignoring identical mapping " << *it);
        continue;
      }

      // Intersect, il devrait continuer ptet qu'il y en a un autre
      NS_LOG_WARN("Mapping " << mapping << " intersects with " << *it );
      ret = *it;
      return true;
    }

  }
  return false;
}



#endif



//! should return a boolean
bool
MpTcpMappingContainer::AddMapping(const MpTcpMapping& mapping)
//MpTcpMappingContainer::AddMappingEnforceSSN(const MpTcpMapping& mapping)
{
  NS_LOG_LOGIC("Adding mapping " << mapping);

  NS_ASSERT(mapping.GetLength() != 0);
//  NS_ASSERT(mapping.HeadSSN() >= );

//  MpTcpMapping temp;


//  if(FindOverlappingMapping(mapping, true, temp))
//  {
//    NS_LOG_WARN("Mapping " << mapping << " conflicts with existing " << temp);
//    Dump();
//    return false;
//  }


//
//  std::pair<MappingList::iterator,bool> res = m_mappings.insert( std::make_pair(mapping.HeadSSN(), mapping));
  std::pair<MappingList::iterator,bool> res = m_mappings.insert( mapping);

  return res.second;
}

bool
MpTcpMappingContainer::FirstUnmappedSSN(SequenceNumber32& ssn) const
{
//  NS_ASSERT(m_txBuffer);
  NS_LOG_FUNCTION_NOARGS();
  if(m_mappings.empty())
  {
      return false;
  }
  ssn = m_mappings.rbegin()->TailSSN() + 1;
  return true;
}


bool
MpTcpMappingContainer::DiscardMapping(const MpTcpMapping& mapping)
{
  NS_LOG_LOGIC("discard mapping "<< mapping);
//  MappingList::iterator it = l.begin(); it != l.end(); it++)
//  std::size_type count = m_mappings.erase(mapping);
//  return count != 0;
//  return m_mappings.erase(HeadSSN());
  return m_mappings.erase(mapping);
}

#if 0
int
MpTcpMappingContainer::DiscardMappingsUpToSN(const SequenceNumber64& dsn,const SequenceNumber32& ssn)
{
  NS_LOG_LOGIC("Discarding mappings up with TailDSN < " << dsn << " AND TailSSN < " << ssn);

  MappingList& l = m_mappings;
  int erasedMappingCount = 0;
  // TODO use reverse iterator and then clear from first found to the begin
  for(MappingList::iterator it = l.begin(); it != l.end(); it++)
  {
    // check that meta socket
    if( it->TailDSN() < dsn && it->TailSSN() < ssn)
    {
      erasedMappingCount++;
      l.erase(it);

    }
  }

  return erasedMappingCount;
}
#endif

bool
MpTcpMappingContainer::GetMappingsStartingFromSSN(SequenceNumber32 ssn, std::set<MpTcpMapping>& missing)
{
    NS_LOG_FUNCTION(this << ssn );
    missing.clear();
    //  std::copy(it,m_mappings.end(),);
//    http://www.cplusplus.com/reference/algorithm/equal_range/
    MpTcpMapping temp;
    temp.MapToSSN(ssn);
    MappingList::const_iterator it = std::lower_bound( m_mappings.begin(), m_mappings.end(), temp);

    std::copy(it, m_mappings.end(), std::inserter(missing, missing.begin()));
    return false;
}

bool
MpTcpMappingContainer::GetMappingForSSN(const SequenceNumber32& ssn, MpTcpMapping& mapping) const
{
  NS_LOG_FUNCTION(ssn);
  if(m_mappings.empty())
    return false;

  MpTcpMapping temp;
  temp.MapToSSN(ssn);

  // Returns the first that is not less
  // upper_bound returns the greater
  MappingList::const_iterator it = std::upper_bound( m_mappings.begin(), m_mappings.end(), temp);
//  if(it == m_mappings.end())
//  {
//    it = m_mappings.begin();
//    NS_LOG_DEBUG("could not find anything mapped to ssn" << ssn << "/" << temp.HeadSSN());
////    return false;
//  }
  it--;
  mapping = *it;
  NS_LOG_DEBUG("Is ssn in " << mapping << " ?");
  return mapping.IsSSNInRange( ssn );


//  if(Mapp)
//  MappingList& l = m_mappings;
//  for( MappingList::const_iterator it = l.begin(); it != l.end(); it++ )
//  {
//    // check seq nb is within the DSN range
//    if (
//      it->IsSSNInRange( ssn )
//    )
//    {
//      mapping = *it;
//      return true;
//    }
//  }

//  return false;
}



} // namespace ns3
