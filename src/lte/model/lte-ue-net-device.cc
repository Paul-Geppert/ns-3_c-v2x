/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2010 TELEMATICS LAB, DEE - Politecnico di Bari
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
 * Author: Giuseppe Piro  <g.piro@poliba.it>
 *         Nicola Baldo <nbaldo@cttc.es>
 *         Marco Miozzo <mmiozzo@cttc.es>
 * Modified by:
 *          Danilo Abrignani <danilo.abrignani@unibo.it> (Carrier Aggregation - GSoC 2015)
 *          Biljana Bojovic <biljana.bojovic@cttc.es> (Carrier Aggregation)
 */

#include "ns3/llc-snap-header.h"
#include "ns3/simulator.h"
#include "ns3/callback.h"
#include "ns3/node.h"
#include "ns3/packet.h"
#include "lte-net-device.h"
#include "ns3/packet-burst.h"
#include "ns3/uinteger.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/pointer.h"
#include "ns3/enum.h"
#include "ns3/lte-enb-net-device.h"
#include "lte-ue-net-device.h"
#include "lte-ue-mac.h"
#include "lte-ue-rrc.h"
#include "ns3/arp-header.h"
#include "ns3/ipv4-header.h"
#include "ns3/ipv6-header.h"
#include "ns3/udp-header.h"
#include "ns3/ipv4.h"
#include "ns3/ipv6.h"
#include "lte-amc.h"
#include "lte-ue-phy.h"
#include "epc-ue-nas.h"
#include <ns3/arp-l3-protocol.h>
#include <ns3/ipv4-l3-protocol.h>
#include <ns3/ipv6-l3-protocol.h>
#include <ns3/udp-l4-protocol.h>
#include <ns3/log.h>
#include "epc-tft.h"
#include <ns3/lte-ue-component-carrier-manager.h>
#include <ns3/object-map.h>
#include <ns3/object-factory.h>

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("LteUeNetDevice");

NS_OBJECT_ENSURE_REGISTERED ( LteUeNetDevice);


TypeId LteUeNetDevice::GetTypeId (void)
{
  static TypeId
    tid =
    TypeId ("ns3::LteUeNetDevice")
    .SetParent<LteNetDevice> ()
    .AddConstructor<LteUeNetDevice> ()
    .AddAttribute ("EpcUeNas",
                   "The NAS associated to this UeNetDevice",
                   PointerValue (),
                   MakePointerAccessor (&LteUeNetDevice::m_nas),
                   MakePointerChecker <EpcUeNas> ())
    .AddAttribute ("LteUeRrc",
                   "The RRC associated to this UeNetDevice",
                   PointerValue (),
                   MakePointerAccessor (&LteUeNetDevice::m_rrc),
                   MakePointerChecker <LteUeRrc> ())
    .AddAttribute ("LteUeComponentCarrierManager",
                   "The ComponentCarrierManager associated to this UeNetDevice",
                   PointerValue (),
                   MakePointerAccessor (&LteUeNetDevice::m_componentCarrierManager),
                   MakePointerChecker <LteUeComponentCarrierManager> ())
    .AddAttribute ("ComponentCarrierMapUe", "List of all component Carrier.",
                   ObjectMapValue (),
                   MakeObjectMapAccessor (&LteUeNetDevice::m_ccMap),
                   MakeObjectMapChecker<ComponentCarrierUe> ())
    .AddAttribute ("Imsi",
                   "International Mobile Subscriber Identity assigned to this UE",
                   UintegerValue (0),
                   MakeUintegerAccessor (&LteUeNetDevice::m_imsi),
                   MakeUintegerChecker<uint64_t> ())
    .AddAttribute ("DlEarfcn",
                   "Downlink E-UTRA Absolute Radio Frequency Channel Number (EARFCN) "
                   "as per 3GPP 36.101 Section 5.7.3. ",
                   UintegerValue (100),
                   MakeUintegerAccessor (&LteUeNetDevice::SetDlEarfcn,
                                         &LteUeNetDevice::GetDlEarfcn),
                   MakeUintegerChecker<uint32_t> (0, 262143))
    .AddAttribute ("CsgId",
                   "The Closed Subscriber Group (CSG) identity that this UE is associated with, "
                   "i.e., giving the UE access to cells which belong to this particular CSG. "
                   "This restriction only applies to initial cell selection and EPC-enabled simulation. "
                   "This does not revoke the UE's access to non-CSG cells. ",
                   UintegerValue (0),
                   MakeUintegerAccessor (&LteUeNetDevice::SetCsgId,
                                         &LteUeNetDevice::GetCsgId),
                   MakeUintegerChecker<uint32_t> ())
    .AddTraceSource ("PacketReceived",
                    "Trace fired when a new packet is received",
                    MakeTraceSourceAccessor (&LteUeNetDevice::m_packetReceivedCb),
                    "ns3::Packet::TracedCallback")
    .AddTraceSource ("PacketSend",
                    "Trace fired when a new packet is ready to send",
                    MakeTraceSourceAccessor (&LteUeNetDevice::m_packetSendCb),
                    "ns3::Packet::TracedCallback")
  ;

  return tid;
}


LteUeNetDevice::LteUeNetDevice (void)
  : m_isConstructed (false)
{
  NS_LOG_FUNCTION (this);
}

LteUeNetDevice::~LteUeNetDevice (void)
{
  NS_LOG_FUNCTION (this);
}

void
LteUeNetDevice::DoDispose (void)
{
  NS_LOG_FUNCTION (this);
  m_targetEnb = 0;

  m_rrc->Dispose ();
  m_rrc = 0;
  
  m_nas->Dispose ();
  m_nas = 0;
  for (uint32_t i = 0; i < m_ccMap.size (); i++)
    {
      m_ccMap.at (i)->Dispose ();
    }
  m_componentCarrierManager->Dispose ();
  LteNetDevice::DoDispose ();
}

void
LteUeNetDevice::UpdateConfig (void)
{
  NS_LOG_FUNCTION (this);

  if (m_isConstructed)
    {
      NS_LOG_LOGIC (this << " Updating configuration: IMSI " << m_imsi
                         << " CSG ID " << m_csgId);
      m_nas->SetImsi (m_imsi);
      m_rrc->SetImsi (m_imsi);
      m_nas->SetCsgId (m_csgId); // this also handles propagation to RRC
    }
  else
    {
      /*
       * NAS and RRC instances are not be ready yet, so do nothing now and
       * expect ``DoInitialize`` to re-invoke this function.
       */
    }
}



Ptr<LteUeMac>
LteUeNetDevice::GetMac (void) const
{
  NS_LOG_FUNCTION (this);
  return m_ccMap.at (0)->GetMac ();
}


Ptr<LteUeRrc>
LteUeNetDevice::GetRrc (void) const
{
  NS_LOG_FUNCTION (this);
  return m_rrc;
}


Ptr<LteUePhy>
LteUeNetDevice::GetPhy (void) const
{
  NS_LOG_FUNCTION (this);
  return m_ccMap.at (0)->GetPhy ();
}

Ptr<LteUeComponentCarrierManager>
LteUeNetDevice::GetComponentCarrierManager (void) const
{
  NS_LOG_FUNCTION (this);
  return m_componentCarrierManager;
}

Ptr<EpcUeNas>
LteUeNetDevice::GetNas (void) const
{
  NS_LOG_FUNCTION (this);
  return m_nas;
}

uint64_t
LteUeNetDevice::GetImsi () const
{
  NS_LOG_FUNCTION (this);
  return m_imsi;
}

uint32_t
LteUeNetDevice::GetDlEarfcn () const
{
  NS_LOG_FUNCTION (this);
  return m_dlEarfcn;
}

void
LteUeNetDevice::SetDlEarfcn (uint32_t earfcn)
{
  NS_LOG_FUNCTION (this << earfcn);
  m_dlEarfcn = earfcn;
}

uint32_t
LteUeNetDevice::GetCsgId () const
{
  NS_LOG_FUNCTION (this);
  return m_csgId;
}

void
LteUeNetDevice::SetCsgId (uint32_t csgId)
{
  NS_LOG_FUNCTION (this << csgId);
  m_csgId = csgId;
  UpdateConfig (); // propagate the change down to NAS and RRC
}

void
LteUeNetDevice::SetTargetEnb (Ptr<LteEnbNetDevice> enb)
{
  NS_LOG_FUNCTION (this << enb);
  m_targetEnb = enb;
}


Ptr<LteEnbNetDevice>
LteUeNetDevice::GetTargetEnb (void)
{
  NS_LOG_FUNCTION (this);
  return m_targetEnb;
}

std::map < uint8_t, Ptr<ComponentCarrierUe> >
LteUeNetDevice::GetCcMap ()
{
  return m_ccMap;
}

void
LteUeNetDevice::SetCcMap (std::map< uint8_t, Ptr<ComponentCarrierUe> > ccm)
{
  m_ccMap = ccm;
}

void 
LteUeNetDevice::DoInitialize (void)
{
  NS_LOG_FUNCTION (this);
  m_isConstructed = true;
  UpdateConfig ();

  std::map< uint8_t, Ptr<ComponentCarrierUe> >::iterator it;
  for (it = m_ccMap.begin (); it != m_ccMap.end (); ++it)
    {
      it->second->GetPhy ()->Initialize ();
      it->second->GetMac ()->Initialize ();
    }
  m_rrc->Initialize ();
}

void
LteUeNetDevice::SetPromiscReceiveCallback (PromiscReceiveCallback cb)
{
  NS_LOG_FUNCTION (this);
  m_promiscRxCallback = cb;
}

bool
LteUeNetDevice::Send (Ptr<Packet> packet, const Address& dest, uint16_t protocolNumber)
{
  NS_LOG_FUNCTION (this << dest << protocolNumber);

  if (!m_promiscRxCallback.IsNull() && protocolNumber == ArpL3Protocol::PROT_NUMBER) {

    /*
    * The LteUeNetDevice is in bridged mode and is asked to send an ARP packet.
    * 
    * This is because the devices connected on the other side of the bridge assume the LteUeNetDevice is compatible
    * with ARP and MAC addresses (like Ethernet and 802.11 Wifi) as it is connected to the bridge.
    * 
    * We imitate this behaviour by answering all ARP packets with our own address.
    * 
    * The LteUeNetDevice should only receive ARP requests for the configured Sidelink destination address.
    * If the configured Sidelink destination is a multicast address, we do not expect to receive an ARP request.
    * 
    * All other traffic from the simulation nodes is expected to be in form of IPv4 or IPv6 packets
    * or transmitted via other network interfaces/devices.
    */

    NS_LOG_INFO ("Received ARP packet and returning own MAC address as answer, as device is in bridged mode");

    auto header = ArpHeader ();
    packet->RemoveHeader (header);

    auto originalRequesterMac = header.GetSourceHardwareAddress();

    header.SetReply(
      // Source HW
      m_address,
      // Source IP
      header.GetDestinationIpv4Address(),
      // Des HW
      originalRequesterMac,
      // Dest IP
      header.GetSourceIpv4Address()
    );
    packet->AddHeader(header);

    m_packetReceivedCb(packet);
    m_promiscRxCallback (this, packet, ArpL3Protocol::PROT_NUMBER, m_address, originalRequesterMac, PACKET_HOST);
    return true;
  }

  if (protocolNumber != Ipv4L3Protocol::PROT_NUMBER && protocolNumber != Ipv6L3Protocol::PROT_NUMBER)
    {
      NS_LOG_INFO ("unsupported protocol " << protocolNumber << ", only IPv4 and IPv6 are supported");
      return true;
    }

  m_packetSendCb(packet);
  return m_nas->Send (packet);
}

void
LteUeNetDevice::Receive (Ptr<Packet> p)
{
  NS_LOG_FUNCTION (this << p);

  // We only send and receive IPv4 and IPv6 packets
  // Extract the received type from the IP header

  uint8_t ipType;
  p->CopyData (&ipType, 1);
  ipType = (ipType>>4) & 0x0f;

  if (!m_promiscRxCallback.IsNull ())
  {
    /**
    * LteUeNetDevice is in bridged mode
    * 
    * The bridge device on the host requires a valid MAC source and destination.
    * 
    * Source:
    * Packages need a suitable source address. For example, 00:00:00:00:00:00 will not work.
    * -> Use a MAC address which is not used by this or one of the other devices connected to the bridge.
    * 00:00:00:ff:ff:ff is not expected to be assigned -> use this address.
    * 
    * Destination:
    * The Sidelink data is behaving like broadcast data (at least until this layer).
    * Routing and packet filtering will happen on higher layers, e.g. IP and UDP.
    * -> Use the Mac48-Broadcast address to deliver the packet to all devices/nodes connected to the bridge.
    * 
    * At the moment, only IP packets are supported, GeoNetworking needs to be added in the future.
    */

    if (ipType == 0x04)
    {
      Ipv4Header ipHeader;
      ipHeader.EnableChecksum();
      p->RemoveHeader (ipHeader);

      bool changedDestination = false;

      // Receiving devices do not know which C-V2X group addresses exist
      // In case the destination is a Multicast address, we therefore change the destination of all C-V2X messages to Broadcast
      // In case of Broadcast and Unicast the message should be received correctly.
      if (ipHeader.GetDestination().IsMulticast())
      {
        ipHeader.SetDestination(Ipv4Address::GetBroadcast());
        ipHeader.SetTtl(32);
        changedDestination = true;
      }

      // IP packet has to contain an UDP packet, this is required by ETSI EN 302 636-3
      // If we manipulated the IP header, we need to update the UDP header as well
      // because the UDP headers checksum relies on the IP header
      if (changedDestination && ipHeader.GetProtocol() == UdpL4Protocol::PROT_NUMBER && ipHeader.GetFragmentOffset() == 0)
      {
        uint8_t * udpRawHeader = new uint8_t[8];
        p->CopyData (udpRawHeader, 8);

        UdpHeader udpHeader;
        p->RemoveHeader (udpHeader);

        // No fragmentation (the first fragment is also the last one)
        if (ipHeader.IsLastFragment())
        {
          // We changed the destination IP address, so the UDP checksum will be wrong
          // Unfortunately, we have to create a new header, otherwise checksum calculation will be wrong
          UdpHeader udpHeaderCopy;
          udpHeaderCopy.EnableChecksums();
          udpHeaderCopy.InitializeChecksum(ipHeader.GetSource(), ipHeader.GetDestination(), ipHeader.GetProtocol());
          udpHeaderCopy.SetSourcePort(udpHeader.GetSourcePort());
          udpHeaderCopy.SetDestinationPort(udpHeader.GetDestinationPort());
          udpHeader = udpHeaderCopy;
        }
        else
        {
          // We changed the destination IP address, so the UDP checksum will be wrong
          // As we do not know the whole UDP payload here, we cannot calculate the checksum correctly
          udpHeader.ForceChecksum(0);
          
          // The payloadSize needs to be forced, otherwise it will just be this (possibly) fragmented part
          uint16_t payloadPart1 = udpRawHeader[4];
          uint16_t payloadPart2 = udpRawHeader[5];
          uint16_t originalPayloadSize = (((payloadPart1 << 8) & 0xff00) | (payloadPart2 & 0x00ff ));
          udpHeader.ForcePayloadSize(originalPayloadSize);
        }
        free(udpRawHeader);
        p->AddHeader(udpHeader);
      }

      p->AddHeader(ipHeader);

      m_promiscRxCallback (this, p, Ipv4L3Protocol::PROT_NUMBER, Mac48Address("00:00:00:ff:ff:ff"), Mac48Address::GetBroadcast(), PACKET_BROADCAST);
    }
    else if (ipType == 0x06)
    {
      m_promiscRxCallback (this, p, Ipv6L3Protocol::PROT_NUMBER, Mac48Address("00:00:00:ff:ff:ff"), Mac48Address::GetBroadcast(), PACKET_BROADCAST);
    }
    else
    {
      NS_ABORT_MSG ("LteUeNetDevice::Receive for m_promiscRxCallback - Unknown IP type...");
    }
  }

  // Forward packet to higher layer

  if (ipType == 0x04)
  {
    m_packetReceivedCb(p);
    m_rxCallback (this, p, Ipv4L3Protocol::PROT_NUMBER, Address ());
  }
  else if (ipType == 0x06) {
    m_packetReceivedCb(p);
    m_rxCallback (this, p, Ipv6L3Protocol::PROT_NUMBER, Address ());
  }
  else
  {
    NS_ABORT_MSG ("LteUeNetDevice::Receive - Unknown IP type...");
  }
}

} // namespace ns3
