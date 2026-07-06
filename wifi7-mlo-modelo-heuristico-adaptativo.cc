#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/wifi-module.h"
#include "ns3/mobility-module.h"
#include "ns3/applications-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/system-path.h"

#include <fstream>
#include <iomanip>
#include <vector>
#include <map>
#include <sstream>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("Wifi7MloHeuristicaMultiKpi");

// ===================== Puertos por tipo =====================
static const uint16_t UDP_VOIP_BASE  = 41000;  // VOIP: 41000..41999
static const uint16_t UDP_IOT_BASE   = 42000;  // IoT : 42000..42999
static const uint16_t UDP_VIDEO_BASE = 43000;  // VIDEO: 43000..43999
static const uint16_t UDP_RANGE      = 1000;   // tamaño de cada rango
static const uint16_t TCP_PORT       = 5000;   // TCP fijo para sinks en APs

// ===================== Perfiles =============================
enum TrafficProfile { VOIP, VIDEO, IOT, TCP_TRAFFIC };

TrafficProfile
GetProfile ()
{
  Ptr<UniformRandomVariable> dist = CreateObject<UniformRandomVariable> ();
  double r = dist->GetValue ();
  if (r < 0.20) return VOIP;        // 20%
  if (r < 0.60) return VIDEO;       // 40%
  if (r < 0.70) return IOT;         // 10%
  return TCP_TRAFFIC;               // 30%
}

// ===================== Clasificador por FiveTuple ==========
static std::string
ClassifyFlowType (const Ipv4FlowClassifier::FiveTuple &t)
{
  // Protocol: TCP=6, UDP=17
  if (t.protocol == 6)
    return "TCP";

  if (t.protocol == 17)
    {
      auto inRange = [] (uint16_t p, uint16_t base, uint16_t span)
        { return (p >= base) && (p < base + span); };

      uint16_t d = t.destinationPort; // clasificamos por puerto destino (AP)
      if (inRange (d, UDP_VOIP_BASE,  UDP_RANGE))  return "VOIP";
      if (inRange (d, UDP_IOT_BASE,   UDP_RANGE))  return "IOT";
      if (inRange (d, UDP_VIDEO_BASE, UDP_RANGE))  return "VIDEO";
      return "UDP-OTRO";
    }
  return "OTRO";
}

// ===================== CSV extendido =======================
static void
WriteFlowMonitorCsv (FlowMonitorHelper &flowHelper,
                     Ptr<FlowMonitor> monitor,
                     const std::string &csvFile)
{
  std::ofstream out (csvFile.c_str (), std::ios::out);
  out << "flowId,src,dst,proto,srcPort,dstPort,txPackets,rxPackets,"
         "throughputKbps,delayMs,jitterMs,lossRatio,trafficType\n";

  Ptr<Ipv4FlowClassifier> classifier =
    DynamicCast<Ipv4FlowClassifier> (flowHelper.GetClassifier ());
  auto stats = monitor->GetFlowStats ();

  for (const auto &kv : stats)
    {
      uint32_t fid = kv.first;
      const auto &st = kv.second;

      Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow (fid);

      double t0 = st.timeFirstTxPacket.GetSeconds ();
      double t1 = st.timeLastRxPacket.GetSeconds ();
      double dur = t1 - t0;
      if (dur <= 0) dur = 1e-6;

      double thrKbps = (st.rxBytes * 8.0 / dur) / 1000.0;
      double meanDelayMs = (st.rxPackets > 0)
                              ? (st.delaySum.GetSeconds () / st.rxPackets) * 1000.0
                              : 0.0;

      double meanJitterMs = 0.0;
      if (st.rxPackets > 1)
        {
          meanJitterMs = (st.jitterSum.GetSeconds () /
                          double(st.rxPackets - 1)) * 1000.0;
        }

      double loss = (st.txPackets > 0)
                      ? (1.0 - double(st.rxPackets) / double(st.txPackets))
                      : 0.0;

      std::string type = ClassifyFlowType (t);

      out << fid << ","
          << t.sourceAddress << ","
          << t.destinationAddress << ","
          << unsigned(t.protocol) << ","
          << t.sourcePort << ","
          << t.destinationPort << ","
          << st.txPackets << ","
          << st.rxPackets << ","
          << std::fixed << std::setprecision (3) << thrKbps << ","
          << meanDelayMs << ","
          << meanJitterMs << ","
          << loss << ","
          << type
          << "\n";
    }
  out.close ();
}

// ===================== Estructuras control MLO =============

struct HeavyApps
{
  Ptr<OnOffApplication> app6;   // app pesada (VIDEO/TCP) en 6 GHz
  Ptr<OnOffApplication> app5;   // app pesada en 5 GHz
  double demandMbps;           // demanda "ofrecida" objetivo (ej. 4 Mbps)
};

// Controlador multi-KPI:
// - Sólo considera flujos VIDEO/TCP hacia AP de 6 GHz.
// - KPIs: load (Mbps en ventana), delay medio, loss.
// - score = 0.5*loadScore + 0.3*delayScore + 0.2*lossScore
//   con cada score normalizado respecto a un valor de referencia.
static void
AdjustRatiosMultiKpi (FlowMonitorHelper *flowmonHelper,
                      Ptr<FlowMonitor> monitor,
                      Ipv4Address ap6Addr,
                      std::vector<HeavyApps> heavyList,
                      double intervalSec,
                      double simEndTime)
{
  // Parámetros "fijos" del controlador
  const double refLoadMbps   = 40.0;  // carga de referencia para 6 GHz
  const double refDelayMs    = 50.0;  // delay de referencia (ms)
  const double refLoss       = 0.05;  // 5% de pérdida como referencia
  const double upperThresh   = 0.7;   // histeresis alta
  const double lowerThresh   = 0.4;   // histeresis baja
  const double dwellTimeSec  = 2.0;   // mínimo tiempo entre cambios
  const double minRatio6     = 0.2;   // límite inferior hacia 6 GHz
  const double maxRatio6     = 0.8;   // límite superior hacia 6 GHz
  const double ratioStep     = 0.1;   // tamaño de paso por ajuste

  // Parámetros variables del controlador
  static bool     firstCall       = true;
  static double   lastTime        = 0.0;
  static uint64_t lastRxBytes6    = 0;
  static double   ratio6          = 0.7;  // estado interno
  static double   lastChangeTime  = 0.0;

  double now = Simulator::Now ().GetSeconds ();

  Ptr<Ipv4FlowClassifier> classifier =
    DynamicCast<Ipv4FlowClassifier> (flowmonHelper->GetClassifier ());
  auto stats = monitor->GetFlowStats ();

  // Acumuladores para KPIs de VIDEO/TCP hacia AP6
  uint64_t sumRxBytes6 = 0;
  uint64_t sumTxPkts   = 0;
  uint64_t sumRxPkts   = 0;
  double   sumDelaySec = 0.0;
  uint32_t heavyFlows6 = 0;

  for (const auto &kv : stats)
    {
      uint32_t fid = kv.first;
      const auto &st = kv.second;
      Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow (fid);
      std::string type = ClassifyFlowType (t);

      bool isHeavy = (type == "VIDEO" || type == "TCP");
      bool toAp6   = (t.destinationAddress == ap6Addr);

      if (isHeavy && toAp6)
        {
          heavyFlows6++;
          sumRxBytes6 += st.rxBytes;
          sumTxPkts   += st.txPackets;
          sumRxPkts   += st.rxPackets;
          sumDelaySec += st.delaySum.GetSeconds ();
        }
    }

  // Throughput en ventana para VIDEO/TCP en 6 GHz
  double loadMbps = 0.0;
  if (!firstCall && now > lastTime)
    {
      double deltaB = double(sumRxBytes6 - lastRxBytes6);
      double deltaT = now - lastTime;
      if (deltaT > 0.0)
        {
          loadMbps = (deltaB * 8.0) / deltaT / 1e6;
        }
    }
  lastRxBytes6 = sumRxBytes6;
  lastTime     = now;
  firstCall    = false;

  // Delay medio global
  double meanDelayMs = 0.0;
  if (sumRxPkts > 0)
    {
      meanDelayMs = (sumDelaySec / double(sumRxPkts)) * 1000.0;
    }

  // Pérdida global
  double lossRatio = 0.0;
  if (sumTxPkts > 0)
    {
      lossRatio = 1.0 - double(sumRxPkts) / double(sumTxPkts);
    }

  // Normalización de KPIs en [0,1]
  auto clamp01 = [] (double x) { return std::max (0.0, std::min (1.0, x)); };

  double loadScore  = clamp01 (loadMbps    / refLoadMbps);
  double delayScore = clamp01 (meanDelayMs / refDelayMs);
  double lossScore  = clamp01 (lossRatio   / refLoss);

  // Score multi-KPI con pesos fijos
  double score = 0.5 * loadScore + 0.3 * delayScore + 0.2 * lossScore;

  // Log de diagnóstico
  NS_LOG_UNCOND ("[MLO-MultiKPI t=" << std::fixed << std::setprecision (2) << now << "s]"
                 << " flows6=" << heavyFlows6
                 << " load=" << loadMbps << "Mbps"
                 << " delay=" << meanDelayMs << "ms"
                 << " loss=" << lossRatio
                 << " score=" << score
                 << " ratio6=" << ratio6);

  // Histeresis + dwell time
  if (now - lastChangeTime >= dwellTimeSec)
    {
      double oldRatio6 = ratio6;
      if (score > upperThresh && ratio6 > minRatio6)
        {
          // muy cargado / mala calidad → bajar uso de 6 GHz
          ratio6 = std::max (minRatio6, ratio6 - ratioStep);
        }
      else if (score < lowerThresh && ratio6 < maxRatio6)
        {
          // buena situación → subir uso de 6 GHz
          ratio6 = std::min (maxRatio6, ratio6 + ratioStep);
        }

      if (ratio6 != oldRatio6)
        {
          lastChangeTime = now;
          NS_LOG_UNCOND ("  -> Ajuste ratio6: " << oldRatio6 << " -> " << ratio6);
        }
    }

  double ratio5 = 1.0 - ratio6;

  // Aplicar el reparto actualizado a todas las apps pesadas
  for (auto &h : heavyList)
    {
      if (h.app6)
        {
          DataRate r6 (std::to_string (std::max (0.001, h.demandMbps * ratio6)) + "Mbps");
          h.app6->SetAttribute ("DataRate", DataRateValue (r6));
        }
      if (h.app5)
        {
          DataRate r5 (std::to_string (std::max (0.001, h.demandMbps * ratio5)) + "Mbps");
          h.app5->SetAttribute ("DataRate", DataRateValue (r5));
        }
    }

  // Reprogramar
  if (now + intervalSec < simEndTime)
    {
      Simulator::Schedule (Seconds (intervalSec),
                           &AdjustRatiosMultiKpi,
                           flowmonHelper, monitor,
                           ap6Addr, heavyList,
                           intervalSec, simEndTime);
    }
}

// ===================== MAIN ================================
int
main (int argc, char *argv[])
{
  // Parámetros base
  uint32_t nSta    = 50;
  double   simTime = 20.0;
  uint32_t seed    = 42;
  std::string baseDir = "results/wifi7-mlo/";
  std::string runTag  = "multikpi";
  double     adjustInterval = 1.0; // cada 1 s ajustar proporciones

  CommandLine cmd;
  cmd.AddValue ("nSta", "Numero de estaciones", nSta);
  cmd.AddValue ("simTime", "Duracion de la simulacion (s)", simTime);
  cmd.AddValue ("seed", "Semilla aleatoria", seed);
  cmd.AddValue ("baseDir", "Directorio base de resultados", baseDir);
  cmd.AddValue ("runTag", "Etiqueta de corrida", runTag);
  cmd.AddValue ("adjustInterval", "Periodo de ajuste (s)", adjustInterval);
  cmd.Parse (argc, argv);

  SeedManager::SetSeed (seed);
  SystemPath::MakeDirectories (baseDir);

  // 1) Nodos
  NodeContainer staNodes; staNodes.Create (nSta);
  NodeContainer ap5; ap5.Create (1);
  NodeContainer ap6; ap6.Create (1);

  // 2) WiFi 7 (802.11be)
  WifiHelper wifi; wifi.SetStandard (WIFI_STANDARD_80211be);
  wifi.SetRemoteStationManager ("ns3::MinstrelHtWifiManager");
  WifiMacHelper mac;

  // 5 GHz
  YansWifiChannelHelper ch5;
  ch5.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
  ch5.AddPropagationLoss ("ns3::FriisPropagationLossModel");
  YansWifiPhyHelper phy5; phy5.SetChannel (ch5.Create ());
  Ssid ssid5 ("ssid-5ghz");
  mac.SetType ("ns3::ApWifiMac", "Ssid", SsidValue (ssid5));
  NetDeviceContainer apDev5 = wifi.Install (phy5, mac, ap5.Get (0));
  mac.SetType ("ns3::StaWifiMac", "Ssid", SsidValue (ssid5),
               "ActiveProbing", BooleanValue (false));
  NetDeviceContainer staDev5 = wifi.Install (phy5, mac, staNodes);

  // 6 GHz
  YansWifiChannelHelper ch6;
  ch6.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
  ch6.AddPropagationLoss ("ns3::FriisPropagationLossModel");
  YansWifiPhyHelper phy6; phy6.SetChannel (ch6.Create ());
  Ssid ssid6 ("ssid-6ghz");
  mac.SetType ("ns3::ApWifiMac", "Ssid", SsidValue (ssid6));
  NetDeviceContainer apDev6 = wifi.Install (phy6, mac, ap6.Get (0));
  mac.SetType ("ns3::StaWifiMac", "Ssid", SsidValue (ssid6),
               "ActiveProbing", BooleanValue (false));
  NetDeviceContainer staDev6 = wifi.Install (phy6, mac, staNodes);

  // 4) Movilidad

  // a) STAs en un grid ~20m x ~10m
  MobilityHelper mobilitySta;
  mobilitySta.SetPositionAllocator ("ns3::GridPositionAllocator",
                                    "MinX", DoubleValue (0.0),
                                    "MinY", DoubleValue (0.0),
                                    "DeltaX", DoubleValue (2.0),   // 2 m entre nodos en X
                                    "DeltaY", DoubleValue (2.0),   // 2 m entre nodos en Y
                                    "GridWidth", UintegerValue (10),
                                    "LayoutType", StringValue ("RowFirst"));
  mobilitySta.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  mobilitySta.Install (staNodes);

  // b) APs colocados en el "centro" del escenario
  MobilityHelper mobilityAp;
  Ptr<ListPositionAllocator> apPos = CreateObject<ListPositionAllocator> ();

  // El grid de STAs va de x = 0..18 m, y = 0..8 m aprox.
  // Colocamos los AP cerca del centro (x≈9, y≈4)
  apPos->Add (Vector (9.0, 4.0, 0.0));  // AP 5 GHz
  apPos->Add (Vector (9.0, 4.5, 0.0));  // AP 6 GHz, ligeramente desplazado

  mobilityAp.SetPositionAllocator (apPos);
  mobilityAp.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  mobilityAp.Install (ap5);
  mobilityAp.Install (ap6);

  // 5) Internet
  InternetStackHelper stack;
  stack.Install (staNodes);
  stack.Install (ap5);
  stack.Install (ap6);

  Ipv4AddressHelper address;
  address.SetBase ("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer if5Sta = address.Assign (staDev5);
  Ipv4InterfaceContainer if5Ap  = address.Assign (apDev5);

  address.SetBase ("10.2.1.0", "255.255.255.0");
  Ipv4InterfaceContainer if6Sta = address.Assign (staDev6);
  Ipv4InterfaceContainer if6Ap  = address.Assign (apDev6);

  Ipv4GlobalRoutingHelper::PopulateRoutingTables ();

  // 6) Aplicaciones base
  // VOIP (UDP)
  OnOffHelper voip ("ns3::UdpSocketFactory", Address ());
  voip.SetAttribute ("DataRate", DataRateValue (DataRate ("100kbps")));
  voip.SetAttribute ("PacketSize", UintegerValue (128));
  voip.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=0.02]"));
  voip.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0.01]"));

  // VIDEO (UDP)
  OnOffHelper videoTmpl ("ns3::UdpSocketFactory", Address ());
  videoTmpl.SetAttribute ("DataRate", DataRateValue (DataRate ("4Mbps")));
  videoTmpl.SetAttribute ("PacketSize", UintegerValue (1024));
  videoTmpl.SetAttribute ("OnTime", StringValue ("ns3::ExponentialRandomVariable[Mean=0.5]"));
  videoTmpl.SetAttribute ("OffTime", StringValue ("ns3::ExponentialRandomVariable[Mean=1.0]"));

  // IoT (UDP)
  OnOffHelper iot ("ns3::UdpSocketFactory", Address ());
  iot.SetAttribute ("DataRate", DataRateValue (DataRate ("50kbps")));
  iot.SetAttribute ("PacketSize", UintegerValue (64));
  iot.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=0.1]"));
  iot.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"));

  // TCP "pesado" como OnOff (para poder controlar DataRate)
  OnOffHelper tcpTmpl ("ns3::TcpSocketFactory", Address ());
  tcpTmpl.SetAttribute ("DataRate", DataRateValue (DataRate ("4Mbps")));
  tcpTmpl.SetAttribute ("PacketSize", UintegerValue (1200));
  tcpTmpl.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"));
  tcpTmpl.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0.0]"));

  // Sinks TCP en APs
  PacketSinkHelper tcpSink5 ("ns3::TcpSocketFactory",
                             InetSocketAddress (Ipv4Address::GetAny (), TCP_PORT));
  PacketSinkHelper tcpSink6 ("ns3::TcpSocketFactory",
                             InetSocketAddress (Ipv4Address::GetAny (), TCP_PORT));
  ApplicationContainer sink5 = tcpSink5.Install (ap5.Get (0));
  ApplicationContainer sink6 = tcpSink6.Install (ap6.Get (0));
  sink5.Start (Seconds (0.2)); sink5.Stop (Seconds (simTime));
  sink6.Start (Seconds (0.2)); sink6.Stop (Seconds (simTime));

  // 7) Asignación de perfiles y MLO
  std::vector<HeavyApps> heavyList;

  for (uint32_t i = 0; i < nSta; ++i)
    {
      TrafficProfile profile = GetProfile ();
      double demandMbps = 0.0;
      if (profile == VOIP)           demandMbps = 0.1;
      else if (profile == IOT)       demandMbps = 0.05;
      else if (profile == VIDEO)     demandMbps = 4.0;
      else if (profile == TCP_TRAFFIC) demandMbps = 4.0;

      ApplicationContainer apps;

      if (profile == VOIP)
        {
          Address dst5 (InetSocketAddress (if5Ap.GetAddress (0), UDP_VOIP_BASE + i));
          voip.SetAttribute ("Remote", AddressValue (dst5));
          apps = voip.Install (staNodes.Get (i));
        }
      else if (profile == IOT)
        {
          Address dst5 (InetSocketAddress (if5Ap.GetAddress (0), UDP_IOT_BASE + i));
          iot.SetAttribute ("Remote", AddressValue (dst5));
          apps = iot.Install (staNodes.Get (i));
        }
      else
        {
          // Flujos pesados (VIDEO / TCP) → MLO "reparto": 2 apps (6 GHz + 5 GHz)
          double ratio6_init = 0.7;
          double ratio5_init = 0.3;
          Ptr<OnOffApplication> app6, app5;

          if (profile == VIDEO)
            {
              // 6 GHz
              {
                Address dst6 (InetSocketAddress (if6Ap.GetAddress (0), UDP_VIDEO_BASE + i));
                OnOffHelper v6 = videoTmpl;
                v6.SetAttribute ("Remote", AddressValue (dst6));
                v6.SetAttribute ("DataRate",
                                 DataRateValue (DataRate (std::to_string (demandMbps * ratio6_init) + "Mbps")));
                ApplicationContainer a = v6.Install (staNodes.Get (i));
                apps.Add (a);
                app6 = DynamicCast<OnOffApplication> (a.Get (0));
              }
              // 5 GHz
              {
                Address dst5 (InetSocketAddress (if5Ap.GetAddress (0), UDP_VIDEO_BASE + i));
                OnOffHelper v5 = videoTmpl;
                v5.SetAttribute ("Remote", AddressValue (dst5));
                v5.SetAttribute ("DataRate",
                                 DataRateValue (DataRate (std::to_string (demandMbps * ratio5_init) + "Mbps")));
                ApplicationContainer a = v5.Install (staNodes.Get (i));
                apps.Add (a);
                app5 = DynamicCast<OnOffApplication> (a.Get (0));
              }
            }
          else if (profile == TCP_TRAFFIC)
            {
              // 6 GHz
              {
                Address dst6 (InetSocketAddress (if6Ap.GetAddress (0), TCP_PORT));
                OnOffHelper t6 = tcpTmpl;
                t6.SetAttribute ("Remote", AddressValue (dst6));
                t6.SetAttribute ("DataRate",
                                 DataRateValue (DataRate (std::to_string (demandMbps * ratio6_init) + "Mbps")));
                ApplicationContainer a = t6.Install (staNodes.Get (i));
                apps.Add (a);
                app6 = DynamicCast<OnOffApplication> (a.Get (0));
              }
              // 5 GHz
              {
                Address dst5 (InetSocketAddress (if5Ap.GetAddress (0), TCP_PORT));
                OnOffHelper t5 = tcpTmpl;
                t5.SetAttribute ("Remote", AddressValue (dst5));
                t5.SetAttribute ("DataRate",
                                 DataRateValue (DataRate (std::to_string (demandMbps * ratio5_init) + "Mbps")));
                ApplicationContainer a = t5.Install (staNodes.Get (i));
                apps.Add (a);
                app5 = DynamicCast<OnOffApplication> (a.Get (0));
              }
            }

          HeavyApps h;
          h.app6 = app6;
          h.app5 = app5;
          h.demandMbps = demandMbps;
          heavyList.push_back (h);
        }

      // Tiempos de inicio aleatorios (usuarios que se conectan en momentos distintos)
      Ptr<UniformRandomVariable> startVar = CreateObject<UniformRandomVariable> ();
      double startTime = startVar->GetValue (0.5, 3.0);
      double stopTime  = simTime - 1.0;
      if (startTime >= stopTime)
        startTime = 0.5;

      apps.Start (Seconds (startTime));
      apps.Stop  (Seconds (stopTime));
    }

  // 8) FlowMonitor + controlador multi-KPI
  FlowMonitorHelper flowmon;
  Ptr<FlowMonitor> monitor = flowmon.InstallAll ();

  double firstAdjust = 2.0;
  Simulator::Schedule (Seconds (firstAdjust),
                       &AdjustRatiosMultiKpi,
                       &flowmon, monitor,
                       if6Ap.GetAddress (0),   // AP 6 GHz
                       heavyList,
                       adjustInterval,
                       simTime - 0.5);

  Simulator::Stop (Seconds (simTime));
  Simulator::Run ();

  // === Impresión en consola con tipo de flujo ===
  monitor->CheckForLostPackets ();
  Ptr<Ipv4FlowClassifier> classifier =
    DynamicCast<Ipv4FlowClassifier> (flowmon.GetClassifier ());
  auto stats = monitor->GetFlowStats ();

  std::cout << ">>> Simulacion completada (virtual " << simTime << "s) <<<\n";
  for (const auto &flow : stats)
    {
      auto t = classifier->FindFlow (flow.first);
      std::string type = ClassifyFlowType (t);

      double t0 = flow.second.timeFirstTxPacket.GetSeconds ();
      double t1 = flow.second.timeLastRxPacket.GetSeconds ();
      double dur = t1 - t0; if (dur <= 0) dur = 1e-6;
      double thrMbps = (flow.second.rxBytes * 8.0) / dur / 1e6;
      double dMean   = (flow.second.rxPackets > 0)
                        ? flow.second.delaySum.GetSeconds () / flow.second.rxPackets
                        : 0.0;

      double jMean   = 0.0;
      if (flow.second.rxPackets > 1)
        {
          jMean = flow.second.jitterSum.GetSeconds () /
                  double(flow.second.rxPackets - 1);
        }

      std::cout << "Flow " << flow.first << " ("
                << t.sourceAddress << " -> " << t.destinationAddress
                << ")  [Type=" << type
                << "  proto=" << unsigned(t.protocol)
                << "  sport=" << t.sourcePort
                << "  dport=" << t.destinationPort << "]\n";
      std::cout << "  Tx Bytes: " << flow.second.txBytes << "\n";
      std::cout << "  Rx Bytes: " << flow.second.rxBytes << "\n";
      std::cout << "  Throughput: " << thrMbps << " Mbps\n";
      std::cout << "  Delay Mean: " << dMean << " s\n";
      std::cout << "  Jitter Mean: " << jMean << " s\n";
      std::cout << "  Lost Packets: " << flow.second.lostPackets << "\n\n";
    }

  // === Guardar archivos ===
  std::string xmlFile = baseDir + "flowmon-" + runTag + ".xml";
  std::string csvFile = baseDir + "metrics-" + runTag + ".csv";
  monitor->SerializeToXmlFile (xmlFile, true, true);
  WriteFlowMonitorCsv (flowmon, monitor, csvFile);

  Simulator::Destroy ();
  return 0;
}
