package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	// "github.com/google/gopacket/pcapgo"
)

var (
	snapshotLen int32 = 1024
	promiscuous bool  = true
	err         error
	// timeout     time.Duration = -1 * time.Second
	handle     *pcap.Handle
	ethLayer   layers.Ethernet
	ipLayer    layers.IPv4
	tcpLayer   layers.TCP
	deviceName *string
	zkPort     *int
	pcapFile   *string
)

type ConnInfo struct {
	Timestamp  time.Time
	ClientAddr string
	ServerAddr string
	OpType     string
	Path       string
	Zxid       int64
	ReqLen     int
	RespLen    int
	Latency    string
	Error      int
}

func init() {
	deviceName = flag.String("device", "eth0", "read packet from network device")
	zkPort = flag.Int("port", 2181, "zookeeper server port")
	pcapFile = flag.String("file", "", "read packet from pcap file")
	flag.Parse()
}

func main() {
	if *pcapFile == "" {
		handle, err = pcap.OpenLive(*deviceName, snapshotLen, promiscuous, pcap.BlockForever)
		if err != nil {
			fmt.Printf("Error opening device %s: %v", *deviceName, err)
			os.Exit(1)
		}
	} else {
		handle, err = pcap.OpenOffline(*pcapFile)
		if err != nil {
			fmt.Printf("Error opening file %s: %v\n", *pcapFile, err)
			os.Exit(1)
		}
	}
	defer handle.Close()
	filter := fmt.Sprintf("tcp and port %d", *zkPort)
	err := handle.SetBPFFilter(filter)
	if err != nil {
		fmt.Printf("Error set filter: %s", err)
		os.Exit(1)
	}

	// Start processing packets
	fmt.Println("Start capture packet...")
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	con_map := make(map[uint32]ConnInfo)
	for packet := range packetSource.Packets() {
		parser := gopacket.NewDecodingLayerParser(
			layers.LayerTypeEthernet,
			&ethLayer,
			&ipLayer,
			&tcpLayer,
		)
		// Process packet here
		foundLayerTypes := []gopacket.LayerType{}
		parser.DecodeLayers(packet.Data(), &foundLayerTypes)
		if len(packet.Layers()) == 4 {
			info := ConnInfo{}
			var ack_id uint32
			var seq_id uint32
			for _, layer := range packet.Layers() {
				switch layer.LayerType() {
				case layers.LayerTypeEthernet:
				case layers.LayerTypeIPv4:
					info.ClientAddr = fmt.Sprintf("%s", ipLayer.SrcIP)
					info.ServerAddr = fmt.Sprintf("%s", ipLayer.DstIP)
				case layers.LayerTypeTCP:
					ack_id = tcpLayer.Ack
					seq_id = tcpLayer.Seq
					info.ClientAddr = fmt.Sprintf("%s:%d", info.ClientAddr, tcpLayer.SrcPort)
					info.ServerAddr = fmt.Sprintf("%s:%d", ipLayer.DstIP, tcpLayer.DstPort)
				default:
					if int(tcpLayer.DstPort) == *zkPort {
						p := gopacket.NewPacket(layer.LayerContents(), LayerTypeZKReq, gopacket.Default)
						zkReqLayer, ok := p.Layers()[0].(*ZKReq)
						if !ok {
							continue
						}
						info.Path = zkReqLayer.Path
						info.OpType = zkReqLayer.Optype
						info.ReqLen = len(layer.LayerContents()) - 4 //去掉4个无用字节
						info.Timestamp = packet.Metadata().Timestamp
						con_map[ack_id] = info
					}
					if int(tcpLayer.SrcPort) == *zkPort {
						reqInfo, ok := con_map[seq_id]
						if ok {
							con_map = map[uint32]ConnInfo{} //清空map,防止map无限增大
							p := gopacket.NewPacket(layer.LayerContents(), LayerTypeZKResp, gopacket.Default)
							zkRespLayer := p.Layers()[0].(*ZKResp)
							if !ok {
								continue
							}
							reqInfo.Zxid = zkRespLayer.Zxid
							reqInfo.Error = int(zkRespLayer.Err)
							if reqInfo.OpType == "CONNECT" && reqInfo.Zxid == 42949695585060 {
								reqInfo.Error = 0
							}
							if reqInfo.Path == "" {
								reqInfo.Path = "None"
							}
							reqInfo.RespLen = len(layer.LayerContents()) - 4 //去掉4个无用字节
							reqInfo.Latency = fmt.Sprintf("%.4f", float32(packet.Metadata().CaptureInfo.Timestamp.Sub(reqInfo.Timestamp).Nanoseconds())/1000.0/1000.0)
							fmt.Printf("%s %s %s %s %s 0x%s %d %d %s %d\n", reqInfo.Timestamp.Local().Format("2006-01-02 15:04:05"), reqInfo.ClientAddr,
								reqInfo.ServerAddr, reqInfo.OpType, reqInfo.Path, strconv.FormatInt(reqInfo.Zxid, 16), reqInfo.ReqLen, reqInfo.RespLen, reqInfo.Latency, reqInfo.Error)
						}
					}
				}
			}
		}
	}
}
