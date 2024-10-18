package pfcp

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	Number_of_simultaneous_workers = 400 //fine tune through testing (until the actual delay stabalizes and this measuring is not delaying it!)
)

var (
	//upLink only
	Time_of_last_issued_report_per_UE_destination_combo sync.Map
	SRR_was_Found                                       = false
	Mu1                                                 sync.Mutex
	keyLocks                                            sync.Map
)

type ToBeReported struct {
	QFI                      uint8
	QoSMonitoringMeasurement uint32
	SentReport               time.Time //change to uint32 later NOT PRESSING
	StartedReporting         time.Time //change to uint32
}

type PacketMonitorResult struct {
	Monitored  bool
	Key        string
	DstIP      string
	delayValue uint32
}

var toBeReported_Chan = make(chan ToBeReported, 400) //buffer size

func GetValuesToBeReported_Chan() <-chan ToBeReported { //everytime they change fill this report and buffer it to the channel
	return toBeReported_Chan
}

// need to make it so that when ue deactivates i kill routine
func StartPacketCapture(interface_name string) {
	go func() {
		for {
			err := GetQoSFlowMonitoringContent()
			if err == nil {
				//fmt.Println(" SRR found in StartPacketCapture ")
				SRR_was_Found = true
				go CapturePackets(interface_name)
				break
			} else {
				fmt.Println("no SRR! error:", err)
			}
			time.Sleep(1 * time.Second)
		}
	}()
}

func CapturePackets(interface_name string) {

	handle, err := pcap.OpenLive(interface_name, 2048, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("udp port 2152"); err != nil { //capture only gtp packets
		log.Fatal(err)
	}

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	fmt.Println("--ahmad implemented -- started capturing packets on:", interface_name)

	packetQueue := make(chan gopacket.Packet, 1000)
	stopChan := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < Number_of_simultaneous_workers; i++ {
		wg.Add(1)
		go worker(packetQueue, stopChan, &wg)
	}

	go func() {
		<-signalChannel
		close(stopChan)
	}()

	for packet := range packetSource.Packets() {
		select {
		case packetQueue <- packet:
		case <-stopChan:
			close(packetQueue)
			wg.Wait()
			return
		}
	}
}

func worker(packetQueue <-chan gopacket.Packet, stopChan <-chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case packet, ok := <-packetQueue:
			if !ok {
				return
			} else if ok && IsThePacketToBeMonitored(packet).Monitored {
				processPacket(packet, IsThePacketToBeMonitored(packet).Key, IsThePacketToBeMonitored(packet).DstIP, IsThePacketToBeMonitored(packet).delayValue)
			}
		case <-stopChan:
			return
		}
	}
}

func processPacket(packet gopacket.Packet, key string, dstIp string, extracted_delay uint32) {
	lock := getLockForKey(key)
	lock.Lock()
	defer lock.Unlock()
	qfiVal, perioOrEvent, waitTime, ulThreshold, err := getQoSParameters(dstIp)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	if perioOrEvent == uint8(1) { //is it event triggered
		//if first packet add start time as time NOW
		lastReportedTime, exists := Time_of_last_issued_report_per_UE_destination_combo.Load(key)
		lastReportedTimeTyped := lastReportedTime.(time.Time)
		if !exists {
			started_reporting := time.Now()
			if extracted_delay > ulThreshold {
				will_send_report := time.Now()
				Time_of_last_issued_report_per_UE_destination_combo.Store(key, will_send_report)
				newValuesToFill := ToBeReported{
					QFI:                      qfiVal,
					QoSMonitoringMeasurement: extracted_delay,
					SentReport:               started_reporting,
					StartedReporting:         will_send_report,
				}
				toBeReported_Chan <- newValuesToFill
			}

		} else if exists && time.Since(lastReportedTimeTyped) >= waitTime {
			started_reporting := time.Now()
			if extracted_delay > ulThreshold {
				will_send_report := time.Now()
				Time_of_last_issued_report_per_UE_destination_combo.Store(key, will_send_report)
				newValuesToFill := ToBeReported{
					QFI:                      qfiVal,
					QoSMonitoringMeasurement: extracted_delay,
					SentReport:               started_reporting,
					StartedReporting:         will_send_report,
				}
				toBeReported_Chan <- newValuesToFill

			}
		}

	}
}

func IsThePacketToBeMonitored(packet gopacket.Packet) *PacketMonitorResult {
	var outerIPv4, innerIPv4 *layers.IPv4
	var gtpLayer *layers.GTPv1U
	var result PacketMonitorResult
	for _, layer := range packet.Layers() {
		switch layer := layer.(type) {
		case *layers.IPv4:
			if outerIPv4 == nil {
				outerIPv4 = layer
			} else {
				innerIPv4 = layer
			}
		case *layers.GTPv1U:
			gtpLayer = layer
		}
	}
	// Check if GTP layer exists and has a payload
	if gtpLayer != nil && innerIPv4 != nil {
		if len(gtpLayer.Payload) > 0 {
			tcpLayer := layers.TCP{}
			if err := tcpLayer.DecodeFromBytes(gtpLayer.Payload, gopacket.NilDecodeFeedback); err == nil {
				if len(tcpLayer.Payload) >= 4 {
					// extract delay
					data := tcpLayer.Payload[:4]
					var extracted_latency uint32
					extracted_latency = binary.BigEndian.Uint32(data)
					fmt.Printf("Extracted integer from TCP payload: %d\n", extracted_latency)

					if gtpLayer != nil && outerIPv4 != nil {
						srcIP := outerIPv4.SrcIP.String()
						dstIP := outerIPv4.DstIP.String()
						key := srcIP + "->" + dstIP
						// Check if the source IP is in the desired range and the destination IP matches
						if strings.HasPrefix(srcIP, "10.60.0") &&
							(dstIP == "10.100.200.12" || dstIP == "10.100.200.16") {
							result = PacketMonitorResult{
								Monitored:  true,
								Key:        key,
								DstIP:      dstIP,
								delayValue: extracted_latency,
							}
						}
					}

				} else {
					fmt.Println("TCP payload does not have enough data; skipping.")
				}
			} else {
				fmt.Println("Failed to decode TCP layer:", err)
			}
		}

		return &result
	}
	return nil
}

func getQoSParameters(dstIp string) (uint8, uint8, time.Duration, uint32, error) {

	var qfiVal uint8
	if dstIp == "10.100.200.12" {
		qfiVal = 1
	} else if dstIp == "10.100.200.16" {
		qfiVal = 2
	} else {
		return 0, 0, 0, 0, fmt.Errorf("invalid destination IP")
	}

	frequency, exists := QoSflow_ReportedFrequency.Load(dstIp)
	if !exists {
		return 0, 0, 0, 0, fmt.Errorf("no reported frequency for this flow")
	}

	perioOrEvent, ok := frequency.(uint8)
	if !ok {
		return 0, 0, 0, 0, fmt.Errorf("not of type uint8 for frequency")
	}

	timeToWaitBeforeNextReport, exists := QoSflow_MinimumWaitTime.Load(dstIp)
	if !exists {
		return 0, 0, 0, 0, fmt.Errorf("no time to wait before next report for this flow")
	}

	timeToWaitBeforeNextReportDuration, ok := timeToWaitBeforeNextReport.(time.Duration)
	if !ok {
		return 0, 0, 0, 0, fmt.Errorf("time to wait is not of type time.Duration")
	}

	// Read uplink packet delay threshold
	ulThresholdForThisFlow, exists := QoSflow_UplinkPacketDelayThresholds.Load(dstIp)
	if !exists {
		return 0, 0, 0, 0, fmt.Errorf("no uplink packet delay threshold for this flow")
	}

	ulThreshold, ok := ulThresholdForThisFlow.(uint32)
	if !ok {
		return 0, 0, 0, 0, fmt.Errorf("loaded value is not of type uint32 for uplink threshold")
	}

	// Return the QFI, frequency, wait time, and uplink threshold
	return qfiVal, perioOrEvent, timeToWaitBeforeNextReportDuration, ulThreshold, nil
}

func getLockForKey(key string) *sync.Mutex {
	lock, _ := keyLocks.LoadOrStore(key, &sync.Mutex{})
	return lock.(*sync.Mutex)
}
