package pfcp

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	Number_of_simultaneous_workers = 20 //fine tune through testing (until the actual delay stabalizes and this measuring is not delaying it!)
)

var (
	//upLink only
	Time_of_last_arrived_packet_per_UE_destination_combo = make(map[string]time.Time)
	Start_time_per_UE_destination_combo                  = make(map[string]time.Time)
	Latest_latency_measured_per_UE_destination_combo     = make(map[string]uint32)
	Time_of_last_issued_report_per_UE_destination_combo  = make(map[string]time.Time)
	SRRFound                                             = false
	Mu1                                                  sync.Mutex
	m                                                    runtime.MemStats
)

type ToBeReported struct {
	QFI                      uint8
	QoSMonitoringMeasurement uint32
	EventTimeStamp           time.Time //change to uint32 later NOT PRESSING
	StartTime                time.Time //change to uint32
}

var toBeReported_Chan = make(chan ToBeReported, 1000) //buffer size

func GetValuesToBeReported_Chan() <-chan ToBeReported { //everytime they change fill this report and buffer it to the channel
	return toBeReported_Chan
}

func StartPacketCapture(interface_name string) {
	runtime.ReadMemStats(&m)
	memBefore := m.Alloc
	go func() {
		for {
			fmt.Println("I am in StartPacketCapture")
			fmt.Printf("Memory usage before method execution: %v bytes\n", memBefore)
			err := GetQoSFlowMonitoringContent()
			if err == nil {
				fmt.Println("I am inside StartPacketCapture and an SRR was found")
				SRRFound = true
				go CapturePackets(interface_name)
				break
			} else {
				fmt.Println("I am inside StartPacketCapture and NO SRR was found yet: ", err)
			}
			runtime.ReadMemStats(&m)
			memAfter := m.Alloc
			fmt.Printf("Memory usage after method execution: %v bytes\n", memAfter)
			time.Sleep(5 * time.Second)
		}
	}()
}

func CapturePackets(interface_name string) {
	fmt.Println("I entered CapturePackets")
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
			}
			go processPacket(packet)
		case <-stopChan:
			return
		}
	}
}

func processPacket(packet gopacket.Packet) {
	fmt.Println("I entered processPacket")
	var outerIPv4, innerIPv4 *layers.IPv4
	var gtpLayer *layers.GTPv1U

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

	if gtpLayer != nil && innerIPv4 != nil {
		srcIP := innerIPv4.SrcIP.String()
		dstIP := innerIPv4.DstIP.String()
		fmt.Println("destination is:", dstIP)

		Mu1.Lock()
		frequency, exists := QoSflow_ReportedFrequency.Load(dstIP)
		if !exists {
			fmt.Println("no reported frequency for this flow")
			Mu1.Unlock()
			return
		}

		perioOrEvent, ok := frequency.(uint8)
		fmt.Println(frequency)
		if !ok {
			fmt.Println("not of type uint8 or does not exist")
			Mu1.Unlock()
			return
		}
		timeToWaitBeforeNextReport, exists := QoSflow_MinimumWaitTime.Load(dstIP)
		if !exists {
			fmt.Println("no time to wait before next report for this flow")
			Mu1.Unlock()
			return
		}
		timeToWaitBeforeNextReportDuration, ok := timeToWaitBeforeNextReport.(time.Duration)

		ulThresholdForThisFlow, exists := QoSflow_UplinkPacketDelayThresholds.Load(dstIP)
		if !exists {
			fmt.Println("No values for this flow")
			Mu1.Unlock()
			return
		}
		ulThreshold, ok := ulThresholdForThisFlow.(uint32)
		if !ok {
			fmt.Println("Loaded value is not of type uint32")
			Mu1.Unlock()
			return
		}
		fmt.Println("here")
		if isInRange(srcIP) { //source IP is one of the UEs
			fmt.Println("there is an UL packet")
			if perioOrEvent == uint8(1) { //is it event triggered
				key := srcIP + "->" + dstIP //store required values for reports for each src dest pair

				//if first packet add start time as time NOW
				if _, exists := Start_time_per_UE_destination_combo[key]; !exists {
					Start_time_per_UE_destination_combo[key] = time.Now() //only when the monitoring starts
					Time_of_last_arrived_packet_per_UE_destination_combo[key] = time.Now()
				}
				//else
				currentTime := time.Now()
				//save the last time a packet from this source and dest arrived REDUNDANT
				lastArrivalTimeForThisSrcAndDest, exists := Time_of_last_arrived_packet_per_UE_destination_combo[key]

				if !exists {
					//if there is none add
					lastArrivalTimeForThisSrcAndDest = currentTime
				}

				timeSinceLastReport, exists := Time_of_last_issued_report_per_UE_destination_combo[key]
				//no report was issued so no even was triggered but it is not the first pccket
				if lastArrivalTimeForThisSrcAndDest != currentTime && !exists {
					latency := currentTime.Sub(lastArrivalTimeForThisSrcAndDest)
					latencyInMs := uint32(latency.Milliseconds())
					if latencyInMs > ulThreshold {
						var qfiVal uint8
						if dstIP == "10.100.200.2" {
							qfiVal = 1
						}

						if dstIP == "10.100.200.3" {
							qfiVal = 2
						}
						Time_of_last_issued_report_per_UE_destination_combo[key] = currentTime
						newValuesToFill := ToBeReported{
							QFI:                      qfiVal,
							QoSMonitoringMeasurement: latencyInMs,
							EventTimeStamp:           currentTime,
							StartTime:                Start_time_per_UE_destination_combo[key],
						}
						toBeReported_Chan <- newValuesToFill
					}
					Latest_latency_measured_per_UE_destination_combo[key] = latencyInMs
					fmt.Printf("Key: %s, Latency: %v ms\n", key, latencyInMs)
					//a previous report was issued
				} else if lastArrivalTimeForThisSrcAndDest != currentTime && exists {
					if time.Since(timeSinceLastReport) >= timeToWaitBeforeNextReportDuration {
						latency := currentTime.Sub(lastArrivalTimeForThisSrcAndDest)
						latency_in_ms := uint32(latency.Milliseconds())
						if latency_in_ms > ulThreshold {
							var qfi_val uint8
							if dstIP == "10.100.200.2" {
								qfi_val = 1
							}

							if dstIP == "10.100.200.3" {
								qfi_val = 2
							}
							new_values_to_fill := ToBeReported{
								QFI:                      qfi_val,
								QoSMonitoringMeasurement: latency_in_ms,
								EventTimeStamp:           currentTime,
								StartTime:                Start_time_per_UE_destination_combo[key],
							}
							toBeReported_Chan <- new_values_to_fill
						}
						Latest_latency_measured_per_UE_destination_combo[key] = latency_in_ms
						fmt.Printf("Key: %s, Latency: %v ms\n", key, latency_in_ms)
					}
				}
				Time_of_last_arrived_packet_per_UE_destination_combo[key] = time.Now()
			}
		}
		Mu1.Unlock()
	}
}

func isInRange(ip string) bool { //if its uplink
	return strings.HasPrefix(ip, "10.60.0") || strings.HasPrefix(ip, "10.61.0")
}
