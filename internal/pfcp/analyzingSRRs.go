package pfcp

import (
	"fmt"
	"log"
	"sync"
)

// QoS flows == destination IPs in our case
var (
	QoSflow_RequestedMonitoring            sync.Map
	QoSflow_ReportedFrequency              sync.Map
	QoSflow_PacketDelayThresholds          sync.Map
	QoSflow_DownlinkPacketDelayThresholds  sync.Map
	QoSflow_UplinkPacketDelayThresholds    sync.Map
	QoSflow_RoundTripPacketDelayThresholds sync.Map
	QoSflow_MinimumWaitTime                sync.Map
	QoSflow_MeasurementPeriod              sync.Map
)

// we know all UEs will get this one SRR with ID 1
func GetSRRContent(srrID uint8) ([]*QoSControlInfo, error) {
	srrInfos, exists := SotredSrrsToBeUsedByUpf[srrID]
	if !exists {
		log.Println("i am inside GetSRRContent, and i did NOT find an srr yet")
		return nil, fmt.Errorf("SRR ID %d not found", srrID)
	}
	log.Println("i am inside GetSRRContent, and i FOUND an srr")
	return srrInfos, nil
}

// will be used by capturePackets to retrieve all required QoSFlow for monitoring
func GetQoSFlowMonitoringContent() error {
	srrInfos, err := GetSRRContent(uint8(1))
	if err != nil {
		return err
	}
	var qfi_destination string
	log.Println("Retrieving values per QoS from the SRR")
	for _, srrInfo := range srrInfos {
		log.Println("Time to extract...")
		qfi := srrInfo.QFI
		log.Println("qfi: ", qfi)
		ReqQoSMonit := srrInfo.RequestedQoSMonitoring
		log.Println("requestMonitoring: ", ReqQoSMonit)
		ReportingFrequency := srrInfo.ReportingFrequency
		log.Println("ReportingFrequency: ", ReportingFrequency)
		PacketDelayThresholds := srrInfo.PacketDelayThresholds
		log.Println("PacketDelayThresholds: ", PacketDelayThresholds)
		DownlinkPacketDelayThresholds := srrInfo.DownlinkPacketDelayThresholds
		log.Println("DownlinkPacketDelayThresholds: ", DownlinkPacketDelayThresholds)
		UplinkPacketDelayThresholds := srrInfo.UplinkPacketDelayThresholds
		log.Println("UplinkPacketDelayThresholds: ", UplinkPacketDelayThresholds)
		RoundTripPacketDelayThresholds := srrInfo.RoundTripPacketDelayThresholds
		log.Println("RoundTripPacketDelayThresholds: ", RoundTripPacketDelayThresholds)
		MinimumWaitTime := srrInfo.MinimumWaitTime
		log.Println("MinimumWaitTime: ", MinimumWaitTime)
		MeasurementPeriod := srrInfo.MeasurementPeriod
		log.Println("MeasurementPeriod: ", MeasurementPeriod)
		if qfi == uint8(1) {
			qfi_destination = "10.100.200.2" //destination1 IP
		}
		if qfi == uint8(2) {
			qfi_destination = "10.100.200.3" //destination2 IP
		}
		QoSflow_RequestedMonitoring.Store(qfi_destination, ReqQoSMonit)
		log.Println("stored RequestedMonitoring for: ", qfi_destination)
		QoSflow_ReportedFrequency.Store(qfi_destination, ReportingFrequency)
		log.Println("stored ReportedFrequency for: ", qfi_destination)
		QoSflow_PacketDelayThresholds.Store(qfi_destination, PacketDelayThresholds)
		log.Println("stored PacketDelayThresholds for: ", qfi_destination)
		QoSflow_DownlinkPacketDelayThresholds.Store(qfi_destination, DownlinkPacketDelayThresholds)
		log.Println("stored DownlinkPacketDelayThresholds for: ", qfi_destination)
		QoSflow_UplinkPacketDelayThresholds.Store(qfi_destination, UplinkPacketDelayThresholds)
		log.Println("stored UplinkPacketDelayThresholds for: ", qfi_destination)
		QoSflow_RoundTripPacketDelayThresholds.Store(qfi_destination, RoundTripPacketDelayThresholds)
		log.Println("stored RoundTripPacketDelayThresholds for: ", qfi_destination)
		QoSflow_MinimumWaitTime.Store(qfi_destination, MinimumWaitTime)
		log.Println("stored MinimumWaitTime for: ", qfi_destination)
		QoSflow_MeasurementPeriod.Store(qfi_destination, MeasurementPeriod)
		log.Println("stored MeasurementPeriod for: ", qfi_destination)
	}
	return nil
}
