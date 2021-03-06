package main

import (
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Prometheus Registry and Metrics
var (
	reg     = prometheus.NewRegistry()
	metrics = promauto.With(reg)

	//
	// Exporter Metrics
	expUpdateTime = metrics.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "airos_exporter_update_time",
		Help:    "Time spent updating AirOS Statistics",
		Buckets: prometheus.DefBuckets,
	}, []string{"device"})

	//
	// AirOS Device Metrics
	airosUptime = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "airos_device_uptime_s",
		Help: "AirOS Device Uptime in Seconds",
	}, []string{"device", "id", "model", "version", "mode", "net_role"})
	airosPowerTime = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "airos_device_powertime_s",
		Help: "Airos PowerTime in Seconds",
	}, []string{"device"})
	airosLoadAvg = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "airos_device_load_avg",
		Help: "Airos Load Average",
	}, []string{"device"})
	airosTemp = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "airos_device_temp",
		Help: "Airos Device Temperature",
	}, []string{"device"})
	airosRamUsage = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "airos_device_ram_usage_percent",
		Help: "Percent of RAM utilized",
	}, []string{"device"})

	//
	// AirOS Interface Metrics
	airosIfMTU = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "airos_if_mtu",
		Help: "Interface Maximum Transmission Unit",
	}, []string{
		"device",
		"if_name",
		"if_mac",
		"if_ip",
		"status",
		"duplex",
	})
	airosIfBytes = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "airos_if_bytes",
		Help: "Interface Bytes Gauge",
	}, []string{"device", "if_name", "direction"})
	airosIfPkts = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "airos_if_packets",
		Help: "Interface Packets Gauge",
	}, []string{"device", "if_name", "direction"})
	airosIfErrors = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "airos_if_errors",
		Help: "Interface Errors Gauge",
	}, []string{"device", "if_name", "direction"})
	airosIfDropped = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "airos_if_dropped",
		Help: "Interface Packets Dropped Gauge",
	}, []string{"device", "if_name", "direction"})
	airosIfCblLen = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "airos_if_cable_length_ft",
		Help: "Interface Cable Length (ft)",
	}, []string{"device", "if_name"})
	airosIfCblSNR = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "airos_if_cable_snr",
		Help: "Interface Cable Signal-to-Noise Ratio",
	}, []string{"device", "if_name"})

	//
	// AirOS Wireless Metrics
	airosWLInfo = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "airos_wireless_info",
		Help: "Info table for AirOS Wireless Device",
	}, []string{
		"device",
		"essid",
		"ieeemode",
		"band",
		"ap_mac",
		"dfs",
		"security",
		"ap_repeater",
	})
	airosWLNoiseFloor = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "airos_wireless_noise_floor",
		Help: "Noise Floor (dBm)",
	}, []string{"device"})
	airosWLAntennaGain = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "airos_wireless_antenna_gain",
		Help: "Antenna Gain (dBm)",
	}, []string{"device"})
	airosWLFreq = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "airos_wireless_frequency",
		Help: "Wireless Frequency (mHz)",
	}, []string{"device"})
	airosWLDistance = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "airos_wireless_distance_ft",
		Help: "Wireless Distance (ft)",
	}, []string{"device"})
	airosWLTXPower = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "airos_wireless_tx_power_dbm",
		Help: "Wireless Transmit Power (dBm)",
	}, []string{"device"})
	airosWLTput = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "airos_wireless_throughput_kbps",
		Help: "Wireless Transmit Throughput (kbps)",
	}, []string{"device", "direction"})
	airosWLSvcTime = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "airos_wireless_service_time_s",
		Help: "Wireless Service Time (s)",
	}, []string{"device"})
	airosWLLinkTime = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "airos_wireless_link_time_s",
		Help: "Wireless Link Time (s)",
	}, []string{"device"})
	airosWLServiceUptime = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "airos_wireless_service_uptime_perc",
		Help: "Percent of time link is available",
	}, []string{"device"})
	airosWLCBCapacity = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "airos_wireless_capacity_cb_kbit",
		Help: "CB Capacity (mbit)",
	}, []string{"device"})
	airosWLDLCapacity = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "airos_wireless_capacity_dl_kbit",
		Help: "DL Capacity (mbit)",
	}, []string{"device"})
	airosWLULCapacity = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "airos_wireless_capacity_ul_kbit",
		Help: "UL Capacity (mbit)",
	}, []string{"device"})
	airosWLSTACount = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "airos_wireless_station_count",
		Help: "Count of Association Stations",
	}, []string{"device"})

	//
	// AirOS Station Metrics
	airosSTALabels = []string{
		"device",
		"remote_device",
	}
	airosSTAInfoLabels = []string{
		"device",
		"remote_device",
		"remote_id",
		"remote_model",
		"remote_version",
		"remote_mode",
		"remote_net_role",
		"remote_mac",
		"remote_ip",
	}
	airosSTAInfo = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "airos_sta_info",
		Help: "Info table for AirOS Remote Station",
	}, airosSTAInfoLabels)
	airosSTASignal = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "airos_sta_signal",
		Help: "Station Signal",
	}, airosSTALabels)
	airosSTARSSI = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "airos_sta_rssi",
		Help: "Station Received Signal Strength Indicator",
	}, airosSTALabels)
	airosSTANoiseFloor = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "airos_sta_noise_floor",
		Help: "Station Noise Floor",
	}, airosSTALabels)
	airosSTATxLatency = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "airos_sta_tx_latency_ms",
		Help: "Station Transmit Latency (ms)",
	}, airosSTALabels)
	airosSTAUptime = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "airos_sta_uptime_s",
		Help: "Station Uptime (s)",
	}, airosSTALabels)
	airosSTABytes = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "airos_sta_bytes",
		Help: "Station Bytes",
	}, append(airosSTALabels, "direction"))
	airosSTAPackets = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "airos_sta_packets",
		Help: "Station Packets",
	}, append(airosSTALabels, "direction"))
	airosSTAPPS = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "airos_sta_pps",
		Help: "Station Packets Per Second",
	}, append(airosSTALabels, "direction"))
	airosSTAPriority = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "airos_sta_priority",
		Help: "Station Actual Priority",
	}, airosSTALabels)
	airosSTACBCap = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "airos_sta_cb_capacity",
		Help: "Station CB Capacity",
	}, airosSTALabels)
	airosSTADLCap = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "airos_sta_dl_capacity",
		Help: "Station DL Capacity",
	}, airosSTALabels)
	airosSTAULCap = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "airos_sta_ul_capacity",
		Help: "Station UL Capacity",
	}, airosSTALabels)
	airosSTAUsage = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "airos_sta_chain_usage",
		Help: "Station Chain Usage",
	}, append(airosSTALabels, "direction"))
	airosSTACINR = metrics.NewGaugeVec(prometheus.GaugeOpts{
		Name: "airos_sta_cinr",
		Help: "Station CINR (SNR)",
	}, append(airosSTALabels, "direction"))
)

// Updates all Prometheus Metrics
func updatePromMetrics(s *airosStatus) {
	device := s.Host.HostName
	deviceLabels := prometheus.Labels{
		"device":   device,
		"id":       s.Host.DeviceID,
		"model":    s.Host.Model,
		"version":  s.Host.FWVersion,
		"mode":     s.Wireless.Mode,
		"net_role": s.Host.NetRole,
	}
	var isRepater string
	if s.Wireless.APRepeater {
		isRepater = "true"
	} else {
		isRepater = "false"
	}
	wirelessLabels := prometheus.Labels{
		"device":      device,
		"essid":       s.Wireless.ESSID,
		"ieeemode":    s.Wireless.IEEEMode,
		"band":        fmt.Sprint(s.Wireless.Band),
		"ap_mac":      s.Wireless.APMac,
		"dfs":         fmt.Sprint(s.Wireless.DFS),
		"security":    s.Wireless.Security,
		"ap_repeater": isRepater,
	}

	// Device Metrics
	airosUptime.With(deviceLabels).Set(float64(s.Host.Uptime))
	airosPowerTime.WithLabelValues(device).Set(float64(s.Host.PowerTime))
	airosLoadAvg.WithLabelValues(device).Set(float64(s.Host.LoadAvg))
	airosTemp.WithLabelValues(device).Set(float64(s.Host.Temperature))
	// Calculate Percent RAM Used
	ramUsagePerc := 1.0 - float64(s.Host.FreeRam)/float64(s.Host.TotalRam)
	airosRamUsage.WithLabelValues(device).Set(ramUsagePerc)

	// Interface Metrics
	for _, i := range s.Interfaces {
		// Check interface status
		var status, duplex string
		if i.Enabled {
			status = "enabled"
		} else {
			status = "disabled"
		}
		if i.Status.Duplex {
			duplex = "true"
		} else {
			duplex = "false"
		}
		// Set labels
		ifLabels := prometheus.Labels{
			"device":  s.Host.HostName,
			"if_name": i.IFName,
			"if_mac":  i.HWAddr,
			"if_ip":   i.Status.IPAddr,
			"status":  status,
			"duplex":  duplex,
		}
		ifLabelsTX := prometheus.Labels{
			"device":    s.Host.HostName,
			"if_name":   i.IFName,
			"direction": "tx",
		}
		ifLabelsRX := prometheus.Labels{
			"device":    s.Host.HostName,
			"if_name":   i.IFName,
			"direction": "rx",
		}
		airosIfMTU.With(ifLabels).Set(float64(i.MTU))
		airosIfBytes.With(ifLabelsTX).Set(float64(i.Status.TXBytes))
		airosIfBytes.With(ifLabelsRX).Set(float64(i.Status.RXBytes))
		airosIfPkts.With(ifLabelsTX).Set(float64(i.Status.TXPackets))
		airosIfPkts.With(ifLabelsRX).Set(float64(i.Status.RXPackets))
		airosIfErrors.With(ifLabelsTX).Set(float64(i.Status.TXErrors))
		airosIfErrors.With(ifLabelsRX).Set(float64(i.Status.RXErrors))
		airosIfDropped.With(ifLabelsTX).Set(float64(i.Status.TXDropped))
		airosIfDropped.With(ifLabelsRX).Set(float64(i.Status.RXDropped))
		airosIfCblLen.WithLabelValues(s.Host.HostName, i.IFName).Set(float64(i.Status.CableLength))
		// Average Cable SNR Values
		if len(i.Status.SNR) > 0 {
			var snrSum int
			var snr float64
			for _, v := range i.Status.SNR {
				snrSum += v
			}
			snr = float64(snrSum) / float64(len(i.Status.SNR))
			airosIfCblSNR.WithLabelValues(s.Host.HostName, i.IFName).Set(snr)
		}
	}

	// Wireless Metrics
	airosWLInfo.With(wirelessLabels).Set(1)
	airosWLNoiseFloor.WithLabelValues(device).Set(float64(s.Wireless.NoiseFloor))
	airosWLAntennaGain.WithLabelValues(device).Set(float64(s.Wireless.AntennaGain))
	airosWLFreq.WithLabelValues(device).Set(float64(s.Wireless.Frequency))
	airosWLDistance.WithLabelValues(device).Set(float64(s.Wireless.Distance))
	airosWLTXPower.WithLabelValues(device).Set(float64(s.Wireless.TXPower))
	airosWLTput.WithLabelValues(device, "tx").Set(float64(s.Wireless.Throughput.TX))
	airosWLTput.WithLabelValues(device, "rx").Set(float64(s.Wireless.Throughput.RX))
	airosWLSvcTime.WithLabelValues(device).Set(float64(s.Wireless.Service.Time))
	airosWLLinkTime.WithLabelValues(device).Set(float64(s.Wireless.Service.Link))
	// Calculate service availability ratio
	svcUptime := 1.0 - ((float64(s.Wireless.Service.Time) - float64(s.Wireless.Service.Link)) / float64(s.Wireless.Service.Time))
	airosWLServiceUptime.WithLabelValues(device).Set(svcUptime)
	airosWLCBCapacity.WithLabelValues(device).Set(float64(s.Wireless.Polling.CBCapacity))
	airosWLDLCapacity.WithLabelValues(device).Set(float64(s.Wireless.Polling.DLCapacity))
	airosWLULCapacity.WithLabelValues(device).Set(float64(s.Wireless.Polling.ULCapacity))
	airosWLSTACount.WithLabelValues(device).Set(float64(s.Wireless.STACount))

	// Associated Station Metrics
	for _, r := range s.Wireless.Stations {
		// Common labels
		staLabels := prometheus.Labels{
			"device":        s.Host.HostName,
			"remote_device": r.Remote.HostName,
		}
		staLabelsTX := prometheus.Labels{
			"device":        s.Host.HostName,
			"remote_device": r.Remote.HostName,
			"direction":     "tx",
		}
		staLabelsRX := prometheus.Labels{
			"device":        s.Host.HostName,
			"remote_device": r.Remote.HostName,
			"direction":     "rx",
		}
		airosSTAInfo.With(prometheus.Labels{
			"device":          s.Host.HostName,
			"remote_device":   r.Remote.HostName,
			"remote_id":       r.Remote.DeviceID,
			"remote_model":    r.Remote.Platform,
			"remote_version":  r.Remote.Version,
			"remote_mode":     r.Remote.Mode,
			"remote_net_role": r.Remote.NetRole,
			"remote_mac":      r.MAC,
			"remote_ip":       r.LastIP,
		}).Set(1)
		airosSTASignal.With(staLabels).Set(float64(r.Signal))
		airosSTARSSI.With(staLabels).Set(float64(r.RSSI))
		airosSTANoiseFloor.With(staLabels).Set(float64(r.NoiseFloor))
		airosSTATxLatency.With(staLabels).Set(float64(r.TXLatency))
		airosSTAUptime.With(staLabels).Set(float64(r.Uptime))
		airosSTABytes.With(staLabelsTX).Set(float64(r.Stats.TXBytes))
		airosSTABytes.With(staLabelsRX).Set(float64(r.Stats.RXBytes))
		airosSTAPackets.With(staLabelsTX).Set(float64(r.Stats.TXPackets))
		airosSTAPackets.With(staLabelsRX).Set(float64(r.Stats.RXPackets))
		airosSTAPPS.With(staLabelsTX).Set(float64(r.Stats.TXPPS))
		airosSTAPPS.With(staLabelsRX).Set(float64(r.Stats.RXPPS))
		airosSTAPriority.With(staLabels).Set(float64(r.AirMax.ActualPriority))
		airosSTACBCap.With(staLabels).Set(float64(r.AirMax.CBCapacity))
		airosSTADLCap.With(staLabels).Set(float64(r.AirMax.DLCapacity))
		airosSTAULCap.With(staLabels).Set(float64(r.AirMax.ULCapacity))
		airosSTAUsage.With(staLabelsTX).Set(float64(r.AirMax.TX.Usage))
		airosSTAUsage.With(staLabelsRX).Set(float64(r.AirMax.RX.Usage))
		airosSTACINR.With(staLabelsTX).Set(float64(r.AirMax.TX.CINR))
		airosSTACINR.With(staLabelsRX).Set(float64(r.AirMax.RX.CINR))
	}
}

// Starts listener at listenAddr and services at /metrics
// Only serves custom registry
func servePromMetrics() {
	http.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	log.WithField("ListenAddress", listenAddr).Info("Serving Prometheus at /metrics")
	http.ListenAndServe(listenAddr, nil)
}
