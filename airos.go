package main

type (

	// Main AirOS Host Status
	airosStatus struct {
		Host     AirOSHost
		Wireless struct {
			ESSID           string
			Mode            string
			IEEEMode        string
			Band            int
			HideESSID       int `json:"hide_essid"`
			APMac           string
			AntennaGain     int
			Frequency       int
			CenterFrequency int
			DFS             int
			Distance        int
			Security        string
			NoiseFloor      int `json:"noisef"`
			TXPower         int
			APRepeater      bool
			RStatus         int
			ChanBW          int
			RXChainmask     int `json:"rx_chainmask"`
			TXChainmask     int `json:"tx_chainmask"`
			CACState        int `json:"cac_state"`
			CACTimeout      int `json:"cac_timeout"`
			RXIDX           int `json:"rx_idx"`
			RXNSS           int `json:"rx_nss"`
			TXIDX           int `json:"tx_idx"`
			TXNSS           int `json:"tx_nss"`
			Throughput      struct {
				TX int
				RX int
			}
			Service struct {
				Time int
				Link int
			}
			Polling struct {
				CBCapacity int `json:"cb_capacity"`
				DLCapacity int `json:"dl_capacity"`
				ULCapacity int `json:"ul_capacity"`
				Use        int
				TXUse      int `json:"tx_use"`
				RXUse      int `json:"rx_use"`
			}
			STACount int        `json:"count"`
			Stations []airosSTA `json:"sta"`
		}
		Interfaces []airosInterface
		GPS        struct {
			Lat float32
			Lon float32
			Fix int
		}
	}

	// AirOS Interface Details
	airosInterface struct {
		IFName  string
		HWAddr  string
		Enabled bool
		MTU     int
		Status  struct {
			Plugged     bool
			TXBytes     int `json:"tx_bytes"`
			RXBytes     int `json:"rx_bytes"`
			TXPackets   int `json:"tx_packets"`
			RXPackets   int `json:"rx_packets"`
			TXErrors    int `json:"tx_errors"`
			RXErrors    int `json:"rx_errors"`
			TXDropped   int `json:"tx_dropped"`
			RXDropped   int `json:"rx_dropped"`
			IPAddr      string
			Duplex      bool
			SNR         []int
			CableLength int `json:"cable_len"`
		}
	}

	// AirOS Host Details (used for target and remote)
	AirOSHost struct {
		HostName    string
		DeviceID    string `json:"device_id"`
		Uptime      int
		PowerTime   int    `json:"power_time"`
		Model       string `json:"devmodel"`
		Platform    string
		Version     string
		FWVersion   string
		NetRole     string
		Mode        string
		LoadAvg     float32
		TotalRam    int
		FreeRam     int
		Temperature float32
		CPULoad     float32
		TXBytes     int      `json:"tx_bytes"`
		RXBytes     int      `json:"rx_bytes"`
		AntennaGain int      `json:"antenna_gain"`
		CableLoss   int      `json:"cable_loss"`
		IPADDRs     []string `json:"ipaddr"`
	}

	// AirOS Station Details
	airosSTA struct {
		MAC              string
		LastIP           string
		Signal           int
		RSSI             int
		NoiseFloor       int
		ChainRSSI        []int
		TXIDX            int   `json:"tx_idx"`
		RXIDX            int   `json:"rx_idx"`
		TXNSS            int   `json:"tx_nss"`
		RXNSS            int   `json:"rx_nss"`
		TXLatency        int   `json:"tx_latency"`
		Distance         int   `json:"distance"`
		TXPackets        int   `json:"tx_packets"`
		TXLRetries       int   `json:"tx_lretries"`
		TXSRetries       int   `json:"tx_sretries"`
		Uptime           int   `json:"uptime"`
		DLSignalExpect   int   `json:"dl_signal_expect"`
		ULSignalExpect   int   `json:"ul_signal_expect"`
		CBCapacityExpect int   `json:"cb_capacity_expect"`
		DLCapacityExpect int   `json:"dl_capacity_expect"`
		ULCapacityExpect int   `json:"ul_capacity_expect"`
		DLRateExpect     int   `json:"dl_rate_expect"`
		ULRateExpect     int   `json:"ul_rate_expect"`
		DLLinkScore      int   `json:"dl_linkscore"`
		ULLinkScore      int   `json:"ul_linkscore"`
		DLAvgLinkScore   int   `json:"dl_avg_linkscore"`
		ULAvgLinkScore   int   `json:"ul_avg_linkscore"`
		TXRateData       []int `json:"tx_ratedata"`
		Stats            struct {
			RXBytes   int `json:"rx_bytes"`
			RXPackets int `json:"rx_packets"`
			RXPPS     int `json:"rx_pps"`
			TXBytes   int `json:"tx_bytes"`
			TXPackets int `json:"tx_packets"`
			TXPPS     int `json:"tx_pps"`
		}
		AirMax struct {
			ActualPriority  int `json:"actual_priority"`
			Beam            int
			DesiredPriority int `json:"desired_priority"`
			CBCapacity      int `json:"cb_capacity"`
			DLCapacity      int `json:"dl_capacity"`
			ULCapacity      int `json:"ul_capacity"`
			ATPCStatus      int
			RX              ChainStats
			TX              ChainStats
		}
		Remote AirOSHost
	}

	// Chain Statistics
	ChainStats struct {
		Usage int
		CINR  int
		EVM   [][]int
	}
)
