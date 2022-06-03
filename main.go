package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
)

// Settings updated via flags
var (
	targets    airosDevices
	useSSL     bool
	insecure   bool
	verbose    bool
	envFile    string
	listenAddr string
	jsonOut    bool
	interval   int64 = 30
)

// Global vars
var (
	baseURL        string = "http://"
	devices        []*airosDevice
	log            *logrus.Logger
	logLevel       logrus.Level = logrus.InfoLevel
	user           map[string]string
	wg             sync.WaitGroup
	updateInterval time.Duration
)

type airosDevice struct {
	Name   string
	client *resty.Client
}

type airosDevices []string // Container for AirOS Targets

// Specify multiple times to monitor multiple devices
func (m *airosDevices) String() string {
	return fmt.Sprintf("%s", *m)
}
func (m *airosDevices) Set(value string) error {
	*m = append(*m, value)
	return nil
}

func init() {
	flag.Var(&targets, "device", "IP or FQDN of AirOS Device, specify more than once for multiple")
	flag.StringVar(&envFile, "envFile", envFile, "File to load environment from")
	flag.StringVar(&listenAddr, "listen", listenAddr, "Specify listen addr:port to enable Prometheus")
	flag.BoolVar(&useSSL, "useSSL", useSSL, "Set to use SSL to connect")
	flag.BoolVar(&insecure, "insecure", insecure, "Set to skip SSL checks")
	flag.BoolVar(&verbose, "verbose", verbose, "Be Verbose")
	flag.BoolVar(&jsonOut, "json", jsonOut, "Simply output JSON")
	flag.Int64Var(&interval, "interval", interval, "Interval at which to poll AirOS devices")
	flag.Parse()

	if jsonOut {
		logLevel = logrus.ErrorLevel
	} else if verbose {
		logLevel = logrus.DebugLevel
	}

	log = logrus.New()
	log.Level = logLevel

	if !jsonOut && listenAddr == "" {
		log.Fatal("Must supply either -json or -listen parameters")
	}

	// Attempt to load environment from file if specified
	// Will not use .env by default, must be provided
	if envFile != "" {
		if err := godotenv.Load(envFile); err != nil {
			log.WithFields(logrus.Fields{
				"envFile": envFile,
				"error":   err,
			}).Fatal("Failed to load environment")
		}
	}

	// airos_user and airos_pass must be set in the environment
	// These can be set directly in the environment or loaded from file
	// using the -envFile flag
	if os.Getenv("airos_user") == "" || os.Getenv("airos_pass") == "" {
		log.Fatal("Must provide airos_user and airos_pass by environment")
	}

	// User for Resty clients
	user = map[string]string{
		"username": os.Getenv("airos_user"),
		"password": os.Getenv("airos_pass"),
	}

	if useSSL {
		baseURL = "https://"
	}

	// Set our update interval
	if listenAddr != "" {
		updateInterval = time.Duration(interval) * time.Second
	}

	// Prepare clients for each AirOS target
	for _, target := range targets {
		url := baseURL + target
		device := &airosDevice{Name: target}
		device.client = resty.New().SetBaseURL(url)
		if insecure {
			device.client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
		}
		devices = append(devices, device)
	}
}

func main() {
	// If we're just dumping JSON, do a single run and die
	if jsonOut {
		for _, d := range devices {
			stats := d.getJSONString()
			fmt.Println(stats)
		}
		os.Exit(0)
	}

	// Serve prometheus metrics at /metrics
	go servePromMetrics()

	// done is used to ask goroutines to die
	// killed handles user termination
	done := make(chan bool, len(devices))
	killed := make(chan os.Signal, 1)

	// Handle SIGINT
	signal.Notify(killed, os.Interrupt, syscall.SIGTERM)
	go func(d chan bool) {
		<-killed
		log.Info("Caught interrupt, trying to die...")
		for range devices {
			d <- true
		}
		wg.Wait()
		os.Exit(0)
	}(done)

	// Launch updaters for each target
	for n, d := range devices {
		log.WithFields(logrus.Fields{
			"DeviceNumber": n,
			"DeviceName":   d.Name,
		}).Info("Launching device update loop goroutine")
		d.updateLoop(done)
		wg.Add(1)
	}

	// Update forever
	for {
		time.Sleep(200 * time.Millisecond)
	}
}

// Simply return a JSON string from parsed output
// Would be more efficient to simply pass through the
// http response, but this details supported / marshalled fields
func (d *airosDevice) getJSONString() string {
	var airosJSON string
	d.login()
	status, _ := d.getStatus()
	out, _ := json.Marshal(status)
	airosJSON = string(out)
	return airosJSON
}

// Updates AirOS statistics at configured interval
// Write true to chan arg to stop
func (d *airosDevice) updateLoop(done <-chan bool) {
	timer := time.NewTicker(updateInterval)
	go func() {
		d.update() // Try right away
		for {
			select {
			case <-timer.C:
				if err := d.update(); err != nil {
					log.WithFields(logrus.Fields{
						"Device": d.Name,
						"Error":  err,
					}).Error("Failed to update AirOS Statistics")
				}
			case <-done:
				log.WithField("Device", d.Name).Info("Finished update loop")
				wg.Done()
				return
			}
		}
	}()
}

// Retrieves statistics from AirOS device and updates
// all Prometheus metrics
func (d *airosDevice) update() error {
	t1 := time.Now()
	status, err := d.getStatus()
	// If update failed, try once to log in
	if err != nil {
		d.login()
		status, err = d.getStatus()
	}

	// Update prometheus metrics
	updatePromMetrics(status)

	// Track duration
	dur := time.Now().Sub(t1)
	expUpdateTime.WithLabelValues(d.Name).Observe(float64(dur.Seconds()))
	return err
}

// Performs http call to retrieve and marshall JSON response
// from AirOS device
func (d *airosDevice) getStatus() (*airosStatus, error) {
	var err error
	status := new(airosStatus)
	stats, err := d.client.R().SetResult(status).Get("/status.cgi")
	if err != nil || stats.StatusCode() != 200 {
		if err == nil {
			err = errors.New("Failed to retrieve AirOS Status")
		}
	}
	return status, err
}

// Attempts login to the AirOS device
func (d *airosDevice) login() {
	log.WithField("URL", d.client.BaseURL).Info("Login Requested")
	login := d.client.R().SetBody(user)
	auth, err := login.Post("/api/auth")
	if err != nil || auth.StatusCode() != 200 {
		log.WithFields(logrus.Fields{"baseURL": baseURL, "response": string(auth.Body())}).
			Error("Login Failed")
	} else {
		log.WithField("URL", d.client.BaseURL).Info("Login Successful")
	}

	cookies := auth.Cookies()
	log.Debug(cookies)
	log.Debug(auth.RawResponse)
}
