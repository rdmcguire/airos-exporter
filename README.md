# AirOS Exporter

This utility will pull status from AirOS devices, and either dump the json to the terminal
for use in your own script or provide a Prometheus metrics endpoint.

## Configuration

The first step is to configure a read-only user on each AirOS device you want to monitor.
Currently only one user/pass pair is supported, so if monitoring multiple devices they would have to be the same.

Username and password are taken via environment, or optionally an environment file specified
using the -envFile flag.

### Parameters

```
Usage of airos-stats:
  -device value
    	IP or FQDN of AirOS Device, specify more than once for multiple
  -envFile string
    	File to load environment from
  -insecure
    	Set to skip SSL checks
  -interval int
    	Interval at which to poll AirOS devices (default 30)
  -json
    	Simply output JSON
  -listen string
    	Specify listen addr:port to enable Prometheus
  -useSSL
    	Set to use SSL to connect
  -verbose
    	Be Verbose
```

Specify -device multiple times to monitor multiple devices
