# Port Scanner

## What it Does

Scans ip addresses using `nmap`, searching for open ports. 
By default it scans the well known ports from `1-1023` but the can be changed from the command line.
Receives a list of ip addresses and the allowed ports for each address.
The test will fail if open ports are found which are not in the list of allowed ports.
Outputs the results to a log file.

## Instructions

Run using `pytest -n auto` or `pytest -n <num of CPU cores>`. This leverages the `pytest-xdist`
plugin and allows us to run multiple scans in parallel.

To change the default port range use `--port_range=<range>`.
To change the default configuration file name or location use `--config_file=<path to config file>`.

Example: `pytest -n auto --port_range=1-2000 --config_file=~/configuration/hosts.json`

Run `pytest -h` to see these options in the `custom options` section.

## Known Issues

When running tests in parallel using `pytest-xdist` only one test gets logged to the external log file.

## Dependencies

* Python version 3.6+
* pytest
* pytest-xdist
* python-nmap