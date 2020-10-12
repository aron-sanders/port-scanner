import nmap
import logging

TCP_CONNECT_FLAG = '-sT'


def get_allowed_ports(ip, config_file):
    return next(item for item in config_file if item["ip"] == ip)["allowed_ports"]  # why are we using "next" 


def scan(ip, port_range):
    scanner = nmap.PortScanner()
    scanner.scan(hosts=ip, ports=port_range, arguments=TCP_CONNECT_FLAG)
    return scanner


def print_scan_results(scanner, ip, allowed_ports):
    logging.info(f"Scanned  {scanner[ip].hostname()}   :   {ip}")
    logging.info(f"Allowed Ports :  {str(allowed_ports).strip('[]')}")

    if scanner[ip].state() == 'up':
        for protocol in scanner[ip].all_protocols():
            logging.info(protocol)

            check_port_state(scanner, ip, protocol, allowed_ports)
    else:
        logging.warning("Host is not available")


def check_port_state(scanner, ip, protocol, allowed_ports):
    ports = scanner[ip][protocol].keys()
    ports_as_expected = True
    invalid_ports = []

    for port in ports:
        port_state = scanner[ip][protocol][port]['state']
        logging.info(f"port : {str(port)} \tstate :  {port_state}")
        if port_state == 'open' and port not in allowed_ports:
            ports_as_expected = False
            invalid_ports.append(port)
    else:  # would work the same also without the "else" block. i am not sure this is relevant here
        if not ports_as_expected:
            logging.error(f"ports: {str(invalid_ports).strip('[]')} should not be open")
        else:
            logging.info("All ports are closed as expected")
        assert ports_as_expected, f"ports: {str(invalid_ports).strip('[]')} should not be open"  # i would probably prefer to refactor and detach this from the "print scan results" flow..


def test_scanner(ip, port_range, get_config_file):
    scanner = scan(ip, port_range)

    if "error" in scanner.scaninfo():
        error_message = str(scanner.scaninfo()["error"])
        logging.error(f"{ip} : {error_message}")
        assert False, error_message
    elif scanner.scanstats()["downhosts"] == '1':
        logging.error(f"{ip} is not responsive")
        assert False, f"{ip} is not responsive"
    else:
        allowed_ports = get_allowed_ports(ip, get_config_file)
        print_scan_results(scanner, ip, allowed_ports)
