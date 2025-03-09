import ipaddress
import os
import uuid
import xml.etree.ElementTree as ET
import yaml
import libnmap.parser

from typing import Any


class Port:
    def __init__(self, address, port, protocol, service):
        self.address = address
        self.port = port
        self.protocol = protocol
        self.service = service if service != "unknown" else ""

class Host:
    all_hosts = {}
    ip_to_host: dict[Any, Any] = {}

    @staticmethod
    def is_in_network(ip_address, network):
        try:
            ip = ipaddress.ip_address(ip_address)
            net = ipaddress.IPv4Interface(network).network
            return ip in net
        except ValueError:
            print(f"Invalid IP address or network: {ip_address} and {network}")
            return False

    @staticmethod
    def generate_unique_id():
        return uuid.uuid4().hex

    @staticmethod
    def by_ip(ip_address):
        return GatewayHost.ip_to_host.get(ip_address)

    @staticmethod
    def create(name, ips=None):
        if ips:
            for ip in ips:
                if ip in host.ip_to_host:
                    return host.ip_to_host[ip]
        return Host(name, ips)

    def __init__(self, name, ips=None):
        self.name = name
        self.id = self.generate_unique_id()
        self.addresses = ips if ips is not None else []
        self.ports = {}
        for ip in self.addresses:
            self.ip_to_host[ip] = self
        self.all_hosts[self.name] = self

    def __repr__(self):
        return f"Host(id={self.id}, name={self.name}, addresses={self.addresses})"

    def __str__(self):
        return self.__repr__()

    def add_port(self, port):
        address = port.address
        if not address in self.ports:
            self.ports[address] = []
        self.ports[address].append(port)

    def dot_label(self):
        label = f'<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0">'
        label += f'<TR><TD><B>{self.name}</B></TD></TR>'
        for address, ports in self.ports.items():
            label += f'<TR><TD ALIGN="CENTER" COLSPAN="3"><I>{address}</I></TD></TR>'
            for port in ports:
                label += f'<TR><TD ALIGN="LEFT">{port.service}</TD><TD ALIGN="LEFT">{port.port}</TD><TD ALIGN="LEFT">{port.protocol}</TD></TR>'
        label += "</TABLE>"
        return label

class GatewayHost(Host):
    all_gateway = []
    network_to_gw = []

    @staticmethod
    def within_network(address):
        for host in GatewayHost.network_to_gw:
            for index, net in enumerate(host.networks):
                if GatewayHost.is_in_network(address, net):
                    return host, net, index
        return None, None, None

    @staticmethod
    def find_gateway(host):
        if isinstance(host, GatewayHost):
            return None, None, None
        for address in host.addresses:
            gw, net, index = GatewayHost.within_network(address)

            if gw:
                return gw, net, index
        return None, None, None

    def __init__(self, name, networks=None):
        GatewayHost.all_gateway.append(self)
        GatewayHost.network_to_gw.append(self)
        self.networks = networks if networks is not None else []
        addresses = []
        for ip_mask in self.networks:
            parts = ip_mask.split("/")
            addresses.append(parts[0])
        super().__init__(name, ips=addresses)

    def __repr__(self):
        return f"GatewayHost(id={self.id}, name={self.name}, addresses={self.addresses}, networks={self.networks})"

    def __str__(self):
        return self.__repr__()


def parse_directory(directory):
    try:
        if not os.path.isdir(directory):
            print(f"Error: Directory '{directory}' does not exist.")
            return

        for filename in os.listdir(directory):
            if filename.endswith(".xml"):
                filepath = os.path.join(directory, filename)
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        report = libnmap.parser.NmapParser.parse(f.read())

                        for nhost in report.hosts:
                            if nhost.is_up():
                                ips = [nhost.address]
                                name = nhost.hostnames[0] if nhost.hostnames else nhost.address
                                host = Host.create(name, ips)
                                for service in nhost.services:
                                    if service.open():
                                        s = Port(nhost.address, service.port, service.protocol, service.service)
                                        host.add_port(s)
                except libnmap.parser.NmapParserException as e:
                    print(f"Error parsing {filename}: {e}")
                except FileNotFoundError:
                    print(f"Error: File '{filepath}' not found.")
                except ET.ParseError as e:
                    print(f"Error parsing XML in {filename}: {e}")
                except UnicodeDecodeError as e:
                    print(f"Error decoding file {filename}: {e}")

    except Exception as general_e:
        print(f"An unexpected error occurred: {general_e}")


def generate_graph():
    directed = False
    graph_type = "digraph" if directed else "graph"
    edge_op = "->" if directed else "--"
    content = [f"{graph_type} G {{"]

    for _, host in Host.all_hosts.items():
        if isinstance(host, GatewayHost):
            content.append(f'  G{host.id} [shape=record, label=<{host.dot_label()}>];')
            for index, item in enumerate(host.networks):
                content.append(f'  I{host.id}Z{index} [label="{item}"];')
        else:
            content.append(f'  H{host.id} [shape=record, label=<{host.dot_label()}>];')

    for _, host in Host.all_hosts.items():
        if isinstance(host, GatewayHost):
            for index, item in enumerate(host.networks):
                content.append(f'  G{host.id} {edge_op} I{host.id}Z{index};')
        else:
            gw, net, index = GatewayHost.find_gateway(host)
            if gw:
                content.append(f'  I{gw.id}Z{index} {edge_op} H{host.id};')

    content.append(f"}}")

    for line in content:
        print(line)



def parse_config(filename):
    """
    Parses a YAML file containing gateway information.
    """
    try:
        with open(filename, 'r') as file:
            data = yaml.safe_load(file)
            return data
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        return None
    except yaml.YAMLError as e:
        print(f"Error parsing YAML: {e}")
        return None
    except Exception as general_e:
        print(f"An unexpected error occurred: {general_e}")
        return None


def gateway_ips(parsed_data):
    """
    Extracts the gateway IPs from the parsed YAML data.
    """
    if not isinstance(parsed_data, dict) or 'gateways' not in parsed_data:
        return None

    gateway_ips = {}
    for gateway_name, ips in parsed_data['gateways'].items():
        gateway_ips[gateway_name] = ips
    return gateway_ips


if __name__ == "__main__":
    parsed_data = parse_config("config/config.yaml")

    if parsed_data:
        gateway_ip_data = gateway_ips(parsed_data)
        if gateway_ip_data:
            for gateway, ips in gateway_ip_data.items():
                host = GatewayHost(gateway, ips)
        else:
            print("Could not extract gateway IP data.")

    directory_path = "results"  # Replace with your directory path
    if not os.path.exists(directory_path):
        os.makedirs(directory_path)  # create the directory if it does not exist.
        print(f"Created directory: {directory_path}. Please place your nmap xml files there.")
    else:
        parse_directory(directory_path)
        generate_graph()
