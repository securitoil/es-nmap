import json
import subprocess
from xml.etree import ElementTree

def parse_port(element):
    service_info = {
        'protocol': element.attrib['protocol'],
        'port': int(element.attrib['portid']),
        'name': element.find("./service").attrib.get('name', None),
        'product': element.find("./service").attrib.get('product', None),
        'version': element.find("./service").attrib.get('version', None),
    }
    return service_info

def handle(options):
    """handle a request to the function
    Args:
        options (dict): json request body
    """
    result = subprocess.check_output(["nmap", "-sV", "-oX", "-", options['host']])
    root = ElementTree.fromstring(result)
    host = {
        'host': options['host'],
        'time': int(root.find('.').attrib['start'])
    }

    results = []
    for node in root.findall("./host/ports/port"):
        service = parse_port(node)
        service.update(host)
        results.append(service)

    return results
