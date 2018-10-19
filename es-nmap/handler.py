import json
import requests
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

def handle(req):
    """handle a request to the function
    Args:
        req (str): request body
    """
    options = json.loads(req)
    result = subprocess.check_output(["nmap", "-sV", "-oX", "-", options['host']])
    root = ElementTree.fromstring(result)
    meta = {
        'index': {
            '_index': 'nmap',
            '_type': 'service',
        }
    }
    host = {
        'host': options['host'],
        'time': int(root.find('.').attrib['start'])
    }

    services = []
    for node in root.findall("./host/ports/port"):
        service = parse_port(node)
        service.update(host)
        services.append(meta)
        services.append(service)

    return '\n'.join(json.dumps(service) for service in services) + '\n'
