from unittest.mock import patch
from xml.etree import ElementTree
import pytest
from es_nmap import handler

XML_STRING = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<!-- Nmap 7.60 scan initiated Sun Oct 21 22:47:16 2018 as: nmap -sV -oX output.xml 192.168.2.1 -->
<nmaprun scanner="nmap" args="nmap -sV -oX output.xml 192.168.2.1" start="1540180036" startstr="Sun Oct 21 22:47:16 2018" version="7.60" xmloutputversion="1.04">
<verbose level="0"/>
<debugging level="0"/>
<host starttime="1540180036" endtime="1540180054"><status state="up" reason="syn-ack" reason_ttl="0"/>
<address addr="192.168.2.1" addrtype="ipv4"/>
<hostnames>
</hostnames>
<ports><extraports state="filtered" count="996">
<extrareasons reason="no-responses" count="996"/>
</extraports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="ssh" product="OpenSSH" version="7.7" extrainfo="protocol 2.0" ostype="FreeBSD" method="probed" conf="10"><cpe>cpe:/a:openbsd:openssh:7.7</cpe><cpe>cpe:/o:freebsd:freebsd</cpe></service></port>
<port protocol="tcp" portid="53"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="domain" product="Unbound" version="1.7.3" method="probed" conf="10"><cpe>cpe:/a:nlnet:unbound:1.7.3</cpe></service></port>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="http" product="lighttpd" version="1.4.49" method="probed" conf="10"><cpe>cpe:/a:lighttpd:lighttpd:1.4.49</cpe></service></port>
<port protocol="tcp" portid="443"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="http" product="lighttpd" version="1.4.49" tunnel="ssl" method="probed" conf="10"><cpe>cpe:/a:lighttpd:lighttpd:1.4.49</cpe></service></port>
</ports>
<times srtt="2667" rttvar="1352" to="100000"/>
</host>
</nmaprun>
"""

SERVICE_STRING = """<port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="ssh" product="OpenSSH" version="7.7" extrainfo="protocol 2.0" ostype="FreeBSD" method="probed" conf="10"><cpe>cpe:/a:openbsd:openssh:7.7</cpe><cpe>cpe:/o:freebsd:freebsd</cpe></service></port>
"""


@pytest.fixture
def service_node():
    """Fixture for a service node"""
    return ElementTree.fromstring(SERVICE_STRING)

def test_parse_port(service_node):
    """Test that parse_port returns a correct representation as a dict"""
    expected = {
        'protocol': 'tcp',
        'port': 22,
        'name': 'ssh',
        'product': 'OpenSSH',
        'version': '7.7'
    }
    assert expected == handler.parse_port(service_node)

@patch('subprocess.check_output')
def test_handle(subprocess_mock):
    options = {
        'host': '192.168.2.1'
    }
    subprocess_mock.return_value = XML_STRING
    expected = [
        {'protocol': 'tcp', 'port': 22, 'name': 'ssh', 'product': 'OpenSSH', 'version': '7.7', 'host': '192.168.2.1', 'time': 1540180036},
        {'protocol': 'tcp', 'port': 53, 'name': 'domain', 'product': 'Unbound', 'version': '1.7.3', 'host': '192.168.2.1', 'time': 1540180036},
        {'protocol': 'tcp', 'port': 80, 'name': 'http', 'product': 'lighttpd', 'version': '1.4.49', 'host': '192.168.2.1', 'time': 1540180036},
        {'protocol': 'tcp', 'port': 443, 'name': 'http', 'product': 'lighttpd', 'version': '1.4.49', 'host': '192.168.2.1', 'time': 1540180036}
    ]
    result = handler.handle(options)
    assert subprocess_mock.called
    subprocess_mock.assert_called_with(['nmap', '-sV', '-oX', '-', '192.168.2.1'])
    assert expected == result
