"""Router port forwarding (UPnP IGD): the messages setup.py sends and how it
reads the answers, against canned replies and a local stand-in router. DDR
forwards UDP ports too (STUN, the match relay), so each port goes with its
protocol."""
import http.server
import threading
import unittest
from unittest import mock

from hostsetup import upnp

REPLY = (b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: urn:schemas-upnp-org:device:"
         b"InternetGatewayDevice:1\r\nLocation: http://192.168.1.1:5000/rootDesc.xml\r\n\r\n")

DESCRIPTION = b"""<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
 <device><deviceList><device><deviceList><device><serviceList>
  <service>
   <serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1</serviceType>
   <controlURL>/ctl/PPP</controlURL>
  </service>
  <service>
   <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
   <controlURL>/ctl/IPConn</controlURL>
  </service>
  <service>
   <serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>
   <controlURL>/ctl/L3F</controlURL>
  </service>
 </serviceList></device></deviceList></device></deviceList></device>
</root>"""

ANSWER = b"""<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>
<u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
<NewExternalIPAddress>203.0.113.9</NewExternalIPAddress></u:GetExternalIPAddressResponse>
</s:Body></s:Envelope>"""

FAULT = b"""<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault>
<faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail>
<UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>718</errorCode>
<errorDescription>ConflictInMappingEntry</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>"""


class Messages(unittest.TestCase):
    def test_search(self):
        msg = upnp.search_message("urn:x", 2).decode()
        self.assertTrue(msg.startswith("M-SEARCH * HTTP/1.1\r\n"))
        self.assertIn('MAN: "ssdp:discover"\r\n', msg)
        self.assertIn("ST: urn:x\r\n", msg)
        self.assertTrue(msg.endswith("\r\n\r\n"))

    def test_reply(self):
        self.assertEqual(upnp.parse_reply(REPLY)["location"], "http://192.168.1.1:5000/rootDesc.xml")
        self.assertIsNone(upnp.parse_reply(b"NOTIFY * HTTP/1.1\r\n\r\n"))

    def test_description(self):
        services = upnp.parse_description(DESCRIPTION, "http://192.168.1.1:5000/rootDesc.xml")
        self.assertEqual(services, [
            ("urn:schemas-upnp-org:service:WANIPConnection:1", "http://192.168.1.1:5000/ctl/IPConn"),
            ("urn:schemas-upnp-org:service:WANPPPConnection:1", "http://192.168.1.1:5000/ctl/PPP")])
        based = DESCRIPTION.replace(b"<device>", b"<URLBase>http://10.0.0.1:80/</URLBase><device>", 1)
        self.assertEqual(upnp.parse_description(based, "http://x/")[0][1], "http://10.0.0.1:80/ctl/IPConn")

    def test_envelope(self):
        body = upnp.envelope("AddPortMapping", "urn:svc:1", [("NewExternalPort", 19580),
                                                               ("NewPortMappingDescription", "A&B <x>")]).decode()
        self.assertIn('<u:AddPortMapping xmlns:u="urn:svc:1">', body)
        self.assertIn("<NewExternalPort>19580</NewExternalPort>", body)
        self.assertIn("<NewPortMappingDescription>A&amp;B &lt;x&gt;</NewPortMappingDescription>", body)

    def test_answer_and_fault(self):
        self.assertEqual(upnp.parse_response(ANSWER), {"NewExternalIPAddress": "203.0.113.9"})
        with self.assertRaises(upnp.UpnpError) as e:
            upnp.parse_response(FAULT)
        self.assertEqual(e.exception.code, 718)

    def test_private_addresses(self):
        for ip in ("10.1.2.3", "172.16.0.1", "172.31.255.1", "192.168.0.10", "100.64.1.1", "100.127.0.1"):
            self.assertTrue(upnp.is_private(ip), ip)
        for ip in ("203.0.113.9", "172.32.0.1", "100.128.0.1", "8.8.8.8", "play.example.net"):
            self.assertFalse(upnp.is_private(ip), ip)


class FakeGateway(upnp.Gateway):
    """Answers like a router that already forwards some ports."""

    def __init__(self, mappings, refuse_lease_0=False):
        super().__init__("http://192.168.1.1/ctl", upnp.SERVICES[1])
        self.mappings, self.refuse_lease_0, self.calls = mappings, refuse_lease_0, []

    def call(self, action, args=()):
        a = dict(args)
        self.calls.append((action, a))
        key = (a.get("NewExternalPort"), a.get("NewProtocol"))
        if action == "GetSpecificPortMappingEntry":
            if key not in self.mappings:
                raise upnp.UpnpError("NoSuchEntryInArray", 714)
            client, port = self.mappings[key]
            return {"NewInternalClient": client, "NewInternalPort": str(port)}
        if action == "AddPortMapping":
            if key in self.mappings:
                raise upnp.UpnpError("ConflictInMappingEntry", 718)
            if self.refuse_lease_0 and a["NewLeaseDuration"] == 0:
                raise upnp.UpnpError("OnlyPermanentLeasesSupported", 725)
            self.mappings[key] = (a["NewInternalClient"], a["NewInternalPort"])
            return {}
        raise AssertionError(action)


class Forwarding(unittest.TestCase):
    def test_open_ports(self):
        g = FakeGateway({(9573, "TCP"): ("192.168.1.20", 9573), (19580, "TCP"): ("192.168.1.99", 19580)})
        results = upnp.open_ports(g, [(9573, "TCP"), (19580, "TCP"), (3478, "UDP")], "192.168.1.20")
        self.assertEqual(results, {(9573, "TCP"): "already", (19580, "TCP"): "taken", (3478, "UDP"): "opened"})
        self.assertEqual(g.mappings[(3478, "UDP")], ("192.168.1.20", 3478))
        add = [a for action, a in g.calls if action == "AddPortMapping"][-1]
        self.assertEqual((add["NewProtocol"], add["NewLeaseDuration"], add["NewEnabled"]), ("UDP", 0, 1))

    def test_same_port_other_protocol_is_separate(self):
        g = FakeGateway({(19600, "TCP"): ("192.168.1.99", 19600)})
        self.assertEqual(upnp.open_ports(g, [(19600, "UDP")], "192.168.1.20"), {(19600, "UDP"): "opened"})

    def test_lease_retry(self):
        g = FakeGateway({}, refuse_lease_0=True)
        self.assertEqual(upnp.open_ports(g, [(29573, "TCP")], "192.168.1.20"), {(29573, "TCP"): "opened"})
        leases = [a["NewLeaseDuration"] for action, a in g.calls if action == "AddPortMapping"]
        self.assertEqual(leases, [0, upnp.WEEK])


class Router(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self._send(200, DESCRIPTION)

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        self.server.seen.append((self.headers["SOAPAction"], body))
        if b"AddPortMapping" in body:
            self._send(500, FAULT)
        else:
            self._send(200, ANSWER)

    def _send(self, code, data):
        self.send_response(code)
        self.send_header("Content-Type", "text/xml")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class OverHttp(unittest.TestCase):
    def setUp(self):
        self.server = http.server.HTTPServer(("127.0.0.1", 0), Router)
        self.server.seen = []
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.base = "http://127.0.0.1:%d" % self.server.server_port

    def test_find_and_call(self):
        location = self.base + "/rootDesc.xml"
        with mock.patch.object(upnp, "discover", return_value=[location]):
            g = upnp.find_gateway("192.168.1.20")
        self.assertEqual(g.control_url, self.base + "/ctl/IPConn")
        self.assertEqual(g.external_ip(), "203.0.113.9")
        action, body = self.server.seen[-1]
        self.assertEqual(action, '"urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress"')
        with self.assertRaises(upnp.UpnpError) as e:
            g.add(19580, "192.168.1.20", "DDR Online")
        self.assertEqual(e.exception.code, upnp.CONFLICT)

    def test_no_router(self):
        with mock.patch.object(upnp, "discover", return_value=[]):
            self.assertIsNone(upnp.find_gateway("192.168.1.20"))


if __name__ == "__main__":
    unittest.main()
