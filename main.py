import json

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sslyze import Scanner, ServerScanRequest, ServerNetworkLocation
from sslyze.plugins.scan_commands import ScanCommand
import dns.resolver


def todict(obj, classkey=None):
    if isinstance(obj, dict):
        data = {}
        for (k, v) in obj.items():
            data[k] = todict(v, classkey)
        return data
    elif hasattr(obj, "_ast"):
        return todict(obj._ast())
    elif hasattr(obj, "__iter__") and not isinstance(obj, str):
        return [todict(v, classkey) for v in obj]
    elif hasattr(obj, "__dict__"):
        data = dict([(key, todict(value, classkey))
                     for key, value in obj.__dict__.items()
                     if not callable(value) and not key.startswith('_')])
        if classkey is not None and hasattr(obj, "__class__"):
            data[classkey] = obj.__class__.__name__
        return data
    elif obj.__class__.__name__ == "UUID":
        return str(obj)
    elif obj.__class__.__name__ == "Certificate":
        data = {}
        data["not_valid_before"] = str(obj.not_valid_before)
        data["not_valid_after"] = str(obj.not_valid_after)
        # data["fingerprint"] = obj.fingerprint
        return data
    elif obj.__class__.__name__ == "PosixPath":
        return "<PosixPath> toString not implemented"
    elif obj.__class__.__name__ == "OCSPResponse":
        # data = {}
        # data["produced_at"] = str(obj.produced_at)
        return "<OCSPResponse> toString not implemented"
    else:
        try:
            json.dumps(obj)
        except Exception as e:
            print(e, dir(obj))

        return obj


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins="*",
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def main():
    return {"message": "Hello World"}


@app.get("/scan/{domain}")
def scan_domain(domain: str):
    a_records = dns.resolver.resolve(qname=domain, rdtype=dns.rdatatype.A)

    ips = [str(a) for a in a_records]

    desired_scans = {
        ScanCommand.SSL_2_0_CIPHER_SUITES, ScanCommand.SSL_3_0_CIPHER_SUITES,
        ScanCommand.TLS_1_0_CIPHER_SUITES, ScanCommand.TLS_1_1_CIPHER_SUITES,
        ScanCommand.TLS_1_2_CIPHER_SUITES, ScanCommand.TLS_1_3_CIPHER_SUITES}
    scan_requests = [ServerScanRequest(server_location=ServerNetworkLocation(hostname=domain, ip_address=ip),
                                       scan_commands=desired_scans) for ip in ips]
    scanner = Scanner()

    scanner.queue_scans(scan_requests)

    results = []
    for result in scanner.get_results():
        print(f"Attaching result for ip: {result.server_location.ip_address}")
        results.append(result)
    return {"results": todict(results)}
