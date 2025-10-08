#!/usr/bin/env python3
import os, time, logging, argparse, datetime
from pymisp import PyMISP
from stix.core import STIXPackage
from stix.indicator import Indicator
from cybox.objects.address_object import Address
from cybox.objects.domain_name_object import DomainName
from cybox.objects.uri_object import URI
from cybox.objects.file_object import File
from cabby import create_client

logging.basicConfig(
    filename='result.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def log(msg, level='info'):
    if level == 'info':
        logging.info(msg)
    else:
        logging.error(msg)
    print(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} {msg}")

def load_ts(path):
    if not os.path.exists(path):
        return 0
    try:
        with open(path, "r") as f:
            return int(f.read().strip())
    except:
        return 0

def save_ts(path, val):
    try:
        with open(path, "w") as f:
            f.write(str(val))
    except Exception as e:
        log(f"Cannot save timestamp: {e}", "error")

def load_attr_ids(path):
    if not os.path.exists(path):
        return set()
    try:
        with open(path, "r") as f:
            return set(f.read().splitlines())
    except:
        return set()

def save_attr_ids(path, ids_):
    try:
        with open(path, "w") as f:
            for i in sorted(ids_):
                f.write(f"{i}\n")
    except Exception as e:
        log(f"Cannot save attribute IDs: {e}", "error")

def get_events(misp, tag, last_ts):
    try:
        return misp.search(controller="events", tags=tag, timestamp=last_ts, include_event=True, enforce_warning=False)
    except Exception as e:
        log(f"MISP query error: {e}", "error")
        return []

class CustomDomain(DomainName):
    def __init__(self, value=None, *args, **kwargs):
        super(CustomDomain, self).__init__(*args, **kwargs)
        if value:
            self.value = value

def process_events(events, known_ids):
    pkg = STIXPackage()
    new_attr_ids = set()
    cutoff = time.time() - 60 * 86400
    for e in events:
        for a in e["Event"].get("Attribute", []):
            aid = a.get("id")
            atype = a.get("type")
            aval = a.get("value")
            ats = int(a.get("timestamp", 0))
            if not aid or not atype or not aval:
                continue
            if aid in known_ids:
                continue
            if ats < cutoff:
                continue
            ind = Indicator()
            if atype in ["ip-dst", "ip-src"]:
                ind.add_observable(Address(address_value=aval, category=Address.CAT_IPV4))
            elif atype == "domain":
                ind.add_observable(CustomDomain(value=aval))
            elif atype == "url":
                ind.add_observable(URI(value=aval, type_=URI.TYPE_URL))
            elif atype in ["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "filename"]:
                fobj = File()
                if atype == "md5":
                    fobj.md5 = aval
                elif atype == "sha1":
                    fobj.sha1 = aval
                elif atype == "sha224":
                    fobj.sha224 = aval
                elif atype == "sha256":
                    fobj.sha256 = aval
                elif atype == "sha384":
                    fobj.sha384 = aval
                elif atype == "sha512":
                    fobj.sha512 = aval
                elif atype == "filename":
                    fobj.file_name = aval
                ind.add_observable(fobj)
            else:
                continue
            pkg.add_indicator(ind)
            new_attr_ids.add(aid)
    return pkg, new_attr_ids

def save_stix(pkg, path):
    try:
        with open(path, "w") as f:
            f.write(pkg.to_xml(encoding="utf-8").decode("utf-8"))
    except Exception as e:
        log(f"STIX save error: {e}", "error")

def push_taxii(path):
    url = "taxii_server_url"
    disc = "/services/discovery"
    inbox = "/services/inbox-a"
    user = "admin"
    pwd = "taxii-password"
    try:
        c = create_client(discovery_path=url + disc, use_https=False)
        c.set_auth(username=user, password=pwd)
        with open(path, "r") as f:
            pkg = f.read()
        r = c.push(
            content=pkg,
            content_binding="urn:stix.mitre.org:xml:1.1.1",
            collection_names=["misp_tag"],
            uri=url + inbox
        )
        if r.status == 200:
            log("STIX successfully pushed to TAXII.")
        else:
            log(f"TAXII push failed: {r.status}", "error")
    except Exception as e:
        log(f"Push TAXII error: {e}", "error")

def main(once=False):
    misp_key = "misp_key"
    misp_url = "misp_url"
    tag = "misp_tag"
    stix_path = "stix_package.xml"
    ts_file = "last_processed_timestamp.txt"
    attr_file = "processed_attribute_ids.txt"
    try:
        misp = PyMISP(misp_url, misp_key, ssl=False)
        log("MISP client created.")
    except Exception as e:
        log(f"MISP client creation failed: {e}", "error")
        return
    known_ids = load_attr_ids(attr_file)
    while True:
        try:
            old_ts = load_ts(ts_file)
            events = get_events(misp, tag, old_ts)
            if events:
                pkg, new_ids = process_events(events, known_ids)
                if pkg.indicators:
                    save_stix(pkg, stix_path)
                    push_taxii(stix_path)
                    known_ids.update(new_ids)
                    save_attr_ids(attr_file, known_ids)
                mx = old_ts
                for ev in events:
                    t = int(ev["Event"].get("timestamp", 0))
                    if t > mx:
                        mx = t
                if mx > old_ts:
                    save_ts(ts_file, mx)
            else:
                log("No new or updated events.")
            if once:
                break
            time.sleep(3600)
        except Exception as e:
            log(f"Main loop error: {e}", "error")
            if once:
                break
            time.sleep(3600)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true", help="Run once then exit.")
    args = parser.parse_args()
    main(args.once)
