#!/usr/bin/env python3
# builtin modules
import os
import ipaddress
import asyncio
from datetime import datetime

# install modules
try:
    import aiohttp
except ImportError:
    print("Error: aiohttp is not installed. Please run 'pip install aiohttp'")
    exit(1)

# Configuration
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RSC_DIR = os.path.join(PROJECT_ROOT, "src", "i18n", "rsc")
MAPPING_DATABASE = os.path.join(RSC_DIR, "mapping.db")

RIR_URLS = [
    "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest",
    "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
    "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
    "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
    "https://ftp.afrinic.net/stats/afrinic/delegated-afrinic-extended-latest",
]

# Fetch content from URL
async def fetch(session, url):
    try:
        async with session.get(url, timeout=300) as response:
            if response.status == 200:
                print(f"[SUCCESS] - {url}")
                content = await response.read()
                filename = url.split("/")[-1]
                filepath = os.path.join(RSC_DIR, filename)
                with open(filepath, "wb") as f:
                    f.write(content)
                return filepath
            else:
                print(f"[ERROR {response.status}] - {url}")
    except Exception as e:
        print(f"[EXCEPTION] - {url}: {e}")
    return None

# Download coroutine
async def download():
    if not os.path.exists(RSC_DIR):
        os.makedirs(RSC_DIR)
    
    async with aiohttp.ClientSession() as session:
        filepaths = await asyncio.gather(*(fetch(session, url) for url in RIR_URLS))
    
    print("Download Complete")
    return [fp for fp in filepaths if fp]

def process_data(filepaths):
    intervals = []
    for filepath in filepaths:
        if not filepath or not os.path.exists(filepath):
            continue
            
        print(f"Processing {filepath}...")
        try:
            with open(filepath, "r", encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if line.startswith("#") or not line.strip():
                        continue
                    parts = line.strip().split("|")
                    # Format: registry|cc|type|start|value|date|status[|extensions]
                    # Example: apnic|AU|ipv4|1.0.0.0|256|20110811|assigned|A9149219
                    if len(parts) < 7 or parts[2] != "ipv4":
                        continue
                    
                    country = parts[1]
                    ip = parts[3]
                    ip_count = parts[4]
                    
                    try:
                        start_ip = int(ipaddress.IPv4Address(ip))
                        count = int(ip_count)
                        end_ip = start_ip + count - 1
                        intervals.append((start_ip, end_ip, country))
                    except (ValueError, ipaddress.AddressValueError):
                        continue
        except Exception as e:
            print(f"Error processing {filepath}: {e}")

    # Save database set
    print(f"Sorting {len(intervals)} intervals...")
    intervals.sort(key=lambda x: x[0])
    
    print(f"Saving to {MAPPING_DATABASE}...")
    with open(MAPPING_DATABASE, "w") as f:
        for interval in intervals:
            line = f"{interval[0]},{interval[1]},{interval[2]}"
            f.write(line + "\n")
    
    # Clean up raw files
    for filepath in filepaths:
        try:
            os.remove(filepath)
        except:
            pass
            
    print("Processing Complete")

async def main():
    print(f"Starting RIR data update at {datetime.now()}")
    filepaths = await download()
    if filepaths:
        process_data(filepaths)
    else:
        print("No files downloaded. Aborting.")

if __name__ == "__main__":
    asyncio.run(main())
