#!/usr/bin/env python3


import sys
import hashlib
if sys.version_info < (3, 6):
   import sha3
import base64
import requests
import glob 
import json

from collections import OrderedDict
try:
    from . import flash_binaries 
except:
    import flash_binaries

FLASH_BINS_JSON = "flash_binaries.py"
REPO_ORG =repo_org = "keepkey"
REPO_NAME = repo_name="keepkey-firmware"

hash_func = hashlib.sha3_256
bin_hash_func = hashlib.sha3_256


def bin_digest(*args, **kwargs):
    return bin_hash_func(*args, **kwargs).hexdigest()


def package_raw_asset(raw_asset):
    #calculate fingerprint, padding out with 0xFFFFFFFF to 256K
    padding = b"\xff" * (1024*256 - len(raw_asset))
    fingerprint = bin_digest(raw_asset + padding)
    b64_asset = base64.b64encode(raw_asset + padding).decode('utf8')
    return {'b64_asset':b64_asset,
            'fingerprint':fingerprint}


def commit_assets(repo_org=REPO_ORG, repo_name=REPO_NAME):
    release_binaries = OrderedDict({})
    with requests.Session() as s:
        #get all tagged releases for this repo
        r = s.get("https://api.github.com/repos/{}/{}/releases".format(repo_org, repo_name))
        if not r.ok: r.raise_for_status()
        releases_by_version = sorted(r.json(), key=lambda x: x.get('tag_name'))
        
        for this_release in releases_by_version:
            #pull the tag name for each release and download attached asset binaries
            tag_name = this_release.get('tag_name')
            release_assets = release_binaries[tag_name] = {}
            
            for this_asset in this_release.get('assets'):            
                #fetch the asset binary
                asset_name = this_asset.get('name')
                if "keepkey_main" in asset_name: continue
                print("Downloading {} asset {}".format(tag_name, asset_name))
                asset_url = this_asset.get('browser_download_url')
                asset_req = s.get(asset_url)
                if not asset_req.ok: asset_req.raise_for_status()
                
                #encode asset into marshallable format
                raw_asset = asset_req.content
                release_assets[asset_name] = package_raw_asset(raw_asset)

    #incorporate early binaries not currently tagged on github
    for fn in glob.glob("./binaries/*.bin"):
        #parse the filename for tag_name and asset_name
        asset_name, tag_name = fn.split("./binaries/")[1].split(".bin")[0].split("_")
        tag_name = "v" + tag_name if not tag_name.startswith("v") else tag_name
        #add the tag if it does not already exist
        if tag_name not in release_binaries: release_binaries[tag_name] = {}
        #package the binary and add to releases
        with open(fn, 'rb') as of:
            raw_asset = of.read()
            print(fn)
            release_binaries[tag_name][asset_name] =  package_raw_asset(raw_asset)
    
    #generate json binary file
    with open(FLASH_BINS_JSON, "w") as of:
        of.write("binaries={}".format(json.dumps(release_binaries)))



def fetch_asset(target_fingerprint):
    for this_release_name, this_release in flash_binaries.binaries.items():
        for this_asset_name, this_asset in this_release.items():
            if this_asset.get('fingerprint') == target_fingerprint:
                return base64.b64decode(this_asset.get('b64_asset'))
    pass

def hash_asset(challenge, target_hash, padding = b'', length=1024*256):
    the_asset = fetch_asset(target_hash)
    #check boundaries
    if the_asset is None: raise ValueError("Binary fingerprint not found in db")
    if (length > len(the_asset + padding)): raise ValueError("length exceeds binary + padding")
    return hash_func(challenge + (fetch_asset(target_hash) + padding)[:length])


if __name__ == "__main__":
    commit_assets()

