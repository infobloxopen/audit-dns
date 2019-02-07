#!/usr/bin/env python3
"""
A script to audit DNS records.

Given a list of networks looks at a specific DNS view on NIOS,
Print any A record that point outside those networks, Print any CNAME
that when followed points outside of the networks (and print the CNAME
chain while doing so).
"""

import argparse
import configparser
import ipaddress
import sys
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def get_args(args=None):
    """Deal with command line arguments."""
    parser = argparse.ArgumentParser(description='Audit DNS records.')
    parser.add_argument('-c', '--configfile',
                        help="/path/to/configfile",
                        default="audit_dns.conf")
    parser.add_argument('-r', '--ranges',
                        help="/path/to/range_file",
                        default="./allowed_networks")
    parser.add_argument('-v', '--view',
                        help="Name of a NIOS DNS view to audit",
                        default="default")
    results = parser.parse_args(args)
    return {'configfile':results.configfile,
            'ranges':results.ranges,
            'view':results.view}

def get_config(configfile):
    """Read our config file for local settings."""
    config = configparser.ConfigParser()
    config.read(configfile)
    return config

def auth_request(user_name, password, url_root):
    """Send an authentication request to NetMRI and catch the cookie coming back."""
    from requests.auth import HTTPBasicAuth
    url = url_root + "/wapi/v1.0/?_schema"
    try:
        response = requests.get(url, auth=HTTPBasicAuth(user_name, password), verify=False)
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError:
            # Whoops it wasn't a 200
            print("ERROR: Infoblox reported an error %s while authenticating."
                  %(response.status_code))
            return False
    except requests.exceptions.RequestException:
        # A serious problem happened, like an SSLError or InvalidURL
        print("WARN: Unable to authenticate with Infoblox.")
        return False
    print("INFO: Successfully authenticated to Infoblox.")
    return response.cookies

def latest_api(cookies, url_root):
    """Ask DDI what the latest API version is that it supports."""
    url = url_root + "/wapi/v1.0/?_schema"
    try:
        response = requests.get(url, cookies=cookies, verify=False)
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError:
            # Whoops it wasn't a 200
            print("ERROR: Infoblox reported an error %s." %(response.status_code))
            print(response.text)
            return False
    except requests.exceptions.RequestException:
        # A serious problem happened, like an SSLError or InvalidURL
        print("WARN: Unable to communicate with Infoblox.")
        return False
    return "%s/wapi/v%s" %(url_root, response.json()["supported_versions"][response.json()\
        ["supported_versions"].index(max(response.json()["supported_versions"]))])

def enumerate_a_by_view(cookies, url_root, view_name):
    """Given a view name, return all A records that are contained in that view."""
    url = url_root + "/wapi/v2.9.1/record:a"
    params = {
        "view": view_name,
    }
    try:
        response = requests.get(url, params=params, cookies=cookies, verify=False)
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError:
            # Whoops it wasn't a 200
            print("ERROR: Infoblox reported an error %s." %(response.status_code))
            print(response.text)
            return False
    except requests.exceptions.RequestException:
        # A serious problem happened, like an SSLError or InvalidURL
        print("WARN: Unable to communicate with Infoblox.")
        return False
    return response.json()

def uniqify(inlist):
    """Given a list, return a new list preserving the list order and deduplicating."""
    return list(dict.fromkeys(inlist))

def read_allowed_networks(args):
    """Open and read in allowed networks CIDR blocks from file."""
    allowed_networks = []
    try:
        infile = open(args["ranges"], "r")
        for line in infile:
            # Ignore lines starting with a hash as comments.
            if not line.lstrip().startswith('#'):
                allowed_networks.append(ipaddress.IPv4Network(line.rstrip()))
        infile.close()
    except FileNotFoundError:
        print("ERROR: Allowed networks file %s not found. Exiting." % args["ranges"])
        sys.exit(1)
    return allowed_networks

def compare_addresses(allowed_networks, test_addresses):
    """Compare addresses from A records to allowed networks, return list of bad addresses."""
    bad_addresses = []
    # Compare addresses to allowed networks.
    for address in test_addresses:
        ok_address = False
        for network in allowed_networks:
        #    print(" %s" % network)
            if ipaddress.IPv4Address(address) in network:
                ok_address = True
        if not ok_address:
            bad_addresses.append(address)
    return bad_addresses

def main():
    """Start the main loop."""
    args = get_args()
    config = get_config(args["configfile"])
    allowed_networks = read_allowed_networks(args)
    url_root = 'https://' + config["infoblox"]["host"]
    cookie_jar = auth_request(config["infoblox"]["user"],
                                       config["infoblox"]["password"],
                                       url_root)
    if not cookie_jar:
        print("ERROR: Authentication token not avaialble. Exiting.")
        sys.exit(1)
    a_records = enumerate_a_by_view(cookie_jar, url_root, args["view"])
    candidate_addresses = []
    for record in a_records:
        candidate_addresses.append(record["ipv4addr"])
    test_addresses = uniqify(candidate_addresses)
    bad_addresses = compare_addresses(allowed_networks, test_addresses)
    if bad_addresses:
        print(bad_addresses)
    sys.exit(0)

if __name__ == '__main__':
    main()
