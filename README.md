# audit-dns
Given a list of IPv4 networks looks at a specific DNS view on NIOS. Print any A record that point outside those networks. Print any CNAME that when followed points outside of the networks (and print the CNAME chain while doing so).

Following config files are in use:

**allowed_networks**

Specify the networks in "IP/Hostmask" format that you manage or expect records to reside in. For a single address, specify e.g. 1.2.3.4/32

**audit_dns.conf**

Configuration file to specify Gridmaster hostname, user and password.

**credit**
Credit to Chris Hindy who wrote this with little notice and has be so kind to allow it to be published under Apache 2.0
