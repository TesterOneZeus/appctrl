function FindProxyForURL(url, host) {
	var privateIP = /^(0|10|127|192\.168|172\.1[6789]|172\.2[0-9]|172\.3[01]|169\.254|192\.88\.99)\.[0-9.]+$/;
	var resolved_ip = dnsResolve(host);

	/* Non-FQDN or private IP goes direct */
	if (isPlainHostName(host) || isInNet(resolved_ip, "192.0.2.0","255.255.255.0") || privateIP.test(resolved_ip)) {
		return "DIRECT";
	}

	/* FTP goes directly */
	if (url.substring(0,4) == "ftp:") {
		return "DIRECT";
	}

	/* ZPA goes direct */
	if (isInNet(resolved_ip, "100.64.0.0","255.255.0.0")) {
		return "DIRECT";
	}
	
	/* GSA FQDNs go direct */
    if (isPlainHostName(host) ||
        dnsDomainIs(host, "internet.edgediagnostic.globalsecureaccess.microsoft.com") ||
        dnsDomainIs(host, "m365.edgediagnostic.globalsecureaccess.microsoft.com") ||
        dnsDomainIs(host, "private.edgediagnostic.globalsecureaccess.microsoft.com") ||
        dnsDomainIs(host, "aps.globalsecureaccess.microsoft.com") ||
        dnsDomainIs(host, "6f70dbff-21f8-4b54-9cd2-1a9a512a83ae.internet.client.globalsecureaccess.microsoft.com") ||
        dnsDomainIs(host, "6f70dbff-21f8-4b54-9cd2-1a9a512a83ae.m365.client.globalsecureaccess.microsoft.com") ||
        dnsDomainIs(host, "6f70dbff-21f8-4b54-9cd2-1a9a512a83ae.private.client.globalsecureaccess.microsoft.com") ||
        dnsDomainIs(host, "6f70dbff-21f8-4b54-9cd2-1a9a512a83ae.private-backup.client.globalsecureaccess.microsoft.com") ||
        dnsDomainIs(host, "6f70dbff-21f8-4b54-9cd2-1a9a512a83ae.internet-backup.client.globalsecureaccess.microsoft.com") ||
        dnsDomainIs(host, "6f70dbff-21f8-4b54-9cd2-1a9a512a83ae.m365-backup.client.globalsecureaccess.microsoft.com"))
        return "DIRECT";
    
    /* GSA IPs go direct*/
    if (isInNet(resolved_ip, "150.171.19.0", "255.255.255.0") ||
        isInNet(resolved_ip, "150.171.20.0", "255.255.255.0") ||
        isInNet(resolved_ip, "13.107.232.0", "255.255.255.0") ||
        isInNet(resolved_ip, "13.107.233.0", "255.255.255.0") ||
        isInNet(resolved_ip, "150.171.15.0", "255.255.255.0") ||
        isInNet(resolved_ip, "150.171.18.0", "255.255.255.0") ||
        isInNet(resolved_ip, "151.206.0.0", "255.255.0.0") ||
        isInNet(resolved_ip, "6.6.0.0", "255.255.0.0"))
        return "DIRECT";
	
	/* Any other bypass */
	if (shExpMatch(host, "zscaler.com") || shExpMatch(host, "*.zscaler.com")) {
		return "DIRECT";
	}
	
	/* Any other bypass */
	if (shExpMatch(host, "yelp.com") || shExpMatch(host, "*.yelp.com")) {
		return "DIRECT";
	}
	
	/* Updates are directly accessible */
	if ((localHostOrDomainIs(host, "trust.zscaler.com") ||
		localHostOrDomainIs(host, "trust.zscaler.net") ||
		localHostOrDomainIs(host, "trust.zscloud.net") ||
		localHostOrDomainIs(host, "trust.zscalerone.net") ||
		localHostOrDomainIs(host, "trust.zscalertwo.net")) &&
		(url.substring(0,5) == "http:" || url.substring(0,6) == "https:")) {
		return "DIRECT";
	}

	/* Default Traffic Forwarding: All traffic goes to Z-App */
	return "PROXY 127.0.0.1:9000";
}
