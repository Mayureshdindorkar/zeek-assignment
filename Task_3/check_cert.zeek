@load base/protocols/ssl
@load base/files/x509

# Gets called during initialization
event zeek_init() {
    print("");
    print fmt("********** Zeek script started **********");
    print("");
}

event ssl_established(c: connection) {    
		
	local source_ip = c$id$orig_h;
	local dest_ip = c$id$resp_h;
	
	# If certificate does not contain chain
	if (!c?$ssl || !c$ssl?$cert_chain)
    {
        return;
    }
	
	local end_entity_certificate = c$ssl$cert_chain[0]$x509$certificate;
    if (end_entity_certificate$cn != "*.badssl.com") {
	    print("Certificate does not belong to 'badssl.com'");
	    return;
	}
    
    if (end_entity_certificate$issuer == end_entity_certificate$subject) {
        print fmt("Destination 'badssl.com': %s has a self-signed certificate", dest_ip);
    }
}

# Called on end
event zeek_done() {
    print("");
    print fmt("*********** Zeek script ended ***********");
    print("");
}

