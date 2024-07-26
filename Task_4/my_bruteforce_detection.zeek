@load base/protocols/ssh

# Dictionary to store <IP:count> pairs
global connection_attempts_dict: table[addr] of count = table();

# Threshold considered for identifying the brute force attack
global threshold: count;

# Gets called during initialization
event zeek_init() {
    print("");
    threshold = 5;
    print fmt("********** Considering threshold of %d attempts for identifying SSH brute force attacks **********", threshold);
    print("");
}

# Event that gets triggrred on each SSH connection attempt
event ssh_auth_attempted(conn: connection, authenticated: bool) {
    
    # If the connection attempt was unsuccessful
    if (!authenticated) {

        local source_host_ip = conn$id$orig_h; 
        local dest_host_ip = conn$id$resp_h;
        
        # Increased the count of unsuccessful attempts for 'source IP' in dictionary
        connection_attempts_dict[source_host_ip] = !(source_host_ip in connection_attempts_dict) ? 1 : connection_attempts_dict[source_host_ip] + 1;

        # Checking whether threshold is exceeded or not
        if (threshold <= connection_attempts_dict[source_host_ip]) {

            local line1 = fmt("Identified bruteforce attack from source IP: %s to dest IP: %s, Number of failed connection attempts: %d, ", source_host_ip, dest_host_ip, connection_attempts_dict[source_host_ip]);
            local line2 = fmt("Analyzed by: Mayuresh Dindorkar (Roll No: CS23MTECH14007)");
            print line1 + line2;

            # Resetting the count
            connection_attempts_dict[source_host_ip] = 0;
        }
    }
}

# Called on end
event zeek_done() {
    print("");
    print fmt("********** Successfully analyzed the pcap for SSH bruteforce attacks **********");
    print("");
}

