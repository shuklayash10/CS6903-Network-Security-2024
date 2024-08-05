# Define a new event handler for SSL certificates
event ssl_established(c: connection) {
    local cert_chain = c$ssl$cert_chain;

    # Check if the certificate is self-signed
    if (|cert_chain| > 0) {
        local server_cert = cert_chain[|cert_chain| - 1];
        if (server_cert$issuer == server_cert$subject) {
            print fmt("Self-signed certificate detected: %s", server_cert$subject);
        }
    }
}
