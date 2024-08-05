@load base/protocols/ssl

# Log SSL certificate details during the handshake
event ssl_established(c: connection) {
  
        local cert_chain = c$ssl$cert_chain;
        
        # Check if the certificate chain contains at least one certificate
        if (|cert_chain| > 0) {
            local cert = cert_chain[0];
		
		print cert$x509$certificate$subject;

		  # Check if the certificate is self-signed
            if (cert$x509$certificate$issuer == cert$x509$certificate$subject) {
                print fmt("Self-signed certificate detected for %s: %s", c$id$orig_h, cert$x509$certificate$subject);
            }            
            # Print specific fields of the SSL certificate
            #print "Certificate Details:";
            #print fmt("    Subject: %s", cert$subject);
            #print fmt("    Issuer: %s", cert$issuer);
            #print fmt("    Valid From: %s", cert$not_valid_before);
            #print fmt("    Valid Until: %s", cert$not_valid_after);
            #print fmt("    Serial Number: %s", cert$serial);
            #print fmt("    Signature Algorithm: %s", cert$signature_algorithm);
            # Add more fields as needed
        }
    }

