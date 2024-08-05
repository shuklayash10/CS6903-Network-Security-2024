# zeek start

event zeek_init()
        {
        print "Here We go ->>>>>>>>>>>>>>>>>";
        }

# zeek end

event zeek_done()
        {

        print "Double BAM! we reached <<<<<<<<<<<<-";
        }

# here we are using the ssl_established event from the ssl events where it takes connection c as argument.

global num_of_ss_certi : count = 0;
global num_of_nss_certi : count = 0;

event ssl_established(c: connection) {

    # Retrieve the SSL certificate chain
    local chain_of_certi = c$ssl$cert_chain;

    # Check if the certificate chain is not empty
    if (|chain_of_certi| > 0) {
        # Retrieve the first certificate from the chain
        local cert = chain_of_certi[0];

	if (|cert$x509$certificate$issuer| < 0){
	print "Invalide issuer for the given certificate";
	}


	if (|cert$x509$certificate$subject| < 0){
	print "Invalide subject name for the given certificate";
	}

	

	if (cert$x509$certificate$issuer != cert$x509$certificate$subject){
	num_of_nss_certi +=1;
	}
        # Check if the certificate is self-signed
        if (cert$x509$certificate$issuer == cert$x509$certificate$subject) {
            # Print a message indicating a self-signed certificate is detected
	    num_of_ss_certi+=1; 
            # Print the subject of the certificate

            print "Certificate Owner name and Issuer name";
            print cert$x509$certificate$subject;
            print cert$x509$certificate$issuer;
            print "-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x";
	    
            print "---->";
            print fmt("Self-signed certificate for the connection: %s", c$id$orig_h);
	    print fmt("till  total number of self-signed certificates found is %d and others are %d",num_of_ss_certi,num_of_nss_certi );
            print "<----";

        }
    }
}
