@load base/protocols/ssh

# Define the maximum number of failed SSH attempts before considering it a brute force attack
const ssh_brute_force_threshold = 5;

# Define a table to store the number of failed SSH attempts per source IP
global ssh_failed_attempts: table[addr] of count = table();

# Event handler for SSH authentication attempts
event ssh_encrypted_packet(c: connection, is_encrypted: bool, ssh_version: count, auth_attempts: count)
{
    local src_ip = c$id$orig_h;

    if (is_encrypted && auth_attempts > 0)
    {
        if (auth_attempts == 1)
        {
            # Clear the failed attempt count for this source IP
            delete ssh_failed_attempts[src_ip];
        }
        else
        {
            # Increment the failed attempt count for the source IP
            if (src_ip in ssh_failed_attempts)
                ssh_failed_attempts[src_ip] += 1;
            else
                ssh_failed_attempts[src_ip] = 1;

            # Check if the number of failed attempts exceeds the threshold
            if (ssh_failed_attempts[src_ip] >= ssh_brute_force_threshold)
            {
                # Log the potential brute force attack
                local log_entry = fmt("Potential SSH brute force attack from %s. Failed attempts: %d. Name: Arjit Banerjee, Roll No: 1901CS22", src_ip, ssh_failed_attempts[src_ip]);
                print log_entry;

                # Clear the failed attempt count for this source IP
                delete ssh_failed_attempts[src_ip];
            }
        }
    }
}
