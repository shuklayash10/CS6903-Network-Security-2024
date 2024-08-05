	@load base/protocols/ssh

# no of failed  SSH attempts before considering it a brute force attack
const ssh_brute_force_threshold = 5;

# Define a table to store the number of failed SSH attempts per source IP
global ssh_failed_attempts: table[addr] of count = table();

# Event handler for SSH authentication attempts
event ssh_auth_result(c: connection, result: bool, auth_attempts: count)
{
    local src_ip = c$id$orig_h;

    if (auth_attempts > 0)
    {
        if (auth_attempts == 1)
        {
            # Clear the failed attempt count for this source IP
            delete ssh_failed_attempts[src_ip];
        }
        else
        {
            # Increasing the failed attempt count for the source IP
            if (src_ip in ssh_failed_attempts)
                ssh_failed_attempts[src_ip] += 1;
            else
                ssh_failed_attempts[src_ip] = 1;

            # no  of failed attempts exceeds the threshold
            if (ssh_failed_attempts[src_ip] >= ssh_brute_force_threshold)
            {
                # Log the potential brute force attack
                local log_entry = fmt("Here is the Potential SSH brute force attack happened from %s. Failed attempts: %d.through Yash Shukla , RN cs23mtech14018", src_ip, ssh_failed_attempts[src_ip]);
                print log_entry;

                # no of the failed attempt count for this source IP
                delete ssh_failed_attempts[src_ip];
            }
        }
    }
}
