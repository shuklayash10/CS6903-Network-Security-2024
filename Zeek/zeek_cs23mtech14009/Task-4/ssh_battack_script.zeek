# Here I am createing dictonary like datasturcutre for saving attempts and ip
global login_attempts_map: table[addr] of count = table();

# attempts thersold
const limit_for_login_attempts = 6;
global total_failed_attempts : count = 0;
global total_sucessufull_login : count = 0;
global cnt :count =0 ;

# Event handler for SSH authentication attempts
event ssh_auth_result(c: connection, result: bool, auth_attempts: count)
{
	
    local SIP_addr = c$id$orig_h;
    cnt+=1;

    if (cnt%10==0){
	print fmt("total number of attempts failed %d succssfull %d",total_failed_attempts,total_sucessufull_login);	
	}
    if (result)
    {
	total_sucessufull_login+=1;
        delete login_attempts_map[SIP_addr];
    }
	else
        {
	    total_failed_attempts +=1; 

            if (SIP_addr in login_attempts_map)
                login_attempts_map[SIP_addr] += 1;
            else
                login_attempts_map[SIP_addr] = 1;

            # no  of failed attempts exceeds the threshold
            if (login_attempts_map[SIP_addr] >= limit_for_login_attempts)
            {
                # Log the potential brute force attack
                local log = fmt("SSH brute force attack might happened from %s. Failed attempts: %d. name Raj Popat , Eno cs23mtech14009", SIP_addr, login_attempts_map[SIP_addr]);
                print log;
		delete login_attempts_map[SIP_addr];
            }
        }
    }

