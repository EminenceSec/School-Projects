#!/bin/bash

# Function to scan for open TCP ports on a network
function BASIC_SCAN {
    echo "Starting Basic Scanning..."
    echo "Scanning for open TCP ports, please wait..."
    
	# Run a comprehensive Nmap scan and save the output
    nmap -Pn -T4 "$target_network" -oN nmap_res.txt > /dev/null 2>&1

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


# Basic Enumeration Function: This runs nmap's service version enumeration on the previously found open ports.
function BASIC_ENUM {
    # Define the file that contains IPs and open ports
    input_file="nmap_hosts_with_ports.txt"

    # Start the header for service version enumeration in the log file
    echo -e "\n==== Nmap service version enumeration results ====\n" >> "$log_file"

    # Read each line of the file containing IP and ports
    while IFS= read -r line; do
        # Extract the IP and open ports
        ip=$(echo $line | awk '{print $1}' | sed 's/://')  # Remove colon from the IP
        ports=$(echo $line | awk '{print $2}')

        # Run nmap for service version detection if ports are non-empty
        echo "Scanning $ip on ports $ports..."
        nmap -sV -p $ports $ip -oN "$results_dir/port_versions_${ip}.txt" > /dev/null 2>&1
        # Append the results of the nmap scan to the log file
        cat "$results_dir/port_versions_${ip}.txt" >> "$log_file"
    done < "$input_file"

    # End the service version enumeration section in the log file
    echo -e "\n==== End of service version enumeration ====\n" >> "$log_file"
    
    # Initialize arrays to store the IPs of Domain Controllers and DHCP servers
    domain_controllers=()
    dhcp_servers=()

    # Loop through each result file to detect Domain Controllers and DHCP servers
    for file in $results_dir/port_versions_*.txt; do
        ip=$(basename "$file" | sed 's/port_versions_\(.*\)\.txt/\1/')

        # Initialize flags for Domain Controller and DHCP server detection
        domain_controller_found=false
        dhcp_server_found=false

        # Check for the presence of Domain Controller signatures (e.g., ldap, kerberos, active directory)
        if grep -qiE "ldap|kerberos|active directory|microsoft-ds|samba" "$file"; then
            domain_controller_found=true
        fi

        # Check for the presence of DHCP server signature
        if grep -qi "dhcp" "$file"; then
            dhcp_server_found=true
        fi

        # Store the IP in respective arrays if found
        if $domain_controller_found; then
            domain_controllers+=("$ip")
        fi

        if $dhcp_server_found; then
            dhcp_servers+=("$ip")
        fi
    done

    # Export arrays as environment variables to be accessed by the parent script
    export DOMAIN_CONTROLLERS="${domain_controllers[*]}"
    export DHCP_SERVERS="${dhcp_servers[*]}"

    # Print out the found Domain Controllers and DHCP servers
    if [ ${#domain_controllers[@]} -gt 0 ]; then # If array greater than 0
        echo -e "\n${GC}Domain Controllers found: ${domain_controllers[*]}${NC}\n"
    else
        echo -e "\nNo Domain Controllers found.\n"
    fi

    if [ ${#dhcp_servers[@]} -gt 0 ]; then # If array greater than 0
        echo -e "\n${GC}DHCP servers found: ${dhcp_servers[*]}${NC}\n"
    else
        echo -e "No DHCP servers found.\n"
    fi

    echo "Service version discovery completed."
}


# Basic Exploitation Function: This performs vulnerability scanning on identified IPs (Domain Controllers/DHCP Servers).
function BASIC_EXPLOIT {
    # Start the vulnerability scan section in the log file
    echo -e "\n==== Nmap vulnerability scan results ====\n" >> "$log_file"

    # Loop through Domain Controllers and DHCP Servers to find their matching IPs in the output file
    for ip in $DOMAIN_CONTROLLERS $DHCP_SERVERS; do
        # Check if the IP exists in the file that contains open ports
        if grep -q "$ip:" "nmap_hosts_with_ports.txt"; then
            # Extract the open ports for the matching IP
            ports=$(grep "open" nmap_res.txt | cut -d '/' -f 1 | tr '\n' ',')
            
            # Run Nmap with the NSE (Nmap Scripting Engine) "vulners" script to scan for vulnerabilities
            echo -e "\nRunning NSE vulners for IP: $ip on ports: $ports"
            nmap -p $ports --script=vuln "$ip" -oN "$results_dir/nmap_vuln_scan_${ip}.txt" > /dev/null 2>&1
            # Append the scan results to the log file
            cat "$results_dir/nmap_vuln_scan_${ip}.txt" >> "$log_file"
        else
            echo "IP $ip not found in nmap_hosts_with_ports.txt"
        fi
    done
    
    echo "Scanning complete."
    
    # End the vulnerability scan section in the log file
    echo -e "\n==== End of vulnerability scan results ====\n" >> "$log_file"
   
}
