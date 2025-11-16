#!/bin/bash

#Student Name - Ron Nisinboym
#Student Code - S11
#Unit Code - TMagen773637
#Program Code - ZX301
#Lecturer Name - Erel Regev

############################
#COLORS AND FONTS:
GC='\e[32m' #GREEN
RC='\e[31m' #RED
CC='\033[0;36m' #CYAN
BOLD='\033[1m' #BOLD
NC='\e[0m' #DEFAULT

#OTHER VARIABLES:
LOCAL_IP=$(hostname -I | xargs) #defines local_ip variable without spaces
service="" #service + version
PORT="" #used to itterate between ports in a later defined array.
MAIN="$(pwd)" #shortcut for pwd
############################

#Function that starts the script
function START()
{
    ROOT_CHECK #calling function to check root
    echo -e "What is the network range to scan?\n(e.g. 192.168.1.0/24) " 
    read network_range
    if [ -z "$network_range" ] || [[ "$network_range" != *.*.*.*/*?* ]]; then #if variable returns empty or with wrong pattern
    echo -e "${RC}Invalid input. Use a format like 192.168.1.1/24${NC}\n"
    START  #restart script
    exit #used to avoid processing all previous instances of START in case of a wrong input
fi

    echo -e "\nPlease choose a name for the output directory: " 
    echo -e "(***Choosing a name of an existing folder in $MAIN will delete the old one***)"
    read dir_name
	if [ -z "$dir_name" ]; then #if variable returns empty(not set)
    	echo -e "${RC}No input was made. Try again.${NC}\n"
    START #start again if wrong input
	elif [ -d "$dir_name" ]; then #if such directory exists
    	rm -rf "$dir_name" #remove
	fi

    mkdir "$dir_name"  #creates defined by user directory
    report_file="$dir_name/full_report.txt" #creates the full_report text file

    DOWNLOAD

    while true; do #letting user to choose scanning level
    	echo ""
        read -p "Please choose a Basic or Full scanning level [B/F]: " LEVEL
        case $LEVEL in
           [bB]*)
                BASIC
                break  #exit the loop 
                ;;
           [fF]*)
                FULL
                break  #exit the loop
                ;;
            *)
                echo -e "${RC}Invalid option, please try again.${NC}" 
                ;;
        esac
    done
}

#Function to check if user is root
function ROOT_CHECK(){
	USER=$(whoami)
	if [ "$USER" != "root" ] #if NOT root.
	then
		echo "You are not root. Exiting.."
		exit
	fi	
}

# Function that lets user define the Brute-Force method that will be applied to all services
function MENU() {
	METHOD=""
	
	while true; do
    echo -e "Please choose a brute-force method that will be used for all services found [CHOOSE A NUMBER]\n\
    [+] 1 - custom username + custom password list\n\
    [+] 2 - custom username + built-in password list\n\
    [+] 3 - custom username list + custom password list\n\
    [+] 4 - custom username list + built-in password list\n\
    [+] 5 - built-in users&password lists\n\
    [+] 0 - Exit"
    
    read -p "Enter your choice: " OPTIONS

    case $OPTIONS in #setting up method choices for each of the menu options to further execute via METHODS function
        1)  #custom username + custom password list
            read -p "Enter username: " USERNAME
            echo "Path to password list: "
            read -e PASS_PATH #read + autocomplete
            
            #checks if the password list file exists
            if [ ! -f "$PASS_PATH" ]; then
  				echo -e "${RC}Error: Password list file not found at '$PASS_PATH', try again.${NC}\n"
  				continue #restarts the loop
			fi
            METHOD="1"
            break #exit loop
            ;;
        2)  #custom username + built-in password list
            read -p "Enter username: " USERNAME
            METHOD="2"
            break #exit loop
            ;;
        3)  #custom username list + custom password list
            echo "Path to users list: "
            read -e USER_PATH #read + autocomplete
            
            #checks if the user list file exists
			if [ ! -f "$USER_PATH" ]; then
  				echo -e "${RC}Error: User list file not found at '$USER_PATH', try again.${NC}\n"
  				continue #restars the loop
			fi
			
            echo "Path to password list: "
            read -e PASS_PATH #read + autocomplete
            
            #checks if the password list file exists
            if [ ! -f "$PASS_PATH" ]; then
  				echo -e "${RC}Error: Password list file not found at '$PASS_PATH', try again.${NC}\n"
  				continue #restarts the loop 
			fi
            METHOD="3"
            break #exit loop
            ;;
        4)  #custom username list + built-in password list
            echo "Path to users list: "
            read -e USER_PATH #read + autocomplete
            
            #checks if the user list file exists
			if [ ! -f "$USER_PATH" ]; then
  				echo -e "${RC}Error: User list file not found at '$USER_PATH', try again.${NC}\n"
  				continue #restarts the loop
			fi
            METHOD="4"
            break #exit loop
            ;;
        5)  #built-in users&password lists
            METHOD="5"
            break #exit loop
            ;;
        0)  
            exit 1
            ;;
        *)  
            echo -e "${RC}Invalid option. Please try again.\n${NC}"
            MENU
            return #used to avoid processing all previous instances of MENU in case of a wrong input
            ;;
    esac

    echo -e "Brute-force method chosen: $METHOD"
    echo -e "Scanning the network, please wait...\n"
    done
}

# Function to check reachable hosts and scan for services + weak password
function BASIC() {
	
	MENU
	
	#checking for reachable hosts | awking for IP only | excluding local-host and VM default IPs(gateway\dhcp)
    nmap $network_range -sn | awk '/Nmap scan report for/ {print $NF}' | grep -Ev "(\.2$|\.254$|^$LOCAL_IP$)" >> "$dir_name/ips.txt"
    
    if [ ! -s "$dir_name/ips.txt" ]; then #if ips.txt returns empty
    	echo -e "${RC}No reachable hosts has been found. Exiting script.${NC}"
    	exit 1
    fi

    for ip in $(cat $dir_name/ips.txt) #for each ip found do the following.
    do
    	mkdir -p $dir_name/$ip #creating file containing list of found ips.
    	echo -e "\n${GC}$ip was found${NC}\n" 
    	echo "==== $ip ====" >> "$report_file" #creating a header for the report file.
    	
		NMAP #NMAP-realated processes
       
		MASSCAN #MASSCAN-realated processes

		METHODS #NSE_BRUTE-related processes
		
    done
    
    echo -e "Showing full report: \n"
    sleep 5 #giving the user time to read the above message
    cat -n $report_file #show report output
    echo -e "\n${CC}This output was saved to $report_file${NC}"
    
    REPORT_SEARCH
    ZIP_RESULTS
}

#Function that runs full scan including mapping vulnerablities
function FULL () {
	
	MENU
	
	#checking for reachable hosts | awking for IP only | excluding local-host and VM default IPs(gateway\dhcp)
    nmap $network_range -sn | awk '/Nmap scan report for/ {print $NF}' | grep -Ev "(\.2$|\.254$|^$LOCAL_IP$)" >> "$dir_name/ips.txt"
    
    if [ ! -s "$dir_name/ips.txt" ]; then #if ips.txt returns empty
    	echo -e "${RC}No reachable hosts has been found. Exiting script.${NC}"
    	exit 1
    fi

    for ip in $(cat $dir_name/ips.txt) #for each ip found do the following
    do
    	
    	mkdir -p $dir_name/$ip #creating file containing list of found ips
    	echo -e "\n${GC}$ip was found${NC}\n" 
    	echo "==== $ip ====" >> "$report_file" #creating a header for the report file
    
		NMAP #NMAP-realated processes
       
		MASSCAN #MASSCAN-realated processes
		
		VULNUDP #NSE_VULN_UDP related processes
		
		VULNTCP #NSE_VULN_TCP-related processes
      
   		SPLOIT #SEARCHSPLOIT-related processes
   		
		METHODS #NSE_BRUTE-related processes
    done
    
    echo -e "Showing full report: \n"
    sleep 5 #giving user time to read the last message
    cat -n $report_file
    echo -e "\n${CC}This output was saved to $report_file${NC}"
    REPORT_SEARCH
    ZIP_RESULTS
        
	
}

#Function that lets the user search for specific strings in the report file
function REPORT_SEARCH() {
	while true; do
	#ask if the user wants to perform a search
	echo "Do you want to search for a specific string in the found results? (y/n): "
	read search_choice

	case "$search_choice" in
	[Yy]*)
		#if user chooses 'y', ask for the string to search for and filter results
		while true; do
		echo "Enter the string to search for: "
		read search_string
		echo -e "Filtered results for '$search_string':\n"
		grep -i -n "$search_string" $dir_name/full_report.txt

		#ask if the user wants to search again
		while true; do
		echo -e "\nDo you want to search again? (y/n): "
		read search_again

		#check for valid input in additional searches (y/n)
		case "$search_again" in
		
		[Yy]*)
			#continue searching if 'y' is chosen
			break  # Break out of this inner loop, continue searching
		
		;;
		
		[Nn]*)
			#break out and return to menu if 'n' is chosen
			echo -e "Exiting search."
			return
		
		;;
		
		*)
			#if invalid input prompt 
			echo -e "${RC}Invalid input. Please enter 'y' or 'n'.${NC}\n"
		
		;;
		
		esac
		done
		done
		
		;;
		
		[Nn]*)
				#if user chooses 'n' in the starting question, skip the search and return to the menu
				echo -e "Exiting search."
				return
				
		;;
		
		*)
			#if invalid input for the starting question, ask again
			echo -e "${RC}Invalid input. Please enter 'y' or 'n'.${NC}\n"
				
		;;
		
	esac
	done
}


#Function to zip all result folder + report.txt. 
function ZIP_RESULTS (){
		echo ""
		read -p "Would you like to save the results into a ZIP-file?(y/n)" ZIP_CHOICE
		
		case $ZIP_CHOICE in
			[Yy]*)
				echo -e "ZIPPING your files, please wait!"
				timestamp=$(date +%Y%m%d_%H%M%S) #current time
				zip -rq "$dir_name"_"$timestamp".zip $dir_name/ #zip the folder without terminal output
				echo -e "${CC}ZIP file was saved to $MAIN/$dir_name"_"$timestamp${NC}\n"
				echo -e "Exiting script. May the Force be with you."
				exit 1
			;;
	
			[Nn]*)
				echo -e "Exiting script. May the Force be with you."	
				exit 1
			;;
	
			*)
				#If invalid input for the starting question, ask again
				echo -e "${RC}Invalid input. Please enter 'y' or 'n'.${NC}\n"
				ZIP_RESULTS
			
			;;
		
		esac
}

#Function to download username and password lists for the script.
function DOWNLOAD () {
    echo -e "\nChecking for username/password lists in $MAIN..."

    #checks if the password list is missing
    if [ ! -f $MAIN/10k-most-common-passwords.txt ]; then
        echo "Downloading 10k-most-common-passwords.txt..."
        #download file from github, hide output.
        wget https://github.com/CookieBotXL/Weak_Passwords/raw/refs/heads/main/10k-most-common-passwords.txt -P $MAIN/ > /dev/null 2>&1
        echo -e "${GC}10k-most-common-passwords.txt has been downloaded successfully${NC}"
    else
        echo "10k-most-common-passwords.txt exists. Skipping download."
    fi

    #checks if the username file is missing
    if [ ! -f $MAIN/top-usernames-shortlist.txt ]; then
        echo "Downloading top-usernames-shortlist.txt..."
        #download file from github, hide output.
        wget https://github.com/CookieBotXL/Weak_Passwords/raw/refs/heads/main/top-usernames-shortlist.txt -P $MAIN/ > /dev/null 2>&1
        echo -e "${GC}top-usernames-shortlist.txt has been downloaded successfully${NC}"
    else
        echo -e "top-usernames-shortlist.txt exists. Skipping download."
    fi
}

#Function to scan for TCP ports
function NMAP (){
    	echo -e "Using nmap to check for reachable TCP ports. Please wait..."
        nmap $ip -sV -oN $dir_name/$ip/nmap_results.txt > /dev/null 2>&1 #run nmap + versions and save to file
        echo -e "==== NMAP ====" >> "$report_file" #header
        cat $dir_name/$ip/nmap_results.txt >> $report_file #add to report
        echo -e "===============\n" >> $report_file #footer
        echo -e "${CC}nmap complete. The output was saved to $dir_name/$ip/nmap_results.txt${NC}"
}

#Function to scan for UDP ports
function MASSCAN () {
	    echo -e "\nUsing masscan to check for reachable UDP ports. Please wait..."
		masscan $ip -pU:1-65535 --rate 10000 2>/dev/null >> $dir_name/$ip/masscan_results.txt #run masscan and save to file
		echo -e "==== MASSCAN ====" >> "$report_file" #header
		cat $dir_name/$ip/masscan_results.txt >> $report_file #add to report
		echo -e "===============\n" >> $report_file #footer
		echo -e "${CC}masscan complete. The output was saved to $dir_name/$ip/masscan_results.txt${NC}\n"
}

#Function to run searchsploit to find vulnerable services and save data.
function SPLOIT () {
		#awking only the version of each service from nmap + removing empty lines
     	grep 'open' $dir_name/$ip/nmap_results.txt | awk '{ $1=$2=$3=""; print $0}' >> $dir_name/$ip/versions.txt
		sed -i '/^\s*$/d' $dir_name/$ip/versions.txt
		
		echo -e "\nRunning searchsploit against the found services. Please wait..."
   		echo -e "==== SEARCHSPLOIT ====" >> "$report_file" #header
	   	IFS=$'\n' #setting the internal field separator to split input by lines only.
		for service in $(cat $dir_name/$ip/versions.txt); do
    {
        echo "===== $service =====" #header
        #running searchsploit against every serivce version found earlier
        searchsploit "$service" | grep -v -E '(Exploits: No Results|Shellcodes: No Results)' 
        echo ""
    } | sudo tee -a $dir_name/$ip/sploit_results.txt > /dev/null #writing output to file.
    	
		done
		echo "SEARCHSPLOIT:" 
		cat "$dir_name/$ip/sploit_results.txt"
		echo ""
		unset IFS #resets the internal field seperator to default.
		echo -e "${CC}searchsploit complete. The output was saved to $dir_name/$ip/sploit_results.txt${NC}\n"
   		cat $dir_name/$ip/sploit_results.txt >> $report_file #add to report
    	echo -e "===============\n" >> $report_file #footer
}

#Function to run TCP .NSE vulners script on each found host
function VULNTCP () {
	
		echo "Searching for known TCP vulnerabilities. Please wait..."
		nmap $ip --script=vulners.nse -sV -oN "$dir_name/$ip/NSE_TCPvuln.txt" > /dev/null 2>&1 #run vulners script and save to file
		echo -e "==== NSE_vulnerabilities_TCP ====" >> "$report_file" #header
		awk '{print $1, $2, $3, $5}' "$dir_name/$ip/NSE_TCPvuln.txt" | tee -a "$report_file" #text-manipulation on the output + adding to report.
		echo -e "${CC}Vulnerabilites scan for TCP ports is complete. Results saved to $dir_name/$ip/NSE_TCPvuln.txt${NC}\n"
		echo -e "===============\n" >> $report_file #footer
}

#Function to run UDP .NSE vulners script on each found host
function VULNUDP () {
    echo "Searching for known vulnerabilities on UDP ports. Please wait..."
    
    IFS=$'\n' #sets IFS to newline to split input correctly
    #loops through each line in masscan_results.txt
    for line in $(cat "$dir_name/$ip/masscan_results.txt"); do
        #extracts the UDP port number from each line
        port=$(echo "$line" | grep -oP '\d+/udp' | cut -d'/' -f1)
        
        #if a valid port is found, run Nmap for vulnerabilities
        if [[ ! -z "$port" ]]; then
            echo "Running Nmap for UDP port $port..."
            
            #runs the Nmap scan using the vulners script and save the results
            sudo nmap -sU -p $port -sV $ip --script=vulners >> "$dir_name/$ip/NSE_UDPvuln.txt" 2>&1     
        fi
    done
    
    unset IFS #unsets IFS to restore default behavior
 
        #adds results to the report
        echo -e "==== NSE_vulnerabilities_UDP ====" >> "$report_file" #header
       	awk '{print $1, $2, $3, $5}' "$dir_name/$ip/NSE_UDPvuln.txt" | tee -a "$report_file" #text-manipulation on the output + adding to report.
        echo -e "===============\n" >> "$report_file" #footer
    	
    echo -e "${CC}Vulnerability scan for UDP ports is complete. Results saved to $dir_name/$ip/NSE_UDPvuln.txt${NC}\n"
}

#Function to use different brute-force methods, against every found service
function METHODS () {
		LOGIN_SERVICES="ssh ftp telnet rdp" #string of services to itterate through
        declare -A SERVICE_PORTS=( ["ftp"]=21 ["ssh"]=22 ["telnet"]=23 ["rdp"]=3389 ) #array of ports for each service.
        
		echo -e "Checking for weak passwords against common services. Please wait...\n"
        echo -e "==== BRUTE_NSE ====" >> "$report_file" #header
        for service in $LOGIN_SERVICES #loop through each service and check if it is found in the nmap results
        do
            if grep -q "$service" $dir_name/$ip/nmap_results.txt; then #if service was found
                echo -e "${GC}$service found, checking for weak passwords...${NC}\n"

                PORT=${SERVICE_PORTS[$service]} #define PORT with the corrospnding one from the previously defined array

                # applying the selected brute-force method in the menu stage.
                case $METHOD in
                    1) 
                    	#custom username + custom password list
                        echo "$USERNAME" > /tmp/single_user.txt #temporary user-defined username
                        nmap -p"$PORT" --script "$service"-brute.nse --script-args userdb=/tmp/single_user.txt,passdb=$PASS_PATH $ip -oN $dir_name/$ip/${service}_brute.txt > /dev/null 2>&1
                        cat "$dir_name/$ip/${service}_brute.txt" >> $report_file
                        grep -i -B 4 "valid" "$dir_name/$ip/${service}_brute.txt" #grep only "valid" occurences + 4 lines prior to it.
                        echo ""
                        rm /tmp/single_user.txt #remove user-defined username
                        echo -e "${CC}$service scan for weak-passwords complete. The output was saved to $dir_name/$ip/${service}_brute.txt${NC}\n"
                        ;;
                    2)  
                    	#custom username + built-in password list
                        echo "$USERNAME" > /tmp/single_user.txt #temporary user-defined username
                        nmap -p"$PORT" --script "$service"-brute.nse --script-args userdb=/tmp/single_user.txt,passdb=./10k-most-common-passwords.txt $ip -oN $dir_name/$ip/${service}_brute.txt > /dev/null 2>&1
                        cat "$dir_name/$ip/${service}_brute.txt" >> $report_file
                        rm /tmp/single_user.txt #remove user-defined username
                        grep -i -B 4 "valid" "$dir_name/$ip/${service}_brute.txt" #grep only "valid" occurences + 4 lines prior to it.
                        echo ""
                        echo -e "${CC}$service scan for weak-passwords complete. The output was saved to $dir_name/$ip/${service}_brute.txt${NC}\n"
                        ;;
                    3)  
                    	#custom username list + custom password list
                        nmap -p"$PORT" --script "$service"-brute.nse --script-args userdb=$USER_PATH,passdb=$PASS_PATH $ip -oN $dir_name/$ip/${service}_brute.txt > /dev/null 2>&1
                        cat "$dir_name/$ip/${service}_brute.txt" >> $report_file
                        grep -i -B 4 "valid" "$dir_name/$ip/${service}_brute.txt" #grep only "valid" occurences + 4 lines prior to it.
                        echo ""
                        echo -e "${CC}$service scan for weak-passwords complete. The output was saved to $dir_name/$ip/${service}_brute.txt${NC}\n"
                        ;;
                    4)  
                    	#custom username list + built-in password list
                        nmap -p"$PORT" --script "$service"-brute.nse --script-args userdb=$USER_PATH,passdb=./10k-most-common-passwords.txt $ip -oN $dir_name/$ip/${service}_brute.txt > /dev/null 2>&1
                        cat "$dir_name/$ip/${service}_brute.txt" >> $report_file
                        grep -i -B 4 "valid" "$dir_name/$ip/${service}_brute.txt" #grep only "valid" occurences + 4 lines prior to it.
                        echo ""
                        echo -e "${CC}$service scan for weak-passwords complete. The output was saved to $dir_name/$ip/${service}_brute.txt${NC}\n"
                        ;;
                    5)  
                    	#built-in users&password lists
                        nmap -p"$PORT" --script "$service"-brute.nse --script-args userdb=top-usernames-shortlist.txt,passdb=./10k-most-common-passwords.txt $ip -oN $dir_name/$ip/${service}_brute.txt > /dev/null 2>&1
                        cat "$dir_name/$ip/${service}_brute.txt" >> $report_file
                        grep -i -B 4 "valid" "$dir_name/$ip/${service}_brute.txt" #grep only "valid" occurences + 4 lines prior to it.
                        echo ""
                        echo -e "${CC}$service scan for weak-passwords complete. The output was saved to $dir_name/$ip/${service}_brute.txt${NC}\n"
                        ;;
                esac	
            else
                echo -e "${RC}$service not found.${NC}\n"
            fi
        done
}

START
