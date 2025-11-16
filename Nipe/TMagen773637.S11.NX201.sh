#!/bin/bash

#Student Name - Ron Nisinboym
#Student Code - S11
#Unit Code - TMagen773637
#Program Code - NX201
#Lecturer Name - Erel Regev

################################
#Global variables:
#Used for folders and files -
HOME=$PWD #home variable for later uses.
TOOL=$HOME/NR_Project # main directory to save the results. for later use. thats why we declare it as a variable.

#Used for Colors&Fonts -
GREEN="\e[0;32m"
RED="\e[31m" 
CYAN="\e[0;36m"
BOLD="\e[1m"
STOP="\e[0m" #Default

#Used to save cURL and GeoIPLookup responses
IP=""
COUNTRY=""

#Array for dependencies
REMOTE_REQUIREMENTS=("tor" "curl" "cpanminus" "git" "geoip-bin" "openssh-client" "sshpass")
################################

#function that start the script
function START() {
	ROOT_CHECK
	figlet -f small "Network Research"
	mkdir -p $TOOL
	
	CLEAR_RESULTS

	NIPE
}

#function that checks if user is root
function ROOT_CHECK(){
	USER=$(whoami)
	if [ "$USER" != "root" ] #if NOT root.
	then
		echo "You are not root. Exiting.."
		exit
	fi	
}

#function that checks if Nipe is installed and starting the service.
function NIPE() {
    if [ ! -d $TOOL/nipe ]; then  # Check if Nipe is installed
        echo -e "${CYAN}[+] Nipe is not installed - checking dependencies...${STOP}" 
        INSTALL_NIPE  #Call the install function
    else
        while true; do  #Start an infinite loop that will keep checking until you're anonymous
            cd $TOOL/nipe #Moving to nipes directory to execute nipe restart.
            echo -e "Nipe folder located, attempting to start Nipe..."
            #Restarting the nipe service
            sudo perl nipe.pl restart  # Restart nipe
            sleep 5  # waits for nipes restart before trying again

            #Re-check anonymity
         	#Update the IP and COUNTRY variables after restart
           	IP=$(curl -s ifconfig.me)
           	#Check if IP is defined and not empty to prevent geolookup errors.
			if [ -z "$IP" ]; then
    		echo -e "${RED}[+] IP address could not be retrieved. Trying again...${STOP}\n"
    		continue  # Exit the script if IP is not defined
			fi
           COUNTRY=$(geoiplookup $IP | awk {'print $4'} | sed 's/,//')
            #Check if COUNTRY is empty (meaning curl failed or returned empty)
            if [ -z "$COUNTRY" ]; then
                #If COUNTRY is empty, treat it as if not anonymous
                echo -e "${RED}[+] Country lookup failed. You're not anonymous!${STOP}\n"
            elif [ "$COUNTRY" != "IL" ]; then
                #If COUNTRY is not Israel (IL), user is anonymous
                echo -e "\n${GREEN}[+] You are anonymous!${STOP}"
                DISPLAY_SPOOFED_COUNTRY
                SSH_PASS
                break  #Exit the loop once user is anonymous
            else
                #If COUNTRY is IL, user is not anonymous
                echo -e "${RED}[+] Country is still $COUNTRY, trying again!{STOP}\n"
            fi
        done
    fi
}

#function that installs nipe and relevant apps
function INSTALL_NIPE()
{	
	#Installing dependencies including TOR
	INSTALL_DEPENDENCIES
	echo -e "${GREEN}[+] All dependencies has been installed, proceeding to Nipe...${STOP}"
	
	#Cloning and installing nipe:
	echo "[#] Cloning Nipe..."
	cd $TOOL #Navigating to the main directory we created
	git clone https://github.com/htrgouvea/nipe.git > /dev/null 2>&1 #Clone nipe to the system
	sudo cpanm install Try::Tiny Config::Simple JSON > /dev/null 2>&1 #Installs different Perl modules needed for Nipe
	echo "[#] Installing Nipe..."
	sudo perl ./nipe/nipe.pl install -y > /dev/null 2>&1 #default installation command of nipe (check github)
	echo -e "${GREEN}[#] Nipe was installed successfuly.${STOP}\n"
	NIPE #Call the nipe function
}

#function that installs different dependencies for a network research
function INSTALL_DEPENDENCIES(){
for package_name in "${REMOTE_REQUIREMENTS[@]}" #using @ to call each element in the given array separtely.
do
dpkg -s "$package_name" >/dev/null 2>&1
    if ! dpkg -s "$package_name" >/dev/null 2>&1; then
		echo -e "[#] $package_name not found. Installing..."
      #If the package is not installed, install it
      sudo apt-get install "$package_name" -y >/dev/null 2>&1
      echo -e "${GREEN}[#] $package_name was successfuly installed!${STOP}\n"
    else
      #If the package is already installed, print a message
      echo -e "${GREEN}[#] $package_name is already installed!${STOP}\n"
    fi
  done
}

#function that displays Nipe status, new ip and the location of that ip
function DISPLAY_SPOOFED_COUNTRY(){
STATUS=$(sudo perl nipe.pl status) #returns status and current external ip and saves into a variable
echo "$STATUS"
LOCATION=$(geoiplookup $IP) #reutrns country name and code.
echo "[+] Your current IP located in: $(echo $LOCATION | awk '{print $4, $5}')" #clearing unnecessary text with awk.
	
}

#function that connects user to a remote host via SSH and runs different commands
function SSH_PASS (){
echo ""
echo -e "${CYAN}PAY ATTENTION! Proceeding with this stage will execute the following steps using SSH:\n [#]Attempt connection to remote host\n [#]Attempt installing research tools if missing\n [#]Attempt to gather information${STOP}\n"
read -p "Please type the username for the remote server:" ssh_user
read -s -p "Please provide the password for the user of the remote server:" ssh_pass
echo ""
read -p "Please provide the IP address of the remote server:" ssh_ip
TARGET_ADDRESS="$ssh_user"@"$ssh_ip"


#SSH into the remote server and execute commands:
#When connected to SSH, automatically try to install nmap\whois\curl on the remote host and hide output
#using different options to bypass secuirty checks
#Using -t to be able to run sudo
sshpass -p "$ssh_pass" ssh -o "StrictHostKeyChecking=no" -o "UserKnownHostsFile=/dev/null" -o "IdentitiesOnly yes" -o "LogLevel=QUIET" -t "$TARGET_ADDRESS" "export ssh_pass='$ssh_pass'; echo \$ssh_pass | sudo -S apt-get install -y nmap whois curl > /dev/null 2>&1"
#Connects to SSH and starts a heredoc for running commands
sshpass -p "$ssh_pass" ssh -o "StrictHostKeyChecking=no" -o "UserKnownHostsFile=/dev/null" -o "IdentitiesOnly yes" -o "LogLevel=QUIET" "$TARGET_ADDRESS" << 'SSH_COMMANDS' 
#Global Variables for sshpass:
GREEN="\e[0;32m" # color code for green
STOP="\e[0m" # color code to end the "painting".
REMOTE_LOCAL_IP=$(hostname -I | awk '{print $1}')
REMOTE_EXTERNAL_IP=$(curl -s https://ifconfig.me)

#Creating output folder on remote host(will be deleted after copied to local machine)
mkdir -p /home/$USER/Desktop/OUTPUT_FILES

#Variables for each output file:
CURL_FILE="/home/$USER/Desktop/OUTPUT_FILES/curl_output.txt"
UPTIME_FILE="/home/$USER/Desktop/OUTPUT_FILES/uptime_output.txt"
COUNTRY_FILE="/home/$USER/Desktop/OUTPUT_FILES/country_output.txt"
WHOIS_FILE="/home/$USER/Desktop/OUTPUT_FILES/whois_output.txt"
NMAP_FILE="/home/$USER/Desktop/OUTPUT_FILES/nmap_output.txt"


#Successfully connected message
echo ""
echo -e "${GREEN}Successfully connected! Gathering information...${STOP}"

#Gather info:

#1 Fetch the local IP address of the server and save it to a file
echo -e "\n# Remote Server Local IP" | tee -a $CURL_FILE
echo $REMOTE_LOCAL_IP | tee -a $CURL_FILE

#2 Fetch the External IP address of the server and save it to a file
echo -e "\n# Remote Server External IP" | tee -a $CURL_FILE
echo $REMOTE_EXTERNAL_IP | tee -a $CURL_FILE

#3 Get country information based on the remote server's external IP and save it to its own file
COUNTRY=$(curl -s "http://ip-api.com/json/$REMOTE_EXTERNAL_IP?fields=countryCode" | awk -F'"countryCode":"' '{print $2}' | awk -F'"' '{print $1}')
echo -e "\n# Remote Server Country" | tee $COUNTRY_FILE
echo $COUNTRY | tee -a $COUNTRY_FILE

#4 Get uptime of the remote server and save it to its own file
UPTIME=$(uptime -p)
echo -e "\n# Remote Server Uptime" | tee $UPTIME_FILE
echo $UPTIME | tee -a $UPTIME_FILE

#5 Perform a Whois lookup using the local IP and save it to its own file
echo -e "\n# Whois lookup for local IP $REMOTE_EXTERNAL_IP" >> $WHOIS_FILE
whois $REMOTE_EXTERNAL_IP >> $WHOIS_FILE 2>&1

#6 Scan open ports on the local IP of the server and save the result to its own file
echo -e "\n# Scanning open ports on the remote server ($REMOTE_LOCAL_IP)" >> $NMAP_FILE
nmap $REMOTE_LOCAL_IP >> $NMAP_FILE 2>&1

SSH_COMMANDS

#Checks If SSH connection was successful based on the resault of the last command before the "heredoc" starts.
if [ $? -eq 0 ]; then

#Notifying user prior to copying the files via scp.
echo ""
echo "[+] Copying the output files to your local machine..."

#Copying the files from the remote server to local machine with scp. Using -r to recursively copy all the files. 
sshpass -p "$ssh_pass" scp -o "StrictHostKeyChecking=no" -o "UserKnownHostsFile=/dev/null" -o "IdentitiesOnly yes" -o "LogLevel=QUIET" -r "$TARGET_ADDRESS":/home/"$ssh_user"/Desktop/OUTPUT_FILES "$TOOL/"

#Deleting the files from the remote machine.
sshpass -p "$ssh_pass" ssh -o "StrictHostKeyChecking=no" -o "UserKnownHostsFile=/dev/null" -o "IdentitiesOnly yes" -o "LogLevel=QUIET" "$TARGET_ADDRESS" "rm -rf /home/$ssh_user/Desktop/OUTPUT_FILES"



#Showing messages to indicate files are saved
echo -e "\n${GREEN}[+] All information saved to individual files on the local machine:"
echo -e "[+] curl info saved to $TOOL/OUTPUT_FILES/curl_output.txt"
echo -e "[+] country info saved to $TOOL/OUTPUT_FILES/country_output.txt"
echo -e "[+] uptime results saved to $TOOL/OUTPUT_FILES/uptime_output.txt"
echo -e "[+] whois results saved to $TOOL/OUTPUT_FILES/whois_output.txt"
echo -e "[+] nmap results saved to $TOOL/OUTPUT_FILES/nmap_output.txt${STOP}"

#Calling the LOG function
LOG

else
#If the SSH connection failed, display a failure message.
echo -e "${RED}\nSSH connection failed! Please check your credentials or server status.${STOP}"
fi

}


#function that makes a single file that summarizes all "output" files information.
function LOG(){
    #Defining log file name and location + adding timestamp.
    AUDIT_LOG="$TOOL/audit_log_$(date +%F_%H-%M-%S).log"

    #Array of output files on the local machine
    OUTPUT_FILES=(
        "$TOOL/OUTPUT_FILES/curl_output.txt"
        "$TOOL/OUTPUT_FILES/country_output.txt"
        "$TOOL/OUTPUT_FILES/uptime_output.txt"
        "$TOOL/OUTPUT_FILES/whois_output.txt"
        "$TOOL/OUTPUT_FILES/nmap_output.txt"
    )
    #Message that starts the log file
    echo "Audit log created on: $(date)" > "$AUDIT_LOG"

    #Loop through each output file and write to the log if it exists
    for FILE in "${OUTPUT_FILES[@]}"; do
        if [ -f "$FILE" ]; then
            #Extract just the filename from the full path and delete .txt extention.
            FILENAME=$(basename "$FILE" | sed 's/.txt//')
            #Write the file's output to the log
            echo -e "\n========== $FILENAME ==========\n" >> "$AUDIT_LOG"
            cat "$FILE" >> "$AUDIT_LOG"
        fi
    done

    #Completion message in terminal
    echo -e "\n${GREEN}Log file generation has been completed, and saved to $AUDIT_LOG${STOP}\n"
    
    NIPE_STOP
}

#function that clears previous OUTPUT_RESULTS (doesn't include LOG file)
function CLEAR_RESULTS (){
   if [ -d "$TOOL/OUTPUT_FILES" ]; then #If the OUTPUT_FILES directory exists
    	echo -e "\n${CYAN}***${BOLD}ATTENTION!${STOP} ${CYAN}Files inside${STOP} $TOOL/OUTPUT_FILES ${CYAN}will be removed. ${BOLD}Consider a backup!!!***${STOP}\n"
 		echo -e "Use CTRL+C to exit the script, or press any key to continue... "
 		read -n 1 -s #Waits for 1 character as user input to proceed. silents the input.
        rm -rf "$TOOL/OUTPUT_FILES/*"  #Deletes all files inside OUTPUT_FILES
        echo -e "${CYAN}\nOUTPUT_FILES folder has been cleared!${STOP}\n"
    else 
   		echo -e "${CYAN}Creating OUTPUT_FILES directory for the results in:${STOP}" $TOOL
		echo -e "${CYAN}To initiate dependecies installation, remove nipe folder if already exists in this folder.${STOP}\n"
    	mkdir -p $TOOL/OUTPUT_FILES #Create folder if doesn't exist
    fi
}

#function that stops nipe and switches the ip back to normal.
function NIPE_STOP(){
echo "Stopping Nipe..."
#Moving to nipe folder to execute nipe.pl stop
cd $TOOL/nipe
sudo perl nipe.pl stop
#Updating IP variable
IP=$(curl -s ifconfig.me)
#Updating COUNTRY variable with current info
COUNTRY=$(geoiplookup $IP | awk {'print $4'} | sed 's/,//')
#Showing user their current ip and location
DISPLAY_SPOOFED_COUNTRY
#Checking if no longer anonymous
if [ "$COUNTRY" == "IL" ];then #If country IS Israel
echo -e "${GREEN}You are back to NOT being anonymous${STOP}\n"
echo -e "${CYAN}Hasta la vista, baby! ^_^"
else
echo -e "${RED}You are still anonymous!${STOP}"
fi
exit 0 #Exiting script
}

START
