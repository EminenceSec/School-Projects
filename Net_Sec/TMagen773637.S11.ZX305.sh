#!/bin/bash

#Student Name - Ron Nisinboym
#Student Code - S11
#Unit Code - TMagen773637
#Program Code - ZX305
#Lecturer Name - Erel Regev

# Define paths and initialize variables
current_dir=$(pwd)  # Get the current working directory
results_dir=$(pwd)/results  # Directory where results will be stored
log_file=$(pwd)/results/log_file.txt  # Log file prior to converting
local_ip=$(hostname -I | xargs)  # Get the local IP address

# Flags to track execution status
advanced_enum_run=false  # Flag to track if Advanced Enumeration was successfully run

# Source external script files for basic, intermediate, and advanced operations
source "$current_dir/basic.sh"
source "$current_dir/intermediate.sh"
source "$current_dir/advanced.sh"

# COLORS AND FONTS:
GC='\e[32m' #GREEN
RC='\e[31m' #RED
CC='\033[0;36m' #CYAN
BOLD='\033[1m' #BOLD
NC='\e[0m' #DEFAULT

#Function to check if user is root
function check_root {
	USER=$(whoami)
	if [ "$USER" != "root" ] #if NOT root.
	then
		echo -e "${RC}You are not root. Exiting...${NC}"
		exit
	fi	
}

# Function to present the user with options to start, show help, or exit
function get_main_menu {
	echo "Welcome to the Security Operations Script"
    while true; do
        echo "Select an option to continue:"
        echo "1. Start (Begin the security operations script)"
        echo "2. Help (Show how the script works and what it does)"
        echo "3. Exit (Exit the script without running)"
        
        # Prompt the user for input
        read -p "Please choose an option (1-3): " start_option
        
        # Handle user input with case structure
        case $start_option in
            1)
                echo -e "Starting the script...\n"
                break  # Proceed to run the script
                ;;
            2)
                # Displaying the help information about the script
				echo -e "\nThis script automates the process of domain mapping on a target network, helping with network scanning, service enumeration, and vulnerability exploitation."
				echo -e "\nWhen selecting a mode or level (Basic, Intermediate, or Advanced), please note that each higher level automatically includes the actions from the lower levels. For example, selecting **Intermediate** will also run the **Basic** step for the same mode, and choosing **Advanced** will run both **Basic** and **Intermediate** steps."

				echo -e "\nSteps Overview:"
				echo "1. **Scanning Mode**: You will select a scanning level that defines how deep the network scanning will go."
				echo "    - **Basic**: Scans hosts assuming they are online (skips host discovery)."
				echo "    - **Intermediate**: Scans all 65535 ports for a more comprehensive overview."
				echo "    - **Advanced**: Adds UDP scanning for a deeper analysis of the network."
				echo "2. **Enumeration Mode**: After scanning, the script will help you enumerate services and gather network information."
				echo "    - **Basic**: Identifies services running on open ports, the IP addresses of Domain Controllers and DHCP servers."
				echo "    - **Intermediate**: Provides more detailed enumeration, including common services (FTP, SSH, SMB, etc.), shared folders, and NSE scripts."
				echo "    - **Advanced**: Extracts detailed user, group, share data, and password policy information (Requires AD credentials)."
				echo "3. **Exploitation Mode**: Based on your previous selection, the script will attempt to exploit vulnerabilities."
				echo "    - **Basic**: Runs a vulnerability scan using NSE scripts."
				echo "    - **Intermediate**: Conducts domain-wide password spraying to find weak credentials (only available if 'Advanced' was selected in Enumeration Mode)."
				echo "    - **Advanced**: Attempts to extract and crack Kerberos tickets using a supplied password list (only available if 'Advanced' was selected in Enumeration Mode)."
				echo -e "\nYou will be prompted for network ranges, Active Directory credentials, and password lists to guide the process."
				echo -e "\nThe results will be generated in a PDF file for review.\n"
				echo -e "**Important**: To successfully run Kerberos ticket cracking with Hashcat, the Linux machine must have at least **4GB of RAM**.\n"


                continue 
                ;;
            3)
                # Exit the script without running it
                echo "Exiting the script."
                exit 0
                ;;
            *)
                # Handle invalid input
                echo -e "${RC}Invalid option, please choose 1, 2, or 3.${NC}"
                ;;
        esac
    done
}

# Function to check for required tools and install missing ones
function check_and_install_dependecies {
    required_tools=("nmap" "masscan" "smbclient" "rpcclient" "enum4linux" "crackmapexec" "hashcat" "enscript" "ghostscript" "python3" "git")
    
# Loop through each tool in the required_tools array
for tool in "${required_tools[@]}"; do
    # Check if the tool is already installed using command -v
    if ! command -v "$tool" &>/dev/null; then # If Missing...
        # If the tool is missing, print a message and proceed with installation
        echo "$tool is missing. Installing, please wait..."
        
        # Install the missing tool using apt-get, suppressing the output
        sudo apt-get install -y "$tool" &>/dev/null
        
        # Notify the user that the tool has been successfully installed
        echo -e "${GC}$tool has successfully installed.${NC}\n"
    fi
done

# After all tools have been processed, display a final message indicating completion
echo -e "${GC}Required dependencies have been installed.${NC}\n"
}

# Function to check if Impacket is installed in /opt
function check_and_install_impacket {
    # Check if /opt/impacket exists
    if [ ! -d "/opt/impacket" ]; then
        # Hide messages from the git clone and setup
        echo "Impacket not found in /opt. Installing..."

        # Clone the Impacket repository
        echo "Cloning Impacket repository..."
        sudo git clone https://github.com/SecureAuthCorp/impacket.git /opt/impacket > /dev/null 2>&1

        # Navigate to the Impacket directory and run the setup script
        echo "Running the setup script..."
        pushd /opt/impacket > /dev/null  # Save current directory and go to /opt/impacket
        sudo python3 setup.py install > /dev/null 2>&1
        popd > /dev/null  # Return to the original directory where the script execute from

        echo -e "${GC}Impacket has been successfully installed.\n${NC}"
    else
        echo -e "Impacket is already installed in /opt.\n"
    fi
}

# Function to check and download the 10k-most-common-passwords.txt file if not found
function check_and_download_passwords {
    # Check if the file exists in the current directory
    if [ ! -f "$current_dir/10k-most-common-passwords.txt" ]; then
        echo "10k-most-common-passwords.txt not found. Downloading..."
        
        # Download the file using wget and hide the output
        wget -q --show-progress https://github.com/CookieBotXL/Weak_Passwords/raw/refs/heads/main/10k-most-common-passwords.txt -P "$current_dir"
        echo ""
    else
        echo "10k-most-common-passwords.txt already exists in $current_dir."
    fi
}

# Function to check if the 'results' folder exists, and create it if necessary
function create_results {
    # Check if the "results" folder exists
    if [ ! -d "results" ]; then
        # Create the folder if it doesn't exist
        mkdir "results"
    else
        remove_text_files # Clear unfinished results if folder exists
    fi  
}

# Function to check if all AD credentials are defined (only called in Advanced Enumeration mode)
function check_ad_credentials {
    # Check if any AD credentials are missing
    if [[ -z "$domain_name" || -z "$ad_username" || -z "$ad_password" ]]; then
        echo -e "${RC}AD credentials are missing, please select a different option.${NC}"
        return 1  # Indicate that credentials are missing
    else
        echo -e "\nAD credentials validated.\n"
        return 0  # Indicate that credentials are valid
    fi
}

# Function to prompt the user to enter the target network range for scanning
function get_target_network {
    # Start an infinite loop to repeatedly prompt the user for input until valid input is given
    while true; do
        # Prompt the user to enter the target network range in CIDR format (e.g., 192.168.1.0/24)
        echo -e "\nEnter the target network range for scanning (e.g., 192.168.1.0/24): "
        
        # Read the user input into the variable 'target_network'
        read -r target_network

        # Check if the input is empty (i.e., the user pressed Enter without providing any input)
        if [ -z "$target_network" ]; then
            # Print an error message if no input is provided
            echo -e "${RC}Invalid input. Use a format like 192.168.1.0/24${NC}\n"
            # Inform the user that no input was detected and prompt them again
            echo "No input detected — please enter a target network range."
            # Skip the rest of the loop and prompt again
            continue
        fi

        # Check if the input does not match the expected format (CIDR notation like 192.168.1.0/24)
        if [[ "$target_network" != *.*.*.*/*?* ]]; then
            # Print an error message if the format is invalid
            echo -e "${RC}Invalid format. Use a format like 192.168.1.0/24${NC}\n"
            # Prompt the user again
            continue
        fi

        # If valid input is detected, exit the loop
        break
    done
}

# Function to prompt the user for Domain name and AD credentials
function get_ad_credentials {
    # Prompt for AD credentials
    read -p "Enter the Domain name (e.g., example.com): " domain_name
    read -p "Enter the AD username: " ad_username
    read -p "Enter the AD password: " ad_password
    echo  # To move to the next line after password input
}

# Function to prompt for the password list, defaulting to 10k-most-common-passwords if none specified
function get_password_list {
    # Use the read builtin with the -e flag (enables line editing features, like TAB-completion)
	read -e -p "Enter the path to the password list for Kerberos ticket cracking (default: $current_dir/10k-most-common-passwords.txt): " password_list    
    # Set default path if input is empty
    if [ -z "$password_list" ]; then
        password_list="$current_dir/10k-most-common-passwords.txt"
        echo "No input detected, using default password list: $password_list"
    fi

    # Check if the file exists, exit if it doesn't
    if [ ! -f "$password_list" ]; then
    	password_list="$current_dir/10k-most-common-passwords.txt"
        echo "The specified password list file does not exist. Selecting default password list: $password_list"
    fi
}

# Function to check if any open ports were found during the scanning process
function check_ports {
    # Check if the file "nmap_hosts_with_ports.txt" exists and is not empty
    if [ ! -s "nmap_hosts_with_ports.txt" ]; then
        # Print an error message if the file is empty or does not exist
        echo -e "${RC}No open ports have been found. Exiting.${NC}"
        
        # Exit the script with a status code of 1, indicating an error or no open ports detected
        exit 1
    fi
}

# Function to prompt the user to select a desired operation level for Scanning Mode
function get_scanning_level {
    while true; do
        echo -e "\nSelect the operation level for Scanning Mode:"
        echo "1. Basic"
        echo "2. Intermediate"
        echo "3. Advanced"
        read -p "Please choose a level (1-3): " scanning_level
        case $scanning_level in
            1) 
                scanning_level="Basic"
                BASIC_SCAN
                check_ports
                break  # Exit the loop after completing Basic scan
                ;;
            2) 
                scanning_level="Intermediate"
                INTERMEDIATE_SCAN
                check_ports
                break  # Exit the loop after completing Intermediate scan
                ;;
            3)
                scanning_level="Advanced"
                ADVANCED_SCAN
                check_ports
                break  # Exit the loop after completing Advanced scan
                ;;
            *) 
                echo -e "${RC}Invalid selection. Please choose a valid level (1-3).${NC}"
                ;;
        esac
    done
}

# Function to prompt the user to select a desired operation level for Enumeration Mode
function get_enumeration_level {
    while true; do
        # Display the menu for selecting the enumeration level
        echo -e "\nSelect the operation level for Enumeration Mode:"
        echo "1. Basic"
        echo "2. Intermediate"
        echo "3. Advanced (only available if AD credentials were provided)"
        echo "4. None (Skip this level)"
        
        # Prompt the user to select a level
        read -p "Please choose a level (1-4): " enumeration_level
        
        case $enumeration_level in
            1)
                # User selected Basic level
                enumeration_level="Basic"
                BASIC_ENUM      # Call function for Basic enumeration
                break            # Exit the loop after completing Basic level
                ;;
            2)
                # User selected Intermediate level
                enumeration_level="Intermediate"
                BASIC_ENUM      # Call function for Basic enumeration
                INTERMEDIATE_ENUM  # Call function for Intermediate enumeration
                break            # Exit the loop after completing Intermediate level
                ;;
            3)
                # User selected Advanced level
                if check_ad_credentials; then
                    # Check if valid Active Directory credentials are provided
                    enumeration_level="Advanced"
                    # Proceed with all levels of enumeration (Basic, Intermediate, Advanced)
                    BASIC_ENUM # Call function for Basic enumeration
                    INTERMEDIATE_ENUM # Call function for Intermediate enumeration
                    ADVANCED_ENUM # Call function for Advanced enumeration
                    advanced_enum_run=true  # Mark Advanced Enumeration was executed for intermediate and advanced exploitaton levels
                    break # Exit the loop after completing Advanced level
                fi
                ;;
            4)
                # User selected the "None" option to skip enumeration
                echo "Skipping Enumeration Mode."
                break  # Exit the loop without calling any enumeration functions
                ;;
            *)
                # If the user provides an invalid input, ask them to choose a valid level
                echo -e "${RC}Invalid selection. Please choose a valid level (1-4).${NC}"
                ;;
        esac
    done
}

# Function to prompt the user to select a desired operation level for Exploitation Mode
function get_exploitation_level {
    while true; do
        echo -e "\nSelect the operation level for Exploitation Mode:"
        echo "1. Basic"
        echo "2. Intermediate (Only available if Advanced Enumeration was executed)"
        echo "3. Advanced (Only available if Advanced Enumeration was executed)"
        echo "4. None (Skip this level)"
        
        # Prompt the user to select a level
        read -p "Please choose a level (1-4): " exploitation_level
        
        case $exploitation_level in
            1)
                # User selected Basic level
                exploitation_level="Basic"
                BASIC_EXPLOIT   # Call function for Basic exploitation
                break           # Exit the loop after completing Basic level
                ;;
            2)
                # User selected Intermediate level, but Advanced Enumeration must be run
                if [ "$advanced_enum_run" = true ]; then
                
                	# Proceed with Basic and Intermediate Exploitation
                    exploitation_level="Intermediate"
                    BASIC_EXPLOIT   # Call function for Basic exploitation
                    INTERMEDIATE_EXPLOIT  # Call function for Intermediate exploitation
                    break           # Exit the loop after completing Intermediate level
                else
                    # Warn the user that they need to run Advanced Enumeration first
                    echo -e "${RC}'Advanced Enumeration' wasn't selected earlier, please restart the script or select the 'Basic Exploitation' option."
                   	echo -e "${RC}For more information, use the Help option in the main menu.${NC}" 
                fi
                ;;
            3)
				# User selected Advanced level, but Advanced Enumeration must be run
				if [ "$advanced_enum_run" = true ]; then
					exploitation_level="Advanced"
					
					# Proceed with Basic, Intermediate, and Advanced Exploitation
					BASIC_EXPLOIT  # Call function for Basic exploitation
					INTERMEDIATE_EXPLOIT  # Call function for Intermediate exploitation
					ADVANCED_EXPLOIT    # Call function for Advanced exploitation
					break  # Exit the loop after completing Advanced Exploitation
				else
                    # Warn the user that they need to run Advanced Enumeration first
                    echo -e "${RC}'Advanced Enumeration' wasn't selected earlier, please restart the script or select the 'Basic Exploitation' option."
                   	echo -e "${RC}For more information, use the Help option in the main menu.${NC}" 
                fi
                ;;
            4)
                # User selected the "None" option to skip exploitation
                echo "Skipping Exploitation Mode."
                break  # Exit the loop without calling any exploitation functions
                ;;
            *)
                # If the user provides an invalid input, ask them to choose a valid level
                echo "Invalid selection. Please choose a valid level (1-4)."
                ;;
        esac
    done
}

# Fucntion to conver log_file.txt into log_file.pdf
function create_pdf {
    # Generate a timestamp
    local timestamp
    timestamp=$(date +"%Y%m%d_%H%M%S")

    # Create a PostScript file first
    enscript -B -f "Courier10" -o "$results_dir/log_file_$timestamp.ps" "$log_file" > /dev/null 2>&1

    # Convert PostScript to PDF
    ps2pdf "$results_dir/log_file_$timestamp.ps" "$results_dir/log_file_$timestamp.pdf" > /dev/null 2>&1

    # Remove the intermediate .ps
    rm -f "$results_dir/log_file_$timestamp.ps"

    echo -e "${CC}PDF created: $results_dir/log_file_$timestamp.pdf${NC}"
}

# Main function to start the operation
function get_operation_level {
    # Scanning Mode Level
    get_scanning_level  # Call for scanning mode

    # Enumeration Mode Level
    get_enumeration_level  # Call for enumeration mode

    # Exploitation Mode Level
    get_exploitation_level  # Call for exploitation mode
}

# Function to delete all .txt files created by the script for data storage.
function remove_text_files {
    rm -f "$results_dir"/*.txt
    rm -f "$current_dir"/*.txt
}

# Functions execution
check_root # Checks if user is root
get_main_menu # Main-Menu (Start, Help, Exit)
check_and_install_dependecies # Check if required tools installed
check_and_install_impacket # Check if impacket installed in /opt/impacket
check_and_download_passwords # Downloads password-list for ticket brute-force.
create_results  # Ensure results directory exists
get_target_network  # Get target network range
get_ad_credentials  # Prompt for AD credentials
get_password_list  # Prompt for password list
get_operation_level  # Proceed to operation levels
create_pdf  # Convert log file to PDF
remove_text_files  # Remove any text files generated during execution
