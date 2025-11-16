#!/bin/bash

#Student Name - Ron Nisinboym
#Student Code - S11
#Unit Code - TMagen773637
#Program Code - NX212
#Lecturer Name - Erel Regev

#Global Variables.
#Used for folder:
HOME=$(pwd)

#Used for colors and fonts:
RED='\033[0;31m'
CYAN='\033[36m'
GREEN='\033[38;5;34m'
BOLD='\033[1m'
NC='\033[0m'

#Used for statistics:
start_time=$(date +%s)
end_time=$(date +%s)


#Function to check if carving and volatility tools exist on system and download\install if not.
function CHECK_APPS()
{
	APPS="bulk_extractor binwalk foremost strings" #defining APPS
	echo "Checking if the following tools exist on the system:"
	echo ""
#list volatility along with carving tools that are about to be checked.
#volatility downloaded from different repository, therefore, is not part of APPS. 		
	echo volatility
	for app in $APPS
	do
	echo "$app"
	done

	
	
	if [ -f $HOME/vol ]; then #checks for volatility_tool inside the folder. Downloading from a raw github link in case it's missing.
		echo -e "${GREEN}Volatility Tool is already installed. skipping...${NC}"
	else
		echo -e "\n${CYAN}Volatility Tool does not exist. Downlading...${NC}"
		sleep 5 #using sleep so the user have time to read the last message.
		wget https://github.com/CookieBotXL/justtakeit/raw/refs/heads/main/vol
		echo -e "${GREEN}Volatility Tool has been downloaded susccesfully!\n${NC}"
fi	
	
#checks each app if installed, and installs it if missing. Uses dev/null to remove the "which" output.
	for app in $APPS
do
    if which "$app" > /dev/null 
    then
        echo -e "${GREEN}$app is already installed. skipping...${NC}"
    else
        echo -e "${CYAN}$app does not exist. Installation is starting!${NC}"
		sleep 5
        if [ "$app" == "bulk_extractor" ]
        then
			apt install bulk-extractor
			echo -e "${GREEN}Bulk_Extractor has been installed susccesfully!\n${NC}"
		
		elif [ "$app" == "binwalk" ]; then
			apt install binwalk
			echo -e "${GREEN}Binwalk has been installed susccesfully!\n${NC}"
			
		elif [ "$app" == "foremost" ];	then
			apt install foremost
			echo -e "${GREEN}Foremost has been installed susccesfully!\n${NC}"
	
		elif [ "$app" == "strings" ]; then
			sudo apt install binutils
			echo -e "${GREEN}Strings has been installed susccesfully!\n${NC}"
			
        fi
        
    fi
done
	
	
	#only after done checking or installing tools - call CLEAR_RESULTS and MENU functions to proceed with operation.
	CLEAR_RESULTS
	MENU
}


#Function to open the Main Menu for the user.
function MENU()
{
	while true; do
	echo ""
	echo -e "What would you like to do with the file? [CHOOSE A NUMBER]\n [+] 1 - Carvers Menu\n [+] 2 - Run Volatility\n\n [+] 0 - Save Report And Exit" 
	read -p "Enter your choice: " OPTIONS
	
	
	case $OPTIONS in
		
	#using echo "" on each step to make a new line ONLY when the option is valid, avoiding that space when the option is invalid.
	1)	echo ""
		CARVING #use carving tools
	;;
	
	2)	echo ""				
		VOL #use volatility tool
	;;
		
	0) 	echo ""
		EXIT #use EXIT function to save a report and ZIP results.
		
	;;
	
	*) echo -e "${RED}Invalid choice. Please try again.${NC}" #blocking user from choosing invalid option.
	esac
	done
}

#Function to open the Carving menu where user can choose the tools he wants to run.
function CARVING() {
	while true; do
	echo -e "What carver would you like to use? [CHOOSE A NUMBER]\n [+] 1 - Bulk_Extractor (Including PCAP Extraction)\n [+] 2 - Binwalk\n [+] 3 - Foremost\n [+] 4 - Strings\n [+] 5 - Use All\n [+] 6 - Back To Menu" 
	read -p "Enter your choice: " CARVERS #prompting the user to enter his choice, and waiting for input.
	
	
	case $CARVERS in
	
		#Using Bulk_Extractor
	1)	echo ""
		echo "Bulk_Extractor is doing its job, please wait!" 
		start_time=$(date +%s)
		bulk_extractor "$path" -o ./memory_analysis/bulk_results > /dev/null 2>&1 #running bulk_extractor on the file and saving results into a folder. Hiding generic output.
		OUTPUT_DIR="./memory_analysis/bulk_results" #defining OUTPUT_DIR for further use in case PCAP function is needed
		DISPLAY_STATISTICS "$OUTPUT_DIR" "Bulk_Extractor" #Using DISPLAY_STATISTICS function 
		
		#letting user decide if he wants details about a PCAP file.
		PCAP_QUESTION
	
	;;
	
	2)	#using Binwalk (with root permissions)
		echo ""
		echo "Binwalk is doing its job, please wait!"
		start_time=$(date +%s)
		binwalk -e "$path" --run-as=root -C ./memory_analysis/binwalk_results > /dev/null 2>&1 #runs binwalk, makes sure that it runs as root to prevent a failure and puts the output in a seperate folder.
		DISPLAY_STATISTICS "./memory_analysis/binwalk_results" "Binwalk"
		break
		
	;;
	
	3) 	#using Foremost
		echo ""
		echo "Foremost is doing its job, please wait!"
		start_time=$(date +%s)
		foremost -i "$path" -o ./memory_analysis/foremost_results > /dev/null 2>&1
		sudo chown -R $(logname):$(logname) ./memory_analysis #makes sure the current user owns the folder and everything inside it to prevent failure.
		chmod -R u+rwX ./memory_analysis #gives permission to current user to read, write and access the folder and it's files.
		DISPLAY_STATISTICS "./memory_analysis/foremost_results" "Foremost"
		break
		#without the ownership and permission changes as executed - current user is unable to access the "foremost_results" folder.
		
	;;
	
	4)	#using Strings
		echo ""
		mkdir -p ./memory_analysis/strings_results
		echo "Strings is doing its job, please wait!"
		start_time=$(date +%s)
		KEYWORDS='password passwd token http auth exec secret hostname'
		strings "$path" > ./memory_analysis/strings_results/strings.txt 2>/dev/null #redirects output to a text file without showing the default output of the tool to the user.
		
		#using for loop to search for different keywords in strings.txt and create output file for each.
		for key in $KEYWORDS
		do
		grep -i "$key" ./memory_analysis/strings_results/strings.txt > ./memory_analysis/strings_results/"$key.txt"
		done
	
		#extract usernames from the strings.txt file, remove duplicates and sort them.
		grep -i 'username=' ./memory_analysis/strings_results/strings.txt | sort | uniq -c | sort -nr > ./memory_analysis/strings_results/users.txt

		DISPLAY_STATISTICS "./memory_analysis/strings_results" "Strings"
		STRING_SEARCH
		break
		
	;;
	
	5) 	#Option to use all carving tools together for user convenience - 
		# 5.1) Bulk Extractor
		echo ""
		echo "Bulk_Extractor is doing its job, please wait!"
		start_time=$(date +%s)
		bulk_extractor "$path" -o ./memory_analysis/bulk_results > /dev/null 2>&1
		OUTPUT_DIR="./memory_analysis/bulk_results" 
		DISPLAY_STATISTICS "$OUTPUT_DIR" "Bulk_Extractor"

		PCAP_QUESTION

		# 5.2) Binwalk (with root permissions)
		echo ""	
		echo "Binwalk is doing its job, please wait!"
		start_time=$(date +%s)
		binwalk -e "$path" --run-as=root -C ./memory_analysis/binwalk_results > /dev/null 2>&1
		DISPLAY_STATISTICS "./memory_analysis/binwalk_results" "Binwalk"
		
		# 5.3) Foremost + fix ownership and permissions
		echo "Foremost is doing its job, please wait!"
		start_time=$(date +%s)
		foremost -i "$path" -o ./memory_analysis/foremost_results > /dev/null 2>&1
		sudo chown -R $(logname):$(logname) ./memory_analysis
		chmod -R u+rwX ./memory_analysis
		DISPLAY_STATISTICS "./memory_analysis/foremost_results" "Foremost"

		# 5.4) Strings + creating human readble "users" output.
		echo ""
		mkdir -p ./memory_analysis/strings_results
		echo "Strings is doing its job, please wait!"
		KEYWORDS='password passwd token http auth exec secret hostname'
		strings "$path" > ./memory_analysis/strings_results/strings.txt 2>/dev/null 
				
		for key in $KEYWORDS
		do
		grep -i "$key" ./memory_analysis/strings_results/strings.txt > ./memory_analysis/strings_results/"$key.txt"
		done
	
		grep -i 'username=' ./memory_analysis/strings_results/strings.txt | sort | uniq -c | sort -nr > ./memory_analysis/strings_results/users.txt
		DISPLAY_STATISTICS "./memory_analysis/strings_results" "Strings"
		STRING_SEARCH
		
		break
	
	;;
		
	6) MENU
	
	;;
	
	*) echo -e "${RED}Invalid choice. Please try again.${NC}\n"
	
	esac
	done
	}


#Function used to ask user if they want to search for network traffic.
function PCAP_QUESTION () {
	while true;do
	echo -n "Do you want to check if a Network traffic file was extracted and get its details? (y/n): "
	read REPLY
	
		
	case $REPLY in
		
	[Yy]) 
		PCAP #Calls a seperate function to check if PCAP file exists and providing its location and size.
		break
	
	;;
	
	[Nn]) 
		echo -e "Skipping Network traffic file check and cotinuing... \n"
		break
		
	;;
	
	*) 
		echo -e "${RED}Invalid choice. Please try again.${NC}\n"
			
	;;
		esac
		done
	
}

#Function checks for a PCAP file informaion if it exists after extracting, and providing that info.
function PCAP(){
	PCAP_FILE="$OUTPUT_DIR/packets.pcap" 
		if [ -f "$PCAP_FILE" ]; then # checks if file exists. 
		echo -e "${GREEN}\nNetwork traffic file found!${NC}" 
		#showing location of the PCAP file. using -e flag to read backslashes in order to paint text in red for user better visibility and user convenience.
		echo -e "${BOLD}${CYAN}Location: $PCAP_FILE${NC}" 
		
		#using disk usage with human readble flag to display the size and using awk to prevent repeating path output
		echo -e "${BOLD}${CYAN}The size of the file is: $(du -h "$PCAP_FILE" | awk '{print $1}')${NC}\n" 
	else
		echo -e "${RED}No network traffic file (packets.pcap) found.\n${NC}"
		fi
}

#Function that runs Volatility Tool plugins.
function VOL()
{
	VOL_CHECK
	sudo chmod +x ./vol #making sure volatility has permission to run(doesn't run wihtout it if been downloaded from github)
	start_time=$(date +%s)
	mkdir -p ./memory_analysis/volatility_results
	PROFILE=$(./vol -f "$path" imageinfo | grep Suggested | awk -F',' '{print $1}' | awk -F':' '{print $2}' | sed 's/ //g')
	echo -e "${BOLD}${CYAN}OS: $PROFILE${NC}"
	PLUGINS="hivelist cmdline driverscan mftparser svcscan hashdump userassist dlllist shutdowntime psscan pslist connscan  "
	KEYS="Run RunOnce"
	REG_KEY_PATH="Software\\Microsoft\\Windows\\CurrentVersion"
	
	
	#running dumpregistry to extract all registry data from memory.
	echo ""
		sudo mkdir -p ./memory_analysis/volatility_results/regdump_results
		echo "Using dumpregistry against the file..."
		sudo ./vol -f "$path" --profile=$PROFILE dumpregistry -D ./memory_analysis/volatility_results/regdump_results > /dev/null 2>&1
		
	
	#using printkey with a variable to extract specific registry keys into seperate text files.
	for key in $KEYS
	do
		echo "Using printkey $key against the file..."
		./vol -f "$path" --profile=$PROFILE printkey -K "$REG_KEY_PATH\\$key" > /dev/null 2>&1 > "memory_analysis/volatility_results/$FILE_NAME/results_printkey_$key.txt"
	done

	for plugin in $PLUGINS
	do
		echo "Using $plugin against the file..." 
		if [[ "$plugin" == "pslist" || "$plugin" == "connscan" ]]; then
		echo -e "${BOLD}${CYAN}Top priority plugin has been detected. Output will be displayed here as well:${NC}"
		sleep 2
		#Display output in terminal and save to file with the use of tee
		./vol -f "$path" --profile=$PROFILE $plugin | tee "memory_analysis/volatility_results/$FILE_NAME/results_$plugin.txt"
		else
		#For other plugins, save output to file silently
		./vol -f "$path" --profile=$PROFILE $plugin > /dev/null 2>&1 > "memory_analysis/volatility_results/$FILE_NAME/results_$plugin.txt"
		fi
	done
	
		DISPLAY_STATISTICS "memory_analysis/volatility_results" "Volatility"
}


	
#this function checks whether the given file exist on the system. if not, shows a message that informs the user, and asks to try again until the correct file is provided.
function FILE_CHECK()
{
	echo "Please insert a full path to the image file:"
	read path
	echo "Checking if file exists..."
	if [ -s "$path" ]
	then
		echo -e "${GREEN}File exists!${NC}\n"
		CHECK_APPS
	else
		echo -e "${RED}File does not exist. Please try again!\n${NC}"
		FILE_CHECK
	fi	
}

#This function checks if the file can be analyzed by Volatility tool. 
function VOL_CHECK(){
	echo "Analyzing $path..."
    if [[ ! "$path" =~ \.(mem|raw|dmp)$ ]]; then #If it's not a .mem, .raw, or .dmp file, print error and go back to MENU.
        echo -e "${RED}The file '$path' is not a valid memory image file. Only .mem, .raw, or .dmp files can be analyzed by Volatility.${NC}"
        MENU
    fi
    # If it's a valid memory image file, continue with the script
    echo -e "${GREEN}The file '$path' is a valid memory image file. Continuing...${NC}"
}

# This function starts the script. checks if the user is root or not, creates a main directory.
function START ()
{
	USER=$(whoami)
	if [ "$USER" != "root" ]
	then
		echo "You are not root. Exiting.."
		exit
	else
		figlet -f small "Forensics Investigation"
		
		#creating memory_analysis folder and giving permission read,write and execute permissions to avoid script errors.
		sudo mkdir -p ./memory_analysis
		sudo chmod 777 ./memory_analysis

		echo -e "${BOLD}${CYAN}\n***Pay attention! memory_analysis folder and report.txt will be cleared once you proceed with this step. consider a backup!***${NC}"

		FILE_CHECK
	fi
	
}


#Function letting the user search for specific strings while using the strings tool.
function STRING_SEARCH() {
	while true; do
	# Ask if the user wants to search for a word in the strings output
	echo -n "Do you want to search for a specific string in the strings output? (y/n): "
	read search_choice

	case "$search_choice" in
	[Yy]*)
		#If user chooses 'y', ask for the string to search for and filter results
		while true; do
		echo -n "Enter the string to search for: "
		read search_string
		echo -e "Filtered results for '$search_string':\n"
		grep -i "$search_string" ./memory_analysis/strings_results/strings.txt

		#Ask if the user wants to search again
		while true; do
		echo -en "\nDo you want to search again? (y/n): "
		read search_again

		#Check for valid input in additional searches (y/n)
		case "$search_again" in
		
		[Yy]*)
			# Continue searching if 'y' is chosen
			break  # Break out of this inner loop, continue searching
		
		;;
		
		[Nn]*)
			# Break out and return to menu if 'n' is chosen
			echo ""
			echo -e "Returning to Menu..."
			MENU
			return
		
		;;
		
		*)
			# If invalid input, prompt again without moving forward
			echo -e "${RED}Invalid input. Please enter 'y' or 'n'.${NC}\n"
		
		;;
		
		esac
		done
		done
		
		;;
		
		[Nn]*)
				#If user chooses 'n' in the starting question, skip the search and return to the menu
				echo ""
				echo -e "Returning to Menu..."
				MENU
				return
				
		;;
		
		*)
			#If invalid input for the starting question, ask again
			echo -e "${RED}Invalid input. Please enter 'y' or 'n'.${NC}\n"
				
		;;
		
	esac
	done
}

#Function to display statistics(number of files and the time it took to run)
function DISPLAY_STATISTICS() {
#Accept output directory and tool name as an arguments when running the function.
  local tool_output_dir=$1
  local tool_name=$2
  #Calculate the time taken for the analysis
  end_time=$(date +%s) #using timestamp to compare with "start_time" variable.
  time_taken=$((end_time - start_time))

  #count the number of files in the memory_analysis directory.
  num_files_carv=$(find "$tool_output_dir" -type f | wc -l)

  #Display statistics to user.
  echo -e "${GREEN}--- $tool_name Analysis Completed ---${NC}"
  echo -e "${GREEN}Time of analysis: $time_taken seconds${NC}"
  echo -e "${GREEN}Number of files found: $num_files_carv${NC}"
  echo -e "${GREEN}files were saved to: $tool_output_dir/${NC}\n"

}

#Exit function including creating a report file and creating a ZIP file with all the results.
function EXIT () {
		total_results_count=$(find "./memory_analysis" -type f | wc -l)
		echo -e "Report generated on: $(date)\n" > "report.txt"
		echo -e "Total number of files found: $total_results_count\nHere are everything that you have found:\n" >> "report.txt"
		find "./memory_analysis" -type f >> "report.txt"

		echo -e "${GREEN}Your report was saved to ./report.txt${NC}"
		
		ZIP_RESULTS #Call ZIP_RESULTS function before exiting script.
		
		echo -e "\n${CYAN}See you later, aligator!!! ^_^${NC}"
		exit 0 #exiting script
}

#Function to zip all result folder + report.txt. 
function ZIP_RESULTS (){
		#creating a small loading so the user will have time to read the following message before zipping starts -
		echo -e "\n${BOLD}${CYAN}WAIT! Before you go, we will pack the results nicely in a ZIP-file for you!"
		echo -e "ZIPPING your files, please wait!${NC}"
		#zipping with -q flag to silence default output and using a timestamp to avoid overwriting the prvious zip and give creation date and time indication while maintaining the same file name.
		timestamp=$(date +%Y%m%d_%H%M%S)
		zip -rq memory_analysis_"$timestamp".zip memory_analysis report.txt 
		echo -e "${GREEN}\nWe're Done! Everything is packed nicely into ./memory_analysis_{$timestamp}.zip${NC}"
}

#Function to clear all results folders, report file, 
function CLEAR_RESULTS () {
	rm -rf ./memory_analysis/* #deletes all folders inside memory_analysis
	echo -e "${CYAN}\nmemory_analysis folder has been cleared!"
	> report.txt #clears report.txt
	echo -e "report.txt has been cleared!${NC}"
}

START


