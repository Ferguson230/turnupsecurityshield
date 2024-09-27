# Define the script name
SCRIPT=./turnupsecurityshield_cptools.sh

# Default target: Install
install:
    bash $(SCRIPT)

# Uninstall target: Revert changes based on log file
uninstall:
    bash ./uninstall.sh
