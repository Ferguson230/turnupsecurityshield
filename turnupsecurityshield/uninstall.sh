#!/bin/bash

LOGFILE="/var/log/turnupsecurityshield.log"

# Example function to remove Comodo WAF rules
uninstall_modsecurity_comodo() {
    if grep -q "ModSecurity Comodo WAF rules added." $LOGFILE; then
        echo "Removing Comodo WAF rules..."
        # Remove Comodo WAF rules
        sed -i '/ModSecurity Comodo WAF rules added./d' $LOGFILE
    fi
}

# Example function to uninstall ClamAV
uninstall_clamav() {
    if grep -q "ClamAV installed." $LOGFILE; then
        echo "Uninstalling ClamAV..."
        # Uninstall ClamAV...
        sed -i '/ClamAV installed./d' $LOGFILE
    fi
}

# Main uninstall flow
uninstall_modsecurity_comodo
uninstall_clamav
