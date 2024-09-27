#!/bin/bash

LOGFILE="/var/log/turnupsecurityshield.log"

echo "################################################################################"
echo "#                                                                              #"
echo "#         TurnUpSecurity Server Security Tools UnInstall Script                #"
echo "#              Maintained by https://turnupsecurityshield.com                  #"
echo "#          Please email support@turnupsecurityshield.com for help              #"
echo "#                                                                              #"
echo "################################################################################"

# Function to remove installed packages
remove_if_installed_by_script() {
    local package=$1

    if grep -q "AFTER $package installed" "$LOGFILE"; then
        echo "$package was installed by this script. Uninstalling..." | tee -a $LOGFILE
        sudo yum remove -y $package | tee -a $LOGFILE
    else
        echo "$package was not installed by this script. Skipping uninstallation." | tee -a $LOGFILE
    fi
}

# Function to undo configuration changes
undo_config_changes() {
    local description=$1
    local command=$2

    if grep -q "AFTER $description" "$LOGFILE"; then
        echo "Reverting configuration change: $description" | tee -a $LOGFILE
        eval $command | tee -a $LOGFILE
    else
        echo "Configuration change for $description was not made by this script. Skipping." | tee -a $LOGFILE
    fi
}

# Uninstall packages if installed by the script
remove_if_installed_by_script "epel-release"
remove_if_installed_by_script "tar"
remove_if_installed_by_script "python3"
remove_if_installed_by_script "python-pip"
remove_if_installed_by_script "rkhunter"
remove_if_installed_by_script "clamav-server clamav-data clamav-update clamav-filesystem clamav clamav-scanner-systemd clamav-devel clamav-lib clamav-server-systemd"
remove_if_installed_by_script "csf"
remove_if_installed_by_script "MailScanner"
remove_if_installed_by_script "mod_security"
remove_if_installed_by_script "lynis"
remove_if_installed_by_script "maldet"
remove_if_installed_by_script "graylog-server"

# Remove symbolic links if created by the script
undo_config_changes "Python linked to /usr/bin/python" "sudo rm -f /usr/bin/python"

# Stop and disable services started by the script
if grep -q "AFTER CSF installed" "$LOGFILE"; then
    echo "Stopping and disabling CSF and LFD services..." | tee -a $LOGFILE
    sudo systemctl stop csf lfd | tee -a $LOGFILE
    sudo systemctl disable csf lfd | tee -a $LOGFILE
fi

if grep -q "AFTER MailScanner installed" "$LOGFILE"; then
    echo "Stopping and disabling MailScanner service..." | tee -a $LOGFILE
    sudo systemctl stop MailScanner | tee -a $LOGFILE
    sudo systemctl disable MailScanner | tee -a $LOGFILE
fi

if grep -q "AFTER mod_security installed" "$LOGFILE"; then
    echo "Disabling ModSecurity..." | tee -a $LOGFILE
    sudo a2dismod security2 | tee -a $LOGFILE
fi

if grep -q "AFTER Graylog installed" "$LOGFILE"; then
    echo "Stopping and disabling Graylog service..." | tee -a $LOGFILE
    sudo systemctl stop graylog-server | tee -a $LOGFILE
    sudo systemctl disable graylog-server | tee -a $LOGFILE
fi

# Revert configuration changes made to files
undo_config_changes "Freshclam configuration" "sudo sed -i -e 's/#Example/^Example/' /etc/freshclam.conf"

# Remove cron jobs set by the script
if grep -q "AFTER Wordfence cron job set" "$LOGFILE"; then
    echo "Removing Wordfence CLI cron job..." | tee -a $LOGFILE
    crontab -l | grep -v 'wordfence' | crontab - | tee -a $LOGFILE
fi

if grep -q "AFTER Lynis weekly scan set" "$LOGFILE"; then
    echo "Removing Lynis weekly scan cron job..." | tee -a $LOGFILE
    crontab -l | grep -v 'lynis audit system' | crontab - | tee -a $LOGFILE
fi

if grep -q "AFTER Maldet weekly scan set" "$LOGFILE"; then
    echo "Removing Maldet weekly scan cron job..." | tee -a $LOGFILE
    crontab -l | grep -v 'maldetect' | crontab - | tee -a $LOGFILE
fi

# Remove any additional files added during installation
if grep -q "AFTER Recaptcha v2 installed" "$LOGFILE"; then
    echo "Removing Recaptcha v2 files..." | tee -a $LOGFILE
    sudo rm -rf /usr/local/src/reCaptcha2_validation-free-master | tee -a $LOGFILE
fi

if grep -q "AFTER OWASP rules installed" "$LOGFILE"; then
    echo "Removing OWASP ModSecurity rules..." | tee -a $LOGFILE
    sudo rm -rf /etc/apache2/owasp | tee -a $LOGFILE
fi

if grep -q "AFTER Comodo WAF installed" "$LOGFILE"; then
    echo "Removing Comodo WAF configurations..." | tee -a $LOGFILE
    sudo rm -f /etc/apache2/conf.d/modsec_vendor_configs/comodo_waf.yaml | tee -a $LOGFILE
fi

# Completion message
echo "Uninstallation completed. Changes have been reversed based on $LOGFILE." | tee -a $LOGFILE
