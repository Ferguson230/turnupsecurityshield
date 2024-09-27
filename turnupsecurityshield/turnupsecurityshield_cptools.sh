#!/bin/bash

LOG_FILE="/var/log/turnupsecurityshield.log"

echo "################################################################################" | tee -a $LOG_FILE
echo "#                                                                              #" | tee -a $LOG_FILE
echo "#         TurnUpSecurity Server Security Tools Installation Script             #" | tee -a $LOG_FILE
echo "#              Maintained by https://turnupsecurityshield.com                  #" | tee -a $LOG_FILE
echo "#          Please email support@turnupsecurityshield.com for help              #" | tee -a $LOG_FILE
echo "#                                                                              #" | tee -a $LOG_FILE
echo "################################################################################" | tee -a $LOG_FILE

# Obtain hostname and IP address of the server
HOSTNAME=$(hostname)
SERVER_IP=$(hostname -I | awk '{print $1}')

# Log state before change
log_before() {
    echo "[BEFORE] $1" | tee -a $LOG_FILE
}

# Log state after change
log_after() {
    echo "[AFTER] $1" | tee -a $LOG_FILE
}

# Function to check if a package is installed
install_if_not_installed() {
    log_before "$1 installation status check"
    if ! rpm -q $1 &> /dev/null; then
        echo "$1 is not installed. Installing..." | tee -a $LOG_FILE
        sudo yum install -y $1 | tee -a $LOG_FILE
        log_after "$1 installed"
    else
        echo "$1 is already installed. Skipping installation." | tee -a $LOG_FILE
    fi
}

# Function to send notification email (HTML format)
send_notification_html() {
    local subject="$1"
    local body="$2"
    local attachment="$3"
    
    if [ -z "$attachment" ]; then
        echo -e "Subject: $subject\nMIME-Version: 1.0\nContent-Type: text/html\n\n<body>$body</body><br>\nHostname: $HOSTNAME<br>IP Address: $SERVER_IP" | sendmail -t "support@turnupsecurityshield.com"
    else
        echo -e "Subject: $subject\nMIME-Version: 1.0\nContent-Type: text/html\n\n<body>$body</body><br>\nHostname: $HOSTNAME<br>IP Address: $SERVER_IP" | mutt -e "set content_type=text/html" -a "$attachment" -s "$subject" -- "support@turnupsecurityshield.com"
    fi
}

# Dependencies
install_if_not_installed epel-release
install_if_not_installed tar
install_if_not_installed python3
log_before "Link Python to /usr/bin/python"
sudo ln -fs /usr/bin/python3.6 /usr/bin/python | tee -a $LOG_FILE
log_after "Python linked to /usr/bin/python"
install_if_not_installed python-pip

# Install Rootkit Hunter
install_if_not_installed rkhunter
sudo rkhunter --update | tee -a $LOG_FILE
sudo rkhunter --propupd | tee -a $LOG_FILE
sudo rkhunter --version | tee -a $LOG_FILE

# Install ClamAV
install_if_not_installed clamav-server clamav-data clamav-update clamav-filesystem clamav clamav-scanner-systemd clamav-devel clamav-lib clamav-server-systemd
log_before "Freshclam configuration"
sudo sed -i -e "s/^Example/#Example/" /etc/freshclam.conf | tee -a $LOG_FILE
sudo freshclam | tee -a $LOG_FILE
sudo systemctl enable clamd@scan | tee -a $LOG_FILE
sudo systemctl start clamd@scan | tee -a $LOG_FILE
log_after "ClamAV configured and started"

# Install CSF (ConfigServer Security & Firewall)
if ! command -v csf &> /dev/null; then
    echo "CSF is not installed. Installing..." | tee -a $LOG_FILE
    cd /usr/local/src/
    wget https://download.configserver.com/csf.tgz
    tar -xzf csf.tgz
    cd csf
    sudo sh install.sh | tee -a $LOG_FILE
else
    echo "CSF is already installed." | tee -a $LOG_FILE
fi
sudo systemctl restart csf lfd | tee -a $LOG_FILE
sudo systemctl enable csf lfd | tee -a $LOG_FILE

# Install MailScanner for cPanel/WHM (following the official cPanel documentation)
if [ ! -d "/usr/msfe" ]; then
    echo "Installing MailScanner for cPanel/WHM..." | tee -a $LOG_FILE
    log_before "Stopping exim"
    sudo systemctl stop exim | tee -a $LOG_FILE
    cd /usr/src
    wget https://downloads.configserver.com/msinstall.tar.gz | tee -a $LOG_FILE
    tar -xzf msinstall.tar.gz | tee -a $LOG_FILE
    cd msinstall
    sudo ./install.sh | tee -a $LOG_FILE
    sudo systemctl enable MailScanner | tee -a $LOG_FILE
    sudo systemctl start MailScanner | tee -a $LOG_FILE
    sudo systemctl start exim | tee -a $LOG_FILE
    log_after "MailScanner installed and exim restarted"
else
    echo "MailScanner is already installed." | tee -a $LOG_FILE
fi

# Install Recaptcha v2 server-wide
if [ ! -d "/usr/local/src/reCaptcha2_validation-free-master" ]; then
    cd /usr/local/src && wget -O reCaptcha2_validation-free.tar.gz https://github.com/turnuphosting/reCaptcha2_validation-free/archive/master.tar.gz && sudo tar -zxvf reCaptcha2_validation-free.tar.gz && cd reCaptcha2_validation-free-master/install/ && sudo ./install.sh | tee -a $LOG_FILE
    cd /usr/local/src && rm -rf reCaptcha2_validation* | tee -a $LOG_FILE
else
    echo "Recaptcha v2 is already installed." | tee -a $LOG_FILE
fi

# Install Python 3.8 for AlmaLinux 8 and Wordfence CLI
if ! python3.8 --version &> /dev/null; then
    echo "Installing Python 3.8 on AlmaLinux 8..." | tee -a $LOG_FILE
    sudo dnf install python38-pip -y | tee -a $LOG_FILE
fi
pip3.8 --version | tee -a $LOG_FILE

if ! pip3.8 show wordfence &> /dev/null; then
    echo "Installing Wordfence CLI..." | tee -a $LOG_FILE
    pip3.8 install wordfence | tee -a $LOG_FILE
else
    echo "Wordfence CLI is already installed." | tee -a $LOG_FILE
fi

# Set up Wordfence CLI to run via cron
log_before "Setting up Wordfence CLI cron job"
(crontab -l 2>/dev/null; echo "0 0 * * * wordfence malware-scan --include-all-files --output-columns filename -m null-delimited --email support@turnupsecurityshield.com /home | wordfence remediate") | crontab - | tee -a $LOG_FILE
log_after "Wordfence cron job set"

# Install and configure Graylog for centralized logging
if ! rpm -q graylog-server &> /dev/null; then
    echo "Installing Graylog for centralized logging..." | tee -a $LOG_FILE
    install_if_not_installed java-11-openjdk-devel
    sudo rpm -Uvh https://packages.graylog2.org/repo/packages/graylog-4.3-repository_latest.rpm
    sudo yum install -y graylog-server | tee -a $LOG_FILE

    echo "Please enter the root password for cPanel/WHM (for Graylog configuration):"
    read -s ROOT_PASSWORD
    HASHED_PASSWORD=$(echo -n $ROOT_PASSWORD | sha256sum | awk '{print $1}')

    sudo cp /etc/graylog/server/server.conf /etc/graylog/server/server.conf.bak
    sudo sed -i "s/password_secret =/password_secret = $ROOT_PASSWORD/" /etc/graylog/server/server.conf
    sudo sed -i "s/root_password_sha2 =/root_password_sha2 = $HASHED_PASSWORD/" /etc/graylog/server/server.conf
    sudo sed -i "s/rest_listen_uri = http:\/\/127.0.0.1:9000\//rest_listen_uri = http:\/\/$SERVER_IP:9000\//" /etc/graylog/server/server.conf

    sudo systemctl daemon-reload | tee -a $LOG_FILE
    sudo systemctl enable graylog-server | tee -a $LOG_FILE
    sudo systemctl start graylog-server | tee -a $LOG_FILE
    echo "Graylog installed. Access it at http://$SERVER_IP:9000" | tee -a $LOG_FILE
else
    echo "Graylog is already installed." | tee -a $LOG_FILE
fi

# Install and configure ModSecurity with Comodo WAF and OWASP rules
if ! rpm -q mod_security &> /dev/null; then
    echo "Installing ModSecurity and Comodo WAF with OWASP rules..." | tee -a $LOG_FILE
    install_if_not_installed mod_security
    cd /etc/apache2/conf.d && wget https://waf.comodo.com/doc/meta_comodo_apache.yaml && sudo mv meta_comodo_apache.yaml /etc/apache2/conf.d/modsec_vendor_configs/comodo_waf.yaml && sudo bash /etc/apache2/conf.d/modsec_vendor_configs/comodo_waf.yaml | tee -a $LOG_FILE
    sudo wget https://github.com/coreruleset/coreruleset/archive/v4.0.0.tar.gz && sudo tar -xvzf v4.0.0.tar.gz -C /etc/apache2/owasp | tee -a $LOG_FILE
else
    echo "ModSecurity and WAF are already installed." | tee -a $LOG_FILE
fi

# Install Lynis
if ! command -v lynis &> /dev/null; then
    echo "Installing Lynis..." | tee -a $LOG_FILE
    sudo yum install -y lynis | tee -a $LOG_FILE
fi
sudo lynis audit system --cronjob | tee -a /var/log/lynis.log
send_notification_html "Lynis Weekly Scan Report" "Lynis weekly scan completed" /var/log/lynis.log

# Configure Lynis for weekly scan
log_before "Setting up Lynis weekly scan"
(crontab -l 2>/dev/null; echo "0 2 * * 7 /usr/bin/lynis audit system --cronjob | tee -a /var/log/lynis.log && /usr/bin/sendmail -s 'Lynis Weekly Scan Report' support@turnupsecurityshield.com < /var/log/lynis.log") | crontab - | tee -a $LOG_FILE
log_after "Lynis weekly scan set"

# Install and configure Maldet (Linux Malware Detect)
if ! command -v maldet &> /dev/null; then
    echo "Installing Maldet..." | tee -a $LOG_FILE
    cd /usr/local/src && wget http://www.rfxn.com/downloads/maldetect-current.tar.gz && tar -xzf maldetect-current.tar.gz && cd maldetect-* && sudo ./install.sh | tee -a $LOG_FILE
    sudo maldet --update | tee -a $LOG_FILE
else
    echo "Maldet is already installed." | tee -a $LOG_FILE
fi
send_notification_html "Maldet Weekly Scan Report" "Maldet scan completed" /usr/local/maldetect/logs/event_log

log_before "Setting up Maldet weekly scan"
(crontab -l 2>/dev/null; echo "0 0 * * 7 /usr/local/maldetect/maldet --scan-all / | tee -a /usr/local/maldetect/logs/event_log && /usr/bin/sendmail -s 'Maldet Weekly Scan Report' support@turnupsecurityshield.com < /usr/local/maldetect/logs/event_log") | crontab - | tee -a $LOG_FILE
log_after "Maldet weekly scan set"

# Script end
echo "Installation completed. All changes have been logged to $LOG_FILE" | tee -a $LOG_FILE
