#!/bin/bash
IP=$(curl http://169.254.169.254/latest/dynamic/instance-identity/document | grep "privateIp")
REGION=$(curl http://169.254.169.254/latest/dynamic/instance-identity/document | grep "region")
AZ=$(curl http://169.254.169.254/latest/dynamic/instance-identity/document | grep "availabilityZone")
sudo sed -i 's/listen       80;/listen       8888;/' /etc/nginx/nginx.conf
sudo echo -e "<h4>$IP</h4><br><h4>$REGION</h4><br><h4>$AZ</h4>" > /usr/share/nginx/html/index.html
sudo systemctl start nginx
sudo systemctl enable nginx
