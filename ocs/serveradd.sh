#!/bin/bash
#
# Script Copyright Fa'i Smart
# ==========================
# 

if [[ $USER != 'root' ]]; then
	echo "Maaf, Anda harus menjalankan ini sebagai root"
	exit
fi
MYIP=$(wget -qO- ipv4.icanhazip.com);

cd
apt-get -y install perl libnet-ssleay-perl openssl libauthen-pam-perl libpam-runtime libio-pty-perl apt-show-versions python
apt-get -y install apt-transport-https
wget http://prdownloads.sourceforge.net/webadmin/webmin_1.831_all.deb
dpkg --install webmin_1.831_all.deb
sed -i 's/ssl=1/ssl=0/g' /etc/webmin/miniserv.conf
service webmin restart
apt-get -y --force-yes -f install libxml-parser-perl

clear
echo ""
echo "-------------------------------------------"
echo "Pemasangan Selesai, Silahkan Tambahkan Server $MYIP ke Panel Reseller kamu."
echo "-------------------------------------------"
echo ""
rm -f /root/webmin_1.831_all.deb
rm -f /root/serveradd.sh