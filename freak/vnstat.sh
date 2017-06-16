#!/bin/bash
#Copyright wwww.fawzya.net

if [[ $USER != 'root' ]]; then
	echo "Maaf, Anda harus menjalankan ini sebagai root"
	exit
fi

MYIP=$(wget -qO- ipv4.icanhazip.com)

# go to root
cd

MYIP=$(wget -qO- ipv4.icanhazip.com);
echo ""
echo ""
echo "URL : http://$MYIP:81/vnstat/"

cd ~/
rm -f /root/daftarip