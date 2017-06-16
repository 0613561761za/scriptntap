#!/bin/bash

if [[ $USER != 'root' ]]; then
	echo "Maaf, Anda harus menjalankan ini sebagai root"
	exit
fi

MYIP=$(wget -qO- ipv4.icanhazip.com)

# go to root
cd


read -p "Username : " Login
read -p "Password : " Pass
read -p "Expired (hari): " fnsaktif

IP=`dig +short myip.opendns.com @resolver1.opendns.com`
useradd -e `date -d "$fnsaktif days" +"%Y-%m-%d"` -s /bin/false -M $Login
exp="$(chage -l $Login | grep "Account expires" | awk -F": " '{print $2}')"
echo -e "$Pass\n$Pass\n"|passwd $Login &> /dev/null
echo -e ""
echo -e "Data Login"
echo -e "=========-account-=========="
echo -e "Host: $IP" 
echo -e "Username: $Login"
echo -e "Password: $Pass"
echo -e "Dropbear Port: 443, 110, 109"
echo -e "OpenSSH Port: 22, 143, 80"
echo -e "Squid: 80, 8080, 3128"
echo -e "OVPN: http://$IP:81/client.ovpn"
echo -e "-----------------------------"
echo -e "Aktif Sampai: $exp"
echo -e "==========================="

cd ~/
rm -f /root/daftarip