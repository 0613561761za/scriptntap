#!/bin/bash

if [[ $USER != 'root' ]]; then
	echo "Maaf, Anda harus menjalankan ini sebagai root"
	exit
fi

MYIP=$(wget -qO- ipv4.icanhazip.com)


# go to root
cd


   NORMAL=`echo "\033[m"`
    MENU=`echo "\033[36m"` #Blue
    NUMBER=`echo "\033[33m"` #yellow
    FGRED=`echo "\033[41m"`
    RED_TEXT=`echo "\033[31m"`
	LGREEN=`echo "\033[0m\033[1;32m"`
    ENTER_LINE=`echo "\033[33m"`
	LRED=`echo "\033[0m\033[1;31m"`
	BLUE=`echo "\033[0m\033[1;36m"`
echo -e "${LGREEN}-------------------------------${NORMAL}"
echo -e "USERNAME          EXP DATE     "
echo -e "${LGREEN}-------------------------------${NORMAL}"
while read expired
do
        AKUN="$(echo $expired | cut -d: -f1)"
        ID="$(echo $expired | grep -v nobody | cut -d: -f3)"
        exp="$(chage -l $AKUN | grep "Account expired" | awk -F": " '{print $2}')"
        if [[ $ID -ge 1000 ]]; then
        printf "%-17s %2s\n" "$AKUN" "$exp"
        fi
done < /etc/passwd
JUMLAH="$(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd | wc -l)"
echo -e "${LGREEN}-------------------------------${NORMAL}"

read -p "Masukkan username: " USER

egrep "^$USER" /etc/passwd >/dev/null
if [ $? -eq 0 ]; then
	read -p "Berapa hari akun [$USER] aktif: " AKTIF
	
	expiredate=$(chage -l $USER | grep "Account expires" | awk -F": " '{print $2}')
	today=$(date -d "$expiredate" +"%Y-%m-%d")
	expire=$(date -d "$today + $AKTIF days" +"%Y-%m-%d")
	chage -E "$expire" $USER


	echo ""
	echo "-----------------------------------"
	echo "Data Login:"
	echo "-----------------------------------"
	echo "Host/IP: $MYIP"
	echo "Username: $USER"
	echo "Dropbear Port: 443, 109, 110"
	echo "OpenSSH Port: 22, 80, 143"
	echo "Squid Proxy: 80, 8080, 3128"
	echo "OpenVPN: http://$MYIP:81/client.ovpn"
	echo "Valid s/d: $(date -d "$today + $AKTIF days" +"%d-%m-%Y")"
	echo "-----------------------------------"
else
	echo "Username [$USER] belum terdaftar!"
	exit 1
fi

cd ~/
rm -f /root/daftarip
