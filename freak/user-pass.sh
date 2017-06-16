#!/bin/bash

if [[ $USER != 'root' ]]; then
	echo "Maaf, Anda harus menjalankan ini sebagai root"
	exit
fi

MYIP=$(wget -qO- ipv4.icanhazip.com)


# go to root
cd


clear
echo "------------------------------- MEMBUAT AKUN SSH -------------------------------"

echo "								Fa'i Smart        		 		                 " 

echo ""
echo ""
echo "-------------------------------"
echo "USERNAME          EXP DATE     "
echo "-------------------------------"
while read expired
do
        AKUN="$(echo $expired | cut -d: -f1)"
        ID="$(echo $expired | grep -v nobody | cut -d: -f3)"
        exp="$(chage -l $AKUN | grep "Account expires" | awk -F": " '{print $2}')"
        if [[ $ID -ge 1000 ]]; then
        printf "%-17s %2s\n" "$AKUN" "$exp"
        fi
done < /etc/passwd
echo "-------------------------------"
echo ""
read -p "Isi username: " username
read -p "Masukkan Password Baru [$username]: " password1
read -p "Ulangi Password Baru [$username]: " password2

# Check both passwords match
if [ $password1 != $password2 ]; then
echo "Password Tidak Sama, Silakan Ulangi Lagi!"
clear
panel
     
fi

# Does User exist?
id $username &> /dev/null
if [ $? -eq 0 ]; then
echo "User $username Ditemukan.. Memulai Mengganti Password."
else
echo "User $username tidak ditemukan - Password gagal diganti untuk $username"; exit 
fi

# Change password
echo -e "$password1\n$password1" | passwd $username
echo ""
echo ""
echo -e "Password dengan Username $username Sudah diperbarui"
echo
echo -e "Password telah diganti dengan $password1"
echo -e "=================================================="
cd ~/