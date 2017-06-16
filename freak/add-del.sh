#!/bin/bash

if [[ $USER != 'root' ]]; then
	echo "Maaf, Anda harus menjalankan ini sebagai root"
	exit
fi

MYIP=$(wget -qO- ipv4.icanhazip.com)



    NORMAL=`echo "\033[m"`
    MENU=`echo "\033[36m"` #Blue
    NUMBER=`echo "\033[33m"` #yellow
    FGRED=`echo "\033[41m"`
    RED_TEXT=`echo "\033[31m"`
    LGREEN=`echo "\033[0m\033[1;32m"`
    ENTER_LINE=`echo "\033[33m"`
    LRED=`echo "\033[0m\033[1;31m"`
    BLUE=`echo "\033[0m\033[1;36m"`

setps3() {
    PS3="$1 (Ketik Enter Untuk Lanjutkan)> "
}
setmainprompt() {
    setps3 "Akun Panel"
}
setaddprompt() {
    setps3 "Panel Tambah Akun"
}

pressenter() {
    read -p "Ketik Enter Untuk Lanjutkan: " _tmp
}

err() {
    echo 1>&2 ${CMDNAME} ERROR: $*
    return 1
}
msg() {
    echo ${CMDNAME} NOTICE: $*
    return 0
}

badchoice() {
    err "Bad choice!";
    return 1
}

do_adduser() {
echo "------------------------------- MEMBUAT AKUN SSH -------------------------------"
echo ""

read -p "Isi username: " USER

egrep "^$USER" /etc/passwd >/dev/null
if [ $? -eq 0 ]; then
	echo "Username [$USER] sudah ada!"
	exit 1
else
	read -p "Isi password akun [$USER]: " PASS
	read -p "Berapa hari akun [$USER] aktif: " AKTIF

	today="$(date +"%Y-%m-%d")"
	expire=$(date -d "$AKTIF days" +"%Y-%m-%d")
	useradd -M -N -s /bin/false -e $expire $USER
	echo $USER:$PASS | chpasswd

	echo ""
	echo "-----------------------------------"
	echo "Data Login:"
	echo "-----------------------------------"
	echo "Host/IP: $MYIP"
	echo "Username: $USER"
	echo "Password: $PASS"
	echo "Dropbear Port: 443, 110, 109"
	echo "OpenSSH Port: 22, 143, 80"
	echo "Squid Proxy: 80, 8080, 3128"
	echo "OpenVPN: http://$MYIP:81/client.ovpn"

	echo "Masa Aktif sampai: $(date -d "$AKTIF days" +"%d-%m-%Y")"
	echo "-----------------------------------"
    echo "Selamat Menggunakan dan Terimakasih"
	echo ""
fi
}

do_genuser() {
echo "--------------------------- AUTO GENERATE AKUN SSH ---------------------------"
echo ""

read -p "Berapa jumlah akun yang akan dibuat: " JUMLAH
read -p "Berapa hari akun aktif: " AKTIF

today="$(date +"%Y-%m-%d")"
expire=$(date -d "$AKTIF days" +"%Y-%m-%d")

echo ""
echo "-----------------------------------------------------------------"
echo "Data Login:"
echo "-----------------------------------------------------------------"
echo "Host/IP: $MYIP"
echo "Dropbear Port: 443, 110, 109"
echo "OpenSSH Port: 22, 143, 80"
echo "Squid Proxy: 80, 8080, 3128"
echo "OpenVPN: http://$MYIP:81/client.ovpn"

for (( i=1; i <= $JUMLAH; i++ ))
do
	USER=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 15 | head -n 1`;
	useradd -M -N -s /bin/false -e $expire $USER
	#PASS=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 15 | head -n 1`;
	echo $USER:$USER | chpasswd
	
	echo "$i. Username/Password: $USER"
done

echo "Masa Aktif sampai : $(date -d "$AKTIF days" +"%d-%m-%Y")"
echo -e "================================================================"
echo    "                           Fa'i Smart					       "
}

do_return_menu() {
clear
menu
exit 0
}

do_deleteuser() {
echo -e "${LGREEN}-------------------------------${NORMAL}"
echo -e "USERNAME          EXP DATE     "
echo -e "${LGREEN}-------------------------------${NORMAL}"
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
read -p "Isi username: " USER

egrep "^$USER" /etc/passwd >/dev/null
if [ $? -eq 0 ]; then
	echo ""
	read -p "Apakah Anda ingin menghapus akun [$USER] [y/n]: " -e -i y REMOVE
	if [[ "$REMOVE" = 'y' ]]; then
		userdel $USER
		echo ""
		echo "Akun [$USER] berhasil dihapus!"
	else
		echo ""
		echo "Penghapusan akun [$USER] dibatalkan!"
	fi
else
	echo "Username [$USER] belum terdaftar!"
	exit 1
fi
}

## MAIN PROGRAM

CMDNAME=$(basename $0)
#uidcheck   #uncomment when need

_arr_main=("Tambah akun" "Auto Generate Akun"  "Hapus Akun" "Kembali Ke Menu Awal")
setmainprompt
select main_action in "${_arr_main[@]}"
do
    case "$REPLY" in
        1) do_adduser ;;
        2) do_genuser  ;;
        3) do_deleteuser  ;;
        4) do_return_menu ;;
        *) badchoice ;;
    esac
    setmainprompt
done