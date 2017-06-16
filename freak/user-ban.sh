#!/bin/bash
#Copyright www.fornesia.com


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
echo ""
        read -p "Masukkan Nama User yang akan di BANNED : " Login
        passwd -l $Login  
echo ""
# Does User exist?
id $Login &> /dev/null
if [ $? -eq 0 ]; then
echo ""
echo -e "${Login} Terdaftar... ${Login} Berhasil di ${LRED}Banned${NORMAL} !!."
else
echo "${Login} Tidak terdaftar - ${Login} Gagal di BANNED !! "; exit 
fi

cd ~/
rm -f /root/daftarip