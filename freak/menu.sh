#!/bin/bash
#script copyright www.fornesia.com


if [[ $USER != 'root' ]]; then
	echo "Maaf, Anda harus menjalankan ini sebagai root"
	exit
fi

MYIP=$(wget -qO- ipv4.icanhazip.com)

# go to root
cd


IP=`dig +short myip.opendns.com @resolver1.opendns.com`
show_menu(){
    NORMAL=`echo "\033[m"`
    MENU=`echo "\033[36m"` #Blue
    NUMBER=`echo "\033[33m"` #yellow
    FGRED=`echo "\033[41m"`
    RED_TEXT=`echo "\033[31m"`
	LGREEN=`echo "\033[0m\033[1;32m"`
    ENTER_LINE=`echo "\033[33m"`
	LRED=`echo "\033[0m\033[1;31m"`
	BLUE=`echo "\033[0m\033[1;36m"`
	
	echo -e "${NUMBER}----------- Selamat Datang di Server - IP: $IP -----------${NORMAL}"
	echo -e "${NORMAL}==========================================================="
    echo -e "${LRED}OpenSSH            : ${BLUE}22, 80, 143"
	echo -e "${LRED}Dropbear           : ${BLUE}443, 109, 110"
	echo -e "${LRED}SquidProxy         : ${BLUE}$IP:8080 (limit to IP SSH)"
	echo -e "${LRED}badvpn             : ${BLUE}badvpn-udpgw port 7300"
	echo -e "${LRED}Webmin             : ${BLUE}https://$IP:10000/"
	echo -e "${LRED}OpenVPN            : ${BLUE}$IP:81/client.ovpn"

	echo -e "${NORMAL}"
    echo -e "${NORMAL}------------------------------------------------------------------${NORMAL}"
	echo -e "${NUMBER}Apa yang ingin anda lakukan? ${NUMBER}"
	echo -e "${NORMAL}"
    echo -e "${LRED} 1)${NORMAL} Buat/Hapus Akun SSH/OpenVPN (${BLUE}add-del${NORMAL})"
    echo -e "${LRED} 2)${NORMAL} Panel Akun PPTP VPN (${BLUE}add-pptp${NORMAL})"
    echo -e "${LRED} 3)${NORMAL} Ganti Password Akun SSH/OpenVPN (${BLUE}user-pass${NORMAL})"
    echo -e "${LRED} 4)${NORMAL} Ubah Masa Aktif Akun SSH/OpenVPN (${BLUE}expiry-change${NORMAL})"
    echo -e "${LRED} 5)${NORMAL} Perbarui Akun SSH/OpenVPN (${BLUE}user-renew${NORMAL})"
    echo -e "${LRED} 6)${NORMAL} Cek Login Dropbear, OpenSSH, PPTP VPN dan OpenVPN (${BLUE}user-login${NORMAL})"
    echo -e "${LRED} 7)${NORMAL} Monitoring Dropbear (${BLUE}dropmon [PORT]${NORMAL})"
	echo -e "${LRED} 8)${NORMAL} Kill Multi-login (${BLUE}user-limit${NORMAL})"
	echo -e "${LRED} 9)${NORMAL} Daftar Akun dan Tanggal Expired (${BLUE}user-list${NORMAL})"
	echo -e "${LRED}10)${NORMAL} Daftar Akun akan Expired Minggu ini (${BLUE}user-expired-list${NORMAL})"
	echo -e "${LRED}11)${NORMAL} Daftar Akun Yang Sudah Expired (${BLUE}user-expired${NORMAL})"
	echo -e "${LRED}12)${NORMAL} Daftar Akun Aktif (${BLUE}user-active-list${NORMAL})"
	echo -e "${LRED}13)${NORMAL} Disable Akun Yang Sudah Expired (${BLUE}disable-user-expired${NORMAL})"
	echo -e "${LRED}14)${NORMAL} Delete Akun Yang Sudah Expired (${BLUE}del-user-expired${NORMAL})"
	echo -e "${LRED}15)${NORMAL} BANNED Akun SSH/VPN (${BLUE}user-ban${NORMAL})"
	echo -e "${LRED}16)${NORMAL} UNBANNED Akun SSH/VPN (${BLUE}user-unban${NORMAL})"
	echo -e "${LRED}17)${NORMAL} Restart Dropbear (${BLUE}service dropbear restart${NORMAL})"
	echo -e "${LRED}18)${NORMAL} Benchmark (${BLUE}benchmark${NORMAL})"
	echo -e "${LRED}19)${NORMAL} Cek Graphic CPU Load dan Memory (${BLUE}mrtg${NORMAL})"
	echo -e "${LRED}20)${NORMAL} Memory Usage (${BLUE}ps-mem${NORMAL})"
	echo -e "${LRED}21)${NORMAL} Speedtest (${BLUE}speedtest --share${NORMAL})"
	echo -e "${LRED}22)${NORMAL} Cek Bandwith VPS (${BLUE}vnstat${NORMAL})"
	echo -e "${LRED}23)${NORMAL} Reboot Server (${BLUE}reboot${NORMAL})"
 

	echo -e "${NORMAL}"
	echo -e "${LRED} x)${NORMAL} Exit"	
	echo -e "${NORMAL}"
    echo -e "${NORMAL}Silakan isi Angka pilihan anda, lalu tekan ${RED_TEXT}ENTER ${NORMAL}"
    read opt
}
function option_picked() {
    COLOR='\033[01;31m' # bold red
    RESET='\033[00;00m' # normal white
    MESSAGE=${@:-"${RESET}Error: No message passed"}
    echo -e "${COLOR}${MESSAGE}${RESET}"
}

clear
show_menu
while [ opt != '' ]
    do
    if [[ $opt = "" ]]; then 
	clear;
            exit;
			
    else
        case $opt in
        1) clear;
		echo -e "${NORMAL}";
			option_picked "Panel Tambah/Delete Akun";
			add-del
        exit
        ;;
		
        2) clear;
		echo -e "${NORMAL}";
			option_picked "Panel Akun PPTP, Untuk pertama kali silahkan pilih Option 1";
			add-pptp
        exit
        ;;

        3) clear;
		   echo -e "${NORMAL}";
            option_picked "Panel Ganti Password Akun SSH/OpenVPN";
            user-pass; 
        exit
            ;;

        4) clear;
		   echo -e "${NORMAL}";
            option_picked "Pengubahan Masa Aktif Akun SSH/OpenVPN";
            expiry-change; 
            exit
            ;;
			
        5) clear;
		   echo -e "${NORMAL}";
            option_picked "Pembaharuan data Akun SSH/OpenVPN";
            user-renew; 
            exit
            ;;

        6) clear;
		   echo -e "${NORMAL}";
            option_picked "Panel Cek User Login";
            user-login; 
			exit
            ;;
			
        7) clear;
		   echo -e "${NORMAL}";
            option_picked "Monitoring Dropbear [443]";
            dropmon 443;
			exit
            ;;
			
        8) clear;
		   echo -e "${NORMAL}";
            option_picked "Limit User Dengan 2 Login";
            user-limit;
			exit
            ;;

        9) clear;
		   echo -e "${NORMAL}";
            option_picked "Melihat Daftar dan Tanggal Akun yang Expired";
            user-list;
			exit
            ;;	
			
		10) clear;
		   echo -e "${NORMAL}";
            option_picked "Melihat Daftar Akun Expired Minggu ini";
            cat /root/infouser.txt;
			exit
            ;;	

        11) clear;
		   echo -e "${NORMAL}";
            option_picked "Melihat Daftar Akun yang sudah Expired";
			user-expired
            cat /root/expireduser.txt;
			exit
            ;;				
			
        12) clear;
		   echo -e "${NORMAL}";
            option_picked "Melihat daftar Akun Aktif";
            cat  /root/activeuser.txt;
			exit
            ;;		


        13) clear;
		   echo -e "${NORMAL}";
            option_picked "Disable Akun Expired";
            user-expired;
			exit
            ;;		

        14) clear;
		   echo -e "${NORMAL}";
            option_picked "Delete Akun Expired";
            del-user-expired;
			exit
            ;;				
			
		15) clear;
		   echo -e "${NORMAL}";
            option_picked "BANNED akun SSH/VPN";
            user-ban;
			exit
            ;;		
			
        16) clear;
		   echo -e "${NORMAL}";
            option_picked "UNBANNED akun SSH/VPN";
            user-unban;
			exit
            ;;		
			
        17) clear;
		   echo -e "${NORMAL}";
            option_picked "Restart Dropbear";
			service dropbear restart;
			exit
            ;;	
			
        18) clear;
		   echo -e "${NORMAL}";
            option_picked "Cek Kualitas VPS";
            benchmark;
			exit
            ;;		
			
        19) clear;
		   echo -e "${NORMAL}";
            option_picked "Cek Graphic CPU Load dan Memory Silakan Kunjungi Alamat Dibawah";
            mrtg;
			exit
            ;;

		20)	clear;
		   echo -e "${NORMAL}";
            option_picked "Cek Memory Usage VPS";
            ps-mem;
			exit
            ;;
			
		21) clear;
		   echo -e "${NORMAL}";
            option_picked "Share Speedtest VPS";
            speedtest --share;
			exit
            ;;	
			
		22)	clear;
		   echo -e "${NORMAL}";
            option_picked "Cek Bandwith VPS Silakan Kunjungi Alamat Dibawah";
            vnstat;
			exit
            ;;
			
        23) clear;
		   echo -e "${NORMAL}";
            option_picked "Reboot Server VPS";
            reboot;
			exit
            ;;
			
			
        x)clear;
		exit;
        ;;

        \n)exit;
        ;;

        *)clear;
        option_picked "Pick an option from the menu";
        show_menu;
        ;;
    esac
fi
done