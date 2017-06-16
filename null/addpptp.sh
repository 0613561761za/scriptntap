#!/bin/bash
# Interactive PoPToP install script for an OpenVZ VPS
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

echo "###############################################################"
echo "Jika Pertama kali Silahkan Install PPTP dengan memilih menu 1."
echo "Selanjutnya kalian pilih menu 2 untuk menambah akun."
echo "###############################################################"
echo
echo
echo "###############################################################"
echo -e "${LGREEN}Silahkan Memilih Menu : ${NORMAL}"
echo
echo "1) Install PPTP server dan Membuat Akun Baru"
echo "2) Membuat Akun PPTP VPN"
echo
echo "###############################################################"
read x
if test $x -eq 1; then
	echo "Silahkan masukan Username Untuk Akun PPTP:"
	read u
	echo "Silahkan masukan Password Untuk Akun PPTP:"
	read p

# get the VPS IP
ip=`ifconfig venet0:0 | grep 'inet addr' | awk {'print $2'} | sed s/.*://`

echo
echo "######################################################"
echo "Download dan install PoPToP"
echo "######################################################"
apt-get update
apt-get -y install pptpd

echo
echo "######################################################"
echo "Membuat config server"
echo "######################################################"
cat > /etc/ppp/pptpd-options <<END
name pptpd
refuse-pap
refuse-chap
refuse-mschap
require-mschap-v2
require-mppe-128
ms-dns 8.8.8.8
ms-dns 8.8.4.4
proxyarp
nodefaultroute
lock
nobsdcomp
END

# setting up pptpd.conf
echo "option /etc/ppp/pptpd-options" > /etc/pptpd.conf
echo "logwtmp" >> /etc/pptpd.conf
echo "localip $ip" >> /etc/pptpd.conf
echo "remoteip 10.1.0.1-100" >> /etc/pptpd.conf

# adding new user
echo "$u	*	$p	*" >> /etc/ppp/chap-secrets

#Forwarding IPv4 and Enabling it on boot

cat >> /etc/sysctl.conf <<END
net.ipv4.ip_forward=1
END
sysctl -p

#Updating IPtables Routing and Enabling it on boot"

iptables -t nat -A POSTROUTING -j SNAT --to $ip
# saves iptables routing rules and enables them on-boot
iptables-save > /etc/iptables.conf

cat > /etc/network/if-pre-up.d/iptables <<END
#!/bin/sh
iptables-restore < /etc/iptables.conf
END

chmod +x /etc/network/if-pre-up.d/iptables
cat >> /etc/ppp/ip-up <<END
ifconfig ppp0 mtu 1400
END

#Restarting PoPToP

sleep 5
/etc/init.d/pptpd restart

echo
echo "######################################################"
echo -e "${LGREEN}SERVER BERHASIL DI INSTALL${NORMAL}"
echo
echo "Silahkan login ke PPTP $ip dengan akun ini:"
echo
echo "Username:$u ##### Password: $p"
echo
echo "######################################################"

# runs this if option 2 is selected
elif test $x -eq 2; then
	echo "Silahkan masukan Username Untuk Akun PPTP:"
	read u
	echo "Silahkan masukan Password Untuk Akun PPTP:"
	read p

# get the VPS IP
ip=`ifconfig venet0:0 | grep 'inet addr' | awk {'print $2'} | sed s/.*://`

# adding new user
echo "$u	*	$p	*" >> /etc/ppp/chap-secrets

echo
echo "######################################################"
echo -e "${LGREEN}PPTP AKUN BERHASIL DITAMBAHKAN !${NORMAL}"
echo
echo "Silahkan login ke PPTP $ip dengan akun ini:"
echo
echo "Username:$u ##### Password: $p"
echo
echo "######################################################"

else
echo "Invalid selection, quitting."
exit
fi
cd ~/
rm -f /root/daftarip