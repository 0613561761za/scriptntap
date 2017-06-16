#!/bin/bash
#script copyright Fa'i Smart

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
echo
  echo -e "${BLUE}----------- Hai Admin, Selamat datang di Server $MYIP -----------${NORMAL}"
        echo -e "   Jika butuh bantuan hubungi Fa'i Smart (Whatsapp: 081556644323)   "
echo -e "${NORMAL}---------- Silakan ketik ${LRED}menu ${NORMAL}untuk masuk ke Fitur Menu VPS ----------${NORMAL}"
echo ""
