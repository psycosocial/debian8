#!/bin/bash

# go to root
cd
echo ""
echo "==========================================="
echo "            Installasi Dimulai             "
echo "==========================================="

myip=`ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0' | head -n1`;
myint=`ifconfig | grep -B1 "inet addr:$myip" | head -n1 | awk '{print $1}'`;

flag=0

if [[ $USER != "root" ]]; then
	echo "Maaf, Anda harus menjalankan ini sebagai root"
	exit
fi

# initialisasi var
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
MYIP=`ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0'`;
MYIP2="s/xxxxxxxxx/$MYIP/g";
Psyco="https://raw.githubusercontent.com/psycosocial/debian8/master";

# install curl dll
apt-get update
apt-get -y install curl nano git screen make zlib1g-dev libssl-dev cmake gcc
apt-get -y install build-essential

# Merubah waktu ke GMT+7
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

# set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
service ssh restart

# remove unused
apt-get -y --purge remove samba*;
apt-get -y --purge remove apache2*;
apt-get -y --purge remove sendmail*;
apt-get -y --purge remove bind9*;

# install screenfetch
cd
wget -O /usr/bin/screenfetch-dev "$Psyco/screenfetch-dev"
chmod +x /usr/bin/screenfetch-dev
echo "clear" >> .profile
echo "screenfetch-dev" >> .profile

#Blockir Torrent
iptables -A OUTPUT -p tcp --dport 6881:6889 -j DROP
iptables -A OUTPUT -p udp --dport 1024:65534 -j DROP
iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP

# install dropbear
apt-get -y install dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=442/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 109 -p 110 -p 666 -p 80"/g' /etc/default/dropbear
sed -i 's/DROPBEAR_BANNER=""/DROPBEAR_BANNER"/etc/issue.net"/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
service ssh restart
service dropbear restart

#upgrade dropbear 2018
wget https://matt.ucc.asn.au/dropbear/releases/dropbear-2018.76.tar.bz2
bzip2 -cd dropbear-2018.76.tar.bz2  | tar xvf -
cd dropbear-2018.76
./configure
make && make install
service dropbear restart
mv /usr/sbin/dropbear /usr/sbin/dropbear1
ln /usr/local/sbin/dropbear /usr/sbin/dropbear
cd
service dropbear restart

#install Badvpn
wget https://github.com/ambrop72/badvpn/archive/1.999.130.tar.gz
tar -xzvf 1.999.130.tar.gz
mkdir badvpn-build
cd badvpn-build
cmake ~/badvpn-1.999.130 -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
make install
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300' /etc/rc.local
cd
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300

# install squid3
apt-get -y install squid3
wget -O /etc/squid3/squid.conf "$Psyco/squid.conf"
sed -i $MYIP2 /etc/squid3/squid.conf;

#install Stunnel
apt-get install stunnel4 -y
wget -O /etc/stunnel/stunnel.conf "$Psyco/stunnel.conf"
openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out cert.pem -days 1095
cat key.pem cert.pem >> /etc/stunnel/stunnel.pem
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
/etc/init.d/stunnel4 restart

#Menambah Ram 1 Gb
cd
dd if=/dev/zero of=/swapfile bs=1024 count=1024k
mkswap /swapfile
swapon /swapfile
echo "/swapfile          swap            swap    defaults        0 0" >> /etc/fstab
chmod 644 /etc/fstab
sysctl vm.swappiness=10
chown root:root /swapfile 
chmod 0600 /swapfile

#restart service
cd
service ssh restart
service dropbear restart
service squid3 restart
service stunnel4 restart

rm -f /root/.bash_history && history -c
echo "unset HISTFILE" >> /etc/profile
echo ""  | tee -a log-install.txt
echo -e "\e[1;34m#####  \  \e[0m\e[1;35m ###### \ \e[0m\e[1;34m..:[\e[0m \e[1;35mIdr@ C4k3pZ\e[0m \e[1;34m]:..\e[0m \e[1;33m##### \  \e[0m"  | tee -a log-install.txt
echo -e "\e[1;34m##  _## \ \e[0m\e[1;35m ##  ___| \e[0m                                               \e[1;33m##  _## |     \e[0m"  | tee -a log-install.txt
echo -e "\e[1;34m## | ## | \e[0m\e[1;35m ## |     \e[0m\e[1;36m ## \ ## \  \e[0m\e[1;31m  ### \ \e[0m\e[1;33m ## |### | \e[0m"  | tee -a log-install.txt
echo -e "\e[1;34m#####   / \e[0m\e[1;35m  #### \  \e[0m\e[1;36m ## | ## | \e[0m\e[1;31m ##  __/ \e[0m\e[1;33m #### ## | \e[0m"  | tee -a log-install.txt
echo -e "\e[1;34m##  ___/  \e[0m\e[1;35m     ## | \e[0m\e[1;36m  #####  / \e[0m\e[1;31m ## |    \e[0m\e[1;33m ### /## | \e[0m"  | tee -a log-install.txt
echo -e "\e[1;34m## |      \e[0m\e[1;35m     ## | \e[0m\e[1;36m    ##  /  \e[0m\e[1;31m ## |    \e[0m\e[1;33m ## | ## | \e[0m"  | tee -a log-install.txt
echo -e "\e[1;34m## |      \e[0m\e[1;35m #####  | \e[0m\e[1;36m  ###  /   \e[0m\e[1;31m   ### \ \e[0m\e[1;33m  #####  | \e[0m"  | tee -a log-install.txt
echo -e "\e[1;34m\__|      \e[0m\e[1;35m \_____/  \e[0m\e[1;36m  \___/    \e[0m\e[1;31m   \___/ \e[0m\e[1;33m  \_____/ \e[0m"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "OpenSSH  : 22"  | tee -a log-install.txt
echo "Dropbear : 80, 109, 110, 442"  | tee -a log-install.txt
echo "SSL      : 443"  | tee -a log-install.txt
echo "Squid3   : 8080, 3128 (limit to IP SSH)"  | tee -a log-install.txt
echo "badvpn   : badvpn-udpgw port 7300"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt

rm -rf dropbear-2018.76
rm -f dropbear-2018.76.tar.bz2
rm -f debian.sh
