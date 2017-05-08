#!/bin/bash

# Colors
red=$'\e[1;31m'
grn=$'\e[1;32m'
yel=$'\e[1;33m'
blu=$'\e[1;34m'
mag=$'\e[1;35m'
cyn=$'\e[1;36m'
end=$'\e[0m'

# Crea fichero log.
exec > >(tee -i /var/log/ispconfig_setup.log)
exec 2>&1

clear

echo "========================================="
echo "Instalacion de ISPConfig 3.1"
echo "========================================="
echo

# Comprobar si el usuario es root.
echo -n " - Comprobando permisos... "
if [ $(id -u) != "0" ]; then
  echo "${red}ERROR: Se debe ejecutar este script como root.${end}"
  exit 1
else
  echo "${grn}OK${end}"
fi

# Comprobar acceso internet
echo -n " - Comprobando conexion a internet... "
ping -q -c 3 git.ispconfig.org > /dev/null 2>&1
if [ ! "$?" -eq 0 ]; then
  echo -e "${red}ERROR: Sin acceso a internet.${end}\n"
  exit 1
else
  echo "${grn}OK${end}"
fi

# Comprobar si ispconfig esta instalado
echo -n " - Comprobando instalaciones previas... "
if [ -f /usr/local/ispconfig/interface/lib/config.inc.php ]; then
  echo -e "${red}ERROR: Instalacion previa detectada. Saliendo...${end}\n"
  exit 1
else
  echo "${grn}OK${end}"
fi

# Importar fichero de variables
echo -n " - Importando fichero install.cfg... "
if [ ! -e "install.cfg" ]; then
  echo -e "${red}ERROR: el fichero no existe${end}\n"
  exit 1
elif grep --quiet "chang3me" install.cfg; then
  echo -e "${red}ERROR: el fichero no ha sido modificado${end}\n"
  exit 1
else
  source install.cfg
  echo -e "${grn}OK${end}\n"
fi

# FQDN
CFG_HOSTNAME_FQDN=`hostname -f`;
# Domain
CFG_DOMAIN=`hostname -d`;

echo "========================================="
echo "Preparando el sistema"
echo "========================================="
echo
echo -n " - Ejecutando actualizacion del sistema operativo... "
apt-get -qq update && apt-get -qq upgrade > /dev/null
echo -e "${grn}OK${end}\n"

echo -n " - Reconfigurando dash... "
debconf-set-selections <<< "dash dash/sh boolean false"
dpkg-reconfigure -f noninteractive dash > /dev/null 2>&1
echo -e "${grn}OK${end}\n"

echo -n " - Desinstalando apparmor... "
service apparmor stop
update-rc.d -f apparmor remove
apt-get -qq remove apparmor apparmor-utils > /dev/null
echo -e "${grn}OK${end}\n"

echo "========================================="
echo "Instalacion de paquetes"
echo "========================================="
echo
echo -n " - Utiles para compilar (binutils, autoconf, automake)... "
apt-get -qq install binutils build-essential autoconf automake1.11 libtool flex bison debhelper > /dev/null 2>&1
echo -e "${grn}OK${end}\n"

echo -n " - Utiles de cifrado (openssl)... "
apt-get -qq install openssl > /dev/null
echo -e "${grn}OK${end}\n"

echo -n " - Servidor NTP: ntp ntpdate... "
apt-get -qq install ntp ntpdate > /dev/null
echo -e "${grn}OK${end}\n"

#echo -n "Servidor SQL: mysql-server... "
#export DEBIAN_FRONTEND="noninteractive"
#debconf-set-selections <<< "mysql-server mysql-server/root_password password $CFG_MYSQL_ROOT_PWD"
#debconf-set-selections <<< "mysql-server mysql-server/root_password_again password $CFG_MYSQL_ROOT_PWD"
#apt-get -qq install mysql-server mysql-client > /dev/null
#echo    "${grn}OK${end}"
#echo    "   · ${blu}Configurando mysql: ${end}(/etc/mysql/mysql.conf.d/mysqld.cnf)"
#echo -n "     · Comentando bind-address... "
#sed -i '/bind-address/s/^/#/' /etc/mysql/mysql.conf.d/mysqld.cnf
#echo    "${grn}OK${end}"

echo -n	" - Servidor SQL: mariadb-server... "
apt-get -qq install mariadb-server mariadb-client > /dev/null
echo    "${grn}OK${end}"
echo    "   · ${blu}Configurando mariadb: ${end}(/etc/mysql/mariadb.conf.d/50-server.cnf)"
echo -n "     · Comentando bind-address... "
sed -i '/bind-address/s/^/#/' /etc/mysql/mariadb.conf.d/50-server.cnf
echo    "${grn}OK${end}"

echo -n "     · Asegurando instalacion... "
mysql_secure_installation &> /dev/null <<EOF

n
y
y
y
y
EOF
echo    "${grn}OK${end}"
echo -n "     · Reiniciando mariadb... "
service mysql restart
echo -e "${grn}OK${end}\n"
#echo "UPDATE mysql.user SET password=PASSWORD('$CFG_MYSQL_ROOT_PWD') WHERE user='root';" |  mysql -u root

echo    " - Servidor MAIL: "
echo -n "   · MTA (Mail Transfer Agent): postfix... "
debconf-set-selections <<< "postfix postfix/mailname string $CFG_HOSTNAME_FQDN"
debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"
apt-get -qq install  postfix postfix-doc > /dev/null
echo    "${grn}OK${end}"
echo    "     · ${blu}Configurando postfix: ${end}(/etc/postfix/master.cf)"
cp /etc/postfix/master.cf /etc/postfix/master.cf.orig
sed -i "s/#submission inet n       -       y       -       -       smtpd/submission inet n       -       -       -       -       smtpd/" /etc/postfix/master.cf
sed -i "/syslog_name=postfix\/submission/s/#/ /" /etc/postfix/master.cf
sed -i "/smtpd_tls_security_level=encrypt/s/#/ /" /etc/postfix/master.cf
sed -i "s/#smtps     inet  n       -       y       -       -       smtpd/smtps     inet  n       -       -       -       -       smtpd/" /etc/postfix/master.cf
sed -i "/syslog_name=postfix\/smtps/s/#/ /" /etc/postfix/master.cf
sed -i "/smtpd_tls_wrappermode=yes/s/#/ /" /etc/postfix/master.cf
sed -i "s/#  -o smtpd_sasl_auth_enable=yes/   -o smtpd_sasl_auth_enable=yes\n   -o smtpd_client_restrictions=permit_sasl_authenticated,reject/" /etc/postfix/master.cf
echo -n "       · Activando sumbission... "
echo "${grn}OK${end}"
echo -n "       · Activando smptps... "
echo "${grn}OK${end}"
echo -n "       · Reiniciando postfix... "
service postfix restart
echo "${grn}OK${end}"
echo -n "   · MUA (Mail User Agent): getmail4... "
apt-get -qq install getmail4 > /dev/null
echo    "${grn}OK${end}"
echo -n "   · MDA (Mail Delivery Agent): dovecot... "
apt-get -qq install dovecot-imapd dovecot-pop3d dovecot-sieve dovecot-lmtpd > /dev/null
echo    "${grn}OK${end}"
echo    "   · Conectores MAIL <--> SQL"
echo -n "     · Conector postfix-mysql... "
apt-get -qq install postfix-mysql > /dev/null
echo   "${grn}OK${end}"
echo -n "     · Conector dovecot-mysql... "
apt-get -qq install dovecot-mysql > /dev/null
echo    "${grn}OK${end}"
echo -n "   · Anti Rootkits: rkhunter... "
apt-get -qq install rkhunter > /dev/null
echo    "${grn}OK${end}"
echo    "   · Instalando complementos para el servidor MAIL"
echo -n "     · Filtros SPAM: amavisd... "
apt-get -qq install amavisd-new zoo unzip bzip2 arj nomarch lzop cabextract apt-listchanges libnet-ldap-perl libauthen-sasl-perl daemon libio-string-perl libio-socket-ssl-perl libnet-ident-perl zip libnet-dns-perl > /dev/null 2>&1
echo    "${grn}OK${end}"
echo -n "                     spamassassin... "
apt-get -qq install spamassassin > /dev/null
echo    "${grn}OK${end}"
echo -n "     · Filtros Malware: clamav... "
apt-get -qq install clamav clamav-docs clamav-daemon > /dev/null
echo    "${grn}OK${end}"
echo -n "     · Listas negras: postgrey... "
apt-get -qq install postgrey > /dev/null
echo    "${grn}OK${end}"
echo    "   · ${blu}Configurando complementos del servidor MAIL:${end}"
echo -n "     · Deteniendo el demonio spamassasin... "
service spamassassin stop
update-rc.d -f spamassassin remove
echo    "${grn}OK${end}"
echo -n "     · Configurando antivirus clamav... "
cp /etc/clamav/clamd.conf /etc/clamav/clamd.conf.orig
sed -i "/AllowSupplementaryGroups/s/false/true/" /etc/clamav/clamd.conf
echo    "${grn}OK${end}"
echo    "     · Actualizando firmas antivirus clamav"
echo -n "${mag}       · Puede tomar unos minutos... ${end}"
service clamav-freshclam stop
freshclam > /dev/null 2>&1
service clamav-freshclam start
service clamav-daemon restart
echo -e "${grn}OK${end}\n"

echo -n " - Servidor WEB: apache2... "
apt-get -qq install apache2 apache2-doc apache2-utils > /dev/null
echo    "${grn}OK${end}"
echo    "   · Instalando modulos para apache2: "
echo -n "     · php (libapache2-mod-php)... "
apt-get -qq install libapache2-mod-php > /dev/null
echo    "${grn}OK${end}"
echo -n "     · python (libapache2-mod-python)... "
apt-get -qq install libapache2-mod-python > /dev/null
echo    "${grn}OK${end}"
echo -n "     · fcgid (libapache2-mod-fcgid)... "
apt-get -qq install libapache2-mod-fcgid > /dev/null
echo    "${grn}OK${end}"
echo -n "     · suexec (apache2-suexec-pristine)... "
apt-get -qq install apache2-suexec-pristine > /dev/null
echo    "${grn}OK${end}"
echo -n "     · ruby (libruby)... "
apt-get -qq install libruby > /dev/null
echo    "${grn}OK${end}"
echo -n "   · Instalando PHP (php7.0)... "
apt-get -qq install php7.0 php7.0-common > /dev/null
echo    "${grn}OK${end}"
echo    "   · Instalando complementos para PHP:"
echo    "     · php-mysql, php-pear"
echo    "     · php-imap, php-mcrypt"
echo    "     · php-cgi, php-auth"
echo -n "     · php-curl, ... "
apt-get -qq install php7.0-gd php7.0-mysql php7.0-imap php7.0-cli php7.0-cgi php-pear php-auth php7.0-mcrypt mcrypt imagemagick php7.0-curl php7.0-intl php7.0-pspell php7.0-recode php7.0-sqlite3 php7.0-tidy php7.0-xmlrpc php7.0-xsl memcached php-memcache php-imagick php-gettext php7.0-zip php7.0-mbstring > /dev/null 2>&1
echo    "${grn}OK${end}"
echo -n "   · Instalando phpmyadmin... "
debconf-set-selections <<< "phpmyadmin phpmyadmin/dbconfig-install boolean true"
debconf-set-selections <<< "phpmyadmin phpmyadmin/app-password-confirm password $CFG_MYSQL_PMA_PWD"
debconf-set-selections <<< "phpmyadmin phpmyadmin/mysql/admin-pass password $CFG_MYSQL_PMA_PWD"
debconf-set-selections <<< "phpmyadmin phpmyadmin/mysql/app-pass password $CFG_MYSQL_PMA_PWD"
debconf-set-selections <<< "phpmyadmin phpmyadmin/reconfigure-webserver multiselect apache2"
apt-get -qq install phpmyadmin  > /dev/null
echo    "${grn}OK${end}"
echo -n "   · Instalando letsencrypt (Certificados SSL)... "
apt-get -qq install letsencrypt > /dev/null 2>&1
echo    "${grn}OK${end}"
echo    "${blu}   · Reconfigurando modulos apache2:${end}"
echo -n "     · suexec, rewerite, ssl, cgi, ... "
a2enmod suexec rewrite ssl actions include cgi > /dev/null
echo    "${grn}OK${end}"

echo -n "     · webdav, auth_digest, headers, ... "
a2enmod dav_fs dav auth_digest headers > /dev/null
echo    "${grn}OK${end}"
echo -n "     · ${red}desactivando httpoxy${end} (vulnerable)... "
echo "
<IfModule mod_headers.c>
    RequestHeader unset Proxy early
</IfModule>
" > /etc/apache2/conf-available/httpoxy.conf
a2enconf httpoxy > /dev/null
echo    "${grn}OK${end}"
echo -n "     · aplicaciones x-ruby... "
sed -i '/x-ruby/s/^/#/' /etc/mime.types 
echo    "${grn}OK${end}"

# https://www.ovh.es/hosting/optimizacion-php-fpm.xml
echo    "   · Instalando optimizadores PHP"
echo -n "     · APCu (PHP Opcode cache)... "
apt-get -qq install php-apcu php7.0-opcache > /dev/null
echo    "${grn}OK${end}"

echo -n "     · FASTCGI + PHP-FPM ... "
apt-get -qq install libapache2-mod-fastcgi php7.0-fpm > /dev/null
a2enmod actions fastcgi alias > /dev/null
service apache2 restart
echo    "${grn}OK${end}"

echo -n "     · HHVM (HipHop Virtual Machine)... "
apt-get -qq install software-properties-common > /dev/null
apt-key adv --recv-keys --keyserver hkp://keyserver.ubuntu.com:80 0x5a16e7281be7a449 > /dev/null 2>&1
add-apt-repository "deb http://dl.hhvm.com/ubuntu xenial main" > /dev/null 2>&1
apt-get -qq update > /dev/null
apt-get -qq install hhvm > /dev/null
service apache2 restart
echo -e "${grn}OK${end}\n"

echo -n " - Servidor FTP: pure-ftpd... "
apt-get -qq install pure-ftpd-common > /dev/null
echo    "${grn}OK${end}"
echo -n "   · Conector FTP <--> SQL (pure-ftpd-mysql)... " 
apt-get -qq install pure-ftpd-mysql > /dev/null
echo    "${grn}OK${end}"
echo    "   · ${blu}Configurando servidor FTP ${end}(/etc/default/pure-ftpd-common)"
echo -n "     · Activando modo standalone ... "
sed -i 's/STANDALONE_OR_INETD=inetd/STANDALONE_OR_INETD=standalone/g'  /etc/default/pure-ftpd-common
echo    "${grn}OK${end}"
echo -n "     · Activando jaula para usuarios... "
sed -i 's/VIRTUALCHROOT=false/VIRTUALCHROOT=true/g'  /etc/default/pure-ftpd-common
echo    "${grn}OK${end}"
echo -n "     · Activando TLS/SSL (cifrado)... "
mkdir -p /etc/ssl/private/
openssl req -new -newkey rsa:4096 -days 97300 -nodes -x509 -subj "/C=$SUBJ_C/ST=$SUBJ_ST/L=$SUBJ_L/O=$SUBJ_O/OU=$SUBJ_OU/CN=$SUBJ_CN" -keyout /etc/ssl/private/pure-ftpd.pem -out /etc/ssl/private/pure-ftpd.pem > /dev/null 2>&1
chmod 600 /etc/ssl/private/pure-ftpd.pem
echo 1 > /etc/pure-ftpd/conf/TLS
echo    "${grn}OK${end}"
echo -n "     · Estableciendo FTP Passive Ports (29799 29899)..."
echo "29799 29899" > /etc/pure-ftpd/conf/PassivePortRange
echo "${grn}OK${end}"
echo -n "     · Limitando el numero maximo de clientes FTP (50)..."
echo "50" > /etc/pure-ftpd/conf/MaxClientsNumber
echo "${grn}OK${end}"
echo -n "     · Reiniciando pure-ftpd... "
service pure-ftpd-mysql restart
echo -e "${grn}OK${end}\n"

echo -n " - Cuotas de disco: quota, quotatool... "
apt-get -qq install quota quotatool > /dev/null
echo    "${grn}OK${end}"
echo -n "   · Activando el uso cuotas de disco en /etc/fstab..."
sed -i 's/errors=remount-ro/errors=remount-ro,usrjquota=quota.user,grpjquota=quota.group,jqfmt=vfsv0/g'  /etc/fstab
echo    "${grn}OK${end}"
echo -n "   · remontando la raiz (/)... "
mount -o remount / > /dev/null
echo    "${grn}OK${end}"
echo -n "   · comprobando particion con quotacheck... "
quotacheck -avugm &> /dev/null
echo    "${grn}OK${end}"
echo -n "   · activando cuotas con quotaon... "
quotaon -avug > /dev/null
echo -e "${grn}OK${end}\n"

echo -n " - Servidor DNS: bind9, dnsutils... "
apt-get -qq install bind9 dnsutils haveged > /dev/null
echo -e "${grn}OK${end}\n"

echo    " - Herramientas webstats... "
echo    "   · Paquetes: vlogger, webalizer,"
echo -n "               awstats, geoip-database... "
apt-get -qq install vlogger webalizer awstats geoip-database libclass-dbi-mysql-perl > /dev/null 2>&1
echo    "${grn}OK${end}"
echo -n "   · ${blu}Deshabilitando awstats en cron... ${end}"
sed -i -r '/^(.)/ s/^#*/#/' /etc/cron.d/awstats
echo -e "${grn}OK${end}\n"

echo    " - Instalando jaula para usuarios"
echo -n "   · Paquetes: jailkit-2.19... "
cd /tmp
wget -q http://olivier.sessink.nl/jailkit/jailkit-2.19.tar.gz 
tar xfz jailkit-2.19.tar.gz
cd jailkit-2.19
./debian/rules binary &> /dev/null
cd ..
dpkg -i jailkit_2.19-1_*.deb &> /dev/null
rm -rf jailkit*
echo -e "${grn}OK${end}\n"

echo    " - Instalando herramienta anti-bots"
echo -n "   · Paquetes: fail2ban... "
apt-get -qq install fail2ban > /dev/null
echo    "${grn}OK${end}"
echo    "   · ${blu}Agregando numero maximo de intentos (maxretry)... ${end}"
echo    "     · pureftpd... ${grn}OK${end}"
echo    "     · dovecot-pop3imap... ${grn}OK${end}"
echo    "     · postfix-sasl... ${grn}OK${end}"
if [ ! -f "/var/log/mail.log" ]; then
  touch "/var/log/mail.log";
fi 
echo '
[pureftpd]
enabled  = true
port     = ftp
filter   = pureftpd
logpath  = /var/log/syslog
maxretry = 3

[dovecot-pop3imap]
enabled = true
filter = dovecot-pop3imap
action = iptables-multiport[name=dovecot-pop3imap, port="pop3,pop3s,imap,imaps", protocol=tcp]
logpath = /var/log/mail.log
maxretry = 5

[postfix-sasl]
enabled  = true
port     = smtp
filter   = postfix-sasl
logpath  = /var/log/mail.log
maxretry = 3
' > /etc/fail2ban/jail.local

echo '
[Definition]
failregex = .*pure-ftpd: \(.*@<HOST>\) \[WARNING\] Authentication failed for user.*
ignoreregex =
' > /etc/fail2ban/filter.d/pureftpd.conf

echo '
[Definition]
failregex = (?: pop3-login|imap-login): .*(?:Authentication failure|Aborted login \(auth failed|Aborted login \(tried to use disabled|Disconnected \(auth failed|Aborted login \(\d+ authentication attempts).*rip=(?P<host>\S*),.*
ignoreregex =
' > /etc/fail2ban/filter.d/dovecot-pop3imap.conf
echo "ignoreregex =" >> /etc/fail2ban/filter.d/postfix-sasl.conf
echo -n "   · Reiniciando fail2ban... "
service fail2ban restart
echo -e "${grn}OK${end}\n"

echo -n " - Instalando firewall: ufw... "
apt-get -qq install ufw
echo -e "${grn}OK${end}\n"

echo -n " - Instalando webmail: roundcube... "
debconf-set-selections <<< "roundcube-core roundcube/dbconfig-install boolean true"
debconf-set-selections <<< "roundcube-core roundcube/database-type select mysql"
debconf-set-selections <<< "roundcube-core roundcube/mysql/app-pass password $CFG_ROUNDCUBE_ADMIN_PWD"
debconf-set-selections <<< "roundcube-core roundcube/app-password-confirm password $CFG_ROUNDCUBE_ADMIN_PWD"
debconf-set-selections <<< "roundcube-core roundcube/language select es_ES"
apt-get -qq install roundcube roundcube-core roundcube-mysql roundcube-plugins roundcube-plugins-extra javascript-common libjs-jquery-mousewheel php-net-sieve tinymce > /dev/null 2>&1
echo    "${grn}OK${end}"
echo -n "   · Creando alias 'webmail' en apache para roundcube... "
cp /etc/apache2/conf-enabled/roundcube.conf /etc/apache2/conf-enabled/roundcube.conf.orig
sed -i "s/#    Alias \/roundcube \/var\/lib\/roundcube/    Alias \/roundcube \/var\/lib\/roundcube\n    Alias \/webmail \/var\/lib\/roundcube/" /etc/apache2/conf-enabled/roundcube.conf
sed -i '/<Directory \/var\/lib\/roundcube\/>/a\  AddType application\/x-httpd-php .php' /etc/apache2/conf-enabled/roundcube.conf
echo    "${grn}OK${end}"
echo -n "   · Editando phpmyadmin.conf para cambiar URL por defecto de /phpmyadmin/ a /$CFG_PMA_ALIAS/ ... "
cp /etc/apache2/conf-available/phpmyadmin.conf /etc/apache2/conf-available/phpmyadmin.conf.orig
sed -i "s/Alias \/phpmyadmin/Alias \/$CFG_PMA_ALIAS/"  /etc/apache2/conf-available/phpmyadmin.conf
echo    "${grn}OK${end}"
service apache2 restart
echo -n "   · Editando roundcube config.inc.php para configurar servidor por defecto como localhost... "
cp /etc/roundcube/config.inc.php /etc/roundcube/config.inc.php.orig
sed -i "/default_host/s/''/'localhost'/"  /etc/roundcube/config.inc.php
echo -e "${grn}OK${end}\n"

cd /tmp
wget -qO ispconfig.tar.gz https://git.ispconfig.org/ispconfig/ispconfig3/repository/archive.tar.gz?ref=stable-3.1
tar xfz ispconfig.tar.gz
cd ispconfig3*/install/
touch autoinstall.ini
echo "[install]" > autoinstall.ini
echo "language=en" >> autoinstall.ini
echo "install_mode=standard" >> autoinstall.ini
echo "hostname=$CFG_HOSTNAME_FQDN" >> autoinstall.ini
echo "mysql_hostname=localhost" >> autoinstall.ini
echo "mysql_root_user=root" >> autoinstall.ini
echo "mysql_root_password=$CFG_MYSQL_ROOT_PWD" >> autoinstall.ini
echo "mysql_database=dbispconfig" >> autoinstall.ini
echo "mysql_charset=utf8" >> autoinstall.ini
echo "http_server=apache" >> autoinstall.ini
echo "ispconfig_port=8082" >> autoinstall.ini
echo "ispconfig_use_ssl=y" >> autoinstall.ini
echo >> autoinstall.ini
echo "[ssl_cert]" >> autoinstall.ini
echo "ssl_cert_country=$SUBJ_C" >> autoinstall.ini
echo "ssl_cert_state=$SUBJ_ST" >> autoinstall.ini
echo "ssl_cert_locality=$SUBJ_L" >> autoinstall.ini
echo "ssl_cert_organisation=$SUBJ_O" >> autoinstall.ini
echo "ssl_cert_organisation_unit=$SUBJ_OU" >> autoinstall.ini
echo "ssl_cert_common_name=$SUBJ_CN" >> autoinstall.ini
echo "ssl_cert_email=hostmaster@$CFG_DOMAIN" >> autoinstall.ini
echo >> autoinstall.ini
echo "[expert]" >> autoinstall.ini
echo "mysql_ispconfig_user=ispconfig" >> autoinstall.ini
echo "mysql_ispconfig_password=$CFG_MYSQL_ISPCONFIG_PWD" >> autoinstall.ini
echo "join_multiserver_setup=n" >> autoinstall.ini
echo "mysql_master_hostname=$CFG_HOSTNAME_FQDN" >> autoinstall.ini
echo "mysql_master_root_user=root" >> autoinstall.ini
echo "mysql_master_root_password=$CFG_MYSQL_ROOT_PWD" >> autoinstall.ini
echo "mysql_master_database=dbispconfig" >> autoinstall.ini
echo "configure_mail=y" >> autoinstall.ini
echo "configure_jailkit=y" >> autoinstall.ini
echo "configure_ftp=y" >> autoinstall.ini
echo "configure_dns=y" >> autoinstall.ini
echo "configure_apache=y" >> autoinstall.ini
echo "configure_nginx=n" >> autoinstall.ini
echo "configure_firewall=y" >> autoinstall.ini
echo "install_ispconfig_web_interface=y" >> autoinstall.ini
echo >> autoinstall.ini
echo "[update]" >> autoinstall.ini
echo "do_backup=yes" >> autoinstall.ini
echo "mysql_root_password=$CFG_MYSQL_ROOT_PWD" >> autoinstall.ini
echo "mysql_master_hostname=$CFG_HOSTNAME_FQDN" >> autoinstall.ini
echo "mysql_master_root_user=root" >> autoinstall.ini
echo "mysql_master_root_password=$CFG_MYSQL_ROOT_PWD" >> autoinstall.ini
echo "mysql_master_database=dbispconfig" >> autoinstall.ini
echo "reconfigure_permissions_in_master_database=no" >> autoinstall.ini
echo "reconfigure_services=yes" >> autoinstall.ini
echo "ispconfig_port=8080" >> autoinstall.ini
echo "create_new_ispconfig_ssl_cert=no" >> autoinstall.ini
echo "reconfigure_crontab=yes" >> autoinstall.ini
echo | php -q install.php --autoinstall=autoinstall.ini
echo 
echo    " - Ultimos ajuste para la instalación de ISPConfig:"
echo -n "   · Eliminando ficheros creados durante la instalacion... "
cd 
rm -rf /tmp/ispconfig*
echo    "${grn}OK${end}"
echo -n "   · Actualizando el logotipo del panel ISPConfig... "
echo "UPDATE dbispconfig.sys_ini set default_logo = '$CFG_ISPCONFIG_LOGO' where sysini_id = 1;" | mysql
echo    "${grn}OK${end}"
echo -n "   · Actualizando password del administrador del panel ISPConfig... "
echo "UPDATE dbispconfig.sys_user set passwort = md5('$CFG_ISPCONFIG_ADMIN_PWD') where username = 'admin';" | mysql
echo    "${grn}OK${end}"
echo -n "   · Creando un usuario remoto para la API de ISPConfig... "
echo "INSERT INTO dbispconfig.remote_user (sys_userid, sys_groupid, sys_perm_user, sys_perm_group, sys_perm_other, remote_username, remote_password, remote_functions) VALUES (1, 1, 'riud', 'riud', '', '$CFG_ISPCONFIG_API_USERNAME', md5('$CFG_ISPCONFIG_API_PWD'), '$CFG_ISPCONFIG_API_PRIVILEGES');" | mysql
echo    "${grn}OK${end}"
echo -n "   · Habilitando redireccion automatica (http --> https) del panel de administracion... "
sed -i '/<\/VirtualHost>/i\  ErrorDocument 400 "<script> if(window.location.protocol !='\'https:\''){ location.href = location.href.replace('\'http://\'', '\'https://\'');}</script>"' /etc/apache2/sites-available/ispconfig.vhost
echo    "${grn}OK${end}"
echo -n "   · Reiniciando apache2... "
service apache2 restart
echo    "${grn}OK${end}"
while true; do
  read -r -n 1 -p "   · ¿Quieres eliminar el script de instalacion? [y/n]: " REPLY
  case $REPLY in
    [yY]) echo ""; rm install.sh; echo "     · Eliminando script de instalacion... ${blu}YES${end}"; break; ;;
    [nN]) echo ""; echo "     · Eliminando script de instalacion... ${red}NO${end}"; break; ;;
    *) 
  esac
done
echo    "${yel}   · AVISO: El fichero de configuracion contiene los usuarios/claves utilizados durante la instalacion!${end}"
while true; do
  read -r -n 1 -p "     · ¿Quieres eliminarlo? [y/n]: " REPLY
  case $REPLY in
    [yY]) echo ""; rm install.cfg; echo "     · Eliminando fichero de configuracion... ${blu}YES${end}"; break; ;;
    [nN]) echo ""; echo "     · Eliminando fichero de configuracion... ${red}NO${end}"; echo "${blu}       · Guardalo en un sitio seguro!!${end}"; break; ;;
    *)
  esac
done
sleep 2
echo
echo    "  ============================================="
echo    "              INSTALACION FINALIZADA           "
echo    "  ============================================="
echo    "   - ISPConfig"
echo    "     · https://$CFG_DOMAIN:8082/"
echo
echo    "   - phpMyAdmin"
echo    "     · https://$CFG_DOMAIN/$CFG_PMA_ALIAS/"
echo
echo    "   - roundcube"
echo    "     · https://$CFG_DOMAIN/webmail/"
echo
echo    "   - Registro de la instalacion"
echo    "     · /var/log/ispconfig_setup.log"
echo    "  ============================================="
read -p "  ====== = = PULSA ENTER PARA SALIR = = ======"
echo
