#!/bin/bash

# -----------------------------------------------------------------------------
# GITEA Installer with Nginx, MariaDB, UFW & Letsencrypt
# Version 0.1
# Written by Maximilian Thoma 2020
# Traducido por b1nar10 aka (Alberto Méndez)
# Visit https://lanbugs.de for further informations.
# -----------------------------------------------------------------------------
# gitea_installer.sh is free software;  you can redistribute it and/or
# modify it under the  terms of the  GNU General Public License  as
# published by the Free Software Foundation in version 2.
# gitea_installer.sh is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; with-out even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the  GNU General Public License for more details.
# You should have  received  a copy of the  GNU  General Public
# License along with GNU Make; see the file  COPYING.  If  not,  write
# to the Free Software Foundation, Inc., 51 Franklin St,  Fifth Floor,
# Boston, MA 02110-1301 USA.
#

LETSENCRYPT='false'
UFW='false'

#GETOPTS
while getopts f:e:i:p:r:lu flag
do
    case "${flag}" in
      f) FQDN=${OPTARG};;
      e) CORREO=${OPTARG};;
      i) IP=${OPTARG};;
      p) CONTRASINAL=${OPTARG};;
      r) SQLROOT=${OPTARG};;
      l) LETSENCRYPT='true';;
      u) UFW='true';;
    esac
done

if [ -z "$FQDN" ] || [ -z "$CORREO" ] || [ -z "$IP" ] || [ -z "$CONTRASINAL" ] || [ -z "$SQLROOT" ]; then
echo "One of the options is missing:"
echo "-f FQDN - Systemname of GITEA system"
echo "-e CORREO - Correo electrónico para Letsencrypt"
echo "-i IP - enderezo IPv4 deste Sistema"
echo "-p CONTRASINAL - Usado para GITEA BD"
echo "-r SQLROOT - Contrasinal ROOT de MariaDB"
echo "-l LETSENCRYPT - Use letsencrypt"
echo "-u UFW - Use UFW"
exit
fi

# Comproba se curl está instalado
if [ ! -x /usr/bin/curl ] ; then
CURL_NOT_EXIST=1
apt install -y curl
else
CURL_NOT_EXIST=0
fi

# Instalar paquetes
apt update
apt install -y nginx mariadb-server git ssl-cert

# Obter a última versión
VER=$(curl --silent "https://api.github.com/repos/go-gitea/gitea/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' | sed 's|[v,]||g' )                                               

# Crear usuario git
adduser --system --group --disabled-password --shell /bin/bash --home /home/git --gecos 'Git Version Control' git

# Descargar gitea
if [ -n "$(uname -a | grep i386)" ]; then
    curl -fsSL -o "/tmp/gitea" "https://dl.gitea.io/gitea/$VER/gitea-$VER-linux-386"
fi

if [ -n "$(uname -a | grep x86_64)" ]; then
  curl -fsSL -o "/tmp/gitea" "https://dl.gitea.io/gitea/$VER/gitea-$VER-linux-amd64"
fi

if [ -n "$(uname -a | grep armv6l)" ]; then
  curl -fsSL -o "/tmp/gitea" "https://dl.gitea.io/gitea/$VER/gitea-$VER-linux-arm-6"
fi

if [ -n "$(uname -a | grep armv7l)" ]; then
  curl -fsSL -o "/tmp/gitea" "https://dl.gitea.io/gitea/$VER/gitea-$VER-linux-arm-7"
fi

# Mover binario
mv /tmp/gitea /usr/local/bin
chmod +x /usr/local/bin/gitea

# Crear cartafoles
mkdir -p /var/lib/gitea/{custom,data,indexers,public,log}
chown git: /var/lib/gitea/{data,indexers,log}
chmod 750 /var/lib/gitea/{data,indexers,log}
mkdir /etc/gitea
chown root:git /etc/gitea
chmod 770 /etc/gitea

# Obter o ficheiro systemd
curl -fsSL -o /etc/systemd/system/gitea.service https://raw.githubusercontent.com/go-gitea/gitea/master/contrib/systemd/gitea.service

# Enable mariadb requirement in systemd gitea.service script
perl -pi -w -e 's/#Requires=mariadb.service/Requires=mariadb.service/g;' /etc/systemd/system/gitea.service

# Recarga e activa o demonio de Gitea
systemctl daemon-reload
systemctl enable --now gitea

# Crear bd en mariadb
mysql -u root -Bse "CREATE DATABASE giteadb;"
mysql -u root -Bse "CREATE USER 'gitea'@'localhost' IDENTIFIED BY '$CONTRASINAL';"
mysql -u root -Bse "GRANT ALL ON giteadb.* TO 'gitea'@'localhost' IDENTIFIED BY '$CONTRASINAL' WITH GRANT OPTION;"
mysql -u root -Bse "ALTER DATABASE giteadb CHARACTER SET = utf8mb4 COLLATE utf8mb4_unicode_ci;"
mysql -u root -Bse "FLUSH PRIVILEGES;"

# Garda a configuración orixinal
cp /etc/mysql/mariadb.conf.d/50-server.cnf /etc/mysql/mariadb.conf.d/50-server.org

cat >> /etc/mysql/mariadb.conf.d/50-server.cnf << XYZ
#
# Estes grupos son lidos polo servidor MariaDB.
# Utilízao para opcións que só o servidor (pero non os clientes) debería ver
#
# Vexa os exemplos de ficheiros my.cnf do servidor en /usr/share/mysql

# isto é lido polo 'demonio' autónomo e polos servidores integrados
[servidor]

# isto é só para o 'demonio' autónomo mysqld
[mysqld]

#
# * Configuración Básica
#
user = mysql
pid-file = /run/mysqld/mysqld.pid
socket = /run/mysqld/mysqld.sock
#port = 3306
basedir = /usr
datadir = /var/lib/mysql
tmpdir = /tmp
lc-messages-dir = /usr/share/mysql
#skip-external-locking

# En lugar de omitir a rede, o predeterminado agora é escoitar só
# localhost que é máis compatible e non é menos seguro.
# Enderezo de Enlace
bind-address  = 127.0.0.1  

#
# * Axuste fino
#
#key_buffer_size = 16M
#max_allowed_packet = 16M
#thread_stack = 192K
#thread_cache_size = 8
# Isto substitúe o script de inicio e verifica as táboas MyISAM se é necesario
# a primeira vez que se tocan
#myisam_recover_options = COPIA DE SEGURIDADE
#max_connections = 100
#table_cache = 64
#thread_concurrency = 10

#
# * Consulta de Configuración da Caché
#
#query_cache_limit = 1M
query_cache_size = 16M

#
# * Rexistro e replicación
#
# Ambas as localizacións son rotadas polo cronjob.
# Teña en conta que este tipo de rexistro é un asasinato de rendemento.
# A partir da versión 5.1 pode activar o rexistro no tempo de execución!
#general_log_file       = /var/log/mysql/mysql.log
#general_log            = 1
#
# Rexistro de erros: debería haber moi poucas entradas.
#
log_error = /var/log/mysql/error.log
#
# Activa o rexistro de consultas lentas para ver consultas cunha duración especialmente longa
#slow_query_log_file    = /var/log/mysql/mariadb-slow.log
#long_query_time        = 10
#log_slow_rate_limit    = 1000
#log_slow_verbosity     = query_plan
#log-queries-not-using-indexes
#
# O seguinte pódese usar como fácil de reproducir rexistros de copia de seguridade ou para a replicación.
# nota: se está a configurar un escravo de replicación, consulte README.Debian sobre
# É posible que teñas que cambiar outras opcións de configuración.
#server-id              = 1
#log_bin                = /var/log/mysql/mysql-bin.log
expire_logs_days        = 10
#max_binlog_size        = 100M
#binlog_do_db           = include_database_name
#binlog_ignore_db       = exclude_database_name

#
# * Security Features
#
# Read the manual, too, if you want chroot!
#chroot = /var/lib/mysql/
#
# For generating SSL certificates you can use for example the GUI tool "tinyca".
#
#ssl-ca = /etc/mysql/cacert.pem
#ssl-cert = /etc/mysql/server-cert.pem
#ssl-key = /etc/mysql/server-key.pem
#
# Accept only connections using the latest and most secure TLS protocol version.
# ..when MariaDB is compiled with OpenSSL:
#ssl-cipher = TLSv1.2
# ..when MariaDB is compiled with YaSSL (default in Debian):
#ssl = on

#
# * Conxuntos de Caracteres
#
# MySQL/MariaDB predeterminado é Latin1, pero en Debian prefire o predeterminado completo
# utf8 conxunto de caracteres de 4 bytes. Consulte tamén client.cnf
#
character-set-server  = utf8mb4
collation-server      = utf8mb4_general_ci


# * InnoDB
#
# InnoDB está habilitado por defecto cun ficheiro de datos de 10 MB en /var/lib/mysql/.
# Lea o manual para obter máis opcións relacionadas con InnoDB. Hai moitos!

innodb_file_format = Barracuda
innodb_large_prefix = 1
innodb_default_row_format = dynamic

#
# * O complemento de autenticación de socket de Unix está integrado desde 10.0.22-6
#
# Necesario para que o usuario da base de datos raíz poida autenticarse sen contrasinal pero
# só cando se executa como usuario root de Unix.
#
# Tamén dispoñible para outros usuarios se é necesario.
# Consulte https://mariadb.com/kb/en/unix_socket-authentication-plugin/

# isto é só para o servidor incorporado
[embedded]

# Este grupo só é lido polos servidores MariaDB, non por MySQL.
# Se usa o mesmo ficheiro .cnf para MySQL e MariaDB,
# aquí pode poñer opcións só para MariaDB
[mariadb]

# Este grupo só é lido polos servidores MariaDB-10.3.
# Se usa o mesmo ficheiro .cnf para MariaDB de diferentes versións,
# use este grupo para opcións que os servidores máis antigos non entenden
[mariadb-10.3]
XYZ

#Reiniciar mariadb
systemctl restart mariadb

#Securizar Mariadb 
mysql -u root -Bse "UPDATE mysql.user SET Password=PASSWORD('$SQLROOT') WHERE User='root'"
mysql -u root -p"$SQLROOT" -Bse "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1')"
mysql -u root -p"$SQLROOT" -Bse "DELETE FROM mysql.user WHERE User=''"
mysql -u root -p"$SQLROOT" -Bse "DELETE FROM mysql.db WHERE Db='test' OR Db='test\_%'"
mysql -u root -p"$SQLROOT" -Bse "FLUSH PRIVILEGES"

# Crear configuración nginx
cat >> /etc/nginx/sites-enabled/$FQDN << XYZ
server {
    listen 80;
    server_name $FQDN;

    return 301 https://$FQDN\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $FQDN;

    proxy_read_timeout 720s;
    proxy_connect_timeout 720s;
    proxy_send_timeout 720s;

    client_max_body_size 50m;

    # Proxy headers
    proxy_set_header X-Forwarded-Host \$host;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_set_header X-Real-IP \$remote_addr;

    # SSL parameters
    ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
    ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;

    # log files
    access_log /var/log/nginx/$FQDN.access.log;
    error_log /var/log/nginx/$FQDN.error.log;

    # Handle / requests
    location / {
       proxy_redirect off;
       proxy_pass http://127.0.0.1:3000;
    }
}
XYZ

# Reiniciar nginx
service nginx restart

#Adquerir certificado letsencrypt
if [ $LETSENCRYPT=='true' ] ; then
apt install -y certbot python3-certbot-nginx
certbot --nginx -d $FQDN --non-interactive --agree-tos -m $CORREO
fi

# Instalar se ufw é esta activado
if [ $UFW=='true' ] ; then

# UFW instalado?
if [ ! -x /usr/sbin/ufw ] ; then
apt install -y ufw
fi

# Políticas UFW
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw logging on
ufw --force enable

fi


#Limpeza de Paquetes
if [[ $CURL_NOT_EXIST == 1 ]]; then
apt remove -y curl
fi


# Mensaxe final
echo "--------------------------------------------------------------------------------------"
echo " GITEA $VER instalado no sistema $FQDN"
echo "--------------------------------------------------------------------------------------"
echo " Base de Datos MariaDB    : giteadb "
echo " Usuario MariaDB          : gitea "
echo " Contrasinal MariaDB      : $CONTRASINAL "
echo " Character set MariaDB    : utf8mb4"
echo "--------------------------------------------------------------------------------------"
echo " Usuario root MariaDB     : root"
echo " Contrasinal root MariaDB : $SQLROOT"
echo "--------------------------------------------------------------------------------------"
echo " Sistema accesible via    : https://$FQDN"
echo "--------------------------------------------------------------------------------------"
echo " >>> You must finish the initial setup <<< "
echo "--------------------------------------------------------------------------------------"
echo " Título do sitio          : Introduza o nome da súa organización."
echo " Ruta Raíz do Repositorio : Deixe o /home/git/gitea-repositories por defecto."
echo " Ruta Raíz de Git LFS     : Deixe o /var/lib/gitea/data/lfs por defecto."
echo " Executar Nome de Usuario : git"
echo " Dominio do Servidor SSH  : Usa $FQDN"
echo " Porto SSH                : 22, cámbiao se SSH escoita noutro porto."
echo " Port Escoita HTTP Gitea  : 3000"
echo " URL base de Gitea        : Usar https://$FQDN/ "
echo " Ruta do Rexistro         : deixe o /var/lib/gitea/log por defecto."
echo "--------------------------------------------------------------------------------------"
if [ $UFW=='true' ] ; then
echo " Aplicáronse as seguintes regras de firewall:"
ufw status numbered
echo "--------------------------------------------------------------------------------------"
fi
