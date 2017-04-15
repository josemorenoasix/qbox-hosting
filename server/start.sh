#!/bin/bash

# Colors
grn=$'\e[1;32m'
blu=$'\e[1;34m'
end=$'\e[0m'

echo -n " - Descargando el script de instalacion desde github... "
wget -q -O install.sh https://raw.githubusercontent.com/josemorenoasix/qbox-hosting/master/server/install.sh > /dev/null
echo "${grn}OK${end}"

echo -n " - Descargando el script el fichero de configuracion desde github... "
wget -q -O install.cfg  https://raw.githubusercontent.com/josemorenoasix/qbox-hosting/master/server/install.cfg > /dev/null
echo "${grn}OK${end}"

echo    " - A continuacion:" 
echo    "   · Edita el fichero de configuracion ejecutando ${blu}nano install.cfg${end}" 
echo    "   · Ejecuta ${blu}sudo bash install.sh${end}"
