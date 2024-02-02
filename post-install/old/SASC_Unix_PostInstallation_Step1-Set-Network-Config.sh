#!/bin/ksh

########################################################################################################################
# Script: SASC_PostInstall_Step1_Set-Network_Config.ksh
#
# Description: Ce script permet de configurer le network sur une machine Unix lors de la post-instalation
# Version: 1.0.3 (ou 1: modification majeure, 2: modification mineure, 3: correction de bug)
#
# Date de creation: 19/03/2019
# Cree par: Jean-Baptiste Meriaux
#
#
# Mise a jour:
#                           Charles BRANSARD - 15/01/2019 - Prise en compte cas newcloud (pas de modification configuration DNS + modification du fichier /etc/hosts pour prendre en compte le SIP NEWCLOUD)
#							Charles BRANSARD - 31/01/2020 - Modification prise en compte du hostname en minuscule + mise en place en FQDN
#							Charles BRANSARD - 01/02/2021 - Ajout log erreur en local sur le serveur en cas de KO (/tmp/<nom_script_KO_date>)
#
# Pre-requis:				Le serveur est de type Unix
#
# Inputs:
#			1:	 			: Zone du serveur
#			2: 				: Site du serveur
#
# Outputs:
#                           0 : le script s'est correctement déroulé
#							4 : Erreur lors de l'installation
#							96 :Mauvais paramètres renseignés
#							97 :OS incompatible avec le script
#							98 : Erreur fichier release non trouve
#
########################################################################################################################

####### DECLARATION DES CONSTANTES FIXES
SCRIPT_NAME="SASC_Unix_PostInstallation_Step1-Set-Network-Config"
LOG="/tmp/${SCRIPT_NAME}_KO_$(date "+%Y%m%d%H%M")"

#####################################################
########## DECLARATION DES FONCTIONS ################
#####################################################
route_newcloud()
{
	# Ajout de la route vers l'outillage pour les serveurs newcloud en général fichier route-eth2
	# 10.149.194.0/24 via <gateway>
	echo "ROUTE NEWCLOUD"
	route_file=$(grep -nr "172.28.239.0/27" /etc/sysconfig/network-scripts/*|awk -F ":" '{print $1}')
	if [ -z $route_file ]
	then
        echo "Recupération impossible du fichier route-eth2 : faire ajout de la route de façon manuelle : " > $LOG
		echo "Ajout de la route 10.149.194.0/24 via la gateway" >> $LOG
		echo "Recupération impossible du fichier route-eth2 : faire ajout de la route de façon manuelle : "
		echo "Ajout de la route 10.149.194.0/24 via la gateway"	  >&2 && exit 4
	else
		interface_admin=$(echo $route_file|cut -d "-" -f3)
		if [ -z $interface_admin ]
		then
			echo "Recupération impossible de l'interface eth2 : faire ajout de la route de façon manuelle : " > $LOG
			echo "Ajout de la route 10.149.194.0/24 via la gateway" >> $LOG
			echo "Recupération impossible de l'interface eth2 : faire ajout de la route de façon manuelle : "
			echo "Ajout de la route 10.149.194.0/24 via la gateway"		  >&2 && exit 4
		else
			gateway=$(cat $route_file|awk -F " " '{print $3}'|sort -u)
			if [ -z $gateway ]
			then
				echo "Recupération impossible de la gateway : faire ajout de la route de façon manuelle : " > $LOG
				echo "Ajout de la route 10.149.194.0/24 via la gateway" >> $LOG
				echo "Recupération impossible de la gateway : faire ajout de la route de façon manuelle : "
				echo "Ajout de la route 10.149.194.0/24 via la gateway"			  >&2 && exit 4
			else
				cat $route_file | grep "10.149.194.0" > /dev/null 2>&1
				if [ $? -eq 0 ]
				then
					echo "route static deja presente dans le fichier $route_file"
				else
					echo "10.149.194.0/24 via $gateway" >> $route_file
					if [ $? -eq 0 ]
					then
						echo "Ajout de la route en static dans le fichier $route_file OK"
					else
                        echo "Erreur sur l'ajout de la route en static dans le fichier $route_file : faire ajout de la route 10.149.194.0/24 via $gateway de façon manuelle" > $LOG
						echo "Erreur sur l'ajout de la route en static dans le fichier $route_file : faire ajout de la route 10.149.194.0/24 via $gateway de façon manuelle"   >&2 && exit 4						
					fi
				fi
				ip route | grep "10.149.194.0" > /dev/null 2>&1
				if [ $? -eq 0 ]
				then
					echo "route dynamique deja presente"
				else
					ip route add 10.149.194.0/24 via $gateway dev $interface_admin
					if [ $? -eq 0 ]
					then
						echo "Ajout de la route en dynamique OK"				
					else
                        echo "Erreur sur l'ajout de la route en dynamique : faire ajout de la route 10.149.194.0/24 via $gateway de façon manuelle en dynamique (route add)" > $LOG
						echo "Erreur sur l'ajout de la route en dynamique : faire ajout de la route 10.149.194.0/24 via $gateway de façon manuelle en dynamique (route add)"   >&2 && exit 4			
					fi
				fi			
			fi
		fi
	fi
	
}

conf_ntp(){
#On verifie que la configuration NTP est correcte.
ETAPE="config NTP"
echo " début ${ETAPE}"
echo "*** Verify ntpq output"
if [ "x${UNAME}" = "xAIX" ]
	then
	#On verifie si le service xntpd demarre automatiquement
	grep -q "^start /usr/sbin/xntpd " /etc/rc.tcpip
	if [ $? -ne 0 ]
		then
		#Si ce n'est pas le cas on rajoute son demarrage automatique
		backup_files /etc/rc.tcpip
		perl -pi.xxx -e "s|^#start /usr/sbin/xntpd |start /usr/sbin/xntpd |g" /etc/rc.tcpip
		perl -pi.xxx -e "s|^#start /usr/sbin/netcd |start /usr/sbin/netcd |g" /etc/rc.tcpip
		rm -f /etc/rc.tcpip.xxx
		res=`lssrc -s xntpd | grep xntpd | awk '{
			if ( NF == 4 ) {print $4}
			if ( NF == 3 ) {print $3}
		}'`
		if [ "x${res}" = "xactive" ]
			then
			stopsrc -s xntpd
			sleep 2
			startsrc -s xntpd
		else
			startsrc -s xntpd
		fi
		res=`lssrc -s netcd | grep netcd | awk '{
			if ( NF == 4 ) {print $4}
			if ( NF == 3 ) {print $3}
		}'`
		if [ "x${res}" = "xactive" ]
			then
			stopsrc -s netcd
			sleep 2
			startsrc -s netcd
		else
			startsrc -s netcd
		fi
	else
		echo "*** ${ETAPE} deja  en place."
	fi
fi
cnt=`ntpq -p 2>&1 | grep -c "ntpq: read: Connection refused"`
if [ ${cnt} -ne 0 ]
	then
    echo "Un pb de connexion au ntp ? merci de revoir la conf du ntpd" > $LOG
	echo "Un pb de connexion au ntp ? merci de revoir la conf du ntpd"     >&2 && exit 4
	echo "******************"
	echo \# cat /etc/ntp.conf
	grep -v \# /etc/ntp.conf
	echo "******************"
	echo \# ntp -q
	ntpq -p
	echo "******************"
	echo \# lssrc -l -s xntpd
	lssrc -l -s xntpd
	echo "******************"
	echo \# lssrc -l -s netcd
	lssrc -l -s netcd
	echo "******************"
else
	ntpq -p
	STRAT=`ntpq -c rv | grep stratum | sed -e 's/.*\(stratum=[0-9]*\),.*/\1/g' | sed -e 's/stratum=//g'`
	if [ ${STRAT} -gt 17 ]
		then
        echo "Stratum \"${STRAT}\" trop eleve, merci de revoir la conf du ntpd" > $LOG
		echo "Stratum \"${STRAT}\" trop eleve, merci de revoir la conf du ntpd"     >&2 && exit 4
	fi
fi	
}

backup_files()
{
        for i in ${*}
        do
                if [ -f "${i}" ]; then
                        cp -p "${i}" "${i}".`date +%Y%m%d-%H%M`
                fi
        done
}

##############
#### MAIN ####
##############

#Check parametres entres
case $1 in
		* )		[  -z $1 ] && echo "Veuillez renseigner comme parametre la zone puis le site" >&2 && exit 96
esac	

case $2 in
		* )		[  -z $2 ] && echo "Veuillez renseigner comme parametre la zone puis le site" >&2 && exit 96
esac

ZONE=$1
SITE=$2

OS=$(uname)
HOSTNAME=`hostname | awk -F. '{print $1}'`
UNAME=`uname -s`

if [[ $ZONE != "zhb" && $ZONE != "dmzhaute" && $ZONE != "dmzbasse" && $ZONE != "zsihaute" && $ZONE != "zsibasse" && $ZONE != "zsa" && $ZONE != "newcloud" && $ZONE != "espace_groupe" && $ZONE != "espace_externe_front_end" && $ZONE != "espace_externe_back_end" && $ZONE != "espace_renforce" && $ZONE != "espace_essentiel" && $ZONE != "espace_admin" ]]
then
	echo "La variable zone doit être égale a la zone réseaux du serveur (zhb|dmzhaute|dmzbasse|zsihaute|zsibasse|zsa|newcloud|espace_groupe|espace_externe_front_end|espace_admin|espace_externe_back_end|espace_renforce|espace_essentiel)"
    exit 96
fi

if [[ $ZONE = "dmzhaute" || $ZONE = "zsihaute" || $ZONE = "zsibasse" || $ZONE = "zsa" || $ZONE = "espace_externe_back_end" ]]
then
		DMZ=1
		DMZBASSE=0
elif [[ $ZONE = "dmzbasse" || $ZONE = "espace_externe_front_end" ]]
then
		DMZ=1
		DMZBASSE=1	
else
		DMZ=0
		DMZBASSE=0
fi

echo
echo "######################################"
echo "######### début set Network  #########"
echo "######################################"
echo

case $OS in
        "Linux")
				# Get release file
				if [ -e /etc/system-release ]
				then
					RELEASE_FILE="/etc/system-release"
				elif [ -e /etc/redhat-release ]
				then
					RELEASE_FILE="/etc/redhat-release"
				else
                    echo "Cannot find file /etc/redhat-release !" > $LOG
					echo "Cannot find file /etc/redhat-release !"
					exit 98
				fi
				# Set YUM Variable
				CASE_OS=$(cat $RELEASE_FILE | awk '{print tolower($1)}')
				case $CASE_OS in
					"red")
						VERSION=$(cat $RELEASE_FILE | awk '{print $7}' |cut -d"." -f1)
					;;
					"centos")
						VERSION=$(cat $RELEASE_FILE | grep -o "[0-9]\.[0-9]" | cut -d"." -f1)
					;;
					*)
                        echo -e "Linux distribution $YUM8 not supported" > $LOG
						echo -e "Linux distribution $YUM8 not supported" && exit 5
				esac
				
				##################################
				#### 	  route_newcloud	  ####
				##################################
				
				if [ $ZONE = "newcloud" ]
				then
					route_newcloud
				fi
		
				#################################################
				#### configuration DNS (hors NEWCLOUD)       ####
				#################################################
				
				#On verifie que la configuration DNS soit correcte
				
				if [ $ZONE != "newcloud" ]
				then
					ETAPE="config DNS"
					echo " début ${ETAPE}"
					#Backup de la configuration actuelle
					backup_files /etc/resolv.conf
					#Sur Linux si la VM est sur Passy les DNS ne sont pas les meme
					if [ "${SITE}" = "pacy" ]
					then
						if [ ${DMZ} = 0 ]
						then
							#On ecrase le resolv.conf avec une configuration qu'on sait bonne pour Passy
							cat > /tmp/resolv.conf <<EOF
search adam.adroot.edf.fr pcy.edfgdf.fr noe.edf.fr cla.edfgdf.fr edf.fr edfgdf.fr
nameserver 192.196.111.47
nameserver 130.98.194.189
EOF
							cp /tmp/resolv.conf /etc/resolv.conf
							echo "*** ${ETAPE} en place."
						else
							#On ecrase le resolv.conf avec une configuration qu'on sait bonne pour les autres sites
							cat > /tmp/resolv.conf <<EOF
search  adam.adroot.edf.fr pcy.edfgdf.fr noe.edf.fr cla.edfgdf.fr edf.fr edfgdf.fr
nameserver 130.98.194.189
nameserver 192.196.111.47
EOF
							cp /tmp/resolv.conf /etc/resolv.conf
							rm -f /tmp/resolv.conf
						fi
						#On supprime les entres SIP pour mettre la bonne:
						sed -i '/SIP/d' /etc/hosts
						if [ "$DMZBASSE" -eq 1 ]
							then
								echo "10.200.146.196  pcyfy636.pcy.edfgdf.fr SIP" >> /etc/hosts
							else
								echo "10.200.146.195  pcyfy635.pcy.edfgdf.fr SIP" >> /etc/hosts
						fi
					else
						#On ecrase le resolv.conf avec une configuration qu'on sait bonne pour les autres sites
						cat > /tmp/resolv.conf <<EOF
search  adam.adroot.edf.fr noe.edf.fr pcy.edfgdf.fr cla.edfgdf.fr edf.fr edfgdf.fr
nameserver 130.98.194.189
nameserver 192.196.111.47
EOF
							cp /tmp/resolv.conf /etc/resolv.conf
							rm -f /tmp/resolv.conf					
						#On supprime les entres SIP pour mettre la bonne:
						sed -i '/SIP/d' /etc/hosts
						if [ "$DMZBASSE" -eq 1 ]
							then
								echo "10.117.0.222 noefy1n8.noe.edf.fr SIP" >> /etc/hosts
							else
								echo "10.117.0.221 noefy1n7.noe.edf.fr SIP" >> /etc/hosts
						fi
					fi
					echo
				fi
				
				# Configuration SIP NEWCLOUD
				if [ $ZONE = "newcloud" ]
				then
					#On supprime les entres SIP pour mettre la bonne:
					backup /etc/hosts
					sed -i '/SIP/d' /etc/hosts
					echo "10.11.75.41 SIP" >> /etc/hosts
				fi

				##################################
				#### configuration NTP        ####
				##################################
				
				conf_ntp
				
				##################################
				#### 	change hostname       ####
				##################################
				
				#Le but est de corriger le hostname, le passer de majuscule à minuscule et en nom long
				ETAPE="config Hostname"
				echo " début ${ETAPE}"
				# Modification du hostname
				FQDN_MIN=$(hostname -f | tr 'A-Z' 'a-z')
				hostname_min_court=$(hostname | awk -F"." '{print $1}' | tr 'A-Z' 'a-z')
				LIGNE_HOSTS=$(cat /etc/hosts | grep -i $hostname_min_court)
				LIGNE_HOSTS_MIN=$(cat /etc/hosts | grep -i $hostname_min_court | tr 'A-Z' 'a-z')
				# Modification fichier /etc/hosts (minuscule)
				echo "$LIGNE_HOSTS" | grep "[A-Z]" > /dev/null 2>&1
				if [ $? -eq 0 ]
				then
					echo "ligne du hostname dans le fichier /etc/hosts contient des majuscules"
					backup_files /etc/hosts
					#On corrige le fichier /etc/hosts
					sed -i -e "s/${LIGNE_HOSTS}/${LIGNE_HOSTS_MIN}/" /etc/hosts
					if [ $? -eq 0 ]
					then
						echo "Modification hostname dans le fichier /etc/hosts en minuscule OK"
					else
						echo "Modification hostname dans le fichier /etc/hosts en minuscule KO"		
					fi
				else
					echo "hostname /etc/hosts conforme"
				fi
				
				# Modification Variable HOSTNAME fichier /etc/sysconfig/NETWORK
				MODIF_NETWORK=0
				cat /etc/sysconfig/network | grep HOSTNAME > /dev/null 2>&1
				if [ $? -eq 0 ]
				then
					HOSTNAME_NETWORK_FILE=$(cat /etc/sysconfig/network | grep HOSTNAME | awk -F"=" '{print $2}')
					if [ -z "$HOSTNAME_NETWORK_FILE" ]
					then
						echo "Variable HOSTNAME vide dans le fichier /etc/sysconfig/network"
					else
						echo "$HOSTNAME_NETWORK_FILE" | grep "[A-Z]" > /dev/null 2>&1
						if [ $? -eq 0 ]
						then
							HOSTNAME_NETWORK_FILE_MIN=$(echo $HOSTNAME_NETWORK_FILE | tr 'A-Z' 'a-z')
							echo "Variable HOSTNAME en majuscule dans le fichier /etc/sysconfig/network"
							backup_files /etc/sysconfig/network
							perl -pi.xxx -e "s|^HOSTNAME=.*|HOSTNAME=${FQDN_MIN}|g" /etc/sysconfig/network
							echo "*** Modification Fichier /etc/sysconfig/network OK"
							MODIF_NETWORK=1
						else
							echo "Variable HOSTNAME /etc/sysconfig/network conforme"
						fi
					fi
				else
					echo "Ligne HOSTNAME non présente dans le fichier /etc/sysconfig/network"
				fi
				if [ $MODIF_NETWORK = 1 ]
				then
					#Reload des services network
					echo "Redemarage du service \"network\" pour la prise en compte"
					service network restart
				fi
				hostname_min=$(hostname | tr 'A-Z' 'a-z')
				hostname | grep "[A-Z]" > /dev/null 2>&1
				if [ $? -eq 0 ]
				then
					if [ "x${VERSION}" = "x7" ]
					then
						#Sur RedHat7 hostnamectl remplace les fichiers
						hostnamectl set-hostname $FQDN_MIN
						echo "*** Modification hostname OK"
					else
						hostname ${FQDN_MIN}
						echo "*** Modification hostname OK"		
					fi
				else
					echo "hostname conforme"
				fi				
				
		;;		
        "AIX")
				##################################
				#### configuration DNS        ####
				##################################

				#On verifie que la configuration DNS soit correcte
					ETAPE="config DNS"
					echo " début ${ETAPE}"
					#Backup de la configuration actuelle
					backup_files /etc/resolv.conf
					if [ "x${UNAME}" = "xAIX" ]
						then
							#Backup de la configuration actuelle
							backup_files /etc/netsvc.conf
							res=`grep ^hosts /etc/netsvc.conf | sed -e 's/ //g'`
							if [ "x${res}" != "xhosts=local,bind" ]
								then
									#Correction de la conf pour binder les dns en local en premier avant de faire des requetes dns
									cp -p /etc/netsvc.conf /etc/netsvc.conf.ntg
									grep -v ^hosts /etc/netsvc.conf > /tmp/netsvc.conf
									echo 'hosts=local,bind' >> /tmp/netsvc.conf
									cp /tmp/netsvc.conf /etc/netsvc.conf
							fi
					fi
					#Sur Linux si la VM est sur Passy les DNS ne sont pas les meme
					if [ "${SITE}" = "pacy" ]
					then
						if [ ${DMZ} = 0 ]
						then
							#On ecrase le resolv.conf avec une configuration qu'on sait bonne pour Passy
							cat > /tmp/resolv.conf <<EOF
search adam.adroot.edf.fr pcy.edfgdf.fr noe.edf.fr cla.edfgdf.fr edf.fr edfgdf.fr
nameserver 192.196.111.47
nameserver 130.98.194.189
EOF
							cp /tmp/resolv.conf /etc/resolv.conf
							echo "*** ${ETAPE} en place."
						else
							#On ecrase le resolv.conf avec une configuration qu'on sait bonne pour les autres sites
							cat > /tmp/resolv.conf <<EOF
search  adam.adroot.edf.fr pcy.edfgdf.fr noe.edf.fr cla.edfgdf.fr edf.fr edfgdf.fr
nameserver 130.98.194.189
nameserver 192.196.111.47
EOF
							cp /tmp/resolv.conf /etc/resolv.conf
							echo "*** ${ETAPE} en place."
							rm -f /tmp/resolv.conf
						fi
					else
						#On ecrase le resolv.conf avec une configuration qu'on sait bonne pour les autres sites
						cat > /tmp/resolv.conf <<EOF
search  adam.adroot.edf.fr noe.edf.fr pcy.edfgdf.fr cla.edfgdf.fr edf.fr edfgdf.fr
nameserver 130.98.194.189
nameserver 192.196.111.47
EOF
						cp /tmp/resolv.conf /etc/resolv.conf
						echo "*** ${ETAPE} en place."
						rm -f /tmp/resolv.conf
					fi
					echo	

				##################################
				#### configuration NTP        ####
				##################################
				
				conf_ntp					

				##################################
				#### 	change hostname       ####
				##################################
				
				#Le but est de corriger le hostname, le passer de majuscule à minuscule
				Title "Hostname"
				if [ "x${UNAME}" = "xAIX" ]
				then
					OLD_UNAME_N=`uname -n`
					OLD_HOSTNAME=`hostname`
					if [ "${OLD_UNAME_N}" != "${OLD_HOSTNAME}" ]
					then
						${SECHO} ${On_Red}
                        echo "Hostname and \"uname -n\" sont differants..." > $LOG
						echo "Hostname and \"uname -n\" sont differants.... why ?????"      >&2 && exit 4
						${SECHO} ${RCol}
					else
						${SECHO} ${BGre}
						echo "Hostname OK"
						${SECHO} ${RCol}
					fi
				fi
				echo				
				;;		
        *)      echo "OS_INCOMPATIBLE_AVEC_CE_SCRIPT" > $LOG
                echo "OS_INCOMPATIBLE_AVEC_CE_SCRIPT"
                >&2 && exit 97
                ;;
esac
>&2 && exit 0