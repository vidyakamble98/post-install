#!/bin/ksh

########################################################################################################################
# Script: SASC_Unix_PostInstallation_Step5-Set-Alterned_Disk
#
# Description: Ce script permet de configurer le disque alterné sur une machine Unix lors de la post-instalation
# Version: 1.0.2 (ou 1: modification majeure, 2: modification mineure, 3: correction de bug)
#
# Date de creation: 27/03/2019
# Cree par: Jean-Baptiste Meriaux
#
#
# Mise a jour:
#                           Charles BRANSARD - 22/09/2020 - Modification récupération YUM8 et YUM9 (correction bug centos)
#							Charles BRANSARD - 01/02/2021 - Ajout log erreur en local sur le serveur en cas de KO (/tmp/<nom_script_KO_date>)
#
# Pre-requis:				Le serveur est de type Unix
#
# Inputs:
#
# Outputs:
#                           0 : le script s'est correctement déroulé
#							4 : Erreur lors de l'installation
#							97 :OS incompatible avec le script
#
########################################################################################################################

####### DECLARATION DES CONSTANTES FIXES
SCRIPT_NAME="SASC_Unix_PostInstallation_Step5-Set-Alterned_Disk"
LOG="/tmp/${SCRIPT_NAME}_KO_$(date "+%Y%m%d%H%M")"

#####################################################
########## DECLARATION DES FONCTIONS ################
#####################################################

##############
#### MAIN ####
##############

#Check parametres entres


OS=$(uname)
HOSTNAME=`hostname | awk -F. '{print $1}'`
UNAME=`uname -s`

echo
echo "######################################"
echo "####### début set alterned disc ######"
echo "######################################"
echo

case $OS in
        "Linux")
				##################################
				#### 	  disque alterné	  ####
				##################################

				if [ "x${UNAME}" = "xLinux" ]
				then
					if [ -e /etc/system-release ]
					then
                        RELEASE_FILE=/etc/system-release
						OS=`cat /etc/system-release|awk '{print $1}'`
					else
                        RELEASE_FILE=/etc/redhat-release
						OS=`cat /etc/redhat-release |awk '{print $1}'`
					fi
					if [ "$OS" = "Red" ]
					then
						YUM_OS="rhel"
						RHE=$(grep -i Linux $RELEASE_FILE | sed -e 's/\(.*\)\(release \)\([0-9,.]*\)\(.*\)/\3/g' | awk -F"." '{print $1"."$2}')
						REL=$(echo ${RHE} | awk -F\. '{print $1}')
					elif [ "$OS" = "CentOS" ]
					then
						YUM_OS="centos"
						RHE=$(grep -i centos $RELEASE_FILE | sed -e 's/\(.*\)\(release \)\([0-9,.]*\)\(.*\)/\3/g' | awk -F"." '{print $1"."$2}')
						if [ -z $RHE ]
						then
							RHE=$(cat /etc/redhat-release | awk '{print $4}')
						fi
						REL=$(echo ${RHE} | awk -F\. '{print $1}')
					fi
				fi	
				
				#Sur Linux un disque est fourni afin de générer une copie du systeme une fois par semaine
				echo "Syteme Alterne"
				export YUM8=$YUM_OS
				export YUM9=$(awk 'NF==8 && $NF~/^(.*)$/ && $0~/^Red Hat Enterprise Linux Server release / { VERSION=NF-1;print $VERSION }' /etc/redhat-release)
		
				echo "*** Installation du svr_sysalt"
				sleep 5
				#On upgrade le package qui contient les scripts
				yum -y install svr_sysalt
		
				if [ "x${REL}" = "x7" ]
					then
						GRUB=/boot/grub2
						GRUB_CONF=grub.cfg
					else
						GRUB=/boot/grub
						GRUB_CONF=grub.conf
				fi
				#On verifie si le deuxième disque est deja identifie dans le conf de grub
				grep -w hd1 ${GRUB}/device.map >/dev/null 2>&1
				if [ $? -eq 0 ]
					then
						echo "*** Disque Alterne deja en place dans le fichier device"
					else
						#Si il n'est pas identifie on le rajoute
						backup_files ${GRUB}/device.map
						cp -p ${GRUB}/device.map /tmp/device.map
						grep -w hd0 ${GRUB}/device.map | sed -e 's/hd0/hd1/g' -e 's/sda$/sdb/g' >> /tmp/device.map
						cp /tmp/device.map ${GRUB}/device.map
						rm -f /tmp/device.map
					fi
					#On verifie si la crontab contient deja une entree pour le disque alterne
					#Si non on en rajoute une
					crontab -l | grep alterne >/dev/null 2>&1
					if [ $? -ne 0 ]
					then
					cat >> /var/spool/cron/root <<EOF
## Sauvegarde disque systeme sur systeme alterne
00 18 * * 5 /outillage/PraSys/bin/systeme_alterne.sh /dev/sdb  >/dev/null 2>&1
EOF
					fi
					#On affiche la crontab pour montrer a l'administrateur le bon deroulement
					crontab -l | grep alterne 
					echo
					#On verifie si le VG alterne est deja configure
					vgs|grep root_vg_alt >/dev/null 2>&1
					if [ $? -eq 0 ]
					then
							echo "Systeme Alterne deja en place."
					else
							#Si il n'est pas configure on lance le script systeme_alterne.sh qui va générer ce VG
							echo "*** Mise en place Disque Alterne et crontab ok"
							echo "Lancement de la copie, twice..."
							/outillage/PraSys/bin/systeme_alterne.sh /dev/sdb
							echo
							#Le script ne sait pas tout traiter en une fois on le lance donc deux fois.
							echo "Relance pour corriger les erreurs"
							sleep 5
							/outillage/PraSys/bin/systeme_alterne.sh /dev/sdb
					fi
					#On verifie que le script a bien mis à jour le grub avec une entree alterne pour booter sur le deuxième disque si probleme
					grep "Systeme Alterne" ${GRUB}/${GRUB_CONF} >/dev/null 2>&1
					if [ $? -eq 0 ]
					then
						echo "Le disque alterne est bien présent dans le grub.conf"
					else
                        echo "Ajouter le disque alterne dans le grub.conf" > $LOG
						echo "Ajouter le disque alterne dans le grub.conf"     >&2 && exit 4
					fi						

		;;		
        "AIX")
				##################################
				####    disque alterné        ####
				##################################
				
				#AIX pas gere encore
				res=`lsvg | grep altinst_rootvg`
				if [ "${res}" = "altinst_rootvg" ]
					then
						echo "Systeme Alterne deja en place."
					else
						echo "Installation via l'outil configure "
						echo "lspv"
				fi
			
				;;		
        *)      echo "OS_INCOMPATIBLE_AVEC_CE_SCRIPT" > $LOG
                echo "OS_INCOMPATIBLE_AVEC_CE_SCRIPT"
                >&2 && exit 97
                ;;
esac
>&2 && exit 0