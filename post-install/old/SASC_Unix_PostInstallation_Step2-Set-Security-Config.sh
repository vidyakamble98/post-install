#!/bin/ksh

########################################################################################################################
# Script: SASC_Unix_PostInstallation_Step2-Set-Security-Config
#
# Description: Ce script permet de configurer la sécurité sur une machine Unix lors de la post-instalation
# Version: 1.0.9 (ou 1: modification majeure, 2: modification mineure, 3: correction de bug)
#
# Date de creation: 19/03/2019
# Cree par: Jean-Baptiste Meriaux
#
#
# Mise a jour:
#                           Charles BRANSARD - 20/09/2019 - Ajout verification open-vptools rhel7
#                           Charles BRANSARD - 15/10/2019 - Modification pour prise en compte patch CVE3 + CVE4
#                           Charles BRANSARD - 08/11/2019 - Modification pour prise en compte installation microcode_ctl si non installé
#							Charles BRANSARD - 15/11/2019 - Ajout des packages manquants dans la commande d'upgrade à savoir les packages pour RHEL6 dracut* elfutils* ghostscript* glib2* gnupg2* nss* polkit* python* yum* qemu* libvirt* 
#																												 			 les packages pour RHEL7 dracut* elfutils* ghostscript* glib2* gnupg2* libssh* microcode* nss* polkit* python* yum* libssh2* qemu* libvirt* libgudev1*
#							Charles BRANSARD - 23/01/2020 - Ajout prise en compte EL 6.10 et 7.7 pour patch CVE
#							Charles BRANSARD - 22/09/2020 - Modification récupération YUM8 YUM9 (correction bug centos)
#                           Charles BRANSARD - 21/12/2020 - Correction bug El 7.7 pour update open-vm-tools (ajout d'un yum clean all avant update)
#							Charles BRANSARD - 01/02/2021 - Ajout log erreur en local sur le serveur en cas de KO (/tmp/<nom_script_KO_date>)
#                           Vincent Mignot - 01/03/2021 - Ajout patch CVE Sudo
#                           Charles BRANSARD - 23/03/2021 - Ajout prise en compte El 7.9 pour patch CVE
#
# Pre-requis:				Le serveur est de type Unix
#
# Inputs:
#			1:  			: fournisseur du serveur
#
# Outputs:
#                           0 : le script s'est correctement déroulé
#							3 : Erreur lors de l'installation microcode_ctl
#							4 : Erreur lors des patchs 
#							6 : Erreur installation open-vm-tools 
#							96: Mauvais paramètres renseignés
#							97: OS incompatible avec le script
#
########################################################################################################################

####### DECLARATION DES CONSTANTES FIXES
SCRIPT_NAME="SASC_Unix_PostInstallation_Step2-Set-Security-Config"
LOG="/tmp/${SCRIPT_NAME}_KO_$(date "+%Y%m%d%H%M")"


#####################################################
########## DECLARATION DES FONCTIONS ################
#####################################################

backup_files()
{
	for i in ${*}
	do
		if [ -f "${i}" ]; then
			cp -p "${i}" "${i}".$(date +%Y%m%d-%H%M)
		fi
	done
}

##############
#### MAIN ####
##############

#Check parametres entres
[  -z $1 ] && echo "Veuillez renseigner le fournisseur" >&2 && exit 96

FOURNISSEUR=$1

if [[ $FOURNISSEUR  != "CONSER" && $FOURNISSEUR  != "PFC" && $FOURNISSEUR != "NEWCLOUD" && $FOURNISSEUR != "PM1000" ]]
then
    echo "La variable Fournisseur doit être égale à CONSER, PFC, PM1000 ou NEWCLOUD" > $LOG
	echo "La variable Fournisseur doit être égale à CONSER, PFC, PM1000 ou NEWCLOUD"
    exit 96
fi

echo "######################################"
echo "######### start set security #########"
echo "######################################"

HOSTNAME=$(hostname | awk -F. '{print $1}')
OS=$(uname)

if [ $OS -eq "Linux" ]
then
	# Get release file
	if [ -e /etc/system-release ]
	then
		RELEASE_FILE="/etc/system-release"
	elif [ -e /etc/redhat-release ]
	then
		RELEASE_FILE="/etc/redhat-release"
	else
        echo "Cannot set YUM Variables !" > $LOG
		echo "Cannot set YUM Variables !"
		exit 98
	fi
	
	# Set YUM Variable
    TYPE_OS=$(cat $RELEASE_FILE | awk '{print $1}' | tr 'A-Z' 'a-z')
	case $TYPE_OS in
		"red")
			YUM8="rhel"
			YUM9=$(grep -i Linux $RELEASE_FILE | sed -e 's/\(.*\)\(release \)\([0-9,.]*\)\(.*\)/\3/g' | awk -F"." '{print $1"."$2}')
		;;
		"centos")
            YUM8="centos"
			YUM9=$(grep -i centos $RELEASE_FILE | sed -e 's/\(.*\)\(release \)\([0-9,.]*\)\(.*\)/\3/g' | awk -F"." '{print $1"."$2}')
		;;
		*)
            echo -e "Linux distribution $YUM8 not supported" > $LOG
			echo -e "Linux distribution $YUM8 not supported" && exit 97
	esac
	
	# Set Version and release
	VERSION=$(echo $YUM9 | awk -F\. '{print $1}')
	RELEASE=$(echo $YUM9 | awk -F\. '{print $2}')
	
	case $VERSION in
		"5")
			echo -e "No Patch for this version !" && exit 0
			MIN_KERNEL_VERSION="2.6.18-433"
		;;
		"6")
			if [ "$RELEASE" = 10 ]
			then
				MIN_KERNEL_VERSION="2.6.32-754.17.1"
				YUM9="6.10"
                YUM9_REF_CVE4=${YUM9}
			elif [ "$RELEASE" = 9 ]
			then
				MIN_KERNEL_VERSION="2.6.32-754.14.2"
				YUM9="6.9"
                YUM9_REF_CVE4=${YUM9}
			else
				MIN_KERNEL_VERSION="2.6.32-754.14.2"
				YUM9="6.9"
                YUM9_REF_CVE4=${YUM9}
			fi
		;;
		"7")
			# Upgragde open-vmtools
			rpm -qa |grep -i open-vm-tools > /dev/null 2>&1
			if [ $? -eq 0 ]
			then
                CMD_UPDATE_VMTOOLS="YUM8=${YUM8} YUM9=${YUM9} yum --enablerepo=* clean all >/dev/null 2>&1 ; YUM8=${YUM8} YUM9=${YUM9} yum -y update open-vm-tools"
                su -l root -c "$CMD_UPDATE_VMTOOLS"
                if [ $? -eq 0 ]
                then
                    echo "open-vm-tools OK"
                else
                    echo "Update open-vm-tools KO via la commande : YUM8=${YUM8} YUM9=${YUM9} yum --enablerepo=* clean all >/dev/null 2>&1 ; YUM8=${YUM8} YUM9=${YUM9} yum -y update open-vm-tools" > $LOG
                    echo "Update open-vm-tools KO" && exit 7
                fi
                
			else
                CMD_INSTALL_VMTOOLS="YUM8=${YUM8} YUM9=${YUM9} yum --enablerepo=* clean all >/dev/null 2>&1 ; YUM8=${YUM8} YUM9=${YUM9} yum -y install open-vm-tools"
                su -l root -c "$CMD_INSTALL_VMTOOLS"
                if [ $? -eq 0 ]
                then
                    echo "Installation open-vm-tools OK"
                else
                    echo "Installation open-vm-tools KO via la commande : YUM8=${YUM8} YUM9=${YUM9} yum --enablerepo=* clean all >/dev/null 2>&1 ; YUM8=${YUM8} YUM9=${YUM9} yum -y install open-vm-tools" > $LOG
                    echo "Installation open-vm-tools KO" && exit 6
                fi
                
			fi
            if [ "${RELEASE}" = 9 ]
            then
                MIN_KERNEL_VERSION="3.10.0-1160.6.1"
                YUM9_REF_CVE3="7.9"
				YUM9_REF_CVE4="7.9"
			elif [ "$RELEASE" = 7 ]
			then
				MIN_KERNEL_VERSION="3.10.0-1062.9.1"
				# version LINUX REF
				YUM9_REF_CVE3="7.7"
				YUM9_REF_CVE4="7.7"
			elif [ "$RELEASE" = 5 ]
			then
				MIN_KERNEL_VERSION="3.10.0-957.27.2"
				# version LINUX REF
				YUM9_REF_CVE3="7.5"
				YUM9_REF_CVE4="7.5"		
			else
				YUM9_REF_CVE3="7.3"
				YUM9_REF_CVE4="7.5"
				MIN_KERNEL_VERSION="3.10.0-957.27.2"	
			fi

		;;
		*)
			echo -e "Bad version !" && exit 97
	esac
			
	# Patch OS
	echo "Patch CVE :"
	uname -r | grep "$MIN_KERNEL_VERSION" > /dev/null
	if [ $? -eq 0 ]
	then
		echo -e "\tCVE Patch already installed !"
        CVE_KERNEL="OK"
	else
        CVE_KERNEL="KO"
    fi
	
	# Check svr_sysalt package 
	SYSALT_PKG=$(rpm -qa | grep svr_sysalt)
	if [ $? -eq 0 ]
	then
		echo -e "\tsvr_sysalt package found. Trying to remove it:"
		SYSALT_UNINSTALL=$(rpm -e $SYSALT_PKG >&2)
		if [ $? -eq 0 ]
		then
			echo -e "\t\tOK"
		else
            echo "erreur suppression package ${SYSALT_PKG} via la commande :  rpm -e $SYSALT_PKG" > $LOG
			echo -e "\t\tError"
			exit 99
		fi
		echo -e "\tPackage will be reinstall in alterned disk part"
	fi
	
	case $VERSION in
		"6")
			if [ "$FOURNISSEUR" = "NEWCLOUD" ]
			then
				echo -e "\tNEWCLOUD server: Add newcloud repository"
				cat >/etc/yum.repos.d/NETINST_el-sysref-updates.repo <<EOF
[sysref-\$YUM8-\$YUM9-updates-base]
name=sysref-\$YUM8-\$YUM9-updates-base
baseurl=http://10.11.75.41/cobbler/localmirror/distributions/\$YUM8/\$releasever/\$basearch/\$YUM9/updates/
enabled=1
priority=99
gpgcheck=0
EOF
			fi
            uname -r | grep "$MIN_KERNEL_VERSION" > /dev/null
            if [ $? -eq 0 ]
            then
                echo -e "\tCVE Patch already installed !"
            else
                CMD_INSTALL_CVE3="yum --enablerepo=* clean all >/dev/null 2>&1 && YUM8=${YUM8} YUM9=${YUM9} yum -y --disablerepo=* --enablerepo=*updates-base update kernel* glibc* samba* dnsmasq java-1.8.0-openjdk* tomcat6* ntp ntpdate microcode* git* dracut* elfutils* ghostscript* glib2* gnupg2* nss* polkit* python* yum* qemu* libvirt* sssd* >/dev/null"
                su -l root -c "$CMD_INSTALL_CVE3"
                if [ $? -eq 0 ]
                then
                    echo -e "\tPatch CVE OK"
                else
                    echo "Patch CVE KO via la commande : yum --enablerepo=* clean all >/dev/null 2>&1 && YUM8=${YUM8} YUM9=${YUM9} yum -y --disablerepo=* --enablerepo=*updates-base update kernel* glibc* samba* dnsmasq java-1.8.0-openjdk* tomcat6* ntp ntpdate microcode* git* dracut* elfutils* ghostscript* glib2* gnupg2* nss* polkit* python* yum* qemu* libvirt* sssd*" > $LOG
                    echo -e "\tPatch CVE KO " && exit 4	     				
                fi
            fi
                
            # Check et installation de microcode_ctl si non présent
            rpm -qa | grep microcode_ctl > /dev/null
            if [ $? -eq 0 ]
            then
                echo -e "\tPackage microcode_ctl found OK"
            else
                echo -e "\tPackage microcode_ctl not found. Trying to install it: "
                CMD_INSTALL_MICROCODE="yum --enablerepo=* clean all >/dev/null 2>&1 && YUM8=${YUM8} YUM9=${YUM9_REF_CVE4} yum -y install microcode_ctl*"
                su -l root -c "$CMD_INSTALL_MICROCODE"
                if [ $? -eq 0 ]
                then
                    echo -e "\tInstallation microcode_ctl OK"
                else
                    echo "Installation microcode_ctl KO via la commande : yum --enablerepo=* clean all >/dev/null 2>&1 && YUM8=${YUM8} YUM9=${YUM9_REF_CVE4} yum -y install microcode_ctl*" > $LOG
                    echo -e "\tInstallation microcode_ctl KO " && exit 3	     				
                fi
            fi
		;;
		"7")
			if [ "$FOURNISSEUR" = "NEWCLOUD" ]
			then
				echo -e "\tNEWCLOUD server: Add newcloud repository"
				cat >/etc/yum.repos.d/NETINST_el-sysref-updates.repo <<EOF
[sysref-\$YUM8-\$YUM9-updates-base]
name=sysref-\$YUM8-\$YUM9-updates-base
baseurl=http://10.11.75.41/cobbler/localmirror/distributions/\$YUM8/\$releasever/\$basearch/\$YUM9/updates/
enabled=1
priority=99
gpgcheck=0
EOF
			fi
			
            uname -r | grep "$MIN_KERNEL_VERSION" > /dev/null
            if [ $? -eq 0 ]
            then
                echo -e "\tCVE Patch already installed !"
            else            
                # Patch CVE3
                CMD_INSTALL_CVE3="yum --enablerepo=* clean all >/dev/null 2>&1 && YUM8=${YUM8} YUM9=${YUM9_REF_CVE3} yum -y --disablerepo=* --enablerepo=*updates-base update kernel* glibc* samba* dnsmasq java-1.8.0-openjdk* tomcat6* ntp ntpdate dracut* elfutils* ghostscript* glib2* gnupg2* libssh* microcode* nss* polkit* python* yum* libssh2* qemu* libvirt* libgudev1* git* sssd* systemd* > /dev/null"
                su -l root -c "$CMD_INSTALL_CVE3"
                if [ $? -eq 0 ]
                then
                    echo -e "\tPatch CVE3 OK"
                else
                    echo "Patch CVE3 KO via la commande : yum --enablerepo=* clean all >/dev/null 2>&1 && YUM8=${YUM8} YUM9=${YUM9_REF_CVE3} yum -y --disablerepo=* --enablerepo=*updates-base update kernel* glibc* samba* dnsmasq java-1.8.0-openjdk* tomcat6* ntp ntpdate dracut* elfutils* ghostscript* glib2* gnupg2* libssh* microcode* nss* polkit* python* yum* libssh2* qemu* libvirt* libgudev1* git* sssd* systemd*" > $LOG
                    echo -e "\tPatch CVE3 KO " && exit 4	     				
                fi
                
                # Patch CVE4
                CMD_INSTALL_CVE4="yum --enablerepo=* clean all >/dev/null 2>&1 && YUM8=${YUM8} YUM9=${YUM9_REF_CVE4} yum -y --disablerepo=* --enablerepo=*updates-base update kernel* > /dev/null"
                su -l root -c "$CMD_INSTALL_CVE4"
                if [ $? -eq 0 ]
                then
                    echo -e "\tPatch CVE4 OK"
                else
                    echo "Patch CVE4 KO via la commande : yum --enablerepo=* clean all >/dev/null 2>&1 && YUM8=${YUM8} YUM9=${YUM9_REF_CVE4} yum -y --disablerepo=* --enablerepo=*updates-base update kernel*" > $LOG
                    echo -e "\tPatch CVE4 KO " && exit 4	     				
                fi
            fi

			# Check et installation de microcode_ctl si non présent
			rpm -qa | grep microcode_ctl > /dev/null
			if [ $? -eq 0 ]
			then
				echo -e "\tPackage microcode_ctl found OK"
			else
				echo -e "\tPackage microcode_ctl not found. Trying to install it: "
				CMD_INSTALL_MICROCODE="yum --enablerepo=* clean all >/dev/null 2>&1 && YUM8=${YUM8} YUM9=${YUM9_REF_CVE4} yum -y install microcode_ctl*"
				su -l root -c "$CMD_INSTALL_MICROCODE"
				if [ $? -eq 0 ]
				then
					echo -e "\tInstallation microcode_ctl OK"
				else
                    echo "Installation microcode_ctl KO via la commande : yum --enablerepo=* clean all >/dev/null 2>&1 && YUM8=${YUM8} YUM9=${YUM9_REF_CVE4} yum -y install microcode_ctl*" > $LOG
					echo -e "\tInstallation microcode_ctl KO " && exit 3	     				
				fi
			fi

			# Mise a jour sssd
			su -l root -c "YUM9=${YUM9_REF_CVE3} yum -y update sssd > /dev/null"
			if [ $? -eq 0 ]
			then
				echo "sssd update OK"
			else
                echo "sssd update KO via la commande : YUM9=${YUM9_REF_CVE3} yum -y update sssd" > $LOG
				echo "sssd update KO" >&2 && exit 4
			fi
            
		;;
		*)
            echo "Unknown $YUM8 version: $YUM9" > $LOG
			echo "Unknown $YUM8 version: $YUM9" && exit 97
	esac
    
    # Mise a jour Patch CVE Sudo

	if [ "$FOURNISSEUR" = "NEWCLOUD" ]
	then
    cat >/etc/yum.repos.d/NETINST_el-sysref-updates.repo <<EOF
[sysref-\$YUM8-\$YUM9-updates-base]
name=sysref-\$YUM8-\$YUM9-updates-base
baseurl=http://10.11.75.41/cobbler/localmirror/distributions/\$YUM8/\$releasever/\$basearch/\$YUM9/updates/
enabled=1
priority=99
gpgcheck=0
EOF
    fi
    case $TYPE_OS in
        red)
            case $VERSION in
                6)
                if [ "$RELEASE" = 10 ]
                then
                    su -l root -c "yum --enablerepo=* clean all && YUM9=6.10 yum -y --disablerepo=* --enablerepo=*updates-base update sudo*" > /dev/null 2>&1
                    if [ $? -eq 0 ]
                    then
                        echo "pacth CVE sudo OK"
                    else
                        echo "patch CVE sudo KO" >&2 && exit 4
                    fi
                else
                    su -l root -c "yum --enablerepo=* clean all && YUM9=6.9 yum -y --disablerepo=* --enablerepo=*updates-base update sudo*" > /dev/null 2>&1
                    if [ $? -eq 0 ]
                    then
                        echo "pacth CVE sudo OK"
                    else
                        echo "patch CVE sudo KO" >&2 && exit 4
                    fi
                fi
                
                ;;
                7)
                su -l root -c "yum --enablerepo=* clean all && yum -y --disablerepo=* --enablerepo=*updates-base update sudo*" > /dev/null 2>&1
                if [ $? -eq 0 ]
                then
                    echo "pacth CVE sudo OK"
                else
                    echo "patch CVE sudo KO" >&2 && exit 4
                fi
                ;;
            esac
        ;;
        centos)
            case $VERSION in
                6)
                su -l root -c "yum --enablerepo=* clean all && YUM9=6.10 yum -y --disablerepo=* --enablerepo=*updates-base update sudo*" > /dev/null 2>&1
                if [ $? -eq 0 ]
                then
                    echo "pacth CVE sudo OK"
                else
                    echo "patch CVE sudo KO" >&2 && exit 4
                fi
                ;;
                7)
                su -l root -c "yum --enablerepo=* clean all && yum -y --disablerepo=* --enablerepo=*updates-base update sudo*" > /dev/null 2>&1
                if [ $? -eq 0 ]
                then
                    echo "pacth CVE sudo OK"
                else
                    echo "patch CVE sudo KO" >&2 && exit 4
                fi
                ;;
            esac
    esac
else
    echo "OS, $OS, not supported" > $LOG
	echo "OS, $OS, not supported"
fi
