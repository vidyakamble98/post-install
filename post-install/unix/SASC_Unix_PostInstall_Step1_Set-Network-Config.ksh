#!/bin/ksh
########################################################################################################################
# Script: SASC_Unix_PostInstall_Step1_Set-Network-Config.ksh.ksh
#
# Description: Ce script permet de configurer le network sur une machine Unix lors de la post-instalation
# Version: 1.1.4 (ou 1: modification majeure, 2: modification mineure, 3: correction de bug)
#
# Date de creation: 19/03/2019
# Cree par: Jean-Baptiste Meriaux
#
#
# Mise a jour:
#                           Charles BRANSARD - 15/01/2019 - Prise en compte cas newcloud (pas de modification configuration DNS + modification du fichier /etc/hosts pour prendre en compte le SIP NEWCLOUD)
#                           Charles BRANSARD - 31/01/2020 - Modification prise en compte du hostname en minuscule + mise en place en FQDN
#                           Charles BRANSARD - 01/02/2021 - Ajout log erreur en local sur le serveur en cas de KO (/tmp/<nom_script_KO_date>)
#                           Piotr Ulaszewski - 07/02/2023 - Modification de la fonction repo_fix, ajout de conf_ntp pour Linux7
#                           Piotr Ulaszewski - 28/02/2023 - Fix pour regle hpsa sur Linux 7 - sauvegarder les iptables
#                           Piotr Ulaszewski - 07/03/2023 - Ajout de conf_ntp_aix (ancien script de post-install)
#                           Piotr Ulaszewski - 07/03/2023 - Redemarage du service network si KO pour redemarage du service NetworkManager
#                           Piotr Ulaszewski - 09/03/2023 - Ancienne methode pour hostname si KO pour la commande hostnamectl
#                           Piotr Ulaszewski - 09/03/2023 - Modification de la detection de version OS pour etre conforme aux autres modules
#                           Piotr Ulaszewski - 30/03/2023 - AIX - forcer la syncho NTP avec le serveur perfere du fichier /etc/ntp.conf
#                           Piotr Ulaszewski - 30/03/2023 - Modification de test pour verfier si xntpd et netcd actif
#                           Piotr Ulaszewski - 19/04/2023 - Ajout des serveurs ntp dans le fichier hosts
#                           Piotr Ulaszewski - 02/05/2023 - Ajout des serveurs ntp dans le fichier hosts pour AIX
#                           Piotr Ulaszewski - 14/08/2023 - Deplacement des repos NETINST vers /etc/yum.repos.d is necessaire
#
# Pre-requis:               Le serveur est de type Unix
#
# Inputs:
#           1:              : Zone du serveur
#           2: 	            : Site du serveur
#
# Outputs:
#                           0 : le script s'est correctement déroulé
#                           3 : Erreur lors de la correction des repo
#                           4 : Erreur lors de l'installation
#                           5 : Distribution de Linux pas supporté
#                           96 : Mauvais paramètres renseignés
#                           97 : OS incompatible avec le script
#                           98 : Erreur fichier release non trouve
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

    ETAPE="config NTP - Chrony"
    echo " debut ${ETAPE}"

	# Ajout des serveurs ntp dans le fichier hosts
    echo "*** Ajout des serveurs ntp dans le fichier hosts"
	cat /etc/hosts | grep "192.168.126.254" >/dev/null 2>&1
	if ! [ $? -eq 0 ]; then 
		backup_files /etc/hosts
       	cat <<EOF >>/etc/hosts
#NTP
192.168.126.254  ntp1.edf.fr
192.168.127.254  ntp2.edf.fr
EOF
	fi

    #On verifie que la configuration NTP - Chrony est correcte.
    echo "*** Verify chrony output"
        service chronyd start
        chronyc tracking | grep -i "cannot"
        if [ $? -eq 0 ]
        then
            echo "Probleme de connexion chrony ; verifier la conf." > $LOG
        else
        
            STRAT=$(chronyc tracking | grep Stratum | awk '{print $3}')
            if [ ${STRAT} -gt 17 ]
                then
                echo "Stratum \"${STRAT}\" trop eleve, merci de revoir la conf chrony" > $LOG
                echo "Stratum \"${STRAT}\" trop eleve, merci de revoir la conf chrony"     >&2 && exit 4
            fi
        fi
}

conf_ntp7(){
    #On verifie que la configuration NTP - ntpd est correcte.
    #ETAPE="config NTP - ntpd"
    #echo " debut ${ETAPE}"
    #echo "*** Verify ntpd output"
    #service ntpd start
    #ntpstat | grep -i "^synchronised to"
    #if ! [ $? -eq 0 ]; then
    #    echo "Probleme de connexion ntpd ; verifier la conf ntpd." > $LOG
    #    echo "******************"
    #	 echo \# cat /etc/ntp.conf
    #    grep -v \# /etc/ntp.conf
    # 	 echo "******************"
    #else
    #    STRAT=$(ntpstat | grep -i stratum | awk '{print $8}')
    #    if [ ${STRAT} -gt 17 ]; then
    #        echo "Stratum \"${STRAT}\" trop eleve, merci de revoir la conf ntpd" > $LOG
    #        echo "Stratum \"${STRAT}\" trop eleve, merci de revoir la conf ntpd" >&2 && exit 4
    #    fi
    #fi

    ETAPE="config NTP"
    echo " début ${ETAPE}"

	# Ajout des serveurs ntp dans le fichier hosts
    echo "*** Ajout des serveurs ntp dans le fichier hosts"
	cat /etc/hosts | grep "192.168.126.254" >/dev/null 2>&1
	if ! [ $? -eq 0 ]; then 
		backup_files /etc/hosts
       	cat <<EOF >>/etc/hosts
#NTP
192.168.126.254  ntp1.edf.fr
192.168.127.254  ntp2.edf.fr
EOF
	fi

    #On verifie que la configuration NTP est correcte.
    echo "*** Verify ntpq output"
    service ntpd start
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

conf_ntp_aix(){

    ETAPE="config NTP"
    echo " début ${ETAPE}"

	# Ajout des serveurs ntp dans le fichier hosts
    echo "*** Ajout des serveurs ntp dans le fichier hosts"
	cat /etc/hosts | grep "192.168.126.254" >/dev/null 2>&1
	if ! [ $? -eq 0 ]; then 
		backup_files /etc/hosts
       	cat <<EOF >>/etc/hosts
#NTP
192.168.126.254  ntp1.edf.fr
192.168.127.254  ntp2.edf.fr
EOF
	fi

    #On verifie si le service xntpd demarre automatiquement
    echo "*** Verify ntpq output"
    grep -q "^start /usr/sbin/xntpd " /etc/rc.tcpip
    if [ $? -ne 0 ]
    then
        #Si ce n'est pas le cas on rajoute son demarrage automatique
        backup_files /etc/rc.tcpip
        perl -pi.xxx -e "s|^#start /usr/sbin/xntpd |start /usr/sbin/xntpd |g" /etc/rc.tcpip
        perl -pi.xxx -e "s|^#start /usr/sbin/netcd |start /usr/sbin/netcd |g" /etc/rc.tcpip
        rm -f /etc/rc.tcpip.xxx

        #retirer le serveur NTP du fichier /etc/ntp.conf
        ntpserver=$(cat /etc/ntp.conf | grep server | grep prefer | awk '{print $2}')
        if [ -z "$ntpserver" ]
        then
            echo "Un pb de connexion au ntp ? merci de revoir la conf du ntpd - /etc/ntp.conf" > $LOG
            echo "Un pb de connexion au ntp ? merci de revoir la conf du ntpd - /etc/ntp.conf"     >&2 && exit 4
        fi

        #forcer la syncho NTP
        lssrc -s xntpd | grep xntpd | grep active >&2
        if [ $? -eq 0 ]
        then
            stopsrc -s xntpd
            ntpdate -b $ntpserver
            date
            sleep 2
            startsrc -s xntpd
        else
            ntpdate -b $ntpserver
            date
            startsrc -s xntpd
        fi

        #demarrer netcd
        lssrc -s netcd | grep netcd | grep active >&2
        if [ $? -eq 0 ]
        then
            stopsrc -s netcd
            sleep 2
            startsrc -s netcd
        else
            startsrc -s netcd
        fi
    else
        echo "*** ${ETAPE} deja  en place."
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

repo_fix()
{
    # les repos netinst et dvdr au bon endroit
    gooddvdr=$(ls /etc/yum.repos.d/backuprepo | grep DVD)
    goodnetinstr=$(ls /etc/yum.repos.d/ | grep NETINST)

    # les derniers repos netinst et dvdr au mauvais endroit
    baddvdr=$(ls /etc/yum.repos.d/ | grep DVD)
    badnetinstr=$(ls /etc/yum.repos.d/svr_sysref-linux-config/ | grep NETINST)

    echo "Verification des repos"
    if [ -z $goodnetinstr ]; then
        # pas de repos NETINST dans /etc/yum.repos.d/
        echo "Aucun repo NETINST trouve dans /etc/yum.repos.d"

        # verification si les repos NETINST sont dans /etc/yum.repos.d/svr_sysref-linux-config/
        if [ -z $badnetinstr ]; then
               echo "[ERROR] Echec pas de repos NETINST dans /etc/yum.repos.d ni dans /etc/yum.repos.d/svr_sysref-linux-config"
               echo "[ERROR] Echec pas de repos NETINST trouves" > $LOG
               repofix="KO"
            return
        else
            # les repos NETINST sont dans /etc/yum.repos.d/svr_sysref-linux-config/ donc on les deplace dans /etc/yum.repos.d
            echo "Deplacement des repos NETINST dans /etc/yum.repos.d"
            mv /etc/yum.repos.d/svr_sysref-linux-config/NETINST* /etc/yum.repos.d/ >/dev/null 2>&1
            if [ $? -eq 0 ]; then
                echo "Repos NETINST deplaces avec succes"
            else
                echo "[ERROR] Echec du deplacement des repos NETINST"
                echo "[ERROR] Echec du deplacement des repos NETINST" > $LOG
                repofix="KO"
                return
            fi
        fi

        # verification si les repos DVD sont dans /etc/yum.repos.d/ (cas d'erreur)
        if [ -z $baddvdr ]; then
               echo "Pas de repos DVD dans /etc/yum.repos.d"
        else
            # Deplacement des repos DVD dans /etc/yum.repos.d/svr_sysref-linux-config
            echo "Deplacement des repos DVD dans /etc/yum.repos.d/svr_sysref-linux-config"
            mv /etc/yum.repos.d/DVD* /etc/yum.repos.d/svr_sysref-linux-config/ >/dev/null 2>&1
            if [ $? -eq 0 ]; then
            echo "Repos DVD deplaces avec succes"
            else
                echo "[ERROR] Echec du deplacement des repos DVD"
                echo "[ERROR] Echec du deplacement des repos DVD" > $LOG
                repofix="KO"
                return
            fi  
        fi
    fi

    # verification finale, pas de repos DVD dans /etc/yum.repos.d/ seulement des repos NETINST
    presdvds=$(ls /etc/yum.repos.d/ | grep DVD)
    if [ -z $presdvds ]; then
        echo "Pas de repos DVD dans /etc/yum.repos.d"
    else
        echo "[ERROR] Erreur repos DVD presents dans /etc/yum.repos.d"
        echo "[ERROR] Erreur repos DVD presents dans /etc/yum.repos.d" > $LOG
        repofix="KO"
        return
    fi
    presnetinstr=$(ls /etc/yum.repos.d/ | grep NETINST)
    if [ -z $presnetinstr ]; then
        echo "[ERROR] Erreur pas de repos NETINST dans /etc/yum.repos.d"
        echo "[ERROR] Erreur pas de repos NETINST dans /etc/yum.repos.d" > $LOG
        repofix="KO"
    else
        echo "Repos NETINST dans le bon repertoire"
        repofix="OK"
    fi
}


##############
#### MAIN ####
##############

#Check parametres entres
case $1 in
        * )		[  -z "$1" ] && echo "Veuillez renseigner comme parametre la zone puis le site" >&2 && exit 96
esac	

case $2 in
        * )		[  -z "$2" ] && echo "Veuillez renseigner comme parametre la zone puis le site" >&2 && exit 96
esac

ZONE=$1
SITE=$2

OS=$(uname)
HOSTNAME=$(hostname | awk -F. '{print $1}')
UNAME=$(uname -s)

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
                # Verif et correction des repo
                repo_fix

                # Get release file
                if [ -e /etc/system-release ]
                then
                    RELEASE_FILE="/etc/system-release"
                    TYPE_OS=$(cat $RELEASE_FILE | awk '{print $1}' | tr 'A-Z' 'a-z') # Exemple de sortie : red ou centos
                elif [ -e /etc/redhat-release ]
                then
                    RELEASE_FILE="/etc/redhat-release"
                    TYPE_OS=$(cat $RELEASE_FILE | awk '{print $1}' | tr 'A-Z' 'a-z')
                else
                    echo "Cannot find file /etc/redhat-release !" > $LOG
                    echo "Cannot find file /etc/redhat-release !"
                    exit 98
                fi

                # set version variable
                case $TYPE_OS in
                "red")
                    YUM8="rhel"
                    RHE_MIN_VERS=$(grep -i Linux $RELEASE_FILE | sed -e 's/\(.*\)\(release \)\([0-9,.]*\)\(.*\)/\3/g' | awk -F"." '{print $1"."$2}')
                    RHE_MAJ_VERS=$(echo ${RHE_MIN_VERS} | awk -F\. '{print $1}') # Exemple de sortie 6
                    ;;
                "centos")
                    YUM8="centos"
                    RHE_MIN_VERS=$(grep -i centos $RELEASE_FILE | sed -e 's/\(.*\)\(release \)\([0-9,.]*\)\(.*\)/\3/g' | awk -F"." '{print $1"."$2}')
                    RHE_MAJ_VERS=$(echo ${RHE_MIN_VERS} | awk -F\. '{print $1}')
                    ;;
                *)
                    echo -e "Linux distribution $YUM8 not supported" > $LOG
                    echo -e "Linux distribution $YUM8 not supported" && exit 5
                    ;;
                esac

                ################################################################################
                #### sauvegarde des iptables pour Linux 7	(regle hpsa a suavegarder)  ####
                ################################################################################

                if [ "$RHE_MAJ_VERS" == "7" ] || [ "$RHE_MAJ_VERS" == "6" ]; then
                    echo "Saving iptables rules for hpsa"
                    service iptables save >/dev/null 2>&1
                fi

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
                
                if [ "$RHE_MAJ_VERS" == "7" ] || [ "$RHE_MAJ_VERS" == "6" ]; then
                    conf_ntp7
                else
                    conf_ntp
                fi
                
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
                    echo "Redemarage du service \"NetworkManager\" pour la prise en compte"
                    systemctl restart NetworkManager.service
                    if ! [ $? -eq 0 ]; then
                        if [ "$RHE_MAJ_VERS" == "7" ] || [ "$RHE_MAJ_VERS" == "6" ]; then
                            echo "Redemarage du service \"network\" pour la prise en compte"
                            service network restart
                        fi
                    fi
                fi
                hostname_min=$(hostname | tr 'A-Z' 'a-z')
                hostname | grep "[A-Z]" > /dev/null 2>&1
                if [ $? -eq 0 ]
                then                   
                    #Sur RedHat7/8 hostnamectl remplace les fichiers
                    hostnamectl set-hostname $FQDN_MIN
                    if ! [ $? -eq 0 ]; then
                        if [ "$RHE_MAJ_VERS" == "6" ]; then
                            hostname ${FQDN_MIN}
                        fi
                    fi
                    echo "*** Modification hostname OK"
                    
                else
                    echo "hostname conforme"
                fi
                if [ $repofix = "KO" ];then
                    echo "[ERROR] Erreur lors de la correction des repo" > $LOG
                    exit 3
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
                
                conf_ntp_aix

                ##################################
                #### 	change hostname       ####
                ##################################
                
                #Le but est de corriger le hostname, le passer de majuscule à minuscule
                ETAPE="Verification Hostname"
                echo " début ${ETAPE}"
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
