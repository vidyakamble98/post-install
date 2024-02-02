#!/bin/ksh

########################################################################################################################
# Script: SASC_Unix_PostInstallation_Step4-Set-Custom-Config
#
# Description: Ce script permet de configurer des éléments divers sur une machine Unix lors de la post-instalation
# Version: 1.0.6 (ou 1: modification majeure, 2: modification mineure, 3: correction de bug)
#
# Date de creation: 19/03/2019
# Cree par: Jean-Baptiste Meriaux
#
#
# Mise a jour:
#                           Charles BRANSARD - 13/09/2019 - Ajout crontab Filtre-sysalt (LINUX) + Saveconfig (LINUX + AIX) + ajout installation ncompress (LINUX)
#                           Charles BRANSARD - 25/03/2020 - Modification crontab Filtre-sysalt passage 4 executions par jour du lundi au samedi
#                           Charles BRANSARD - 20/08/2020 - Modification récupération YUM9 pour centos 6.10
#                           Charles BRANSARD - 22/09/2020 - Modification récupération YUM8 et YUM9 (correction bug centos)
#                           Charles BRANSARD - 25/09/2020 - Ajout mise en place graceful_shutdown pour centreon (verification si reboot normal ou crash d'une vm)
#							Charles BRANSARD - 01/02/2021 - Ajout log erreur en local sur le serveur en cas de KO (/tmp/<nom_script_KO_date>)
#							Vincent MIGNOT   - 08/11/2021 - Ajout du check iptables -L | grep 1002 pour cas de VM Guess
#
# Pre-requis:				Le serveur est de type Unix
#
# Inputs:
#
# Outputs:
#                           0 : le script s'est correctement déroulé
#							4 : Script a ajouter en cron non present
#							5 : Erreur backup fichier cron
#							6 : Erreur modification fichier cron
#							7 : Erreur Activation crontab
#							8 : Erreur installation ncompress
#							9 : Distribution linux non supportée
#                           10 : Erreur creation script set_gracefulshutdown.service ou check_graceful.service
#                           11 : Erreur activation service set_gracefulshutdown.service ou check_graceful.service
#                           12 : Erreur premiere execution (initialisation du service) check_graceful.service
#                           13 : Erreur passage du service check_graceful en no manual start
#							97 : OS incompatible avec le script
#							98 : Erreur recuperation release
#
########################################################################################################################

####### DECLARATION DES CONSTANTES FIXES
SCRIPT_NAME="SASC_Unix_PostInstallation_Step4-Set-Custom-Config"
LOG="/tmp/${SCRIPT_NAME}_KO_$(date "+%Y%m%d%H%M")"

#####################################################
########## DECLARATION DES FONCTIONS ################
#####################################################

INIT_LINUX_VERSION()
{
    # Récupération des variables de version RH
	if [ -f /etc/system-release ]
	then
		RELEASE_FILE=/etc/system-release
		CHECK_OS_VERSION=$(cat $RELEASE_FILE)                             # Exemple de sortie : Red Hat Enterprise Linux Server release 6.6 (Santiago)
		TYPE_OS=$(cat $RELEASE_FILE | awk '{print $1}' | tr 'A-Z' 'a-z')  # Exemple de sortie : red ou centos
	else
		RELEASE_FILE=/etc/redhat-release
		CHECK_OS_VERSION=$(cat $RELEASE_FILE)
		TYPE_OS=$(cat $RELEASE_FILE | awk '{print $1}' | tr 'A-Z' 'a-z')
	fi
    
    case $TYPE_OS in
    (red)
            YUM8="rhel"
            RHE_MIN_VERS=$(grep -i Linux $RELEASE_FILE | sed -e 's/\(.*\)\(release \)\([0-9,.]*\)\(.*\)/\3/g' | awk -F"." '{print $1"."$2}')
            RHE_MAJ_VERS=$(echo ${RHE_MIN_VERS} | awk -F\. '{print $1}') # Exemple de sortie 6
            ;;
    (centos)
            YUM8="centos"
            RHE_MIN_VERS=$(grep -i centos $RELEASE_FILE | sed -e 's/\(.*\)\(release \)\([0-9,.]*\)\(.*\)/\3/g' | awk -F"." '{print $1"."$2}')		
            RHE_MAJ_VERS=$(echo ${RHE_MIN_VERS} | awk -F\. '{print $1}')	
            ;;
    (*) 
            echo "TYPE OS INCOMPATIBLE_AVEC_CE_SCRIPT" > $LOG
            echo "TYPE OS INCOMPATIBLE_AVEC_CE_SCRIPT"
            exit 98 
            ;;
    esac
}

##############
#### MAIN ####
##############

#Check parametres entres


OS=$(uname)
HOSTNAME=`hostname | awk -F. '{print $1}'`
UNAME=`uname -s`

echo
echo "######################################"
echo "######### début set custom   #########"
echo "######################################"
echo

case $OS in
        "Linux")
                INIT_LINUX_VERSION
				
				###################################
				###  Check Port Connexion HPSA  ###
				###################################
				
				cat /etc/sysconfig/iptables | grep 1002
				if [ $? -eq 0 ];
				then
					echo "Port 1002 hpsa deja en place"
				else
					echo "Setup ouverture port 1002 iptables dynamique"
					sed -i '/--dport 22/ a -A INPUT -p tcp -m state --state NEW -m tcp --dport 1002 -m comment --comment "Ouverture ports svr_hpsa" -j ACCEPT\' /etc/sysconfig/iptables
				fi
				
			
				##################################
				####  Crontab Filtre-sysalt   ####
				##################################
				ETAPE="Crontab Filtre-sysalt"
				echo "${ETAPE}"
				crontab -l | grep filtre-sysalt.ksh > /dev/null 2>&1
				if [ $? -eq 0 ]
				then
					echo "*** ${ETAPE} deja  en place."
				else
					if [ -e /var/spool/cron/root ]
					then
						cp -p /var/spool/cron/root /var/spool/cron/root.$(date +%Y%m%d%H%M)
						if [ $? -eq 0 ]
						then
							echo "Backup fichier /var/spool/cron/root OK"
							cat >> /var/spool/cron/root <<EOF
20 8,12,16,20 * * 1-6 /exploit/isim/SCRIPTS/SYSTEM/filtre-sysalt.ksh > /dev/null 2>&1
EOF
							if [ $? -eq 0 ]
							then
								echo "Mise en place crontab Filtre-sysalt OK"
							else
                                echo "Mise en place crontab Filtre-sysalt KO" > $LOG
								echo "Mise en place crontab Filtre-sysalt KO" >&2 && exit 6
							fi
						else
                            echo "Backup fichier /var/spool/cron/root KO" > $LOG
							echo "Backup fichier /var/spool/cron/root KO"	 >&2 && exit 4
						fi						
					else
						cat >> /var/spool/cron/root <<EOF
20 8,12,16,20 * * 1-6 /exploit/isim/SCRIPTS/SYSTEM/filtre-sysalt.ksh > /dev/null 2>&1
EOF
						if [ $? -eq 0 ]
						then
							echo "Mise en place crontab Filtre-sysalt OK"
						else
                            echo "Mise en place crontab Filtre-sysalt KO" > $LOG
							echo "Mise en place crontab Filtre-sysalt KO" >&2 && exit 6
						fi
					fi
				fi
				##################################
				####  Crontab Saveconfig      ####
				##################################
				ETAPE="Crontab Saveconfig"
				echo "${ETAPE}"
				crontab -l | grep SaveConfig.sh > /dev/null 2>&1
				if [ $? -eq 0 ]
				then
					echo "*** ${ETAPE} deja  en place."
				else
					if [ -e /var/spool/cron/root ]
					then
						cp -p /var/spool/cron/root /var/spool/cron/root.$(date +%Y%m%d%H%M)
						if [ $? -eq 0 ]
						then
							echo "Backup fichier /var/spool/cron/root OK"
							cat >> /var/spool/cron/root <<EOF
########## CRONTAB Saveconfig Server ##########
00 08 * * 1,5 /exploit/isim/SCRIPTS/SYSTEM/Saveconfig/SaveConfig.sh >/dev/null 2>&1
#
EOF
							if [ $? -eq 0 ]
							then
								echo "Mise en place crontab Saveconfig OK"
							else
                                echo "Mise en place crontab Saveconfig KO" > $LOG
								echo "Mise en place crontab Saveconfig KO" >&2 && exit 6
							fi
						else
                            echo "Backup fichier /var/spool/cron/root KO" > $LOG
							echo "Backup fichier /var/spool/cron/root KO"	 >&2 && exit 4
						fi						
					else
						cat >> /var/spool/cron/root <<EOF
########## CRONTAB Saveconfig Server ##########
00 08 * * 1,5 /exploit/isim/SCRIPTS/SYSTEM/Saveconfig/SaveConfig.sh >/dev/null 2>&1
#
EOF
						if [ $? -eq 0 ]
						then
							echo "Mise en place crontab Saveconfig OK"
						else
                            echo "Mise en place crontab Saveconfig KO" > $LOG
							echo "Mise en place crontab Saveconfig KO" >&2 && exit 6
						fi
					fi
				fi
				######################################
				####  Installation ncompress      ####
				######################################
				ETAPE="Installation ncompress"
				echo "${ETAPE}"
				rpm -qa | grep -i ncompress >/dev/null 2>&1
				if [ $? -eq 0 ]
				then
					echo "*** ${ETAPE} deja  en place."
				else
					CMD_INSTALL_NCOMPRESS="YUM8=${YUM8} YUM9=${RHE_MIN_VERS} yum -y install ncompress > /dev/null"
					su -l root -c "$CMD_INSTALL_NCOMPRESS"
					if [ $? -eq 0 ]
					then
						echo "${ETAPE} OK"
					else
                        echo "${ETAPE} KO" > $LOG
						echo "${ETAPE} KO" >&2 && exit 8
					fi
				fi
                
				################################################################################################
				####  DEBUT Mise en place services graceful_shutdown pour centreon (controle crash vm)      ####
				################################################################################################
				ETAPE="Mise en place graceful_shutdown (controle crash vm pour centreon)"
				echo "${ETAPE}"
                DATE=$(date +[%Y%m%d-%H%M%S])
                
                case $RHE_MAJ_VERS in
								7 )
								
								###Variables
								Path_Script="/etc/systemd/system/"
								Set_Script="set_gracefulshutdown.service"
								Check_Script="check_graceful.service"
								Flag="/var/log/graceful_shutdown"
								FILE_CHECK_CENTREON="/var/log/check_graceful_shutdown"
								
								#Creation du premier script set_graceful.service
								if [ -f ${Path_Script}${Set_Script} ];
								then
									echo "Script ${Path_Script}${Set_Script} deja  en place."
								else
                                    touch ${Path_Script}${Set_Script} > /dev/null 2>&1
                                    if [ $? -ne 0 ];
                                    then
                                        echo "Could not create ${Path_Script}${Set_Script}" > $LOG
                                        echo "Could not create ${Path_Script}${Set_Script}"
                                        exit 10
                                    fi
                                    cat > ${Path_Script}${Set_Script} << EOF
[Unit]
Description=Set flag for graceful shutdown
DefaultDependencies=no
RefuseManualStart=true
Before=shutdown.target

[Service]
Type=oneshot
ExecStart=/bin/touch ${Flag}


[Install]
WantedBy=shutdown.target
EOF

                                    if [ $? -ne 0 ];
                                    then
                                        echo "Could not fill up ${Path_Script}${Set_Script}" > $LOG
                                        echo "Could not fill up ${Path_Script}${Set_Script}"
                                        exit 10
                                    
                                    fi                                    
                                fi
                                
                                # Ajout aux services
                                systemctl is-enabled ${Set_Script} > /dev/null 2>&1
                                if [ $? -eq 0 ]
                                then
                                    echo "service ${Set_Script} already enabled"
                                else
                                    systemctl daemon-reload && systemctl enable ${Set_Script} > /dev/null 2>&1
                                    if [ $? -ne 0 ];
                                    then
                                        echo "Could not reload or enable systemctl for ${Set_Script}" > $LOG
                                        echo "Could not reload or enable systemctl for ${Set_Script}"
                                        exit 11
                                    fi
                                fi
                                
                                #Creation du second script check_graceful.service
								if [ -f ${Path_Script}${Check_Script} ];
								then
									echo "Script deja en place."
								else
                                    touch ${Path_Script}${Check_Script}
                                    cat > ${Path_Script}${Check_Script} << EOF
[Unit]
Description=Check if previous system shutdown was graceful
#ConditionPathExists=${Flag}
RefuseManualStart=false
RefuseManualStop=true

[Service]
Type=oneshot
RemainAfterExit=true
ExecStart=/bin/sh -c 'DATE=\$(date) && if [ -f ${Flag} ];then /bin/echo "\$DATE : Flag ${Flag} supprime : OK" > $FILE_CHECK_CENTREON && /bin/rm ${Flag};else /bin/echo "\$DATE : Flag ${Flag} non existant : KO" > $FILE_CHECK_CENTREON;fi'

[Install]
WantedBy=multi-user.target

EOF

                                    if [ $? -ne 0 ];
                                    then
                                        echo "Could not fill up ${Path_Script}${Check_Script}"
                                        exit 10
                                    
                                    fi                                    
                                fi

                                # Ajout aux services 2eme script
                                systemctl is-enabled ${Check_Script} > /dev/null 2>&1
                                if [ $? -eq 0 ]
                                then
                                    echo "service ${Check_Script} already enabled"
                                else								
                                    systemctl daemon-reload && systemctl enable ${Check_Script}  > /dev/null 2>&1
                                    if [ $? -ne 0 ];
                                    then
                                        echo "Could not reload or enable systemctl for ${Check_Script}" > $LOG
                                        echo "Could not reload or enable systemctl for ${Check_Script}"
                                        exit 11
                                    fi
                                fi
								
								#Activation du script pour la première fois sans reboot
								systemctl start ${Check_Script} > /dev/null 2>&1
								echo "${DATE} : Mise en place OK" > $FILE_CHECK_CENTREON
								if [ $? -ne 0 ];
								then
                                    echo "Could not initialize ${Check_Script}" > $LOG
									echo "Could not initialize ${Check_Script}"
									exit 12
								fi
								
								#Modification second script pour repasser en RefuseManualStart=true
								sed -i "s/RefuseManualStart=false/RefuseManualStart=true/" ${Path_Script}${Check_Script} > /dev/null 2>&1
								if [ $? -ne 0 ];
								then
                                    echo "Could not set RefuseManualStart to true in ${Check_Script}" > $LOG
									echo "Could not set RefuseManualStart to true in ${Check_Script}"
									exit 13
								fi
								
								
								echo "${ETAPE} OK"
								;;
							
							6)
                                ##Variables
                                Path_Script="/etc/init.d/"
                                Set_Script="check_graceful_shutdown"
                                
                                #Script Set_Script déjà présent ?
                                if [ -f ${Path_Script}${Set_Script} ];
                                then
                                    echo "Script ${Path_Script}${Set_Script} already present"
                                else
                                    touch ${Path_Script}${Set_Script}
                                    if [ $? -ne 0 ];
                                    then
                                        echo "Could not create ${Path_Script}${Set_Script}" > $LOG
                                        echo "Could not create ${Path_Script}${Set_Script}"
                                        exit 10
                                    fi
                                    cat > ${Path_Script}${Set_Script} << EOF
#!/bin/sh
#
# Startup script for check_graceful_shutdown
#
# chkconfig: 2345 20 02
# description: startup/stop script

# Source function library.


RETVAL=0
prog="check_graceful_shutdown"

DIR=/var/log
DATE=\$(date +[%Y%m%d-%H%M%S])
FLAG=\$DIR/graceful_shutdown
LOG=\$DIR/log_check_graceful_shutdown
FILE_CHECK_CENTREON=\$DIR/check_graceful_shutdown
LOCKFILE=/var/lock/subsys/\$prog


# Source function library.
. /etc/init.d/functions

purge_log()
{
	if [ -f \$LOG ]
	then
		LOG_TMP=/tmp/log_check_graceful_shutdown_tmp
		NB_LINE_LOG=\$(cat \$LOG | wc -l)
		if [ \$NB_LINE_LOG -gt 150 ]
		then
			# Récupération des 30 dernières lignes
			tail -30 \$LOG > \$LOG_TMP && cat \$LOG_TMP > \$LOG
			echo "\$DATE : Rotation du fichier \$LOG effectue" >> \$LOG
		else
			echo "\$DATE : pas de rotation de log necessaire" >> \$LOG
		fi
	else
		echo "\$DATE : Fichier \$LOG inexistant" >> \$LOG
	fi
	
	if [ -f \$LOG_TMP ]
	then
		rm -f \$LOG_TMP
	fi
}

start() {
	echo "\$DATE : DEBUT FONCTION START" >> \$LOG
	echo "\$DATE : Mise en place lock \$LOCKFILE" >> \$LOG
	touch \${LOCKFILE}
    if [ -f \$FLAG ]
	then
		echo "\$DATE : Flag \$FLAG existant : OK" >> \$LOG
		rm -f \$FLAG
		RETVAL=\$?
		if [ \$RETVAL -eq 0 ]
		then
			echo "\$DATE : Flag \$FLAG supprime : OK" >> \$LOG
		else
			echo "\$DATE : Flag \$FLAG non supprime : KO" >> \$LOG
		fi
		echo "\$DATE : Flag \$FLAG supprime : OK" > \$FILE_CHECK_CENTREON
	else
		echo "\$DATE : Flag \$FLAG non existant : KO" >> \$LOG
		echo "\$DATE : Flag \$FLAG non existant : KO" > \$FILE_CHECK_CENTREON
		RETVAL=1
	fi
	purge_log
	echo "\$DATE : FIN FONCTION START" >> \$LOG
    return \$RETVAL
}

stop() {
	echo "\$DATE : DEBUT FONCTION STOP" >> \$LOG
    echo "\$DATE : Reboot serveur" > \$FLAG
    RETVAL=\$?
	if [ \$RETVAL -eq 0 ]
	then
		echo "\$DATE : Flag \$FLAG mis en place : OK" >> \$LOG
	else
		echo "\$DATE : Flag \$FLAG non mis en place : KO" >> \$LOG
	fi
	echo "\$DATE : FIN FONCTION STOP" >> \$LOG
    return \$RETVAL
}



case "\$1" in
    start)
        \$1
        ;;
    stop)
        \$1
        ;;
    *)
    echo \$"Usage: \$0 {start}"
    exit 2
esac
exit \$?
EOF
                                    if [ $? -ne 0 ];
                                    then
                                        echo "Could not fill up ${Path_Script}${Check_Script}" > $LOG
                                        echo "Could not fill up ${Path_Script}${Check_Script}"
                                        exit 10
                                    fi                            
                                fi
                                                        
                                # Creation du service
                                if [ ${RHE_MAJ_VERS} = 5 ]
                                then
                                    cd /etc/init.d && chkconfig --add ${Set_Script} > /dev/null 2>&1
                                    if [ $? -ne 0 ];
                                    then
                                        echo "chkconfig error ${Set_Script}" > $LOG
                                        echo "chkconfig error ${Set_Script}"
                                        exit 4
                                    fi
                                else
                                    chkconfig --add ${Path_Script}${Set_Script} > /dev/null 2>&1
                                    if [ $? -ne 0 ];
                                    then
                                        echo "chkconfig error ${Set_Script}" > $LOG
                                        echo "chkconfig error ${Set_Script}"
                                        exit 4
                                    fi
                                fi
                                
                                touch /var/lock/subsys/check_graceful_shutdown
                                if [ $? -ne 0 ];
                                then
                                    echo "Could not create the Lockfile." > $LOG
                                    echo "Could not create the Lockfile."
                                    exit 12
                                fi
                                
                                touch /var/log/check_graceful_shutdown && echo "${DATE} : Initialisation /var/log/check_graceful_shutdown : OK" > /var/log/check_graceful_shutdown
                                if [ $? -ne 0 ];
                                then
                                    echo "Could not initialize ${Check_Script}" > $LOG
                                    echo "Could not initialize ${Check_Script}"
                                    exit 12
                                fi
                                
                                chmod 775 /var/log/check_graceful_shutdown && chmod 775 /etc/init.d/check_graceful_shutdown
                                echo "${ETAPE} OK"
                            ;;
                esac            
				##########################################################################################
				####  FIN Mise en place services graceful_shutdown pour centreon (controle crash vm)  ####
				##########################################################################################                
                
                
                
		;;		
        "AIX")
				##################################
				####  Crontab extract-errpt   ####
				##################################
				ETAPE="Crontab extract-errpt"
				echo "${ETAPE}"
				crontab -l | grep "/exploit/isim/SCRIPTS/SYSTEM/ExtractErrpt/extract_errpt.ksh" >/dev/null 2>&1
				if [ $? -eq 0 ]
				then
					echo "*** ${ETAPE} deja  en place."
				else
					if [ -f /exploit/isim/SCRIPTS/SYSTEM/ExtractErrpt/extract_errpt.ksh ]
					then
						cp -p /var/spool/cron/crontabs/root /var/spool/cron/crontabs/root.$(date +%Y%m%d%H%M)
						if [ $? -eq 0 ]
						then
							echo "Backup fichier /var/spool/cron/crontabs/root OK"
							cat >> /var/spool/cron/crontabs/root <<EOF
########## DEBUT CRONTAB extract_errpt pour centreon ##########
* * * * *  /exploit/isim/SCRIPTS/SYSTEM/ExtractErrpt/extract_errpt.ksh  >/dev/null 2>/dev/null
########## FIN CRONTAB extract_errpt pour centreon ##########
EOF
							if [ $? -eq 0 ]
							then
								echo "Mise en place crontab extract_errpt.ksh OK"
								crontab /var/spool/cron/crontabs/root
								if [ $? -eq 0 ]
								then
									echo "Activation crontab extract-errpt OK"
									touch /var/adm/errpt-centreon
								else
									echo "Activation crontab extract-errpt : KO"	 >&2 && exit 7
								fi
							else
								echo "Mise en place crontab extract_errpt" >&2 && exit 6
							fi
						else
							echo "backup /var/spool/cron/crontabs/root KO"	 >&2 && exit 5	
						fi
					else
						echo "Script /exploit/isim/SCRIPTS/SYSTEM/ExtractErrpt/extract_errpt.ksh non present (verifier arborescence /exploit/isim)" 	 >&2 && exit 4	
					fi
				fi
				
				##################################
				####  Crontab Saveconfig      ####
				##################################
				ETAPE="Crontab Saveconfig"
				echo "${ETAPE}"
				crontab -l | grep SaveConfig.sh > /dev/null 2>&1
				if [ $? -eq 0 ]
				then
					echo "*** ${ETAPE} deja  en place."
				else
					cp -p /var/spool/cron/crontabs/root /var/spool/cron/crontabs/root.$(date +%Y%m%d%H%M)
					if [ $? -eq 0 ]
					then
						echo "Backup fichier /var/spool/cron/crontabs/root OK"
						cat >> /var/spool/cron/crontabs/root <<EOF
########## CRONTAB Saveconfig Server ##########
00 08 * * 1,5 su - root -c "/exploit/isim/SCRIPTS/SYSTEM/Saveconfig/SaveConfig.sh" >/dev/null 2>&1
#
EOF
						if [ $? -eq 0 ]
						then
							echo "Mise en place crontab Saveconfig OK"
							crontab /var/spool/cron/crontabs/root
							if [ $? -eq 0 ]
							then
								echo "Activation crontab Saveconfig OK"
								touch /var/adm/errpt-centreon
							else
								echo "Activation crontab Saveconfig : KO"	 >&2 && exit 7
							fi
						else
							echo "Mise en place crontab Saveconfig" >&2 && exit 6
						fi
					else
						echo "backup /var/spool/cron/crontabs/root KO"	 >&2 && exit 5	
					fi
				fi

				################################################################################################
				####  DEBUT Mise en place services graceful_shutdown pour centreon (controle crash vm)      ####
				################################################################################################
				ETAPE="Mise en place graceful_shutdown (controle crash vm pour centreon)"
				echo "${ETAPE}"				
                Path_Script="/etc/init.d/"
				Set_Script="check_graceful_shutdown"
				
				if [ -f ${Path_Script}${Set_Script} ];
				then
					echo "Script ${Path_Script}${Set_Script} already present"
				else
                    touch ${Path_Script}${Set_Script}
                    if [ $? -ne 0 ];
                    then
                        echo "Could not create ${Path_Script}${Set_Script}"
                        exit 10
                    fi
                    
                    cat > ${Path_Script}${Set_Script} << EOF
#!/bin/ksh

##################################################
# name: graceful_shutdown
# purpose: script that will set a flag if the server has been shutdown
##################################################

DIR=/var/log
DATE=\$(date +[%Y%m%d-%H%M%S])
FLAG=\$DIR/graceful_shutdown
FILE_CHECK_CENTREON=\$DIR/check_graceful_shutdown
LOG=\$DIR/log_check_graceful_shutdown
RETVAL=0


purge_log()
{
	if [ -f \$LOG ]
	then
		LOG_TMP=/tmp/log_check_graceful_shutdown_tmp
		NB_LINE_LOG=\$(cat \$LOG | wc -l)
		if [ \$NB_LINE_LOG -gt 150 ]
		then
			# Récupération des 30 dernières lignes
			tail -30 \$LOG > \$LOG_TMP && cat \$LOG_TMP > \$LOG
			echo "\$DATE : Rotation du fichier \$LOG effectue" >> \$LOG
		else
			echo "\$DATE : pas de rotation de log necessaire" >> \$LOG
		fi
	else
		echo "\$DATE : Fichier \$LOG inexistant" >> \$LOG
	fi
	
	if [ -f \$LOG_TMP ]
	then
		rm -f \$LOG_TMP
	fi
}

case "\$1" in
start )
	echo "\$DATE : DEBUT FONCTION START" >> \$LOG
	echo "\$DATE : Mise en place lock \$LOCKFILE" >> \$LOG
    if [ -f \$FLAG ]
    then
		echo "\$DATE : Flag \$FLAG existant : OK" >> \$LOG
        rm -f \$FLAG
        RETVAL=\$?
		if [ \$RETVAL -eq 0 ]
		then
			echo "\$DATE : Flag \$FLAG supprime : OK" >> \$LOG
			echo "\$DATE : Flag \$FLAG supprime : OK" > \$FILE_CHECK_CENTREON
		else
			echo "\$DATE : Flag \$FLAG non supprime : KO" >> \$LOG
			echo "\$DATE : Flag \$FLAG present mais non supprime (supprimer le flag a la main) : KO" > \$FILE_CHECK_CENTREON
		fi
    else
		echo "\$DATE : Flag \$FLAG non existant : KO" >> \$LOG
        echo "\$DATE : Flag \$FLAG non existant : KO" > \$FILE_CHECK_CENTREON
        RETVAL=1
    fi
	purge_log
	echo "\$DATE : FIN FONCTION START" >> \$LOG
    return \$RETVAL
        ;;
stop )
    
	echo "\$DATE : DEBUT FONCTION STOP" >> \$LOG    
	#touch \$FLAG && chmod 775 \$FLAG && chmod +x \$FLAG
    echo "\$DATE : Reboot serveur" > \${FLAG} && chmod 775 \$FLAG && chmod +x \$FLAG
    RETVAL=\$?
	if [ \$RETVAL -eq 0 ]
	then
		echo "\$DATE : Flag \$FLAG mis en place : OK" >> \$LOG
	else
		echo "\$DATE : Flag \$FLAG non mis en place : KO" >> \$LOG
	fi
	echo "\$DATE : FIN FONCTION STOP" >> \$LOG

    return \$RETVAL

        ;;
* )
        echo "Usage: \$0 (start | stop)"
        exit 1
esac

EOF
							
                    if [ $? -ne 0 ];
                    then
                        echo "Could not fill up ${Path_Script}${Set_Script}"
                        exit 10
                    fi
                fi
				
				chmod 775 ${Path_Script}${Set_Script} && chmod +x ${Path_Script}${Set_Script}

                # Creation des liens
                if [ -L /etc/init.d/S21${Set_Script} ]
                then
                    echo "Link /etc/init.d/S21${Set_Script} already exist"
                else
                    ln -s ${Path_Script}${Set_Script} /etc/init.d/S21${Set_Script}
                    if [ $? -ne 0 ];
                    then
                        echo "Could not create symbolic from ${Path_Script}${Set_Script} to /etc/init.d/S21${Set_Script} "
                        exit 11
                    fi                
                fi
                if [ -L /etc/init.d/K21${Set_Script} ]
                then
                    echo "Link /etc/init.d/K21${Set_Script} already exist"                    
                else
                    ln -s ${Path_Script}${Set_Script} /etc/init.d/K21${Set_Script}
                    if [ $? -ne 0 ];
                    then
                        echo "Could not create symbolic from ${Path_Script}${Set_Script} to /etc/init.d/K21${Set_Script} "
                        exit 11
                    fi                
                fi
				
				DATE=$(date +[%Y%m%d-%H%M%S])
				touch /var/log/check_graceful_shutdown && echo "${DATE} : Initialisation /var/log/check_graceful_shutdown : OK" > /var/log/check_graceful_shutdown
				if [ $? -ne 0 ];
				then
					echo "Could not initialize ${Set_Script}"
					exit 12
				fi
				
				chmod 775 /var/log/check_graceful_shutdown
                
                echo "${ETAPE} OK"
				##############################################################################################
				####  FIN Mise en place services graceful_shutdown pour centreon (controle crash vm)      ####
				##############################################################################################                
				;;		
        *)      echo "OS_INCOMPATIBLE_AVEC_CE_SCRIPT"
                >&2 && exit 97
                ;;
esac
>&2 && exit 0