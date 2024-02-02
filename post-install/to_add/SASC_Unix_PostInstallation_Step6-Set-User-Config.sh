#!/bin/ksh

########################################################################################################################
# Script: SASC_Unix_PostInstallation_Set-User-Config
#
# Description: Ce script permet de configurer les users sur une machine Unix lors de la post-instalation
# Version: 1.0.4 (ou 1: modification majeure, 2: modification mineure, 3: correction de bug)
#
# Date de creation: 19/03/2019
# Cree par: Jean-Baptiste Meriaux
#
#
# Mise a jour:
#                           Charles BRANSARD - 13/09/2019 - Ajout modification access.conf (LINUX) suppression connexion avec user admsrv
#							Charles BRANSARD - 01/02/2021 - Ajout log erreur en local sur le serveur en cas de KO (/tmp/<nom_script_KO_date>)
#                           Charles BRANSARD - 11/03/2021 - Ajout création / configuration users oi2squash
#                           Charles BRANSARD - 06/04/2021 - Correction bug centos pour ajout user access.conf
#                           David LEPOITTEVIN- 01/09/2021 - Passage du MdP de 12 a 14 caracteres
#                           Tommy STYCZEN -    17/05/2022 - Supression changement mdp root/cac/admsrv par ce script, fait par Tower
#
# Pre-requis:				Le serveur est de type Unix
#
# Inputs:
#
#
# Outputs:
#                           0 : le script s'est correctement déroulé
#							4 : user not found
#							5 : set password error
#							6 : Backup access.conf KO
#							7 : Modif access.conf KO
#                           8 : Creation repertoire /home/oi2squash/.ssh KO
#                           9 : Execution script caccia modification access.conf KO
#							97 :OS incompatible avec le script
#
########################################################################################################################

####### DECLARATION DES CONSTANTES FIXES
SCRIPT_NAME="SASC_Unix_PostInstallation_Set-User-Config"
LOG="/tmp/${SCRIPT_NAME}_KO_$(date "+%Y%m%d%H%M")"

#####################################################
########## DECLARATION DES FONCTIONS ################
#####################################################
random_passwd_aix()
{
        # Fonction qui permet la génération d'un mdp
        # Liste caracteres spéciaux
        LISTE_CAR_SPEC="_,:,$,?,!,-,!,$,?,+,=,:"

        # Random pour le caractere specifique à remplacer dans le mdp
        RAND_SPEC=$(echo $RANDOM | cut -c 2)
        while [ $RAND_SPEC == 0 ]
        do
            RAND_SPEC=$(echo $RANDOM | cut -c 2)
        done

        # choisis un caractere de façon aléatoire dans les caracteres spécifiques
        CAR_SPEC=$(echo $LISTE_CAR_SPEC | cut -d"," -f$RAND_SPEC)

        # remplacement du caractere aleaoire
        RAND_CAR=$(echo $RANDOM | cut -c 2)
        while [ $RAND_CAR == 0 ]
        do
            RAND_CAR=$(echo $RANDOM | cut -c 2)
        done
        # chiffre entre 0 et 9 pour remplacer le dernier caractere
        RAND_NUM=$(echo $RANDOM | cut -c 2)

        # 2eme Random pour le caractere specifique à remplacer dans le mdp
        RAND_SPEC_2=$(echo $RANDOM | cut -c 2)
        while [[ $RAND_SPEC_2 == 0 || $RAND_SPEC_2 == $RAND_SPEC ]]
        do
            RAND_SPEC_2=$(echo $RANDOM | cut -c 2)
        done
        # choisis un caractere de façon aléatoire dans les caracteres spécifiques
        CAR_SPEC_2=$(echo $LISTE_CAR_SPEC | cut -d"," -f$RAND_SPEC_2)
		# remplacement du 2eme caractere aleaoire
        RAND_CAR_2=$(echo $RANDOM | cut -c 1)
        while [[ $RAND_CAR_2 == 0 || $RAND_CAR_2 == $RAND_CAR ]]
        do
            RAND_CAR_2=$(echo $RANDOM | cut -c 2)
        done
        # Generation du mdp sur 14 caracteres + modification de 2 caracteres par un caractere specifique (entre 1 et 9) et remplacement dernier caractere par un chiffre aleatoire entre 0 et 9
		#MDP_TEMP=$(openssl rand -base64 8)
        MDP_TEMP=$(openssl rand -base64 14 | head -c14)
        MDP=$(echo $MDP_TEMP | sed "s/./${CAR_SPEC}/${RAND_CAR}" | sed "s/.$/${RAND_NUM}/" | sed "s/./${CAR_SPEC_2}/${RAND_CAR_2}")
		
}

random_passwd_linux()
{
        # Fonction qui permet la génération d'un mdp
        # Liste caracteres spéciaux
        LISTE_CAR_SPEC="_,é,$,?,&,!,-,è,$,?,+,="

        # Random pour le caractere specifique à remplacer dans le mdp
        RAND_SPEC=$(echo $RANDOM | cut -c 2)
        while [ $RAND_SPEC == 0 ]
        do
                        RAND_SPEC=$(echo $RANDOM | cut -c 2)
        done

        # choisis un caractere de façon aléatoire dans les caracteres spécifiques
        CAR_SPEC=$(echo $LISTE_CAR_SPEC | cut -d"," -f$RAND_SPEC)

        # remplacement du caractere aleaoire
        RAND_CAR=$(echo $RANDOM | cut -c 2)
        while [ $RAND_CAR == 0 ]
        do
                        RAND_CAR=$(echo $RANDOM | cut -c 2)
        done

        # chiffre entre 0 et 9 pour remplacer le dernier caractere
        RAND_NUM=$(echo $RANDOM | cut -c 2)

        # Generation du mdp sur 14 caracteres + modification d'un caractere par un caractere specifique (entre 1 et 9) et remplacement dernier caractere par un chiffre aleatoire entre 0 et 9
        MDP_TEMP=$(openssl rand -base64 14 | head -c14)
        MDP=$(echo $MDP_TEMP | sed "s/./${CAR_SPEC}/${RAND_CAR}" | sed "s/.$/${RAND_NUM}/")
}


##############
#### MAIN ####
##############

OS=$(uname)
HOSTNAME=`hostname | awk -F. '{print $1}'`
echo "######################################"
echo "######### début User Config  #########"
echo "######################################"
echo

case $OS in
        "Linux")
		
				##################################
				#### Création du user exp_cac ####
				##################################
				GID_USER=9574
				UID_USER=9574
				USER_ADD=exp_cac
				USER_COMMENT="user exploit cac"
				HOME=/home/exp_cac
				SUDO_TMP=/tmp/sudoers_exploitcac
				
				ETAPE="Création user exp_cac"
				echo " début ${ETAPE}"
				echo
				cat /etc/passwd | grep $USER_ADD > /dev/null 2>&1
				if [ $? != 0 ]
				then
					echo "creation user $USER_ADD"
					groupadd -g $GID_USER $USER_ADD
					useradd -c "$USER_COMMENT" -u $UID_USER -g $USER_ADD $USER_ADD
					if [ $? = 0 ]
					then
						echo "creation user OK"
						echo
						echo "Modification password $USER_ADD"
						echo "$USER_ADD:U3xPl@1t_cAc" | chpasswd
						if [ $? = 0 ]
						then
							echo "Modification password OK"
							echo
							echo "Modification du fichier sudoers"
							cp -p /etc/sudoers /etc/sudoers.$(date +%Y%m%d-%H%M)
							if [ $? = 0 ]
							then
								echo "Backup fichier sudoers OK"
								echo
								cat /etc/sudoers > $SUDO_TMP
								if [ "$ZONE" = "newcloud" ]
								then
						cat >> $SUDO_TMP <<EOF
########## DEBUT SUDO user exploit $USER_ADD ##########
$USER_ADD  ALL=(root) NOPASSWD: /usr/newcloud/bin/ldapnewcloud-config.sh
########## FIN SUDO user exploit $USER_ADD ##########
EOF
					else
						cat >> $SUDO_TMP <<EOF
########## DEBUT SUDO user exploit $USER_ADD ##########
$USER_ADD  ALL=(root) NOPASSWD: /usr/cac/bin/caccia2-config.sh
########## FIN SUDO user exploit $USER_ADD ##########
EOF
								fi
								visudo -c -f $SUDO_TMP > /dev/null 2>&1
								if [ $? = 0 ]
								then
									mv $SUDO_TMP /etc/sudoers
									chmod 440 /etc/sudoers
									echo "Modification du fichier sudoers OK"
									echo
									echo "${ETAPE} OK"
									
								else
                                    echo "Fichier temporaire $SUDO_TMP inccorect" > $LOG
									echo "Fichier temporaire $SUDO_TMP inccorect"
									echo "Modification du fichier sudoers KO"  >&2 && exit 4
								fi					
							else
                                echo "Backup fichier sudoers KO" > $LOG
								echo "Backup fichier sudoers KO"   >&2 && exit 4			
							fi
						else
							echo "Modification password OK"			
						fi
					else
                        echo "creation user $USER_ADD KO" > $LOG
						echo "creation user KO"   >&2 && exit 4
					fi
				else
					echo "$USER_ADD deja present"
				fi
				
				###################################################
				######### Modification access.conf admsrv #########
				###################################################	
				ETAPE="Modification access.conf admsrv"
				ACCESS_FILE=/etc/security/access.conf
				cat $ACCESS_FILE | grep -v "#" | grep "admsrv " | grep "ALL$"  > /dev/null 2>&1
				if [ $? -eq 0 ]
				then
					cp -p $ACCESS_FILE $ACCESS_FILE.$(date +%Y%m%d-%H%M)
					if [ $? -eq 0 ]
					then
						echo "Backup $ACCESS_FILE OK"
						sed -i -e "/admsrv.*ALL$/ s/admsrv //" $ACCESS_FILE
						if [ $? -eq 0 ]
						then
							cat $ACCESS_FILE | grep -v "#" | grep "admsrv" | grep "ALL$"  > /dev/null 2>&1
							if [ $? -eq 0 ]
							then
                                echo "${ETAPE} KO" > $LOG
								echo "${ETAPE} KO" >&2 && exit 7
							else
								echo "${ETAPE} OK"
							fi
						else
                            echo "Erreur modification $ACCESS_FILE" > $LOG
							echo "Erreur modification $ACCESS_FILE" >&2 && exit 7
						fi
					else
                        echo "Backup fichier $ACCESS_FILE KO" > $LOG
						echo "Backup fichier $ACCESS_FILE KO"   >&2 && exit 6
					fi					
				else
					echo "*** ${ETAPE} deja  en place."
				fi

				##############################################
				#### Création / configuration user squash ####
				##############################################
                echo ""
				GID_USER=9628
				UID_USER=9629
				USER_ADD=oi2squash
				USER_COMMENT="OI2 Tests applicatifs"
				HOME=/home/oi2squash
				SUDO_TMP=/tmp/sudoers_oi2squash

                ETAPE="Création / configuration user $USER_ADD"
				echo " début ${ETAPE}"
				echo
				cat /etc/passwd | grep $USER_ADD > /dev/null 2>&1
				if [ $? != 0 ]
				then
					echo "creation user $USER_ADD"
					groupadd -g $GID_USER $USER_ADD
					useradd -c "$USER_COMMENT" -u $UID_USER -g $USER_ADD $USER_ADD
					if [ $? = 0 ]
					then
						echo "creation user $USER_ADD OK"
						echo
                    else
                        echo "creation user $USER_ADD KO" > $LOG
						echo "creation user KO"   >&2 && exit 4
                    fi
                else
                    echo "$USER_ADD deja present"
                fi
                
                # Ajout partie sudoers
				echo "Modification du fichier sudoers"
                cat /etc/sudoers | grep $USER_ADD > /dev/null 2>&1
                if [ $? -eq 0 ]
                then
                    echo "Sudo oi2squash deja present"
                else
                    cp -p /etc/sudoers /etc/sudoers.$(date +%Y%m%d-%H%M)
                    if [ $? = 0 ]
					then
						echo "Backup fichier sudoers OK"
						echo
						cat /etc/sudoers > $SUDO_TMP
                        cat >> $SUDO_TMP <<EOF
########## DEBUT SUDO user $USER_ADD ##########
oi2squash  ALL=(ALL) NOPASSWD: ALL
Defaults:oi2squash !requiretty
########## FIN SUDO user $USER_ADD ##########
EOF
						visudo -c -f $SUDO_TMP > /dev/null 2>&1
						if [ $? = 0 ]
						then
							mv $SUDO_TMP /etc/sudoers
							chmod 440 /etc/sudoers
							echo "Modification du fichier sudoers OK"
							echo
                        else
                            echo "Fichier temporaire $SUDO_TMP inccorect" > $LOG
							echo "Fichier temporaire $SUDO_TMP inccorect"
							echo "Modification du fichier sudoers KO"  >&2 && exit 4
						fi					
					else
                        echo "Backup fichier sudoers KO" > $LOG
						echo "Backup fichier sudoers KO"   >&2 && exit 4			
					fi
                fi
                
                # Ajout partie clés ssh (authorized key)
                DIR=/home/oi2squash/.ssh
                AUTH_FILE=$DIR/authorized_keys
                if [ -f $AUTH_FILE ]
                then
                    echo "Fichier $AUTH_FILE deja present"
                else
                    if [ ! -d $DIR ]
                    then
                        su -l oi2squash -c "mkdir -p $DIR"
                        if [ $? -eq 0 ]
                        then
                            chmod 700 $DIR
                            chown oi2squash:root $DIR
                            echo "Creation repertoire $DIR OK"                    
                        else
                            echo "Creation repertoire $DIR KO" > $LOG
                            echo "Creation repertoire $DIR KO"   >&2 && exit 8                         
                        fi
                    fi
                    cat > $AUTH_FILE <<EOF
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDzEVzJpmJ2BngIelaE44nVA7Bh48P7zyjPzsMyvLlfgjr8UPo3JxBy1lonc6FoHnXv/fRZU04kmGO4QCbPe2Hebs3E2C7j39QWQoCJ15gzhc5JcMOedHTl6f0Gr/fUlT7RtYwovt//5ELuNeZRF5qjBP+yU+Tb/hasU0T00+vnjM9g9iMyN8LeHT4AKKQ1oGGMGDQ3SJZXwz3odfyMD0sc3sAK0YaQ6TTSZK2nxlCm/e6w+F9sGengWbLWSeagqw9OtlGZH/zMNvDIsvthMn+r/aRtq06WZsdGKy8pHJlQgULiw8J25gaSAt3vFn2XbjMG44Fm4M5SeRoWd6b9bv2l jenkins@prstabn02.noe.edf.fr
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDzEVzJpmJ2BngIelaE44nVA7Bh48P7zyjPzsMyvLlfgjr8UPo3JxBy1lonc6FoHnXv/fRZU04kmGO4QCbPe2Hebs3E2C7j39QWQoCJ15gzhc5JcMOedHTl6f0Gr/fUlT7RtYwovt//5ELuNeZRF5qjBP+yU+Tb/hasU0T00+vnjM9g9iMyN8LeHT4AKKQ1oGGMGDQ3SJZXwz3odfyMD0sc3sAK0YaQ6TTSZK2nxlCm/e6w+F9sGengWbLWSeagqw9OtlGZH/zMNvDIsvthMn+r/aRtq06WZsdGKy8pHJlQgULiw8J25gaSAt3vFn2XbjMG44Fm4M5SeRoWd6b9bv2l jenkins@prstazn01.noe.edf.fr
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDzEVzJpmJ2BngIelaE44nVA7Bh48P7zyjPzsMyvLlfgjr8UPo3JxBy1lonc6FoHnXv/fRZU04kmGO4QCbPe2Hebs3E2C7j39QWQoCJ15gzhc5JcMOedHTl6f0Gr/fUlT7RtYwovt//5ELuNeZRF5qjBP+yU+Tb/hasU0T00+vnjM9g9iMyN8LeHT4AKKQ1oGGMGDQ3SJZXwz3odfyMD0sc3sAK0YaQ6TTSZK2nxlCm/e6w+F9sGengWbLWSeagqw9OtlGZH/zMNvDIsvthMn+r/aRtq06WZsdGKy8pHJlQgULiw8J25gaSAt3vFn2XbjMG44Fm4M5SeRoWd6b9bv2l jenkins@prstabp04.pcy.edfgdf.fr
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDzEVzJpmJ2BngIelaE44nVA7Bh48P7zyjPzsMyvLlfgjr8UPo3JxBy1lonc6FoHnXv/fRZU04kmGO4QCbPe2Hebs3E2C7j39QWQoCJ15gzhc5JcMOedHTl6f0Gr/fUlT7RtYwovt//5ELuNeZRF5qjBP+yU+Tb/hasU0T00+vnjM9g9iMyN8LeHT4AKKQ1oGGMGDQ3SJZXwz3odfyMD0sc3sAK0YaQ6TTSZK2nxlCm/e6w+F9sGengWbLWSeagqw9OtlGZH/zMNvDIsvthMn+r/aRtq06WZsdGKy8pHJlQgULiw8J25gaSAt3vFn2XbjMG44Fm4M5SeRoWd6b9bv2l jenkins@prstazp03.pcy.edfgdf.fr

EOF
                    chmod 440 $AUTH_FILE
                    chown oi2squash:root $AUTH_FILE
                    if [ $? -eq 0 ]
                    then
                        echo "Fichier $AUTH_FILE mis en place"
                    else
                        echo "Creation fichier $AUTH_FILE KO" > $LOG
                        echo "Creation fichier $AUTH KO"   >&2 && exit 8                       
                    fi
                fi
                
                # Partie configuration accès distant (access.conf)
                echo "Authorisation remote $USERADD"
                if [ -f /usr/newcloud/bin/newcloud_remote_access.sh ]
                then
                    SCRIPT_CAC_ACCESS="/usr/newcloud/bin/newcloud_remote_access.sh"
                elif [ -f /usr/cac/bin/caccia_remote_access.sh ]
                then
                    SCRIPT_CAC_ACCESS="/usr/cac/bin/caccia_remote_access.sh"
                else
                    echo "Script caccia remote access non present" > $LOG
                    echo "Script caccia remote access non present" >&2 && exit 9
                fi
                
                $SCRIPT_CAC_ACCESS -u $USER_ADD
                if [ $? -eq 0 ]
                then
                    echo "Execution script $SCRIPT_CAC_ACCESS -u $USER_ADD OK"
                else
                    SCRIPT_CAC_ACCESS="/usr/cac/bin/caccia_remote_access.sh"
                    $SCRIPT_CAC_ACCESS -u $USER_ADD
                    if [ $? -eq 0 ]
                    then
                        echo "Execution script $SCRIPT_CAC_ACCESS -u $USER_ADD OK"
                    else
                        echo "Execution script $SCRIPT_CAC_ACCESS -u $USER_ADD KO" > $LOG
                        echo "Execution script $SCRIPT_CAC_ACCESS -u $USER_ADD KO" >&2 && exit 9
                    fi
                fi
                
                # Partie conformisation conf
                if [ -f /etc/sudo-ldap.conf ]
                then
                    cat /etc/sudo-ldap.conf | grep -q -E 'nss_initgroups_ignoreusers(.*)oi2squash(.*)'
                    if [ $? -eq 0 ]
                    then
                        echo "Conformisation fichier /etc/sudo-ldap.conf deja OK"
                    else
                        echo "Conformisation fichier /etc.sudo-ldap.conf (ajout user oi2squash nss_initgroups_ignoreusers)"
                        cp -p /etc/sudo-ldap.conf /etc/sudo-ldap.conf_$(date "+%Y%m%d%H%M")
                        sed -i '/^nss_initgroups_ignoreusers/ s/$/, oi2squash/' /etc/sudo-ldap.conf && touch /tmp/sssdrestart
                    fi
                fi
                if [ -f /etc/sssd/sssd.conf ]
                then
                    cat /etc/sssd/sssd.conf | grep -q -E 'filter_users(.*)oi2squash(.*)'
                    if [ $? -eq 0 ]
                    then
                        echo "Conformisation fichier /etc/sssd/sssd.conf deja OK"
                    else
                        echo "Conformisation fichier /etc/sssd/sssd.conf (ajout user oi2squash filter_users)"
                        cp -p /etc/sssd/sssd.conf /etc/sssd/sssd.conf_$(date "+%Y%m%d%H%M")
                        sed -i '/^filter_users/ s/$/, oi2squash/' /etc/sssd/sssd.conf && touch /tmp/sssdrestart
                    fi
                fi
                
                # Redémarrage sssd si modifications
                if [ -f /tmp/sssdrestart ]
                then
                    rm -f /tmp/sssdrestart
                    service sssd restart
                    if [ $? -eq 0 ]
                    then
                        echo "Redémarrage sssd OK"
                        echo "Conformisation configuration ldap OK"
                    else
                        echo "Redémarrage sssd KO" > $LOG
                        echo "Redémarrage sssd KO" >&2 && exit 10
                    fi
                fi
                
                echo "$ETAPE OK"
                echo
                
		;;		
        "AIX")

				##################################
				#### Création du user exp_cac ####
				##################################
				GID_USER=9574
				UID_USER=9574
				USER_ADD=exp_cac
				USER_COMMENT="user exploit cac"
				HOME=/home/exp_cac
				SUDO_TMP=/tmp/sudoers_exploitcac
				
				#Création du user exp_cac 
				ETAPE="Création user exp_cac"
				echo " début ${ETAPE}"
				cat /etc/passwd | grep $USER_ADD > /dev/null 2>&1
				if [ $? != 0 ]
				then
					echo "creation user $USER_ADD"
					mkgroup id=$GID_USER $USER_ADD
					useradd -c "$USER_COMMENT" -u $UID_USER -g $USER_ADD $USER_ADD
					if [ $? = 0 ]
					then
						echo "creation user OK"
						echo
						echo "Modification password $USER_ADD"
						echo "$USER_ADD:U3xPl@1t_cAc" | chpasswd -c
						if [ $? = 0 ]
						then
							echo "Modification password OK"
							# Suppression de l'expiration
							chuser maxage=0 $USER_ADD
							echo
							echo "Modification du fichier sudoers"
							cp -p /etc/sudoers /etc/sudoers.$(date +%Y%m%d-%H%M)
							if [ $? = 0 ]
							then
								echo "Backup fichier sudoers OK"
								echo
								cat /etc/sudoers > $SUDO_TMP
								cat >> $SUDO_TMP <<EOF
########## DEBUT SUDO user exploit $USER_ADD ##########
$USER_ADD  ALL=(root) NOPASSWD: /usr/cac/bin/caccia2-config.sh
########## FIN SUDO user exploit $USER_ADD ##########
EOF
								visudo -c -f $SUDO_TMP > /dev/null 2>&1
								if [ $? = 0 ]
								then
									mv $SUDO_TMP /etc/sudoers
									chmod 440 /etc/sudoers
									echo "Modification du fichier sudoers OK"
									echo
									echo "${ETAPE} OK"									
								else
                                    echo "Fichier temporaire $SUDO_TMP inccorect / Modification du fichier sudoers KO" > $LOG
									echo "Fichier temporaire $SUDO_TMP inccorect"
									echo "Modification du fichier sudoers KO"    >&2 && exit 4
								fi					
							else
                                echo "Backup fichier sudoers KO" > $LOG
								echo "Backup fichier sudoers KO"	   >&2 && exit 4		
							fi
						else
							echo "Modification password OK"			
						fi
					else
                        echo "creation user KO" > $LOG
						echo "creation user KO"    >&2 && exit 4
					fi
				else
					echo "$USER_ADD deja present"
				fi
                

				##############################################
				#### Création / configuration user squash ####
				##############################################
                echo ""
				GID_USER=9628
				UID_USER=9629
				USER_ADD=oi2squas
				USER_COMMENT="OI2 Tests applicatifs"
				HOME=/home/oi2squas
				SUDO_TMP=/tmp/sudoers_oi2squas

                ETAPE="Création / configuration user $USER_ADD"
				echo " début ${ETAPE}"
				echo
				cat /etc/passwd | grep $USER_ADD > /dev/null 2>&1
				if [ $? != 0 ]
				then
					echo "creation user $USER_ADD"
					mkgroup id=$GID_USER $USER_ADD
					useradd -c "$USER_COMMENT" -u $UID_USER -g $USER_ADD $USER_ADD
					if [ $? = 0 ]
					then
						echo "creation user $USER_ADD OK"
                        echo "$USER_ADD" | chpasswd -c -e
						echo
                    else
                        echo "creation user $USER_ADD KO" > $LOG
						echo "creation user KO"   >&2 && exit 4
                    fi
                else
                    echo "$USER_ADD deja present"
                fi
                
                # Ajout partie sudoers
				echo "Modification du fichier sudoers"
                cat /etc/sudoers | grep $USER_ADD > /dev/null 2>&1
                if [ $? -eq 0 ]
                then
                    echo "Sudo oi2squash deja present"
                else
                    cp -p /etc/sudoers /etc/sudoers.$(date +%Y%m%d-%H%M)
                    if [ $? = 0 ]
					then
						echo "Backup fichier sudoers OK"
						echo
						cat /etc/sudoers > $SUDO_TMP
                        cat >> $SUDO_TMP <<EOF
########## DEBUT SUDO user $USER_ADD ##########
oi2squas  ALL=(ALL) NOPASSWD: ALL
Defaults:oi2squas !requiretty
########## FIN SUDO user $USER_ADD ##########
EOF
						visudo -c -f $SUDO_TMP > /dev/null 2>&1
						if [ $? = 0 ]
						then
							mv $SUDO_TMP /etc/sudoers
							chmod 440 /etc/sudoers
							echo "Modification du fichier sudoers OK"
							echo
                        else
                            echo "Fichier temporaire $SUDO_TMP inccorect" > $LOG
							echo "Fichier temporaire $SUDO_TMP inccorect"
							echo "Modification du fichier sudoers KO"  >&2 && exit 4
						fi					
					else
                        echo "Backup fichier sudoers KO" > $LOG
						echo "Backup fichier sudoers KO"   >&2 && exit 4			
					fi
                fi
                
                # Ajout partie clés ssh (authorized key)
                DIR=/home/oi2squas/.ssh
                AUTH_FILE=$DIR/authorized_keys
                if [ -f $AUTH_FILE ]
                then
                    echo "Fichier $AUTH_FILE deja present"
                else
                    if [ ! -d $DIR ]
                    then
                        su -l oi2squash -c "mkdir -p $DIR"
                        if [ $? -eq 0 ]
                        then
                            chmod 700 $DIR
                            chown oi2squash:0 $DIR
                            echo "Creation repertoire $DIR OK"                    
                        else
                            echo "Creation repertoire $DIR KO" > $LOG
                            echo "Creation repertoire $DIR KO"   >&2 && exit 8                         
                        fi
                    fi
                    cat > $AUTH_FILE <<EOF
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDzEVzJpmJ2BngIelaE44nVA7Bh48P7zyjPzsMyvLlfgjr8UPo3JxBy1lonc6FoHnXv/fRZU04kmGO4QCbPe2Hebs3E2C7j39QWQoCJ15gzhc5JcMOedHTl6f0Gr/fUlT7RtYwovt//5ELuNeZRF5qjBP+yU+Tb/hasU0T00+vnjM9g9iMyN8LeHT4AKKQ1oGGMGDQ3SJZXwz3odfyMD0sc3sAK0YaQ6TTSZK2nxlCm/e6w+F9sGengWbLWSeagqw9OtlGZH/zMNvDIsvthMn+r/aRtq06WZsdGKy8pHJlQgULiw8J25gaSAt3vFn2XbjMG44Fm4M5SeRoWd6b9bv2l jenkins@prstabn02.noe.edf.fr
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDzEVzJpmJ2BngIelaE44nVA7Bh48P7zyjPzsMyvLlfgjr8UPo3JxBy1lonc6FoHnXv/fRZU04kmGO4QCbPe2Hebs3E2C7j39QWQoCJ15gzhc5JcMOedHTl6f0Gr/fUlT7RtYwovt//5ELuNeZRF5qjBP+yU+Tb/hasU0T00+vnjM9g9iMyN8LeHT4AKKQ1oGGMGDQ3SJZXwz3odfyMD0sc3sAK0YaQ6TTSZK2nxlCm/e6w+F9sGengWbLWSeagqw9OtlGZH/zMNvDIsvthMn+r/aRtq06WZsdGKy8pHJlQgULiw8J25gaSAt3vFn2XbjMG44Fm4M5SeRoWd6b9bv2l jenkins@prstazn01.noe.edf.fr
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDzEVzJpmJ2BngIelaE44nVA7Bh48P7zyjPzsMyvLlfgjr8UPo3JxBy1lonc6FoHnXv/fRZU04kmGO4QCbPe2Hebs3E2C7j39QWQoCJ15gzhc5JcMOedHTl6f0Gr/fUlT7RtYwovt//5ELuNeZRF5qjBP+yU+Tb/hasU0T00+vnjM9g9iMyN8LeHT4AKKQ1oGGMGDQ3SJZXwz3odfyMD0sc3sAK0YaQ6TTSZK2nxlCm/e6w+F9sGengWbLWSeagqw9OtlGZH/zMNvDIsvthMn+r/aRtq06WZsdGKy8pHJlQgULiw8J25gaSAt3vFn2XbjMG44Fm4M5SeRoWd6b9bv2l jenkins@prstabp04.pcy.edfgdf.fr
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDzEVzJpmJ2BngIelaE44nVA7Bh48P7zyjPzsMyvLlfgjr8UPo3JxBy1lonc6FoHnXv/fRZU04kmGO4QCbPe2Hebs3E2C7j39QWQoCJ15gzhc5JcMOedHTl6f0Gr/fUlT7RtYwovt//5ELuNeZRF5qjBP+yU+Tb/hasU0T00+vnjM9g9iMyN8LeHT4AKKQ1oGGMGDQ3SJZXwz3odfyMD0sc3sAK0YaQ6TTSZK2nxlCm/e6w+F9sGengWbLWSeagqw9OtlGZH/zMNvDIsvthMn+r/aRtq06WZsdGKy8pHJlQgULiw8J25gaSAt3vFn2XbjMG44Fm4M5SeRoWd6b9bv2l jenkins@prstazp03.pcy.edfgdf.fr

EOF
                    chmod 440 $AUTH_FILE
                    chown oi2squas:0 $AUTH_FILE
                    if [ $? -eq 0 ]
                    then
                        echo "Fichier $AUTH_FILE mis en place"
                    else
                        echo "Creation fichier $AUTH_FILE KO" > $LOG
                        echo "Creation fichier $AUTH KO"   >&2 && exit 8                       
                    fi
                fi
                
                # Partie configuration accès distant (access.conf)
                echo "Authorisation remote $USERADD"
                if [ -f /usr/newcloud/bin/newcloud_remote_access.sh ]
                then
                    SCRIPT_CAC_ACCESS="/usr/newcloud/bin/newcloud_remote_access.sh"
                elif [ -f /usr/cac/bin/caccia_remote_access.sh ]
                then
                    SCRIPT_CAC_ACCESS="/usr/cac/bin/caccia_remote_access.sh"
                else
                    echo "Script caccia remote access non present" > $LOG
                    echo "Script caccia remote access non present" >&2 && exit 9
                fi
                
                $SCRIPT_CAC_ACCESS -u $USER_ADD
                if [ $? -eq 0 ]
                then
                    echo "Execution script $SCRIPT_CAC_ACCESS -u $USER_ADD OK"
                else
                    echo "Execution script $SCRIPT_CAC_ACCESS -u $USER_ADD KO" > $LOG
                    echo "Execution script $SCRIPT_CAC_ACCESS -u $USER_ADD KO" >&2 && exit 9
                fi
                
                echo "$ETAPE OK"
                echo

				;;
			
        *)      echo "OS_INCOMPATIBLE_AVEC_CE_SCRIPT" > $LOG
                echo "OS_INCOMPATIBLE_AVEC_CE_SCRIPT"
                >&2 && exit 97
                ;;
esac
>&2 && exit 0