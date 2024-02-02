#!/bin/ksh
########################################################################################################################
# Script: SASC_Unix_PostInstall_Step3-Set-Storage-Config.ksh
#
# Description: Ce script permet de configurer le stockage sur une machine Unix lors de la post-instalation
# Version: 1.1.0 (ou 1: modification majeure, 2: modification mineure, 3: correction de bug)
#
# Date de creation: 19/03/2019
# Cree par: Jean-Baptiste Meriaux
#
#
# Mise a jour:
#                           Charles BRANSARD - 22/09/2020 - Modification récupération YUM8 YUM9 (correction bug centos)
#                           Charles BRANSARD - 01/02/2021 - Ajout check FS exploit postinstall (cas de Build to run)
#                                                         - Ajout log erreur en local sur le serveur en cas de KO (/tmp/<nom_script_KO_date>)
#                           Piotr Ulaszewski - 23/06/2023 - Creation du repertoire /logiciels/tmp si il n'existe pas et les FS sont crées
#                                                           Avant, le repertoire n'etait pas crée si les FS existaient déjà
#
# Pre-requis:               Le serveur est de type Unix
#
# Inputs:
#
# Outputs:
#                           0 : le script s'est correctement déroulé
#                           60 : FS infra non créés / non montés
#                           4 : Erreur lors de l'installation
#                           97 :OS incompatible avec le script
#
########################################################################################################################

####### DECLARATION DES CONSTANTES FIXES
SCRIPT_NAME="SASC_Unix_PostInstallation_Step3-Set-Storage-Config"
LOG="/tmp/${SCRIPT_NAME}_KO_$(date "+%Y%m%d%H%M")"

#####################################################
########## DECLARATION DES FONCTIONS ################
#####################################################

backup_files() {
    for i in ${*}; do
        if [ -f "${i}" ]; then
            cp -p "${i}" "${i}".$(date +%Y%m%d-%H%M)
        fi
    done
}

##############
#### MAIN ####
##############

#Check parametres entres

OS=$(uname)
HOSTNAME=$(hostname | awk -F. '{print $1}')
UNAME=$(uname -s)
DATA_DISK=/dev/sdc

echo
echo "######################################"
echo "######### début set storage  #########"
echo "######################################"
echo

case $OS in
"Linux")
    ##################################
    #### 	  Creation du VG	  ####
    ##################################

    if [ "x${UNAME}" = "xLinux" ]; then
        # Get release file
        if [ -e /etc/system-release ]; then
            RELEASE_FILE="/etc/system-release"
        elif [ -e /etc/redhat-release ]; then
            RELEASE_FILE="/etc/redhat-release"
        else
            echo "Cannot set YUM Variables !"
            echo "Cannot set YUM Variables !" >$LOG
            exit 98
        fi

        TYPE_OS=$(cat $RELEASE_FILE | awk '{print $1}' | tr 'A-Z' 'a-z')
        case $TYPE_OS in
        "red")
            YUM8="rhel"
            YUM9=$(grep -i Linux $RELEASE_FILE | sed -e 's/\(.*\)\(release \)\([0-9,.]*\)\(.*\)/\3/g' | awk -F"." '{print $1"."$2}')
            RHE=$(grep -i Linux $RELEASE_FILE | sed -e 's/\(.*\)\(release \)\([0-9,.]*\)\(.*\)/\3/g' | awk -F"." '{print $1"."$2}')
            REL=$(echo ${RHE} | awk -F\. '{print $1}')
            ;;
        "centos")
            YUM8="centos"
            YUM9=$(grep -i centos $RELEASE_FILE | sed -e 's/\(.*\)\(release \)\([0-9,.]*\)\(.*\)/\3/g' | awk -F"." '{print $1"."$2}')
            RHE=$(grep -i centos $RELEASE_FILE | sed -e 's/\(.*\)\(release \)\([0-9,.]*\)\(.*\)/\3/g' | awk -F"." '{print $1"."$2}')
            REL=$(echo ${RHE} | awk -F\. '{print $1}')
            ;;
        *)
            echo -e "Linux distribution $YUM8 not supported"
            echo -e "Linux distribution $YUM8 not supported" >$LOG
            exit 97
            ;;
        esac

        FS_TYPE=xfs

    fi

    #Creation du VG de data si il y a un disque de libre
    echo "Disk(s) DATA"
    #On vérifie si un VG de data existe deja
    MYVG=$(vgdisplay -C --noheadings 2>/dev/null | awk '{print $1}' | grep "^data_vg$")
    if [ "x${MYVG}" = "x" ]; then
        if [ ! -b ${DATA_DISK} ]; then
            echo "Bad device ${DATA_DISK}, ABORT"
            echo "Bad device ${DATA_DISK}, ABORT" >$LOG
            exit 4
        fi
        #Une fois le disque de data identifié, on verifie qu'il n'est pas utilise
        DISK_ID_HEX=$(fdisk -l ${DATA_DISK} | grep "^Disk ide" | awk -F: '{print $2}')
        DISK_ID=$(printf "%d\n" ${DISK_ID_HEX})
        if [ $DISK_ID -ne 0 ]; then
            pvs --noheadings | grep ${DATA_DISK} >/dev/null
            if [ $? -eq 0 ]; then
                echo "Le disk ${DATA_DISK} n est pas libre pour cette operation."
                echo "Selectionner un autre disk et relancer."
                echo "Le disk ${DATA_DISK} n est pas libre pour cette operation." >$LOG
                echo "Selectionner un autre disk et relancer." >>$LOG
                exit 4
            fi
        fi
        #une fois la partition cree, on en cree un PV su'on integre dans le vg data
        echo "Creation du PV et du VG"
        vgcreate data_vg ${DATA_DISK}
        echo
        #On cree les FS de base en commencant par crer les repertoires de montage
        echo "Creation des repertoires.... /appli /logiciels /exploit /var/projects"
        mkdir -p /appli /logiciels /exploit /var/projects
        chmod 755 /appli /logiciels /exploit /var/projects
        echo
        #On cree les LV et FS de ces repertoires
        echo "Creation des LV et FS pour: appli, logiciels"
        lvcreate -A y -L 5G -n lv_appli data_vg
        mkfs.${FS_TYPE} /dev/mapper/data_vg-lv_appli >/dev/null 2>&1
        lvcreate -A y -L 10G -n lv_logiciels data_vg
        mkfs.${FS_TYPE} /dev/mapper/data_vg-lv_logiciels >/dev/null 2>&1
        lvcreate -A y -L 1G -n lv_var_projects data_vg
        mkfs.${FS_TYPE} /dev/mapper/data_vg-lv_var_projects >/dev/null 2>&1
        echo
        echo "Creation des LV et FS pour: exploit"
        lvcreate -A y -L 512m -n lv_exploit root_vg
        mkfs.${FS_TYPE} /dev/mapper/root_vg-lv_exploit >/dev/null 2>&1
        echo
        #On va rajouter le montage de ces FS dans la fstab
        #On commence par faire un backup
        echo "Maj du /etc/fstab"
        backup_files /etc/fstab
        cp -p /etc/fstab /etc/fstab.$(date +%Y%m%d-%H%M)
        cp -p /etc/fstab /tmp
        #On integre les nouvelles lignes dans le backup
        echo -e "/dev/mapper/root_vg-lv_exploit\t\t/exploit\t${FS_TYPE}\tdefaults\t1 2" >>/tmp/fstab
        echo -e "/dev/mapper/data_vg-lv_appli\t\t/appli\t\t${FS_TYPE}\tdefaults\t1 2" >>/tmp/fstab
        echo -e "/dev/mapper/data_vg-lv_logiciels\t/logiciels\t${FS_TYPE}\tdefaults\t1 2" >>/tmp/fstab
        echo -e "/dev/mapper/data_vg-lv_var_projects\t/var/projects\t${FS_TYPE}\tdefaults\t1 2" >>/tmp/fstab
        #On integre la fstab modifie a la place de l'ancienne
        cp /tmp/fstab /etc
        rm -f /tmp/fstab
        echo
        #On corrige les droits des FS et on les monte
        echo "Montage des FS crees."
        mount -a
        df -h
        echo "Correction des droits pour les repertoires."
        chmod 755 /appli /logiciels /exploit /var/projects
    else
        echo "*** VG ${MYVG} deja  en place."
    fi

    # Creation du FS /logiciels/tmp si il existe pas
    mkdir -p /logiciels/tmp
    chmod 777 /logiciels/tmp

    # Check de l'existance des différents FS d'exploit / montage
    ERROR=""
    LIST_FS="/exploit /appli /var/projects /logiciels"
    for FS in $LIST_FS; do
        if [ -d $FS ]; then
            TEST_MOUNT=$(df -mP $FS | grep -v "Filesystem" | awk '{print $6}')
            if [ "$FS" = "$TEST_MOUNT" ]; then
                echo "*** FS $FS deja en place : OK"
            else
                echo "*** FS $FS non monte : KO"
                if [ -z "$ERROR" ]; then
                    ERROR="${FS} "
                else
                    ERROR="${ERROR} ${FS}"
                fi
            fi
        else
            if [ -z "$ERROR" ]; then
                ERROR="${FS} "
            else
                ERROR="${ERROR} ${FS}"
            fi
        fi
    done
    if [ -z "$ERROR" ]; then
        echo "*** FS $LIST_FS deja en place : OK"
    else
        echo
        echo "*** FS $ERROR non crees/montes : KO"
        echo
        echo "Voir creation des FS manquants manuellement : $ERROR"
        echo "*** FS $ERROR non crees/montes : KO" >$LOG
        echo "Voir creation des FS manquants manuellement : $ERROR" >>$LOG
        exit 60
    fi
    echo

    ;;

\
    "AIX")
    ##################################
    #### Creation du FS /exploit  ####
    ##################################

    #Creation du FS /exploit
    echo "FS exploit"
    if [ "x${UNAME}" = "xAIX" ]; then
        lslv lvexploit >/dev/null 2>&1
        if [ $? -eq 1 ]; then
            #Creation du FS de base lvexploit
            echo "Creation du LV, du FS et montage /exploit"
            /usr/sbin/mklv -y'lvexploit' -t'jfs2' rootvg 4
            if [ $? = 0 ]; then
                /usr/sbin/crfs -v jfs2 -d'lvexploit' -m'/exploit' -A'yes'
                if [ $? = 0 ]; then
                    mount /exploit
                    if [ $? = 0 ]; then
                        echo "Creation et montage /exploit OK"
                    else
                        echo "Probleme de montage du FS /exploit" >&2
                        echo "Probleme de montage du FS /exploit" >$LOG
                        exit 4
                    fi
                else
                    echo "Probleme de creation du FS /exploit" >&2
                    echo "Probleme de creation du FS /exploit" >$LOG
                    exit 4
                fi
            else
                echo "Probleme de creation du lv lvexploit" >&2
                echo "Probleme de creation du lv lvexploit" >$LOG
                exit 4
            fi
        else
            echo "lv lvexploit deja existant"
        fi
    fi
    echo

    ;;
*)
    echo "OS_INCOMPATIBLE_AVEC_CE_SCRIPT"
    >&2
    echo "OS_INCOMPATIBLE_AVEC_CE_SCRIPT" >$LOG
    exit 97
    ;;
esac
>&2 && exit 0
