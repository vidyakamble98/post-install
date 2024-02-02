#---------------------------------------------------------------------------------------------------------------------
# Script: Postinstall_Step1_System
#
# Description: Ce script fait la conf. PostInstall hors installation softwares 
#
# Date de creation: /04/2020
# Cree par: Aurelie Astien
# Modification :
#			11/2021 / Aurelie Astien / Adaptation appro via MyCloud (pour vm standard et non standard)
#			11/2021 / Aurelie Astien / Nettoyage du script
#			11/2021 / Aurelie Astien / Integration wsus param + winrm config
#
# Pre-requis:
# 				-----------------------------------
#				-----------------------------------
#
# Inputs:
#		-IP		(-IP IP1,IP2...)| IP des cartes reseau a modifier
#		-name	(-name nom1,nom2)|-nom des cartes reseau = FO, BO ou Admin
#		-AppId	(-AppId NomAppid| AppID de l'application
#		-ENV	(-ENV PROD)| PROD /RECETTE /FORM /BACKUP /DEV /PREPROD /INTEG ou QUALIF 
#		-AssetTag	(-AssetTag ISRV12345)| AssetTag du serveur (ISRV)
#		-Bkp	(-Bkp HEB)| HEB ou MEN (Fréquence de la tache 'pose de fanions' si différent de quotidien
#		-IP IP1,IP2 -name nomIP1,nomIP2 -AppId NomAppid -ENV environment -AssetTag ISRV12345 
#		-IP IP1,IP2 -name FO,Admin -AppId 901 -ENV RECETTE -AssetTag ISRV12345 
#
# Outputs:
#		0 : le script s'est correctement deroule		6 : Middleware deja installe
#		1 : Un repertoire/fichier est manquant			96 : Mauvais parametres renseignes
#		2 : Un package est manquant						97 : OS incompatible avec le script
#		3 : Espace disque insuffisant					98 : Distribution incompatible avec le script
#		4 : Erreur lors de l'installation				99 : Version incompatible avec le script
#		5 : Verifications post installation en echec
#---------------------------------------------------------------------------------------------------------------------

Param(
	#[string[]]$IP=@(),
	#[string[]]$name=@(),
	[alias("ENV")][String]$Environment,
	[Parameter(Mandatory=$false)][string] $AppId,
	[Parameter(Mandatory=$false)][string] $Bkp,
	[Parameter(Mandatory=$false)][string] $AssetTag
	)

#--------------------------------------------------------------------------------------------------------
# CONFIG_SYSTEM
#--------------------------------------------------------------------------------------------------------

#Fixe Date and Time
$FullDateTime_LOG = Get-Date -format 'dd-MM-yyyy_HH-mm-ss'
$FullDateTime_LOG_FIXE = $FullDateTime_LOG

Function Info_Log([string]$ID_MESSAGE, [string]$TYPE, [string]$COMMENT){
#********************************************************************************************************
#~ Fonction Info([string]$ID_MESSAGE, [string]$TYPE, [string]$COMMENT)
#********************************************************************************************************
#~ Description : 	Cette fonction permet de faire une sortir log et ecran d'un message
#~					Le comportement de cette fonction est similaire Ã  celle de linux ce nommant "Info"
#~
#~ Argument(s) en Entrée: 	ID_MESSAGE 	=	ID du message permettant d'améliorer la recherche/debug
#~							TYPE 		=	Type de message. e=erreur ; i=info ; a=alerte
#~							COMMENT 	=	Message/Commantaire que l'on veut loguer et sortir Ã  l'écran
#~
#********************************************************************************************************
#
# /!\ Fonction reprise des OIs EDF
#
###################################
#Initialisation fichier de logs
$Log_File_Temp_LOG_FIXE = "C:\Winnt\Srv\Log\PostInstall_ISIM2_$FullDateTime_LOG_FIXE.log"
#Chemin complet du log et nom
$FULL_PATCH_LOG = "$Log_File_Temp_LOG_FIXE"
#Récupération de la date
$DATE = Get-Date
#Récupération du nom de la machine
$MACHINE_NAME = [Environment]::MachineName
#Récupération du script en cours
$SCRIPT_PATH = $MyInvocation.ScriptName
$SCRIPT_NAME = $SCRIPT_PATH.Split("\")[-1]

###################################
#Traitement du type d'info
if ( $TYPE -eq "i" ) {
	$TYPE_NAME = "INFO"
	$COLOR = "white"
}
elseif ( $TYPE -eq "a" ) {
	$TYPE_NAME = "ALERTE"
	$COLOR = "yellow"
}
elseif ( $TYPE -eq "e" ) {
	$TYPE_NAME = "ERREUR"
	$COLOR = "red"
    $LASTEXITCODE = "10"
    exit $LASTEXITCODE
}
else {
	Write-Host "Le type de message -$TYPE- n'est pas supporte ..." -ForegroundColor red
	exit $kResultFailure
}

###################################
#Valeur de sortie
$SORTIE="$DATE|$MACHINE_NAME|$SCRIPT_NAME|$ID_MESSAGE|0|_${TYPE_NAME}_||||| $COMMENT"

###################################
#Ecriture dans le fichier - Sortie Log
Add-Content -Path $FULL_PATCH_LOG -Value "$SORTIE"
#Sortie écran
Write-Host $SORTIE -ForegroundColor $COLOR
}

#-------------------------------
#####  Lancement de la post-installation initiale  
#-------------------------------
Function Launch-PostInstall-init {

	#Set-NetAdapter
	Set-ConfDisk
	Set-PCDisableFW
	$signatureWsusParam = "C:\Windows\signatures\svr_param-wsus*"
	if ($signatureWsusParam){Set-WsusParam}
	Set-PCConfigNTP
	Set-PageFile
	Set-PCConfigAll
	Set-Conf_Fanion
	Set-PCConfigFTP
	Set-PCFTPFWRules
	Set-PCAddUserSogeti
	Set-GroupMember
	Set-KMS_Windows
	Get-ActivationStatus
	Set-PCEnableFW
	#Set-WinrmConfig
	if ($AssetTag){
		Create-logonScript
	}else {Write-Host "Valeur de l'assettag :"}
	Get-Content "C:\Windows\Srv\Config\ASSETTAG" 
	$LASTEXITCODE = "0"
	exit $LASTEXITCODE
}

#-------------------------------
#####  CONFIG NETADAPTER (FO BO ADMIN)
#-------------------------------
Function Set-NetAdapter {

	#---------------------------------------------  
	# Rename Adapter (FO, Admin, BO) 
	#---------------------------------------------  

	if ($IP){
		$i= 0

		foreach($IPn in $IP){

			$nameN = $name[$i]
			$i += 1 
			if (($nameN -ne 'FO') -xor ($nameN -ne 'BO') -xor ($nameN -ne 'Admin')) {
				Write-Host (   $IPn +': name = FO , BO ou Admin')
				exit 1
			}
			$GetAdaptOldName = Get-NetIPAddress -IPAddress $IPn | Select-Object -ExpandProperty InterfaceAlias
			$NetAdaptOldName = Get-NetAdapter -Name $GetAdaptOldName | Select-Object -ExpandProperty Name
			
			if ($GetAdaptOldName -eq $NetAdaptOldName){ 
				Write-Host ('IP : '+$IPn)
				Write-Host ('   ancien_nom : '+$NetAdaptOldName)
				Rename-NetAdapter -Name $NetAdaptOldName -NewName $nameN
				Write-Host ('   nouveau_nom : '+$nameN)
			}  
		} 
	}
	#---------------------------------------------  
	#	SET GATEWAY ( FO) / DELETE GATEWAY (Other Interface)
	#---------------------------------------------  
	# Supression gateway si NetAdapter not equal Front Office (FO)
	(Get-NetAdapter | Where-Object {$_.name -ne "FO"})| Set-DnsClientServerAddress -ResetServerAddresses

	# Suppression gateway Admin / BO -------------
	if ((Get-NetAdapter).Name -eq "FO" ){

		if (((Get-NetIPConfiguration -ifAlias FO).IPv4DefaultGateway).NextHop ){
			if ((Get-NetAdapter).Name -eq "admin" ){
				$NextHopAdmin = ((Get-NetIPConfiguration -ifAlias Admin -ErrorAction SilentlyContinue).IPv4DefaultGateway).NextHop
					if ($NextHopAdmin){ Remove-NetRoute -NextHop $NextHopAdmin -Confirm:$False }
			}
			if ((Get-NetAdapter).Name -eq "BO" ){
			$NextHopBO = ((Get-NetIPConfiguration -ifAlias BO -ErrorAction SilentlyContinue).IPv4DefaultGateway).NextHop
			if ($NextHopBO){ Remove-NetRoute -NextHop $NextHopBO -Confirm:$False }
			}
		}
	}
	#---------------------------------------------
	#	SET DNS ( FO) / DELETE DNS (Other Interface)
	#---------------------------------------------  

	# Zone hors DMZ
	# DNS nationaux
	$dns1,$dns2 = '130.98.194.189','192.196.111.47' 
	$dnsList = Get-DnsClientServerAddress -AddressFamily IPv4 -InterfaceAlias FO -ErrorAction SilentlyContinue

	foreach ($i in $dnsList){
		$dnsIn = $dnsList | Select-Object -ExpandProperty ServerAddresses
		if (!($dnsIn -eq $dns1) -and !($dnsIn -eq $dns2)){
			Set-DnsClientServerAddress -InterfaceAlias FO -ServerAddresses $dns1,$dns2,$dnsIn 
		}
		else{
			Set-DnsClientServerAddress -InterfaceAlias FO -ServerAddresses $dns1,$dns2
		}
	$dsnFO = $dnsList| Select-Object -ExpandProperty ServerAddresses
	Write-Host ('   dns de FO : ') 
	$dsnFO
	}

	Get-DnsClientServerAddress -AddressFamily IPv4 -InterfaceAlias Admin | Set-DnsClientServerAddress -ResetServerAddresses
	Get-DnsClientServerAddress -AddressFamily IPv4 -InterfaceAlias BO | Set-DnsClientServerAddress -ResetServerAddresses

}

#-------------------------------
#####  CONFIG DISKS
#-------------------------------
Function Set-ConfDisk {

	# Initialisation et configuration des volumes /diskmgmt.msc
	# Change le nom du lecteur cdRom en Z:
	# Passage en Online et formatage en NTFS des volumes Offline
	# Volume D: = Data


	#1_CD-ROM #--- Change name 
	$cdRom = Get-Volume | Where-Object {$_. DriveType -like 'CD-ROM'} | Select-Object -ExpandProperty DriveLetter
	Get-WmiObject -Class Win32_volume -Filter "DriveLetter = '${cdRom}:'" | Set-WmiInstance -Arguments @{DriveLetter='Z:'} -Confirm:$false

	$Devices = Get-Disk | Where-Object {$_.OperationalStatus -like 'Offline'}
	If (!([string]::IsNullOrEmpty($Devices))){
		Stop-Service -Name ShellHWDetection # Stop prompt

		$Devices = Get-Disk | Where-Object {$_.OperationalStatus -like 'Offline'}

		foreach ($Device in $Devices){                        # Pour chaque volume offline
			$Num = $Device | Select-Object -ExpandProperty Number

			#2_Initialize-Disk #--- Initialisation/ GPT
			Set-Disk -Number $Num -IsOffline $false           # passage en online
			Set-Disk -Number $Num -IsReadOnly $false          # mode lecture /ecriture (obligatoire avt initialisation)
			Initialize-Disk -Number $Num                      # initialisation du disque en GPT

			#3_New-Partition #--- Partition #4_Format-Volume #---Formatage en NTFS
			New-Partition -DiskNumber $Num -AssignDriveLetter -UseMaximumSize | Format-Volume -FileSystem NTFS -NewFileSystemLabel "Vol_${Letter}" -Force -Confirm:$false
		}
		Set-Volume -DriveLetter 'D' -NewFileSystemLabel 'Data'

	Start-Service -Name ShellHWDetection
	}
}

#-------------------------------
#####  DISABLE FIREWALL
#-------------------------------
Function Set-PCDisableFW {
	Write-host "`n#####  Désactivation du firewall  " -ForegroundColor Green
	Info_Log "DESACTIVATION_FIREWALL" "i" "#####  Désactivation du firewall  "
	Info_Log "DISABLED_FIREWALL" "i" "[INFO] - Vérification du firewall avant action"
	netsh advfirewall show allprofiles | ?{$_ -match "state" -or $_ -match "Profile Settings:"}
	netsh advfirewall set allprofiles state off
	Info_Log "DISABLED_FIREWALL" "i" "Désactivation du firewall effectuée"
	Info_Log "DISABLED_FIREWALL" "i" "[INFO] - Vérification du firewall aprés action"
	netsh advfirewall show allprofiles | ?{$_ -match "state" -or $_ -match "Profile Settings:"}
	Info_Log "DISABLED_FIREWALL" "i" "[INFO] - Désactivation du firewall effectuée"
}

#-------------------------------
#####  LOCAL POLICIES
#-------------------------------
Function Set-PCConfigAll {
	#Activation BGInfo si present	
	Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -name "BgInfo" -value "$env:SystemDrive\outillage\bginfo\bginfo.exe $env:SystemDrive\outillage\bginfo\EDF.bgi /TIMER:0 /NOLICPROMPT"
	Write-host "`n#####  Set local policies  " -ForegroundColor Green
	Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name fDisableClip -Value 0
	Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name fDisableCdm -Value 0
	Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name fDisableCam -Value 1
	Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name fDisableAudioCapture -Value 1
	Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name fDisableCcm -Value 1
	Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name fDisableLPT -Value 1
	Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name fEnableSmartCard -Value 0
	Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name fDisablePNPRedir -Value 1
	gpupdate /force
	Info_Log "CONFIG_SYSTEME_BASE" "i" "Set local policies : OK"
	Info_Log "CONFIG_SYSTEME_BASE" "i" "Activation copy/paste : OK"
}

#-------------------------------
#####  CONFIG NTP 
#-------------------------------
Function Set-PCConfigNTP {
	Write-host "`n#####  Configuration du NTP  " -ForegroundColor Green
	Info_Log "CONFIG_NTP" "i" "#####  Configuration du NTP  "
	if((get-service w32time).status -eq "running") {net stop w32time ; sleep 2}
	w32tm /config /syncfromflags:manual /manualpeerlist:"ntp1.edf.fr ntp2.edf.fr"
	w32tm /config /reliable:yes
	net start w32time
	w32tm /resync
	w32tm /query /status
	Info_Log "CONFIG_NTP" "i" "Configuration NTP effectuée"
}

#-------------------------------
##### CREATE SCRIPTS BACKUP (Fanion) 
#-------------------------------
Function Set-Conf_Fanion {
	Write-host "`n#####  Configuration Fanion  " -ForegroundColor Green
	Info_Log "CONFIG_Fanion" "a" "#####  Configuration Fanion  "

	#Variables
	$RemoteComp = $env:ComputerName
	$FullDateTime = Get-Date -format 'dd-MM-yyyy_HH-mm-ss'
	$LogDateTime = Get-Date -format 'dd/MM/yyyy HH:mm'

	$Fanion_Directory = "C:\Program Files\Legato\nsr\fanion"
	$Fanion_Old_Directory = "C:\Program Files\Legato\nsr\fanion.old-$FullDateTime"

	#Debut du script
	Info_Log "CONFIG_Fanion" "i" "Attente saisie APPID"
	
	Function CREATE_FANION {
	
		#Creations du repertoire fanion
		Info_Log "CONFIG_Fanion" "i" "Début de la création des repertoires"
		if ((Test-Path "C:\Program Files\Legato\nsr\fanion") -eq $True) {
			Info_Log "CONFIG_Fanion" "a" "Dossier fanion déjÃ  présent"
			Move-Item -Path $Fanion_Directory -Destination $Fanion_Old_Directory -Force
			Info_Log "CONFIG_Fanion" "a" "Dossier de fanion déplacé"
			New-Item -Path "C:\Program Files\Legato\nsr\" -Name "fanion" -ItemType directory
			Info_Log "CONFIG_Fanion" "a" "Dossier de fanion recréé"
		}
		Else {
			New-Item -Path "C:\Program Files\Legato\nsr\" -Name "fanion" -ItemType directory
			Info_Log "CONFIG_Fanion" "a" "Dossier de fanion créé"
		}#Creations de repertoire APPID
		if ((Test-Path "C:\Program Files\Legato\nsr\fanion\$APPID_Value") -eq $True) {
			Info_Log "CONFIG_Fanion" "i" "Dossier de l'APPID déjÃ  présent"
		}
		Else {
			New-Item -Path "C:\Program Files\Legato\nsr\fanion\" -Name "$APPID_Value" -ItemType directory
			Info_Log "CONFIG_Fanion" "a" "Dossier de l'APPID ($APPID_Value) créé"
		}

		#Creation du batch variables.bat
		Info_Log "CONFIG_Fanion" "i" "Creation du batch variables.bat"
		$CMD_variables_file = @"
		rem # Nom du client
		rem SET CLIENT=%computername%
		set client=$RemoteComp

		rem # Pentagramme Applicatif
		set APPLI=$APPID_Value

		rem # Repertoire de localisation des scripts
		set REPRACINE="C:\Program Files\Legato\nsr\fanion"

		rem # Repertoire local de localisation des fanions
		set REPLOCAL="C:\Program Files\Legato\nsr\fanion\%APPLI%"

		rem # Repertoire distant de localisation des fanions
		set REPDISTANT=/nsr/fanion/windows/%CLIENT%

		rem # Serveur NWK
		set NWK=pcyydsvg

		rem # Login de connection
		set LOGIN=ogdpub
"@
		New-item -Path "$Fanion_Directory\variables.bat" -ItemType File -Value $CMD_variables_file -force |Out-Null

		#Creation du batch EVAGD_pose_fanion.bat
		Info_Log "CONFIG_Fanion" "i" "Creation du batch EVAGD_pose_fanion.bat"
		$CMD_EVAGD_pose_fanion = @"
		@echo off
		rem ###############################################################################
		rem #   Fichier     : EVAGD_arret.bat (pour WINDOWS)				                   #
		rem #   Date        : Le 31/01/2005						                               #
		rem #   Description : Arret Appli + Depot fanion d'arret sur serveur local et distant  #
		rem ###############################################################################

		CALL "C:\Program Files\Legato\nsr\fanion\variables.bat"

		rem ################
		rem # Purge des fanions #
		rem ################

		del %REPLOCAL%\%APPLI%.arret
		del %REPLOCAL%\%APPLI%.savegrp.arret
		del %REPLOCAL%\%APPLI%.timeout
		del %REPLOCAL%\%APPLI%.demarre
		del %REPLOCAL%\%APPLI%.pret-svg
		del %REPLOCAL%\%APPLI%.pas-svg

		rem ####################################
		rem # Commandes d arret de l'application    #
		rem ####################################
		time /T
		echo Arret de l'application %APPLI%
		rem # A REMPLIR Exemple stop appli_1

		rem ##################################################
		rem # Positionnement fanion arret appli local et distant  #
		rem ##################################################
		echo fanion > %REPLOCAL%\%APPLI%.pret-svg

		cd /D %REPLOCAL%

		rcp %APPLI%.pret-svg %NWK%.%LOGIN%:%REPDISTANT%

		rem ######################################################
		rem # Lancement de l'attente du timeout ou fanion de fin SVG  #
		rem ######################################################
		cd /D %REPRACINE%
		rem # A REMPLIR Si une application doit etre relance decommenter la ligne ci dessous
		rem CALL EVAGD_attente.bat
"@
		New-item -Path "$Fanion_Directory\EVAGD_pose_fanion.bat" -ItemType File -Value $CMD_EVAGD_pose_fanion -force |Out-Null

		#Creation du batch EVAGD_pose_fanion_archivage.bat
		Info_Log "CONFIG_Fanion" "i" "Creation du batch EVAGD_pose_fanion_archivage.bat"
		$CMD_EVAGD_pose_fanion_archivage = @"
		@echo off
		rem ###################################################################################
		rem #   Fichier     : EVAGD_pose_fanion_archivage.bat (pour WINDOWS)     				   #
		rem #   Date        : Le 31/01/2005						                                   #
		rem #   Description : Arret Appli + Depot fanion d'archivage sur serveur local et distant  #
		rem ###################################################################################

		CALL "C:\Program Files\Legato\nsr\fanion\variables.bat"

		rem ################
		rem # Purge des fanions #
		rem ################

		del %REPLOCAL%\%APPLI%.arret
		del %REPLOCAL%\%APPLI%.savegrp.arret
		del %REPLOCAL%\%APPLI%.timeout
		del %REPLOCAL%\%APPLI%.demarre
		del %REPLOCAL%\%APPLI%.pret-svg

		rem ####################################
		rem # Commandes d arret de l'application    #
		rem ####################################
		time /T
		echo Arret de l'application %APPLI%
		rem # A REMPLIR Exemple stop appli_1

		rem ##################################################
		rem # Positionnement fanion arret appli local et distant  #
		rem ##################################################
		echo fanion > %REPLOCAL%\%APPLI%.archivage.pret

		cd /D %REPLOCAL%

		rcp %APPLI%.pret-svg %NWK%.%LOGIN%:%REPDISTANT%

		rem ######################################################
		rem # Lancement de l'attente du timeout ou fanion de fin SVG  #
		rem ######################################################
		cd /D %REPRACINE%
		rem # A REMPLIR Si une application doit etre relance decommenter la ligne ci dessous
		rem CALL EVAGD_attente.bat
"@
		New-item -Path "$Fanion_Directory\EVAGD_pose_fanion_archivage.bat" -ItemType File -Value $CMD_EVAGD_pose_fanion_archivage -force |Out-Null

		#Creation du batch EVAGD_pose_fanion_pasdesvg.bat
		Info_Log "CONFIG_Fanion" "i" "Creation du batch EVAGD_pose_fanion_pasdesvg.bat"
		$CMD_EVAGD_pose_fanion_pasdesvg = @"
		@echo off
		rem ###############################################################################
		rem #   Fichier     : EVAGD_pose_fanion_pasdesvg.bat (pour WINDOWS)				       #
		rem #   Date        : Le 31/01/2005						                               #
		rem #   Description : Depot fanion d'empÃªchement sur serveur local et distant          #
		rem ###############################################################################

		CALL "C:\Program Files\Legato\nsr\fanion\variables.bat"

		rem ################
		rem # Purge des fanions #
		rem ################

		del %REPLOCAL%\%APPLI%.arret
		del %REPLOCAL%\%APPLI%.savegrp.arret
		del %REPLOCAL%\%APPLI%.timeout
		del %REPLOCAL%\%APPLI%.demarre
		del %REPLOCAL%\%APPLI%.pret-svg

		rem ####################################
		rem # Commandes d arret de l'application    #
		rem ####################################
		time /T
		echo Arret de l'application %APPLI%
		rem # A REMPLIR Exemple stop appli_1

		rem ##################################################
		rem # Positionnement fanion arret appli local et distant  #
		rem ##################################################
		echo fanion > %REPLOCAL%\%APPLI%.pas-svg

		cd /D %REPLOCAL%

		rcp %APPLI%.pas-svg %NWK%.%LOGIN%:%REPDISTANT%

		rem ######################################################
		rem # Lancement de l'attente du timeout ou fanion de fin SVG  #
		rem ######################################################
		cd /D %REPRACINE%
		rem # A REMPLIR Si une application doit etre relance decommenter la ligne ci dessous
		rem CALL EVAGD_attente.bat
"@
		New-item -Path "$Fanion_Directory\EVAGD_pose_fanion_pasdesvg.bat" -ItemType File -Value $CMD_EVAGD_pose_fanion_pasdesvg -force |Out-Null

		#Creation du batch EVAGD_relance.bat
		Info_Log "CONFIG_Fanion" "i" "Creation du batch EVAGD_relance.bat"
		$CMD_EVAGD_relance = @"
		rem ###############################################################################
		rem #   Fichier     : EVAGD_relance.bat (pour WINDOWS)				                   #
		rem #   Date        : Le 31/01/2005						                               #
		rem #   Description : Relance applis apres sauvegarde EVAGD, pose fanion               #
		rem ###############################################################################

		rem ####################################
		rem # Commandes de relance de l'application #
		rem ####################################
		time /T
		echo Redemarrage de l'application %APPLI%
		rem # A REMPLIR Exemple start appli_1
"@
		New-item -Path "$Fanion_Directory\EVAGD_relance.bat" -ItemType File -Value $CMD_EVAGD_relance -force |Out-Null

		#Creation du batch EVAGD_timeout.bat
		Info_Log "CONFIG_Fanion" "i" "Creation du batch EVAGD_timeout.bat"
		$CMD_EVAGD_timeout = @"
		rem ###############################################################################
		rem #   Fichier     : EVAGD_timeout.bat (pour WINDOWS)				                   #
		rem #   Date        : Le 31/01/2005						                               #
		rem #   Description : Relance applis apres sauvegarde EVAGD, pose fanion               #
		rem ###############################################################################

		rem ####################################
		rem # Commandes de relance de l'application #
		rem ####################################
		time /T
		echo Redemarrage de l'application %APPLI%
		rem # A REMPLIR Exemple start appli_1

		rem ######################################################
		rem # Positionnement fanion demarrage appli local et distant  #
		rem # FTP ou RCP					                          #
		rem ######################################################
		echo fanion > %REPLOCAL%\%APPLI%.demarre

		cd /D %REPLOCAL%
		rcp %APPLI%.demarre %NWK%.%LOGIN%:%REPDISTANT%
"@
		New-item -Path "$Fanion_Directory\EVAGD_timeout.bat" -ItemType File -Value $CMD_EVAGD_timeout -force |Out-Null

		#Creation du batch EVAGD_attente.bat
		Info_Log "CONFIG_Fanion" "i" "Creation du batch EVAGD_attente.bat"
		$CMD_EVAGD_attente = @"
		rem ###############################################################################
		rem #   Fichier     : EVAGD_attente.bat (pour WINDOWS)				                   #
		rem #   Date        : Le 31/01/2005						                               #
		rem #   Description : Attente fin de SVG ou timeout 			                       #
		rem ###############################################################################

		set DELAI=15
		set FIN_ATTENTE=0

		rem # A REMPLIR Exemple 20:00 ou 8:00 PM en fonction de la commande time cf proc. #
		set FINTIME=11:00

		time /T
		echo "Debut de la boucle d'attente de la fin de SVG ou du timeout"

		:BOUCLE
		rem #############################################################
		rem # Boucle de vérification des fanions de fin de SVG ou de timeout #
		rem #############################################################

		sleep %DELAI%

		time /T >%systemdrive%\test_time.txt
		FOR /F %%i IN (%systemdrive%\test_time.txt) DO SET CHKTIME=%%i
		del /Q %systemdrive%\test_time.txt

		echo %CHKTIME% %FINTIME%

		rem ###########################
		rem # Appel au script de timeout   #
		rem ###########################
		if %CHKTIME% == %FINTIME% (
		set FIN_ATTENTE=1
		echo "Temps d'attente depasse"

		cd /D %REPRACINE%
		CALL EVAGD_timeout.bat
		GOTO SORTIE
		)

		rsh %NWK% -l %LOGIN% "ls -l %REPDISTANT%/%APPLI%.savegrp.arret 2>/dev/null | wc -l" > %REPLOCAL%\finsvg.tmp

		cd /D %REPLOCAL%
		for /F %%x in (finsvg.tmp) do (
		if "%%x"=="1" (
		set FIN_ATTENTE=1
		time /T
		echo "Sauvegarde terminée"

		cd /D %REPRACINE%
		CALL EVAGD_relance.bat
		GOTO SORTIE
		)
		)

		if "%FIN_ATTENTE%"=="0" GOTO BOUCLE
		:SORTIE
"@
		New-item -Path "$Fanion_Directory\EVAGD_attente.bat" -ItemType File -Value $CMD_EVAGD_attente -force |Out-Null

		#Creation du batch EVAGD_enleve_fanion_pasdesvg.bat
		Info_Log "CONFIG_Fanion" "i" "Creation du batch EVAGD_enleve_fanion_pasdesvg.bat"
		$CMD_EVAGD_enleve_fanion_pasdesvg = @"
		@echo off
		rem ###############################################################################
		rem #   Fichier     : EVAGD_enleve_fanion_pasdesvg.bat (pour WINDOWS)				                   #
		rem #   Date        : Le 31/01/2005						                               #
		rem #   Description : Arret Appli + Depot fanion d'arret sur serveur local et distant  #
		rem ###############################################################################

		CALL "C:\Program Files\Legato\nsr\fanion\variables.bat"

		rem ################
		rem # Purge des fanions #
		rem ################

		del %REPLOCAL%\%APPLI%.arret
		del %REPLOCAL%\%APPLI%.savegrp.arret
		del %REPLOCAL%\%APPLI%.timeout
		del %REPLOCAL%\%APPLI%.demarre
		del %REPLOCAL%\%APPLI%.pret-svg

		rem ####################################
		rem # Commandes d arret de l'application    #
		rem ####################################
		time /T
		echo Arret de l'application %APPLI%
		rem # A REMPLIR Exemple stop appli_1

		rem ##################################################
		rem # Positionnement fanion arret appli local et distant  #
		rem ##################################################
		del %REPLOCAL%\%APPLI%.pas-svg

		cd /D %REPLOCAL%
		rem rcp %APPLI%.pas-svg %NWK%.%LOGIN%:%REPDISTANT%

		rem ######################################################
		rem # Lancement de l'attente du timeout ou fanion de fin SVG  #
		rem ######################################################
		cd /D %REPRACINE%
		rem # A REMPLIR Si une application doit etre relance decommenter la ligne ci dessous
		rem CALL EVAGD_attente.bat
"@
		New-item -Path "$Fanion_Directory\EVAGD_enleve_fanion_pasdesvg.bat" -ItemType File -Value $CMD_EVAGD_enleve_fanion_pasdesvg -force |Out-Null
	}
#--------------------------------------------------------------------------------------------------------
	# Creation pose fanions (si Appid renseigné) sinon arret de la fonction
	If (!([string]::IsNullOrEmpty($Appid))){
		Info_Log "CONFIG_Fanion" "i" "Saisie APPID effectuée ($APPID)"
		$VAR_APPID_FLAG = $AppId
		$APPID_Value = $AppId
		CREATE_FANION
	}
	Else {
		Info_Log "CONFIG_Fanion" "i" "Saisie APPID manquante"
		Info_Log "CONFIG_Fanion" "i" "Arret Config_Fanion"
	}
}

#-------------------------------
#####  CONFIG FTP SITE (IIS) 
#-------------------------------
Function Set-PCConfigFTP {
	Write-host "`n#####  Configuration FTP  " -ForegroundColor Green
	Info_Log "CONFIG_FTP" "i" "#####  Configuration FTP  "

	$VERS_MINEUR = [int]((gwmi win32_operatingsystem).version -split '\.')[1]
	$VERS_MAJEUR = [int]((gwmi win32_operatingsystem).version -split '\.')[0]
	$VERS_FINALE = "$VERS_MAJEUR.$VERS_MINEUR"

	switch ($VERS_FINALE)
	{
		"6.0" {
			Info_Log "CONF_IIS" "i" "Version d'OS MS Windows 2008"
			Import-Module Servermanager
			Add-WindowsFeature -Name Web-Ftp-Server -IncludeAllSubFeature #Installe le serveur FTP
			Add-WindowsFeature -Name Web-Server                           #Installe le serveur Web
			Add-WindowsFeature -Name Web-Mgmt-Tools -IncludeAllSubFeature #Installe la mngt console
		} "6.1" {
			Info_Log "CONF_IIS" "i" "Version d'OS MS Windows 2008r2"
			Import-Module Servermanager
			Add-WindowsFeature -Name Web-Ftp-Server -IncludeAllSubFeature #Installe le serveur FTP
			Add-WindowsFeature -Name Web-Server                           #Installe le serveur Web
			Add-WindowsFeature -Name Web-Mgmt-Tools -IncludeAllSubFeature #Installe la mngt console
		} "6.2" {
			Info_Log "CONF_IIS" "i" "Version d'OS MS Windows 2012"
			Install-WindowsFeature -Name Web-Ftp-Server -IncludeAllSubFeature #Installe le serveur FTP
			Install-WindowsFeature -Name Web-Server                           #Installe le serveur Web
			Install-WindowsFeature -Name Web-Mgmt-Tools -IncludeAllSubFeature #Installe la mngt console
		} "6.3" {
			Info_Log "CONF_IIS" "i" "Version d'OS MS Windows 2012r2"
			Install-WindowsFeature -Name Web-Ftp-Server -IncludeAllSubFeature #Installe le serveur FTP
			Install-WindowsFeature -Name Web-Server                           #Installe le serveur Web
			Install-WindowsFeature -Name Web-Mgmt-Tools -IncludeAllSubFeature #Installe la mngt console
		} "10.0" {
			Info_Log "CONF_IIS" "i" "Version d'OS MS Windows 2016"
			Install-WindowsFeature -Name Web-Ftp-Server -IncludeAllSubFeature #Installe le serveur FTP
			Install-WindowsFeature -Name Web-Server                           #Installe le serveur Web
			Install-WindowsFeature -Name Web-Mgmt-Tools -IncludeAllSubFeature #Installe la mngt console
		} default {
			Info "CONF_IIS" "a" "La version de Windows est absente de la liste de versions supportees : $VERS_FINALE" }
	}

	#Installation et parametrage du serveur FTP #  Partie commune
	#Importer le module d'administration IIS
	Import-Module WebAdministration

	#Vars
	$ftpSiteTitle = "FTP_591_LEGATO"
	#$target = "C:\Progra~1\Legato\"
	$target = "C:\Program Files\Legato"


	Info_Log "CONFIG_FTP" "i" "Le site aura comme nom : $ftpSiteTitle"

	# CREATE FTP SITE 
	$ftpprotocol = "ftp"
	$bindingInformation = "*:591:"
	$bindings = '@{protocol="' + $ftpprotocol + '";bindingInformation="'+ $bindingInformation +'"}'
	$objects = systeminfo.exe /FO CSV | ConvertFrom-Csv
	$DomainEnv = ($objects.Domain).Split(".")[0]
	$AccessUser = "L0-S0000021@$DomainEnv"

	Info_Log "CONFIG_FTP" "i" "Création du site FTP $ftpSiteTitle"

	# CREATE FOLDER
	if(!(Test-Path "$target")) {
		New-Item $target -itemType directory
	}

	# ADD BASIC AUTHENTICATION AND CONNECTION WITHOUT SSL
	Info_Log "CONFIG_FTP" "a" "Ajout du lien et du port pour le site $ftpSiteTitle"
	New-Item IIS:\Sites\$ftpSiteTitle -bindings $bindings -physicalPath $target -Verbose:$false -Force | Out-Null
	Info_Log "CONFIG_FTP" "a" "Activation de l'authentification et de la connexion avec support SSL pour le site $ftpSiteTitle"
	Set-ItemProperty IIS:\Sites\$ftpSiteTitle -Name ftpServer.security.authentication.basicAuthentication.enabled -Value $true
	Set-ItemProperty IIS:\Sites\$ftpSiteTitle -Name ftpServer.security.ssl.controlChannelPolicy -Value 0
	Set-ItemProperty IIS:\Sites\$ftpSiteTitle -Name ftpServer.security.ssl.dataChannelPolicy -Value 0

	# ADD PERMISSIONS
	Info_Log "CONFIG_FTP" "a" "Ajout des permissions pour le site $ftpSiteTitle"
	Add-WebConfiguration -Filter /System.FtpServer/Security/Authorization -Value (@{AccessType="Allow"; Roles="Administrators, Administrateurs, Admins"; Permissions="Read, Write"}) -PSPath IIS: -Location "$ftpSiteTitle"
	Add-WebConfiguration -Filter /System.FtpServer/Security/Authorization -Value (@{AccessType="Allow"; Users="$AccessUser"; Permissions="Read, Write"}) -PSPath IIS: -Location "$ftpSiteTitle"
	# SET ACCESSRULES TO FOLDER : $target
	$acl = Get-Acl $target
	$AccesRules = New-Object system.security.AccessControl.FileSystemAccessRule("$AccessUser", "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
	$acl.SetAccessRule($AccesRules)
	$acl | Set-Acl $target

	# RESTART FTP SITE
	Restart-WebItem "IIS:\sites\$ftpSiteTitle"
	Info_Log "CONFIG_FTP" "i" "Site FTP créé et redémarré"
}

#-------------------------------
#####  ADD FIREWALL FTP RULES  
#-------------------------------
Function Set-PCFTPFWRules{
	Write-host "`n#####  Ajout regle Firewall FTP  " -ForegroundColor Green
	Info_Log "CONFIG_RULES_FIREWALL" "i" "#####  Ajout regles Firewall FTP  "
	Info_Log "CONFIG_RULES_FIREWALL" "i" "Creation des regles FTP"
	Info_Log "CONFIG_RULES_FIREWALL" "i" "NAME=FTP_TCP_591 - PORT=591 - PROTOCOLE=TCP - DIR=IN - ALLOW"
	Info_Log "CONFIG_RULES_FIREWALL" "i" "NAME=FTP_UDP_591 - PORT=591 - PROTOCOLE=UDP - DIR=IN - ALLOW"
	Info_Log "CONFIG_RULES_FIREWALL" "i" "NAME=FTP_TCP_591 - PORT=591 - PROTOCOLE=TCP - DIR=OUT - ALLOW"
	Info_Log "CONFIG_RULES_FIREWALL" "i" "NAME=FTP_UDP_591 - PORT=591 - PROTOCOLE=UDP - DIR=OUT - ALLOW"

	netsh advfirewall firewall add rule name="FTP_TCP_591" protocol=TCP dir=in  localport=591 action=Allow # Allow IN TCP 591
	netsh advfirewall firewall add rule name="FTP_UDP_591" protocol=UDP dir=in  localport=591 action=Allow # Allow IN UDP 591
	netsh advfirewall firewall add rule name="FTP_TCP_591" protocol=TCP dir=out localport=591 action=Allow # Allow OUT TCP 591
	netsh advfirewall firewall add rule name="FTP_UDP_591" protocol=UDP dir=out localport=591 action=Allow # Allow OUT UDP 591
	Info_Log "CONFIG_RULES_FIREWALL" "i" "Creation des regles FTP effectuee"
}

#-------------------------------
#####  SET SWAP (pagefile.sys)
#-------------------------------
Function Set-PageFile {
	Write-host "`n#####  Configuration SWAP  " -ForegroundColor Green
	Info_Log "CONFIG_SWAP" "i" "#####  Configuration SWAP  "
	<#PARAM(
		[string]$Path = "C:\pagefile.sys",
		[int]$InitialSize = 4096,
		[int]$MaximumSize = 4096
	)#>
	$Path = "D:\pagefile.sys"
	$totalmemory = [Math]::Round((Get-WmiObject -Class win32_computersystem -ComputerName localhost).TotalPhysicalMemory/1Gb)
	$totalswapGB = $totalmemory * 1.5
	$totalswapMB = $totalswapGB * 1024
	Info_Log "CONFIG_SWAP" "a" "Swap preconisée $totalswapGB Gb"
	$totalswapMB = 8192
	$InitialSize = $totalswapMB
	$MaximumSize = $totalswapMB
	$ComputerSystem = $null
	$CurrentPageFile = $null
	$modify = $false

	# Disables automatically managed page file setting first
	$ComputerSystem = Get-WmiObject -Class Win32_ComputerSystem -EnableAllPrivileges
	if ($ComputerSystem.AutomaticManagedPagefile) {
		$ComputerSystem.AutomaticManagedPagefile = $false
		$ComputerSystem.Put()
	}

	$CurrentPageFile = Get-WmiObject -Class Win32_PageFileSetting
	if ($CurrentPageFile.Name -eq $Path) {
		# Keeps the existing page file
		if ($CurrentPageFile.InitialSize -ne $InitialSize) {
			$CurrentPageFile.InitialSize = $InitialSize
			$modify = $true
		}
		if ($CurrentPageFile.MaximumSize -ne $MaximumSize) {
			$CurrentPageFile.MaximumSize = $MaximumSize
			$modify = $true
		}
		if ($modify) { $CurrentPageFile.Put() }
	}
	else {
		# Creates a new page file
		if ( $CurrentPageFile -ne $null)
		{
			$CurrentPageFile.Delete()
		}
		Set-WmiInstance -Class Win32_PageFileSetting -Arguments @{Name=$Path; InitialSize = $InitialSize; MaximumSize = $MaximumSize}
	}
	Info_Log "CONFIG_SWAP" "a" "Swap fixee a 8Gb"
}

#-------------------------------
#####  ADD LOCAL ACCOUNTS 
#-------------------------------
Function Set-PCAddUserSogeti{
	Write-host "`n#####  Création des comptes Admin_Sogeti, AdamMember, Patrol & Patclt  " -ForegroundColor Green
	Info_Log "ADD_USERS_SOGETI" "i" "#####  Création des comptes locaux: Admin_Sogeti & AdamMember"
	$computerName = "$env:computername"
	$fichier = "C:\temp\$computerName-Accounts.csv"
	$List = @{}
	$computer = [ADSI]"WinNT://$computerName,computer"

	Function Get-Password {
		for ($i=0;$i -lt 4;$i++) {
			$min += Get-Random -InputObject "a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z"
		}
		for ($i=0;$i -lt 4;$i++) {
			$maj += Get-Random -InputObject "A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z"
		}
			$nombre = Get-Random -Minimum 1000 -Maximum 9999
		for ($i=0;$i -lt 4;$i++) {
			$caracspec += Get-Random -InputObject "$","!","%","*","_","-","+","=","?","[","]",":","@","&","#","|","(",")","{","}"
		}
		$Pass_Simple = $min+$caracspec+$maj+$nombre
		$length = 12
		for ( $i = 0 ; $i -lt $length ; $i++ ){
			$newpos = (( $i + (Get-Random -Maximum $length -Minimum 0 ))%$length)
			$tmp = $Pass_Simple[$i]
			$Pass_Simple = ($Pass_Simple.Remove($i,1)).Insert($i,$Pass_Simple[$newpos])
			$Pass_Simple = ($Pass_Simple.Remove($newpos,1)).Insert($newpos,$tmp)
		}
		$Pass_Simple
	}

	#Account Sogeti
	$ACCOUNT_NAME_1 = 'Admin_Sogeti'
	$PWD_ACCOUNT_NAME_1 = Get-Password
	$grouplist = $computer.psbase.Children | Where-Object { $_.psbase.schemaclassname -eq 'group' }
	foreach ($Group in $grouplist)
	{
		Try {
			$objgroup = New-Object System.Security.Principal.NTAccount($Group.Name)
			$strSID = $objgroup.Translate([System.Security.Principal.SecurityIdentifier])
			#if($strSID -eq 'S-1-5-32-544') {
				$groupname = $Group.Name
				#$User = $computer.Create("user",$ACCOUNT_NAME_1)
                #$User = Get-localUser -Name $ACCOUNT_NAME_1
                $User = [ADSI]"WinNT://$computerName/$ACCOUNT_NAME_1"
				$User.SetPassword($PWD_ACCOUNT_NAME_1)
                #$User | Set-LocalUser -Password (ConvertTo-SecureString -AsPlainText $PWD_ACCOUNT_NAME_1 -Force)
				#$User.SetInfo()
				#([ADSI]"WinNT://$computerName/$groupname,group").Add("WinNT://$ACCOUNT_NAME_1")
				$user.put("Description","Compte d'administration utilisé par le LOT27")
                #Set-LocalUser -Name $ACCOUNT_NAME_1 -Description "Compte d'administration utilisé par le LOT27"
				$user.setInfo()
				$flag=$User.UserFlags.value -bor 0x10000
				$User.put("userflags",$flag)
				$user.SetInfo()
				$user.put("FullName", "Administrateur Sogeti")
                #Set-LocalUser -Name $ACCOUNT_NAME_1 -FullName "Administrateur Sogeti"
				$user.SetInfo()
			}
		
		Catch {
			Write-Host -Fore 'red' "$($_.Exception.Message)"
		}
	}
	Info_Log "ADD_USERS_SOGETI" "i" "Création du compte Admin_Sogeti effectuée"

	#Account AdamMember
	$ACCOUNT_NAME_2 = 'AdamMember'
	$PWD_ACCOUNT_NAME_2 = Get-Password
	$grouplist = $computer.psbase.Children | Where-Object { $_.psbase.schemaclassname -eq 'group' }
	foreach ($Group in $grouplist)
	{
		Try {
			$objgroup = New-Object System.Security.Principal.NTAccount($Group.Name)
			$strSID = $objgroup.Translate([System.Security.Principal.SecurityIdentifier])
			if($strSID -eq 'S-1-5-32-544')
			{
				$groupname = $Group.Name
				$User = $computer.Create("user",$ACCOUNT_NAME_2)
				$User.SetPassword($PWD_ACCOUNT_NAME_2)
				$User.SetInfo()
				([ADSI]"WinNT://$computerName/$groupname,group").Add("WinNT://$ACCOUNT_NAME_2")
				$user.put("Description","Compte d'administration utilisé par le LOT27")
				$user.setInfo()
				$flag=$User.UserFlags.value -bor 0x10000
				$User.put("userflags",$flag)
				$user.SetInfo()
				$user.put("FullName", "Administrateur Sogeti")
				$user.SetInfo()
			}
		}
		Catch {
			Write-Host -Fore 'red' "$($_.Exception.Message)"
		}
	}
	Info_Log "ADD_USERS_SOGETI" "i" "Création du compte AdamMember effectuée"
	Info_Log "ADD_USERS_SOGETI" "i" "Résumé de la création des comptes locaux"
	Write-Host "-----------------------"
	$ACCOUNT_NAME_1
	$PWD_ACCOUNT_NAME_1
	Write-Host "-----------------------"
	$ACCOUNT_NAME_2
	$PWD_ACCOUNT_NAME_2
	Write-Host "-----------------------"
	Info_Log "ADD_USERS_SOGETI" "i" "Ajout dans le fichier Accounts les comptes créé avec les mots de passe (C:\temp\$env:ComputerName-Accounts.csv)"
	ADD-content -path $fichier -value '"Account","Login Name","Password","Web Site","Comments"'
	ADD-content -path $fichier -value "$env:ComputerName,$ACCOUNT_NAME_1,$PWD_ACCOUNT_NAME_1,,"
	ADD-content -path $fichier -value "$env:ComputerName,$ACCOUNT_NAME_2,$PWD_ACCOUNT_NAME_2,,"
	Info_Log "ADD_USERS_SOGETI" "i" "Création des comptes Admin_Sogeti & AdamMember effectuée"

	# SET SCHEDULED-TASKS
	
	#--------------------------------------------------------------------------------------------------------
	# Creation tache planifiee EVAGD (Quotidienne par défaut ) 
	$Fanion_Directory = "C:\Progra~1\Legato\nsr\fanion"

	Write-host "`n#####  Configuration de la tache EVAGD " -ForegroundColor Green
	Info_Log "CONFIG_Fanion" "a" "Creation de la tache : Pose de Fanion"
	If (!([string]::IsNullOrEmpty($Bkp))){
		$TaskBkp = $Bkp 
	}
	if($TaskBkp -match "Heb"){
		SCHTASKS /Create /S $env:ComputerName /RU "Admin_sogeti" /RP "$PWD_ACCOUNT_NAME_1"  /NP /SC WEEKLY /D SUN /ST "19:00" /RL HIGHEST /TN "POSE_FANION_EVAGD_HEB" /TR "$Fanion_Directory\EVAGD_pose_fanion.bat" /F
		Info_Log "CONFIG_Fanion" "i" "Choix de  la sauvegarde: Hebdomadaire "
	}
	elseif($TaskBkp -match "Men"){
		SCHTASKS /Create /S $env:ComputerName /RU "Admin_sogeti" /RP "$PWD_ACCOUNT_NAME_1"  /NP /SC MONTHLY /MO FIRST /D SUN /ST "19:00" /RL HIGHEST /TN "POSE_FANION_EVAGD_MEN" /TR "$Fanion_Directory\EVAGD_pose_fanion.bat" /F
		SCHTASKS /Create /S $env:ComputerName /RU "Admin_sogeti" /RP "$PWD_ACCOUNT_NAME_1"  /NP /SC MONTHLY /MO SECOND /D SUN /ST "19:00" /RL HIGHEST /TN "POSE_FANION_NO-EVAGD_MEN" /TR "$Fanion_Directory\EVAGD_pose_fanion_pasdesvg.bat" /F
		Info_Log "CONFIG_Fanion" "i" "Choix de  la sauvegarde: Mensuel "
	}
	else {
		SCHTASKS /Create /S $env:ComputerName /RU "Admin_sogeti" /RP "$PWD_ACCOUNT_NAME_1"  /NP /SC DAILY /MO 1 /ST "19:00" /RL HIGHEST /TN "POSE_FANION_EVAGD_QUO" /TR "$Fanion_Directory\EVAGD_pose_fanion.bat" /F
		Info_Log "CONFIG_Fanion" "i" "Choix de  la sauvegarde: Quotidien "
	}
	Info_Log "CONFIG_Fanion" "i" "Configuration de pose de fanion terminée"	   
#--------------------------------------------------------------------------------------------------------
	# Creation tache planifiee REBOOT (WEEKLY /sunday at 02:00 ) 
	Write-host "`n#####  Configuration de la tache de reboot  " -ForegroundColor Green
    Info_Log "SCHTASK" "i" "#####  Configuration de la tache de reboot  "
	SCHTASKS /Create /S $env:ComputerName /RU "Admin_sogeti" /RP "$PWD_ACCOUNT_NAME_1"  /NP /SC WEEKLY /D SUN /ST "02:00" /RL HIGHEST /TN "REBOOT_SYSTEME" /TR "C:\Windows\system32\shutdown.exe -r -f /d p:0:0" /F | Out-Null
    Info_Log "SCHTASK" "a" "Tache de reboot Hebdomadaire mise en place"
	
	$ACCOUNT_NAME_1 = $PWD_ACCOUNT_NAME_1 = $ACCOUNT_NAME_2 = $PWD_ACCOUNT_NAME_2 = $Pass_Simple = $fichier = $null
}

#-------------------------------
#####    SET KMS    
#-------------------------------
Function Set-KMS_Windows {
	Write-host "`n#####  Configuration du KMS Windows  " -ForegroundColor Green
	Info_Log "CONF_KMS" "i" "#####  Configuration du KMS Windows  "
	Set-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform\" -Name "KeyManagementServiceName" -Type String -Value "kms.edf.fr"
	$VERS_MINEUR = [int]((gwmi win32_operatingsystem).version -split '\.')[1]
	$VERS_MAJEUR = [int]((gwmi win32_operatingsystem).version -split '\.')[0]
	$VERS_FINALE = "$VERS_MAJEUR.$VERS_MINEUR"

	switch ($VERS_FINALE){
		"6.0" {
			Info_Log "CONF_KMS" "i" "Version d'OS MS Windows 2008"
			$sku = $((gwmi win32_operatingsystem).OperatingSystemSKU)
			switch ($sku){
				0  {
				Info_Log "CONF_KMS" "a" "Type d'OS inconnu"
				"Undefined";break
				}
				7  {
					Info_Log "CONF_KMS" "i" "Type d'OS : Standard Server Edition"
					$KEY_KMS_EDITION = "TM24T-X9RMF-VWXK6-X8JC9-BFGM2";break
				}
				8  {
					Info_Log "CONF_KMS" "i" "Type d'OS : Datacenter Server Edition"
					$KEY_KMS_EDITION = "7M67G-PC374-GR742-YH8V4-TCBY3";break
				}
				10  {
					Info_Log "CONF_KMS" "i" "Type d'OS : Enterprise Server Edition"
					$KEY_KMS_EDITION = "YQGMW-MPWTJ-34KDK-48M3W-X4Q6V";break
				}
				13  {
					Info_Log "CONF_KMS" "i" "Type d'OS : Standard Server Core Edition"
					$KEY_KMS_EDITION = "TM24T-X9RMF-VWXK6-X8JC9-BFGM2";break
				}
				12  {
					Info_Log "CONF_KMS" "i" "Type d'OS : Datacenter Server Core Edition"
					$KEY_KMS_EDITION = "7M67G-PC374-GR742-YH8V4-TCBY3";break
				}
				14  {
					Info_Log "CONF_KMS" "i" "Type d'OS : Enterprise Server Core Edition"
					$KEY_KMS_EDITION = "YQGMW-MPWTJ-34KDK-48M3W-X4Q6V";break
				}
				default {
					Info_Log "CONF_KMS" "a" "Type d'OS inconnu"
					$KEY_KMS_EDITION = "7M67G-PC374-GR742-YH8V4-TCBY3"
				}
			}
		}
		"6.1" {
			Info_Log "CONF_KMS" "i" "Version d'OS MS Windows 2008r2"
			$sku = $((gwmi win32_operatingsystem).OperatingSystemSKU)
			switch ($sku){
				0  {
					Info_Log "CONF_KMS" "a" "Type d'OS inconnu"
					"Undefined";break
				}
				7  {
					Info_Log "CONF_KMS" "i" "Type d'OS : Standard Server Edition"
					$KEY_KMS_EDITION = "YC6KT-GKW9T-YTKYR-T4X34-R7VHC";break
				}
				8  {
					Info_Log "CONF_KMS" "i" "Type d'OS : Datacenter Server Edition"
					$KEY_KMS_EDITION = "74YFP-3QFB3-KQT8W-PMXWJ-7M648";break
				}
				10  {
					Info_Log "CONF_KMS" "i" "Type d'OS : Enterprise Server Edition"
					$KEY_KMS_EDITION = "489J6-VHDMP-X63PK-3K798-CPX3Y";break
				}
				13  {
					Info_Log "CONF_KMS" "i" "Type d'OS : Standard Server Core Edition"
					$KEY_KMS_EDITION = "YC6KT-GKW9T-YTKYR-T4X34-R7VHC";break
				  }
				12  {
					Info_Log "CONF_KMS" "i" "Type d'OS : Datacenter Server Core Edition"
					$KEY_KMS_EDITION = "74YFP-3QFB3-KQT8W-PMXWJ-7M648";break
				}
				14  {
					Info_Log "CONF_KMS" "i" "Type d'OS : Enterprise Server Core Edition"
					$KEY_KMS_EDITION = "489J6-VHDMP-X63PK-3K798-CPX3Y";break
				}
				default {
					Info_Log "CONF_KMS" "a" "Type d'OS inconnu"
					$KEY_KMS_EDITION = "74YFP-3QFB3-KQT8W-PMXWJ-7M648"
				}
			}
		}
		"6.2" {
			Info_Log "CONF_KMS" "i" "Version d'OS MS Windows 2012"
			$sku = $((gwmi win32_operatingsystem).OperatingSystemSKU)
			switch ($sku){
				0  {
					Info_Log "CONF_KMS" "a" "Type d'OS inconnu"
					"Undefined";break
				}
				7  {
					Info_Log "CONF_KMS" "i" "Type d'OS : Standard Server Edition"
					$KEY_KMS_EDITION = "XC9B7-NBPP2-83J2H-RHMBY-92BT4";break
				}
				8  {
					Info_Log "CONF_KMS" "i" "Type d'OS : Datacenter Server Edition"
					$KEY_KMS_EDITION = "48HP8-DN98B-MYWDG-T2DCC-8W83P";break
				}
				13  {
					Info_Log "CONF_KMS" "i" "Type d'OS : Standard Server Core Edition"
					$KEY_KMS_EDITION = "XC9B7-NBPP2-83J2H-RHMBY-92BT4";break
				}
				12  {
						Info_Log "CONF_KMS" "i" "Type d'OS : Datacenter Server Core Edition"
						$KEY_KMS_EDITION = "48HP8-DN98B-MYWDG-T2DCC-8W83P";break
				}
				default {
					Info_Log "CONF_KMS" "a" "Type d'OS inconnu"
					$KEY_KMS_EDITION = "48HP8-DN98B-MYWDG-T2DCC-8W83P"
				}
			}
		}
		"6.3" {
			Info_Log "CONF_KMS" "i" "Version d'OS MS Windows 2012r2"
			$sku = $((gwmi win32_operatingsystem).OperatingSystemSKU)
			switch ($sku){
				0  {
					Info_Log "CONF_KMS" "a" "Type d'OS inconnu"
					"Undefined";break
				}
				7  {
					Info_Log "CONF_KMS" "i" "Type d'OS : Standard Server Edition"
					$KEY_KMS_EDITION = "D2N9P-3P6X9-2R39C-7RTCD-MDVJX";break
				}
				8  {
					Info_Log "CONF_KMS" "i" "Type d'OS : Datacenter Server Edition"
					$KEY_KMS_EDITION = "W3GGN-FT8W3-Y4M27-J84CP-Q3VJ9";break
				}
				13  {
					Info_Log "CONF_KMS" "i" "Type d'OS : Standard Server Core Edition"
					$KEY_KMS_EDITION = "WC2BQ-8NRM3-FDDYY-2BFGV-KHKQY";break
				}
				12  {
					Info_Log "CONF_KMS" "i" "Type d'OS : Datacenter Server Core Edition"
					$KEY_KMS_EDITION = "W3GGN-FT8W3-Y4M27-J84CP-Q3VJ9";break
				}
				default {
						Info_Log "CONF_KMS" "a" "Type d'OS inconnu"
						$KEY_KMS_EDITION = "W3GGN-FT8W3-Y4M27-J84CP-Q3VJ9"
				}
			}
		}
		"10.0" {
			Info_Log "CONF_KMS" "i" "Version d'OS MS Windows 2016"
			$sku = $((gwmi win32_operatingsystem).OperatingSystemSKU)
			switch ($sku){
				0  {
					Info_Log "CONF_KMS" "a" "Type d'OS inconnu"
					"Undefined";break
				}
				7  {
					Info_Log "CONF_KMS" "i" "Type d'OS : Standard Server Edition"
					$KEY_KMS_EDITION = "WC2BQ-8NRM3-FDDYY-2BFGV-KHKQY";break
				}
				8  {
					Info_Log "CONF_KMS" "i" "Type d'OS : Datacenter Server Edition"
					$KEY_KMS_EDITION = "CB7KF-BWN84-R7R2Y-793K2-8XDDG";break
				}
				13  {
						Info_Log "CONF_KMS" "i" "Type d'OS : Standard Server Core Edition"
						$KEY_KMS_EDITION = "WC2BQ-8NRM3-FDDYY-2BFGV-KHKQY";break
				}
				12  {
					Info_Log "CONF_KMS" "i" "Type d'OS : Datacenter Server Core Edition"
					$KEY_KMS_EDITION = "CB7KF-BWN84-R7R2Y-793K2-8XDDG";break
				}
				default {
					Info_Log "CONF_KMS" "a" "Type d'OS inconnu"
					$KEY_KMS_EDITION = "CB7KF-BWN84-R7R2Y-793K2-8XDDG"
				}
			}
		}
		default {
			 Info "CONF_KMS" "a" "La version de Windows est absente de la liste de versions supportees : $VERS_FINALE" }
		}
	slmgr.vbs //B /upk
	Start-Sleep -s 2
	slmgr.vbs //B /cpky
	Start-Sleep -s 2
	slmgr.vbs //B /ipk $KEY_KMS_EDITION
	Start-Sleep -s 2
	slmgr.vbs //B /skms kms.edf.fr
	Start-Sleep -s 2
	slmgr.vbs //B /ato
	Start-Sleep -s 2
	Info_Log "CONF_KMS" "i" "Configuration du KMS realisee"
	}

#-------------------------------
#####    CHECK LICENSE
#-------------------------------
Function Get-ActivationStatus {
	[CmdletBinding()]
	param(
	[Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
	[string]$DNSHostName = $Env:COMPUTERNAME
	)
	process {
		try {
		$wpa = Get-WmiObject SoftwareLicensingProduct -ComputerName $DNSHostName `
		-Filter "ApplicationID = '55c92734-d682-4d71-983e-d6ec3f16059f'" `
		-Property LicenseStatus -ErrorAction Stop
		} catch {
			$status = New-Object ComponentModel.Win32Exception ($_.Exception.ErrorCode)
			$wpa = $null
		}
		$out = New-Object psobject -Property @{
			ComputerName = $DNSHostName;
			Status = [string]::Empty;
		}
		if ($wpa) {
			:outer foreach($item in $wpa) {
				switch ($item.LicenseStatus) {
					0 {$out.Status = "Sans licence"}
					1 {$out.Status = "Sous licence"; break outer}
					2 {$out.Status = "Période de grÃ¢ce hors cadre"; break outer}
					3 {$out.Status = "Période de grÃ¢ce hors tolérance"; break outer}
					4 {$out.Status = "Période de grÃ¢ce non authentique"; break outer}
					5 {$out.Status = "Notification"; break outer}
					6 {$out.Status = "Période de grÃ¢ce étendue"; break outer}
					default {$out.Status = "Valeur inconnue"}
				}
			}
		} else { $out.Status = $status.Message }
	$out
	}
}

#-------------------------------
#####  ENABLE FIREWALL
#-------------------------------
Function Set-PCEnableFW {
	Write-host "`n#####  Réactivation du firewall selon sécurisation OS (N1/N3)  " -ForegroundColor Green
	Info_Log "REACTIVATION_FIREWALL" "i" "#####  Réactivation du firewall selon sécurisation OS (N1/N3)  "
	$error.clear()
	$SecureLvlKey = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\COMPOSANT\PPI"
	Try{
		If(test-path $SecureLvlKey){
			$SecureValue = (Get-ItemProperty -Path $SecureLvlKey).'Security Level'
			If($SecureValue -eq "N3"){
				Info_Log "REACTIVATION_FIREWALL" "i" "[INFO] - Vérification du firewall avant action"
				netsh advfirewall show allprofiles | ?{$_ -match "state" -or $_ -match "Profile Settings:"}
				netsh advfirewall set allprofiles state on
				Info_Log "REACTIVATION_FIREWALL" "i" "réactivation du firewall effectuée"
				Info_Log "REACTIVATION_FIREWALL" "i" "[INFO] - Vérification du firewall aprés action"
				netsh advfirewall show allprofiles | ?{$_ -match "state" -or $_ -match "Profile Settings:"}
				Info_Log "REACTIVATION_FIREWALL" "a" "[INFO] - réactivation du firewall effectuée"
			}else{
				If($SecureValue -eq "N1"){
					Info_Log "REACTIVATION_FIREWALL" "i" "[INFO] - Vérification du firewall avant action"
					netsh advfirewall show allprofiles | ?{$_ -match "state" -or $_ -match "Profile Settings:"}
					netsh advfirewall set allprofiles state off
					Info_Log "REACTIVATION_FIREWALL" "i" "Désactivation du firewall effectuée"
					Info_Log "REACTIVATION_FIREWALL" "i" "[INFO] - Vérification du firewall aprés action"
					netsh advfirewall show allprofiles | ?{$_ -match "state" -or $_ -match "Profile Settings:"}
					Info_Log "REACTIVATION_FIREWALL" "i" "[INFO] - Désactivation du firewall effectuée"
				}else{
					Info_Log "REACTIVATION_FIREWALL" "e" "Niveau de sécurisation incorrect (N1 ou N3) : $SecureValue"
					$SecureValue = "Niveau de sécurisation incorrect (N1 ou N3) : $SecureValue"
					Return $SecureValue
				}
			}
		}else{
			Info_Log "REACTIVATION_FIREWALL" "e" "Impossible de détecter le niveau de sécurisation (N1 ou N3)"
			$SecureValue = "Impossible de détecter le niveau de sécurisation (N1 ou N3)"
		}
	}Catch {
		#Write-Log -LogFilePath $LogFilePath -level ERROR -Message "Une erreur est survenue. $Error"
		$SecureValue = "ERR_Unexpected_$ERROR"
	}
	Return $SecureValue
	$Error.clear()
}

#-------------------------------
#####  SET ASSETTAG
#-------------------------------
Function Create-logonScript{ 

	if(!(test-path "C:\Windows\Srv\Config\ASSETTAG" -pathtype leaf)) {
		Write-host "`nLe fichier C:\Windows\Srv\Config\ASSETTAG n'a pas ete trouve, il va etre cree. "
		New-item -Path "C:\Windows\Srv\Config\ASSETTAG" -ItemType File -Value $AssetTag -Force -ErrorAction SilentlyContinue
		Write-host "`nCreation effectuee avec la valeur: " $AssetTag
	}else{
		Write-host "`nLe fichier C:\Windows\Srv\Config\ASSETTAG a ete trouve, modification en cours"
		Move-Item -Path "C:\Windows\Srv\Config\ASSETTAG" -Destination "C:\Windows\Srv\Config\ASSETTAG.old" -Force -ErrorAction SilentlyContinue
		New-item -Path "C:\Windows\Srv\Config\ASSETTAG" -ItemType File -Value $AssetTag -Force -ErrorAction SilentlyContinue
		Write-host "`nModification effectuee de l'assettag avec la valeur: "$AssetTag
	}
}

#-------------------------------
#####  Ajout de comptes ds le groupe Admin
#-------------------------------
Function Set-GroupMember{
$objects = systeminfo.exe /FO CSV | ConvertFrom-Csv
$DomainEnv = ($objects.Domain).Split(".")[0]
Add-LocalGroupMember -Group "Administrators" -Member "$DomainEnv\L27-APPSERVERADMINS-SL" -ErrorAction SilentlyContinue
Info_Log "Add-LocalGroupMember" "i" "Ajout de $DomainEnv\L27-APPSERVERADMINS-SL dans le group Administrators"
#-------------------------------
}

Function Set-WsusParam{
# WSUS SET VALUES

#---------------------------------------------
# Infos
	$wsusinfo = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\")
	$targ = $wsusinfo.TargetGroup
	$wu = $wsusinfo.WUServer
	$WsusParam = $wu+"|"+$targ
#---------------------------------------------

switch($Environment) 
{
	{($_ -eq "BACKUP") -or ($_ -eq "DEV") -or ($_ -eq "PREPROD")} { $TARGET = 'SERVEURS_APPL_PRODUCTION1_ISIM2'}
	{($_ -eq "PROD") -or ($_ -eq "RECETTE") -or ($_ -eq "FORM")}  { $TARGET = 'SERVEURS_APPL_PRODUCTION2_ISIM2'}
	{($_ -eq "INTEG") -or ($_ -eq "QUALIF")} { $TARGET = 'SERVEURS_APPL_PILOTE_ISIM2'}
	Default {$TARGET = 'SERVEURS_APPL_PRODUCTION1_ISIM2'}
}
#---------------------------------------------
# SET Regkey TargetGroup value ("HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate) 

$WsusInfoRegkey = "TargetGroup"
$WsusInfoRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$WsusInfoRegkeyValue = $TARGET
$WsusInfoRegType = "String"
$regKeyExists = (Get-Item $WsusInfoRegPath -EA Ignore).Property -contains $WsusInfoRegkey

If (!($regKeyExists -eq $True)){
	New-ItemProperty -Path $WsusInfoRegPath -Name $WsusInfoRegkey -PropertyType $WsusInfoRegType -Value $WsusInfoRegkeyValue
	Write-Host "Wsus TargetGroup regkey added : $WsusInfoRegkeyValue" 
}else{
	Set-Itemproperty -path $WsusInfoRegPath -Name $WsusInfoRegkey -value $WsusInfoRegkeyValue
	Write-Host "Wsus TargetGroup regkey modified : $WsusInfoRegkeyValue"
}
#---------------------------------------------
# WSUS SET TASK

$SchWsus = "*wsus*"
$TasknameWsus = "\param-wsus\TASK_WSUS"
$WsusTrigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 1am
Set-ScheduledTask -TaskName $TasknameWsus -Trigger $WsusTrigger 
Write-Host `n
$WsusParam
(Get-ScheduledTask -TaskName $SchWsus).Triggers
}

function Set-WinrmConfig {

	$ErrorActionPreference = "SilentlyContinue"
	$listener = winrm e winrm/config/listener
	# Creation du certificat dans cert:\LocalMachine\My*
		Write-Host "Creation du certificat..."
		New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation "Cert:\LocalMachine\My"
		$MyCert = (Get-ChildItem -Path cert:\LocalMachine\My* -Recurse -ErrorAction SilentlyContinue|? {$_.Subject -eq "CN=$env:COMPUTERNAME"})
		$thumbprint = $MyCert.Thumbprint | select -Last 1
		$MCert = (Get-ChildItem -Path cert:\LocalMachine\My* -Recurse -ErrorAction SilentlyContinue |Where-Object {$_.Thumbprint -eq $thumbprint})
	#-----------------------------------------------------------------
	<#
	WARNING: Disabling the session configurations does not undo all the changes made by the Enable-PSRemoting or Enable-PSSessionConfiguration cmdlet. You
	 might have to manually undo the changes by following these steps:
		1. Stop and disable the WinRM service.
		2. Delete the listener that accepts requests on any IP address.
			delete a listener with the command,
			winrm delete winrm/config/Listener?Address=*+Transport=HTTP
		3. Disable the firewall exceptions for WS-Management communications.
		4. Restore the value of the LocalAccountTokenFilterPolicy to 0, which restricts remote access to members of the Administrators group on the comput
	er.
	#>

	#Stop-Service WinRM -PassThruSet-Service WinRM -StartupType Disabled -PassThru
	Stop-Service WinRM -Force
	Disable-PSRemoting -Force -ErrorAction SilentlyContinue
	dir wsman:\localhost\listener
	Remove-Item -Path WSMan:\Localhost\listener\listener* -Recurse
	Set-NetFirewallRule -DisplayName 'Windows Remote Management (HTTP-In)' -Enabled False -PassThru | Select-Object -Property DisplayName, Profile, Enabled
	Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system -Name LocalAccountTokenFilterPolicy -Value 0
	#-----------------------------------------------------------------
	#-----------------------------------------------------------------
	# Set the thumbprint value # On associe le certificat au HTTPS
	Set-Item -Path WSMan:\localhost\Service\CertificateThumbprint -Value $thumbprint
	# Create the hashtables of settings to be used.
	$valueset = @{}
	$valueset.add('Hostname',$env:COMPUTERNAME)
	$valueset.add('CertificateThumbprint',$thumbprint)
	$selectorset = @{}
	$selectorset.add('Transport','HTTPS')
	$selectorset.add('Address','*')
	Write-Verbose "Enabling SSL-based remoting"

	try{
		New-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet $selectorset -ValueSet $valueset | Out-Null
		Write-Host "New-WSManInstance | winrm/config/Listener | https | $thumbprint"
	}catch{
		Set-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet $selectorset -ValueSet $valueset | Out-Null
		Write-Host "Set-WSManInstance | winrm/config/Listener | https | $thumbprint"
	} 

	Write-Host "Enable-PSRemoting..."
	Enable-PSRemoting -Force
	Write-Host "Enable-WSManCredSSP..."
	Enable-WSManCredSSP -Role Server -Force #| Out-Null

	Write-Host "Restart WinRM"
	Stop-Service WinRM -Force
	Start-Service WinRM

	# delete CertificateThumbprint value from the config/service
	Write-Host "Suppression du CertificateThumbprint du service"
	winrm set winrm/config/service '@{CertificateThumbprint=""}'
	#-----------------------------------------------------------------

	Write-Host "Ajout des comptes de service (L27-SOGALL-6 et L27-SOGALL-2) au groupe admin"
	Add-LocalGroupMember -Group "Administrators" -Member "$DomainEnv\L27-SOGALL-6" -ErrorAction SilentlyContinue
	Add-LocalGroupMember -Group "Administrators" -Member "$DomainEnv\L27-SOGALL-2" -ErrorAction SilentlyContinue
	Add-LocalGroupMember -Group "Administrateurs" -Member "$DomainEnv\L27-SOGALL-6" -ErrorAction SilentlyContinue
	Add-LocalGroupMember -Group "Administrateurs" -Member "$DomainEnv\L27-SOGALL-6" -ErrorAction SilentlyContinue

	#Check/Comptes de service
	function AdminUser($User) {
		$AdminMembers = net localgroup "Administrators"
		if (!($AdminMembers)){
			$AdminMembers = net localgroup "Administrateurs"
			}if (!($AdminMembers)){$UserStatus = "KO"}
		if ($AdminMembers -match $User){$UserStatus = "OK"
		}else {$UserStatus = "KO"}
		$UserStatus
	}
	$L27SOGALL6 = AdminUser('L27-SOGALL-6')
	$L27SOGALL2 = AdminUser('L27-SOGALL-2')
	winrm enumerate winrm/config/listener
	write-host "SOGALL6 = $L27SOGALL6"
	write-host "SOGALL2 = $L27SOGALL2"
}


#-------------------------------
####### MAIN ##
#-------------------------------

Info_Log "AUTO_SCRIPT" "i" "Lancement du script en mode automatique"
#Start-Sleep -Seconds 5
Launch-PostInstall-init

exit 0
