# [AE337] Post-install des serveurs (RHEL/AIX/Windows)

Le cas d'usage permet de proceder à la post-installation des serveurs. Les principales taches sont, dans l'ordre d'execution:
- ajouter le serveur à l'inventaire Tower,
- (facultatif) installer Caccia sur des Unix non standard,
- jouer les scripts OS présent dans le repo "post-install",
- effectuer un premier reboot
- installer les softwares nécessaires (via AE310),
- changer les mots de passe par défaut (via AE352),
- déployer les scripts d'exploitation (via AE366),
- faire un reboot final.

## Prérequis et dépendances

Les scripts de post-install doivent etre présent dans le repo "post-install".
Les cas d'usages dont la post-install dépend doivent etre présent dans Tower.

## Usage

Variables d'entrées:
- post_install_assettag: Asset tag du serveur (ex: ISRV0xxxxxx)
- post_install_caccia_password: Mot de passe Caccia
- post_install_environment: Environnement du serveur (ex: INTEG)
- post_install_hostname: Hostname du serveur (ex: pcyyyxxx)
- post_install_network_area: Zone réseau (ex: espace_groupe)
- post_install_os: (UNIX|WINDOWS) OS du serveur
- post_install_osi: OSI du serveur (ex: OSC)
- post_install_provider: Provider du serveur (CONSER
- post_install_site: (PCY|NOE) Site du serveur
- post_install_trigram: Trigramme du serveur (ex: OI2)
- (windows only) post_install_domain: Domaine du serveur windows
- (windows only) post_install_win_appid: AppID du serveur windows
- (windows only) post_install_win_bkp_freq: Frequence de backup du serveur windows
- (windows only) post_install_win_net_ips: Liste d'IPs du serveur windows
- (windows only) post_install_win_net_names: Liste de nom des NICs du serveur windows
- (windows only) post_install_win_type_appro: Type d'appro du serveur windows
- use_case_environment: (DEV|PRD) environnement d'execution du cas d'usage.
- use_case_report_email: liste de mails (comma separated) qui recevront le rapport d'execution.