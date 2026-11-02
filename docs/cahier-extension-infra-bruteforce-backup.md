# CodeGate — Extension sécurité infrastructure, brute force et sauvegardes

**Document d’évolution produit : Modules Infra Shield, BruteForce Shield et Backup Shield**

Version : 1.0  
Date : 2 novembre 2026  
Produit : CodeGate  
Statut : Cahier des charges d’extension

---

## 1. Résumé exécutif

CodeGate évolue d’une plateforme de sécurisation du code généré par IA vers une plateforme de **sécurité continue full-stack**.

Elle couvre désormais :

```text
Code IA  ->  Application  ->  API  ->  Serveur / VPS  ->  Base de données  ->  Sauvegardes  ->  Cloud
```

Les trois nouveaux modules sont :

| Module | Objectif |
|---|---|
| **Infra Shield** | Sécuriser le VPS, les ports, SSH, Docker, firewall et services |
| **BruteForce Shield** | Protéger login, OTP, reset password, API, SSH et accès sensibles |
| **Backup Shield** | Vérifier que les sauvegardes existent, sont chiffrées, intègres, isolées et restaurables |

La promesse produit devient :

> **CodeGate sécurise toute la chaîne créée par le vibe coding : le code IA, l’application, le serveur, la base de données, les accès et les sauvegardes.**

---

## 2. Principes non négociables

CodeGate est une plateforme défensive. Elle ne doit jamais devenir un outil d’attaque non contrôlé.

Règles absolues :

- Aucun scan réseau sans preuve de propriété ou autorisation explicite.
- Aucun test offensif sans compte de test dédié.
- Aucun scan destructif, DoS ou test de charge massif.
- Aucune exfiltration de données.
- Aucun stockage de secrets en clair.
- Aucun affichage de secret dans un rapport.
- Aucune restauration de sauvegarde en production sans confirmation explicite.
- Journalisation complète de chaque action sensible.
- Mode lecture seule par défaut.
- Possibilité d’interrompre un scan à tout moment.

Nmap recommande d’obtenir une autorisation écrite avant de scanner un réseau, car même un scan léger peut être considéré comme intrusif par un administrateur ou un hébergeur. [web:85][web:86]

---

## 3. Module Infra Shield

### 3.1 Objectif

Infra Shield vérifie que le serveur, le VPS, les conteneurs et les services exposés sont correctement configurés.

Il répond aux questions :

- Quels ports sont ouverts ?
- Quels services sont exposés à Internet ?
- SSH est-il correctement sécurisé ?
- Le firewall est-il actif ?
- Docker est-il configuré de manière sûre ?
- Les mises à jour de sécurité sont-elles appliquées ?
- Des services inutiles ou dangereux sont-ils actifs ?

### 3.2 Fonctionnalités

| Fonctionnalité | Description |
|---|---|
| Port Discovery | Détection des ports ouverts et services exposés |
| Service Fingerprinting | Identification des services et versions |
| SSH Audit | Vérification de la configuration SSH |
| Firewall Audit | Contrôle UFW, nftables, iptables et security groups |
| Docker Audit | Analyse des conteneurs, images, secrets et permissions |
| Patch Level | Vérification des mises à jour de sécurité |
| Service Audit | Détection des services inutiles ou dangereux |
| TLS Audit | Analyse des certificats et configurations HTTPS |
| Cloud Audit | Vérification des règles cloud et permissions |
| Security Score | Score global du serveur |

### 3.3 Contrôles SSH

CodeGate vérifie :

- Authentification par mot de passe désactivée.
- Connexion root directe désactivée.
- Clés SSH fortes et autorisées.
- Fail2ban ou équivalent actif.
- Rate limiting SSH.
- Journalisation des connexions.
- Alerte après tentatives répétées.
- Port SSH non exposé inutilement.

Exemple de configuration recommandée :

```text
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
LoginGraceTime 30
AllowUsers deploy
```

### 3.4 Contrôles firewall

CodeGate vérifie :

- Firewall actif.
- Seuls les ports nécessaires sont ouverts.
- Base de données non exposée publiquement.
- Redis non exposé publiquement.
- Docker API non exposée publiquement.
- Règles entrantes minimales.
- Journalisation des connexions refusées.

Configuration type :

```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable
```

Ports qui ne doivent jamais être publics par défaut :

| Port | Service | Risque |
|---|---|---|
| 3306 | MySQL | Accès direct à la base |
| 5432 | PostgreSQL | Accès direct à la base |
| 6379 | Redis | Lecture, modification ou suppression du cache |
| 27017 | MongoDB | Accès direct à la base |
| 2375 | Docker API | Prise de contrôle du serveur |
| 9200 | Elasticsearch | Exposition de données |
| 8080 | Admin / debug | Accès à des interfaces internes |

### 3.5 Contrôles Docker

CodeGate vérifie :

- Conteneurs exécutés sans root.
- Docker socket non monté dans les conteneurs.
- Secrets absents des images.
- Images à jour et scannées.
- Ports inutiles non publiés.
- Capacités Linux limitées.
- Filesystem en lecture seule lorsque possible.
- Réseaux Docker isolés.
- Limites CPU, RAM et processus.

### 3.6 Outils recommandés

| Besoin | Outil | Rôle |
|---|---|---|
| Scan de ports | Nmap, RustScan | Découverte des ports et services |
| Fingerprinting | Nmap | Identification des services et versions |
| Audit SSH | ssh-audit | Analyse de la configuration SSH |
| Firewall | UFW, nftables, iptables | Vérification des règles |
| Docker | Docker Bench for Security, Trivy | Audit conteneurs et images |
| Vulnerabilités OS | Trivy, Grype | Détection des CVE |
| Configuration serveur | Lynis, OpenSCAP | Audit de durcissement |
| Benchmarks | CIS Benchmarks | Référentiel de configuration sécurisée |
| TLS | testssl.sh, SSL Labs | Analyse HTTPS |
| Cloud | Checkov, tfsec | Analyse Terraform et configuration cloud |

Les CIS Benchmarks fournissent des recommandations de durcissement pour les systèmes, bases de données, conteneurs, services cloud et équipements réseau. [web:83][web:84][web:91]

---

## 4. Module BruteForce Shield

### 4.1 Objectif

BruteForce Shield protège les points d’authentification et les accès sensibles contre :

- Brute force de mots de passe.
- Password spraying.
- Credential stuffing.
- Brute force OTP.
- Brute force de tokens.
- Énumération d’utilisateurs.
- Brute force SSH.
- Brute force de base de données.

La vulnérabilité correspondante est CWE-307 : restriction insuffisante des tentatives d’authentification excessives. [web:98][web:100]

### 4.2 Points à protéger

| Surface | Exemples |
|---|---|
| Authentification | Login, inscription, session |
| Récupération | Reset password, magic link |
| MFA | OTP, TOTP, code de récupération |
| API | Tokens, clés API, webhooks |
| Administration | Panel admin, endpoints internes |
| Infrastructure | SSH, VPS, base de données |

### 4.3 Fonctionnalités

| Fonctionnalité | Description |
|---|---|
| Rate Limiting Audit | Détection des endpoints sans limite de tentatives |
| Login Testing | Test du blocage après échecs répétés |
| OTP Testing | Vérification de l’expiration et du nombre de tentatives |
| Reset Password Testing | Test des tokens, expiration et réutilisation |
| Account Enumeration Test | Détection des réponses révélant l’existence d’un compte |
| Distributed Attack Simulation | Test avec plusieurs identités simulées |
| SSH Brute Force Audit | Vérification de Fail2ban et de la politique SSH |
| API Abuse Detection | Analyse du rate limiting par clé API et utilisateur |
| Alerting | Notification Slack, email ou webhook |
| Progressive Lockout | Recommandation de blocage progressif |

### 4.4 Politique recommandée

| Endpoint | Tentatives | Fenêtre | Action |
|---|---:|---|---|
| Login | 5 échecs | 10 minutes | Délai progressif + CAPTCHA |
| OTP | 3 échecs | 5 minutes | Code invalidé + blocage temporaire |
| Reset password | 3 demandes | 15 minutes | Blocage temporaire |
| Inscription | 5 demandes | 1 heure | CAPTCHA / vérification email |
| API sensible | 100 requêtes | 1 minute | Réponse 429 |
| SSH | 3 échecs | 10 minutes | Blocage IP via Fail2ban |

OWASP recommande un compteur d’échecs associé au compte, et non uniquement à l’adresse IP, afin de résister aux attaques distribuées. [web:99] OWASP WSTG décrit également comment tester les mécanismes de verrouillage faibles, notamment avec des comptes de test autorisés et des tentatives échouées répétées. [web:104][web:109]

### 4.5 Réponses API sécurisées

Ne jamais révéler si un email existe :

```json
{
  "error": "invalid_credentials",
  "message": "Email ou mot de passe incorrect."
}
```

Après plusieurs échecs :

```json
{
  "error": "too_many_attempts",
  "message": "Trop de tentatives. Réessayez dans 5 minutes.",
  "retry_after": 300
}
```

Pour un OTP invalide ou expiré :

```json
{
  "error": "otp_invalidated",
  "message": "Trop de tentatives. Un nouveau code a été envoyé.",
  "retry_after": 300
}
```

### 4.6 Outils recommandés

| Besoin | Outil | Rôle |
|---|---|---|
| Rate limiting backend | rate-limiter-flexible, Redis | Limiter les tentatives |
| WAF / protection edge | Cloudflare, AWS WAF, Vercel Firewall | Bloquer les abus avant l’application |
| Test brute force web | OWASP ZAP, ffuf, Burp Suite | Tests contrôlés sur staging |
| Test OTP | Scripts custom CodeGate | Vérifier expiration et tentatives |
| Protection SSH | Fail2ban, CrowdSec | Bloquer les IP malveillantes |
| Détection d’abus | CrowdSec, Fail2ban | Analyse des logs et blocage |
| CAPTCHA | Cloudflare Turnstile, hCaptcha | Défi après échecs répétés |
| Monitoring | Grafana, Prometheus, Sentry | Alertes et métriques |

### 4.7 Exemple de politique JSON

```json
{
  "endpoint": "/api/auth/login",
  "max_attempts": 5,
  "window_seconds": 600,
  "lockout_seconds": 300,
  "strategy": "progressive",
  "apply_to": ["ip", "account", "device"],
  "captcha_after": 3,
  "alert_after": 5
}
```

---

## 5. Module Backup Shield

### 5.1 Objectif

Backup Shield vérifie que les sauvegardes automatiques sont :

- Présentes.
- Automatiques.
- Complètes.
- Chiffrées.
- Intègres.
- Isolées du serveur production.
- Non modifiables pendant une période définie.
- Réellement restaurables.

Une sauvegarde non testée n’est pas une sauvegarde fiable.

### 5.2 Distinction hash / chiffrement

| Mécanisme | Rôle | Exemple |
|---|---|---|
| Chiffrement | Rendre la sauvegarde illisible sans clé | AES-256-GCM |
| Hash | Vérifier que le fichier n’a pas été modifié | SHA-256 |
| Signature numérique | Prouver l’origine et l’intégrité | Ed25519, RSA |
| Immutable storage | Empêcher modification ou suppression | S3 Object Lock, WORM |
| Test de restauration | Prouver que la sauvegarde fonctionne | Restore en environnement isolé |

Le hash ne chiffre pas : il vérifie l’intégrité. Le chiffrement protège la confidentialité. Les deux sont nécessaires.

NIST recommande de maintenir l’intégrité et la disponibilité des sauvegardes grâce au hachage, au chiffrement et aux supports non modifiables. [web:113]

### 5.3 Fonctionnalités

| Fonctionnalité | Description |
|---|---|
| Backup Discovery | Détection des cron, systemd timers, scripts et jobs cloud |
| Coverage Check | Vérifie base de données, fichiers, uploads et configurations |
| Encryption Check | Vérifie AES-256, TLS, algorithme et gestion des clés |
| Key Isolation Check | Vérifie que la clé n’est pas sur le même VPS que le backup |
| Integrity Check | Vérifie SHA-256, checksum et signature |
| Retention Check | Vérifie la durée de conservation et le nombre de versions |
| Immutability Check | Vérifie Object Lock, WORM ou équivalent |
| Isolation Check | Vérifie que le backup est hors du serveur production |
| Restore Test | Teste la restauration dans un environnement isolé |
| Recovery Score | Note la capacité réelle de récupération |
| Ransomware Readiness | Évalue la résistance à une attaque ransomware |

### 5.4 Contrôles de sécurité des sauvegardes

| Contrôle | Exigence |
|---|---|
| Chiffrement au repos | AES-256-GCM ou équivalent moderne |
| Chiffrement en transit | TLS 1.2 minimum, TLS 1.3 recommandé |
| Clé de chiffrement | Stockée dans un KMS ou gestionnaire de secrets |
| Séparation des clés | Clé jamais stockée sur le même VPS que le backup |
| Intégrité | SHA-256 obligatoire |
| Signature | Recommandée pour prouver l’origine |
| Rétention | 30 jours minimum, 90 jours recommandé |
| Immutabilité | 7 à 30 jours minimum |
| Test de restauration | Hebdomadaire ou mensuel |
| Accès | Moindre privilège, MFA, compte séparé |
| Stockage | Externalisé, versionné et isolé |

### 5.5 Exemple de rapport

```text
Rapport Backup Shield — monapp.com
Date : 02/11/2026

Sauvegarde PostgreSQL quotidienne
- Dernière exécution : 02/11/2026 à 03:00
- Chiffrement au repos : AES-256-GCM : OK
- Chiffrement en transit : TLS 1.3 : OK
- Clé de chiffrement : KMS externe : OK
- Intégrité SHA-256 : OK
- Signature numérique : OK
- Stockage : S3 versionné + Object Lock : OK
- Isolation : Compte cloud séparé : OK
- Rétention : 90 jours : OK
- Test de restauration : OK en 4 min 12 s
- Statut : PRÊTE POUR RECOVERY

Sauvegarde des fichiers uploads
- Dernière exécution : 02/11/2026 à 03:30
- Chiffrement : OK
- Intégrité : OK
- Test de restauration : Non effectué
- Statut : ATTENTION

Score global : 86/100
```

### 5.6 Exemple de vérification JSON

```json
{
  "backup_postgres_daily": {
    "exists": true,
    "last_run": "2026-11-02T03:00:00Z",
    "encrypted_at_rest": true,
    "encryption_algorithm": "AES-256-GCM",
    "encrypted_in_transit": true,
    "key_location": "external_kms",
    "integrity_hash": "sha256",
    "integrity_verified": true,
    "immutable": true,
    "retention_days": 90,
    "restore_tested": true,
    "last_restore_test": "2026-10-30T10:00:00Z",
    "restore_duration_seconds": 252,
    "status": "healthy"
  }
}
```

### 5.7 Outils recommandés

| Besoin | Outil | Rôle |
|---|---|---|
| Backup PostgreSQL | pgBackRest, Barman, pg_dump | Sauvegarde et restauration |
| Backup MySQL | Percona XtraBackup, mysqldump | Sauvegarde et restauration |
| Backup MongoDB | mongodump, Percona Backup for MongoDB | Sauvegarde et restauration |
| Chiffrement fichier | age, GnuPG, rclone crypt | Chiffrement avant stockage |
| Chiffrement disque | LUKS | Chiffrement du volume |
| Transfert sécurisé | rclone, restic, SFTP, HTTPS | Transfert chiffré |
| Stockage immuable | S3 Object Lock, Backblaze B2, Wasabi | Protection anti-suppression |
| Intégrité | SHA-256, minisign, age | Hash et signature |
| Test restauration | Docker Compose, scripts CodeGate | Restauration isolée |
| KMS | AWS KMS, Vault, GCP KMS | Gestion des clés |
| Monitoring | Prometheus, Grafana, Healthchecks.io | Alertes de backup |

NIST souligne que les sauvegardes doivent être protégées contre la compromission, l’exfiltration, le ransomware et la suppression malveillante, notamment par chiffrement, contrôle d’accès et immutabilité. [web:121][web:123]

---

## 6. Architecture globale

```text
[CodeGate Console]
        |
        +--> Code Review Engine
        +--> App Scan Engine
        +--> Infra Shield Agent
        +--> BruteForce Shield Engine
        +--> Backup Shield Agent
        |
        v
[Risk Decision Engine]
        |
        +--> Score de sécurité
        +--> Vulnérabilités
        +--> Recommandations
        +--> Correctifs
        |
        v
[Linear / Jira Ticket]
        |
        v
[Compliance Evidence Pack]
```

### 6.1 Architecture Infra Shield

```text
[VPS / Docker / Cloud]
          |
          v
[CodeGate Agent]
          |
          +--> Ports et services
          +--> SSH
          +--> Firewall
          +--> Docker
          +--> Mises à jour
          +--> Logs
          |
          v
[External Network Scanner]
          |
          +--> Scan ciblé autorisé
          +--> TLS
          +--> Services publics
          |
          v
[Risk Engine]
```

### 6.2 Architecture BruteForce Shield

```text
[Application / VPS]
          |
          v
[Request Analyzer]
          |
          +--> IP
          +--> Compte
          +--> Appareil
          +--> Endpoint
          +--> Fréquence
          |
          v
[BruteForce Policy Engine]
          |
          +--> Rate limiting
          +--> Délai progressif
          +--> CAPTCHA
          +--> Verrouillage temporaire
          +--> MFA challenge
          +--> Alerte
          |
          v
[Audit Log + Ticket]
```

### 6.3 Architecture Backup Shield

```text
[VPS / Docker / Database]
          |
          v
[Backup Job]
          |
          +--> Dump base de données
          +--> Archive fichiers
          +--> Chiffrement AES-256-GCM
          +--> Hash SHA-256
          +--> Signature numérique
          |
          v
[Secure Transfer]
          |
          v
[External Encrypted Storage]
          |
          +--> Versioning
          +--> Object Lock / WORM
          +--> Accès restreint
          |
          v
[Integrity Verifier]
          |
          v
[Restore Test Sandbox]
          |
          v
[CodeGate Report]
```

---

## 7. Modèle de données

```text
Server
- id
- organization_id
- name
- provider
- ip_address
- environment
- ssh_port
- agent_installed
- security_score
- last_scan_at

PortFinding
- id
- server_id
- port
- protocol
- service
- exposure
- risk_level
- recommendation

SshAudit
- id
- server_id
- password_auth_enabled
- root_login_enabled
- fail2ban_enabled
- key_auth_enabled
- last_audit_at

ContainerFinding
- id
- server_id
- container_name
- runs_as_root
- docker_socket_mounted
- exposed_ports
- image_age_days
- risk_level

BruteForcePolicy
- id
- organization_id
- endpoint
- max_attempts
- window_seconds
- lockout_seconds
- strategy
- captcha_after
- alert_after

BruteForceTest
- id
- target_id
- test_type
- attempts
- blocked_after
- result
- evidence
- created_at

BackupJob
- id
- server_id
- name
- type
- frequency
- last_run_at
- encrypted_at_rest
- encryption_algorithm
- encrypted_in_transit
- key_location
- integrity_hash
- immutable
- retention_days
- status

BackupRestoreTest
- id
- backup_job_id
- started_at
- completed_at
- duration_seconds
- result
- restored_tables
- restored_records
- evidence_url
```

---

## 8. API proposée

| Méthode | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/servers/connect` | Connecter un VPS via agent |
| GET | `/api/v1/servers` | Liste des serveurs |
| GET | `/api/v1/servers/:id/security-score` | Score de sécurité |
| POST | `/api/v1/servers/:id/scan` | Lancer un scan autorisé |
| GET | `/api/v1/servers/:id/ports` | Liste des ports détectés |
| GET | `/api/v1/servers/:id/ssh-audit` | Audit SSH |
| GET | `/api/v1/servers/:id/docker-audit` | Audit Docker |
| POST | `/api/v1/bruteforce/policies` | Créer une politique anti-brute force |
| POST | `/api/v1/bruteforce/tests` | Lancer un test autorisé |
| GET | `/api/v1/bruteforce/tests/:id` | Résultat du test |
| GET | `/api/v1/backups` | Liste des sauvegardes |
| GET | `/api/v1/backups/:id` | Détail d’une sauvegarde |
| POST | `/api/v1/backups/:id/verify` | Vérifier intégrité et chiffrement |
| POST | `/api/v1/backups/:id/restore-test` | Lancer un test de restauration |
| GET | `/api/v1/reports/infrastructure` | Rapport infrastructure |
| GET | `/api/v1/reports/backup` | Rapport sauvegardes |

---

## 9. User stories

### US01 — Scan serveur autorisé

> En tant qu’administrateur, je veux connecter mon VPS à CodeGate afin de détecter les ports et services dangereux.

Critères d’acceptation :

- L’utilisateur prouve la propriété du serveur.
- L’agent CodeGate est installé.
- Le scan est limité au serveur déclaré.
- Les ports critiques sont identifiés.
- Chaque finding contient une recommandation.

### US02 — Audit SSH

> En tant que responsable technique, je veux vérifier que SSH est sécurisé afin d’éviter une prise de contrôle du serveur.

Critères d’acceptation :

- CodeGate détecte l’authentification par mot de passe.
- CodeGate détecte la connexion root directe.
- CodeGate vérifie Fail2ban.
- CodeGate propose les corrections exactes.

### US03 — Test brute force login

> En tant que développeur, je veux vérifier que mon endpoint de login résiste aux tentatives répétées.

Critères d’acceptation :

- Le test utilise uniquement un compte de test.
- Le test est exécuté sur staging ou avec autorisation explicite.
- Le nombre de tentatives avant blocage est mesuré.
- Le résultat indique si la protection est par IP, compte ou appareil.
- Un rapport clair est généré.

### US04 — Test OTP

> En tant que responsable sécurité, je veux vérifier que mon OTP ne peut pas être deviné.

Critères d’acceptation :

- Le code expire correctement.
- Le nombre de tentatives est limité.
- Le code ne peut pas être réutilisé.
- Le blocage est déclenché après échecs répétés.
- L’utilisateur reçoit une alerte.

### US05 — Vérification des sauvegardes

> En tant que fondateur, je veux savoir si mes sauvegardes sont réellement récupérables en cas d’incident.

Critères d’acceptation :

- CodeGate détecte les jobs de sauvegarde.
- Il vérifie le chiffrement au repos et en transit.
- Il vérifie l’emplacement de la clé.
- Il vérifie le hash et l’intégrité.
- Il vérifie l’isolation et l’immutabilité.
- Il propose un test de restauration.

### US06 — Test de restauration

> En tant qu’administrateur, je veux tester la restauration d’une sauvegarde sans toucher à la production.

Critères d’acceptation :

- La restauration se fait dans un environnement isolé.
- La production n’est jamais modifiée.
- La durée de restauration est mesurée.
- Le résultat indique si la base est exploitable.
- Un rapport est généré.

---

## 10. Règles de sécurité et conformité

### 10.1 Autorisation

Avant tout scan réseau ou test offensif :

- Preuve de propriété du domaine ou du serveur.
- Agent installé OU validation DNS / fichier.
- Périmètre écrit.
- Fenêtre horaire définie.
- Types de tests autorisés.
- Limite de requêtes.
- Environnement cible : staging ou production.
- Confirmation explicite pour la production.

### 10.2 Données

- Aucun secret affiché en clair.
- Aucun dump de base de données stocké inutilement.
- Aucune donnée personnelle extraite.
- Masquage automatique dans les rapports.
- Rétention limitée des preuves.
- Suppression sur demande.
- Hébergement UE par défaut.

### 10.3 Conformité

Le module doit produire des preuves utiles pour :

- ISO 27001.
- SOC 2.
- NIS2.
- RGPD.
- Audits clients.
- Questionnaires de sécurité.

---

## 11. Plan d’implémentation

### Phase 1 — Infra Shield : 3 semaines

| Semaine | Livrable |
|---|---|
| 1 | Agent VPS, connexion serveur, modèle de données |
| 2 | Audit SSH, firewall, ports, services, Docker |
| 3 | Score serveur, rapport, recommandations et correctifs |

### Phase 2 — BruteForce Shield : 3 semaines

| Semaine | Livrable |
|---|---|
| 1 | Détection des endpoints sensibles et politiques |
| 2 | Tests login, OTP, reset password et API |
| 3 | Alertes, rapports, recommandations et intégration Linear |

### Phase 3 — Backup Shield : 3 semaines

| Semaine | Livrable |
|---|---|
| 1 | Détection des jobs de sauvegarde et couverture |
| 2 | Chiffrement, hash, intégrité, rétention et immutabilité |
| 3 | Test de restauration, score de récupération et rapports |

---

## 12. Indicateurs de succès

| Indicateur | Objectif |
|---|---|
| Serveurs connectés par organisation | 1 à 10 |
| Vulnérabilités critiques détectées par serveur | Suivi mensuel |
| Taux de faux positifs | Inférieur à 15 % |
| Politiques brute force conformes | Supérieur à 90 % |
| Sauvegardes chiffrées | 100 % |
| Sauvegardes testées par restauration | 100 % des sauvegardes critiques |
| Temps moyen de restauration | Mesuré et affiché |
| Temps de détection d’un backup manquant | Moins de 24 heures |

---

## 13. Risques et parades

| Risque | Impact | Parade |
|---|---|---|
| Scan non autorisé | Problème légal / hébergeur | Preuve de propriété obligatoire |
| Scan trop agressif | Indisponibilité | Rate limiting, scan ciblé, staging par défaut |
| Faux positifs | Perte de confiance | Mode observation, preuve claire, validation humaine |
| Accès trop large au VPS | Compromission | Agent minimal, permissions limitées, révocable |
| Stockage de secrets | Fuite | KMS, chiffrement, masquage, absence de logs sensibles |
| Test de restauration dangereux | Écrasement production | Sandbox obligatoire |
| Backup accessible par l’attaquant | Perte totale | Isolation, immutabilité, clé séparée |
| Trop d’alertes | Fatigue utilisateur | Priorisation et alertes uniquement sur risques réels |

---

## 14. Conclusion produit

Avec ces trois modules, CodeGate ne se limite plus à vérifier du code généré par IA.

Il devient une plateforme de défense continue :

- **Code Review** : le code IA est analysé avant fusion.
- **App Scan** : l’application est testée avant déploiement.
- **BruteForce Shield** : les accès sont protégés contre les attaques automatisées.
- **Infra Shield** : le VPS, Docker et les services sont durcis.
- **Backup Shield** : les données sont réellement récupérables en cas d’incident.
- **Compliance Pack** : les preuves sont disponibles pour les audits.

La phrase produit à retenir :

> **CodeGate protège votre application avant, pendant et après le déploiement : code, accès, serveur, base de données et sauvegardes.**
