# Tester CodeGate sur tes vrais repos (via tunnel)

But : faire analyser de vraies pull requests GitHub par CodeGate qui tourne en
local, exposé par un tunnel HTTPS. ~20 minutes.

## Prérequis (déjà en place)

- Postgres + Redis en Docker (`docker compose -f infra/docker/docker-compose.yml up -d`)
- Migrations appliquées, API (:4000) + worker + tunnel démarrés par l'assistant
- Une organisation CodeGate (créée à l'inscription — voir étape 4)

## 1. Récupérer l'URL publique du tunnel

L'assistant démarre ngrok ; l'URL ressemble à `https://xxxx.ngrok-free.app`.
On l'appellera `TUNNEL`. Le webhook GitHub pointera sur `TUNNEL/webhooks/github`.

## 2. Créer la GitHub App

GitHub → **Settings → Developer settings → GitHub Apps → New GitHub App**.

- **Nom** : CodeGate (Dev) — unique sur GitHub
- **Homepage URL** : `TUNNEL`
- **Callback URL** : `TUNNEL/api/v1/integrations/github/callback`
  - coche **Request user authorization (OAuth) during installation**
    (CodeGate vérifie ainsi que ton compte GitHub a bien accès à l’installation)
- **Webhook → Active** : coché
  - **Webhook URL** : `TUNNEL/webhooks/github`
  - **Webhook secret** : choisis une valeur (ex. générée ci-dessous) → ce sera `GITHUB_WEBHOOK_SECRET`
- **Permissions du dépôt** :
  - **Pull requests** : Read & write (commentaire)
  - **Checks** : Read & write (statut CodeGate)
  - **Contents** : Read-only (lecture du diff)
  - **Metadata** : Read-only (obligatoire)
- **Subscribe to events** : **Pull request**, **Installation target** (optionnel)
- **Where can this app be installed?** : Only on this account
- Crée l'app, puis :
  - Note l'**App ID**, le **slug** (l'URL publique `github.com/apps/<slug>`) et le **Client ID**
  - **Generate a new client secret** → `GITHUB_CLIENT_SECRET`
  - **Generate a private key** → télécharge le `.pem`

Secret webhook (si besoin) :

```bash
node -e "console.log(require('crypto').randomBytes(24).toString('hex'))"
```

## 3. Renseigner le `.env`

Dans `D:\codegate\.env` :

```
GITHUB_APP_ID=<ton App ID>
GITHUB_WEBHOOK_SECRET=<le secret saisi dans l'app>
GITHUB_APP_PRIVATE_KEY=<clé PEM sur une seule ligne, voir ci-dessous>
GITHUB_APP_SLUG=<slug de l'app>
GITHUB_CLIENT_ID=<Client ID>
GITHUB_CLIENT_SECRET=<client secret>
PUBLIC_API_URL=TUNNEL
```

La clé privée PEM est multi-lignes ; convertis-la en une seule ligne (avec des
`\n`) pour le `.env` :

```bash
node -e "console.log('GITHUB_APP_PRIVATE_KEY=' + JSON.stringify(require('fs').readFileSync('CHEMIN/vers/ta-cle.pem','utf8')).slice(1,-1))"
```

Copie la ligne produite dans `.env`. (La config déséchappe les `\n`.)

L'API en `tsx watch` redémarre et recharge le `.env` au prochain changement de
fichier — l'assistant peut la relancer proprement.

## 4. Créer ton organisation CodeGate

Via le dashboard (`http://localhost:3000` → page de connexion → inscription) ou
en API :

```bash
curl -s -X POST http://127.0.0.1:4000/api/v1/auth/signup -H "content-type: application/json" \
  -d '{"email":"toi@exemple.com","password":"mot-de-passe-12+","name":"Toi","organizationName":"Mon Org"}'
```

> Tant qu'il n'existe **qu'une seule** organisation, CodeGate associe
> automatiquement toute nouvelle installation GitHub à celle-ci (pratique en
> dev). En production, un flux de connexion explicite remplacerait ce
> raccourci.

## 5. Connecter GitHub depuis CodeGate + ouvrir une PR

- Dashboard → **Intégrations → Connecter GitHub** (owner ou admin).
- GitHub demande d'installer l'app sur un ou plusieurs repos, puis d'autoriser
  CodeGate à vérifier ton identité. Tu reviens sur **Intégrations** avec
  « GitHub connecté » et tes repos sont importés.
- CodeGate n'accepte la liaison que si **ton compte GitHub a accès à
  l'installation** (vérifié auprès de GitHub) ; une installation déjà liée à une
  autre organisation n'est jamais déplacée.
- Ouvre/mets à jour une **pull request** sur un des repos.

> En développement, tant qu'il n'existe **qu'une seule** organisation, une
> installation reçue par webhook lui est encore liée automatiquement.

## 6. Observer

- Sur la PR : un **check « CodeGate »** apparaît + un **commentaire** structuré
  (secrets, dépendances, problèmes, décision).
- Dans le dashboard : **Pull requests** liste la PR avec son score et son statut ;
  le détail montre findings/secrets/dépendances.
- Journal d'audit : `pr.opened` → `pr.analyzed` → `pr.feedback_posted`.

## Dépannage

- **Rien ne se passe** : vérifie dans *GitHub App → Advanced → Recent Deliveries*
  que le webhook renvoie 202. 401 = secret qui ne correspond pas. 503 =
  `GITHUB_WEBHOOK_SECRET` non défini côté API.
- **PR analysée mais pas de commentaire/check** : permissions Pull requests/Checks
  manquantes, ou `GITHUB_APP_ID`/`GITHUB_APP_PRIVATE_KEY` absents (le diff et le
  retour GitHub nécessitent un token d'installation).
- **« unknown installation — skipped »** : l’installation n’est liée à aucune organisation → utilise **Intégrations → Connecter GitHub**.
- **Retour « Lien expiré ou invalide »** : le lien de connexion dure 15 min ; relance le bouton.
- **Retour « n’a pas accès à cette installation »** : le compte GitHub connecté ne voit pas l’installation (autre compte, ou OAuth non coché dans l’app).
- **L'URL ngrok change** à chaque redémarrage du tunnel → mets à jour la Webhook
  URL de l'app en conséquence (ou garde le tunnel ouvert).
