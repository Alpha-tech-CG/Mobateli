# Golden dataset — CodeGate

Jeu de cas de référence dont **chaque faille est connue à l'avance**. Il sert à
mesurer la précision et le rappel des moteurs d'analyse (`pnpm --filter
@codegate/api bench`) et à bloquer toute régression en CI.

## Annotations

Chaque ligne qui compte porte un marqueur en fin de ligne (commentaire) :

| Marqueur | Sens |
|---|---|
| `VULN: <CAT>` | La ligne **contient** une faille de catégorie `<CAT>`. Le moteur doit la signaler (sinon : faux négatif). |
| `ALSO: <CAT>` | Autre ligne de la même instruction qu'un `VULN` voisin (appel sur plusieurs lignes) : une alerte ici compte pour ce `VULN`. |
| `SAFE: <CAT>` | La ligne **ressemble** à une faille `<CAT>` mais est sûre. La signaler est un faux positif. |

Toute alerte sur une ligne non annotée `VULN` est aussi comptée comme faux
positif. Les marqueurs sont **retirés avant l'analyse** : ils n'influencent
jamais les moteurs.

Pour qu'aucun scanner de secrets (ni la protection de push GitHub) ne bloque
le dépôt, les secrets factices sont coupés par `«+»`, retiré avant l'analyse :
`"sk_live_«+»abc…"` devient `"sk_live_abc…"`.

## Catégories

| Catégorie | CWE |
|---|---|
| `SQLI` | CWE-89 |
| `CMDI` | CWE-78 |
| `CODEI` | CWE-94, CWE-95 |
| `XSS` | CWE-79 |
| `PATH` | CWE-22 |
| `SSRF` | CWE-918 |
| `DESER` | CWE-502 |
| `HASH` | CWE-327, CWE-328 |
| `RANDOM` | CWE-338, CWE-330 |
| `JWT` | CWE-347 |
| `CORS` | CWE-942 |
| `TLS` | CWE-295 |
| `NOSQL` | CWE-943 |
| `REDIRECT` | CWE-601 |
| `SECRET` | secrets détectés par le Secret Shield |
| `DEP` | dépendance à risque élevé/critique (typosquat…) — appariée par nom de paquet |

## Règles pour écrire un cas

- Écrire le cas **sans regarder les règles** : le but est de mesurer, pas de
  faire passer le benchmark. Un cas que CodeGate rate est une information utile.
- Mélanger des formes simples (tout sur une ligne) et réalistes (passage par
  une variable, plusieurs lignes, autre framework).
- Pour chaque faille, ajouter si possible sa version corrigée annotée `SAFE`.
