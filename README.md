# dodofinance-sentinel

Moniteur externe du domaine `dodofinance.io` : DNS multi-vantage + Certificate
Transparency + RDAP. Tourne dans GitHub Actions (schedule 5 min), **hors** de
l'infrastructure surveillée, et alerte par des canaux indépendants du domaine
(push ntfy + email direct). **Alerte seule : aucune action automatique.**

## Ce qui est surveillé

| Check | Source | Détecte |
|---|---|---|
| A apex, NS, CAA, MX, CNAME www | 4 résolveurs publics + les 3 autoritatifs Gandi en direct | zone altérée, empoisonnement de cache |
| DS DNSSEC | résolveurs publics + registre .io en direct | dégradation/substitution DNSSEC |
| Délégation NS | registre .io en direct (RD=0) | hijack registrar |
| Statuts + registrar + NS | RDAP | transfert de domaine, verrou levé |
| Nouveaux certificats | crt.sh | cert frauduleux (couvre aussi le hijack BGP) |
| NotAfter du cert le plus récent | crt.sh | panne de renouvellement (Traefik / PAT Gandi / GitHub Pages) |
| Expiration PAT Gandi | date statique `baseline.json` | panne HTTPS à venir |

Un renouvellement Let's Encrypt légitime (émetteur + SAN attendus) part en
notification INFO ; tout le reste est CRITICAL (push urgent + email + job en
échec → notification GitHub native en second canal). Throttle : une même
anomalie ne ré-alerte qu'une fois par heure. Heartbeat hebdomadaire (preuve de
vie + maintient le cron GitHub actif).

## Configuration

Secrets du repo (`Settings → Secrets and variables → Actions`) :

- `NTFY_TOPIC` — topic ntfy.sh secret (chaîne aléatoire longue). S'abonner au
  même topic dans l'app ntfy sur téléphone. Sans ce secret, le moniteur tourne
  en mode log-only (les CRITICAL font quand même échouer le job → email GitHub).
- `ALERT_EMAIL` — adresse email directe pour les CRITICAL (hors dodofinance.io).

`baseline.json` = l'état attendu. Toute modification légitime de l'infra
(changement d'IP, de MX, rotation DNSSEC, nouveau PAT Gandi) doit être reportée
ici, sinon le moniteur crie. C'est voulu.

## Source de vérité

Ce repo est déployé depuis le repo principal privé (`sentinel/` +
`scripts/deploy-sentinel.sh`). Ne pas éditer ici directement, à l'exception de
`state/` (committé par le workflow lui-même).
