#!/usr/bin/env python3
"""dodofinance-sentinel — moniteur DNS + Certificate Transparency HORS infra.

Item 1 de la doctrine « confiance client » (cf. SECURITY.md du repo principal) :
détecter en minutes un détournement du domaine (hijack registrar, empoisonnement
DNS, zone LiveDNS altérée, certificat frauduleux) et alerter par des canaux
INDÉPENDANTS du domaine surveillé. ALERTE SEULE, aucune action automatique.

Tourne dans GitHub Actions (repo public dédié, schedule */5 min). Vérifie :
  1. Zone DNS vue par 4 résolveurs publics + les 3 autoritatifs Gandi en direct
     (A apex, NS, CAA, MX, CNAME www) contre la baseline.
  2. DS DNSSEC via résolveurs publics ET en direct au registre .io (vérité de
     la délégation, insensible à un cache empoisonné).
  3. Délégation NS au registre .io en direct.
  4. RDAP : registrar, verrou transfert, NS côté registre, DNSSEC signé.
  5. crt.sh : tout nouveau certificat → INFO si émetteur/SAN attendus
     (renouvellement LE normal), CRITICAL sinon. + Renouvellement en retard
     (NotAfter du cert le plus récent < N jours) — couvre l'apex que le runner
     ne peut PAS joindre en TLS (allowlist L3 sur la VM).
  6. Expiration du PAT Gandi (date statique dans baseline.json — le jeton
     lui-même n'est JAMAIS stocké ici : repo public).

Alertes : ntfy.sh (topic secret NTFY_TOPIC) ; CRITICAL ajoute un email direct
(X-Email → ALERT_EMAIL, adresse hors dodofinance.io) et fait échouer le job
(exit 1) → notification GitHub native en 2e canal. Throttle 60 min par anomalie.
Heartbeat hebdo (preuve de vie + garde le cron GitHub actif).
"""

from __future__ import annotations

import datetime as dt
import json
import os
import sys
import time
from pathlib import Path

import dns.flags
import dns.message
import dns.query
import dns.rdatatype
import dns.resolver
import requests

ROOT = Path(__file__).resolve().parent
STATE_PATH = ROOT / "state" / "state.json"

BOOTSTRAP_RESOLVER = "8.8.8.8"  # uniquement pour résoudre les IP des serveurs à interroger

PUBLIC_RESOLVERS = {
    "google": "8.8.8.8",
    "cloudflare": "1.1.1.1",
    "quad9": "9.9.9.9",
    "opendns": "208.67.222.222",
}

SEV_CRITICAL = "CRITICAL"
SEV_WARNING = "WARNING"
SEV_INFO = "INFO"


# ---------------------------------------------------------------- utilitaires

def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def load_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default


def norm(value: str) -> str:
    """Normalise un enregistrement pour comparaison (casse, point final)."""
    return " ".join(str(value).lower().rstrip(".").split())


def norm_set(values) -> set[str]:
    return {norm(v) for v in values}


class Vantage:
    """Un point d'observation DNS (résolveur public ou serveur autoritatif)."""

    def __init__(self, name: str, ip: str):
        self.name = name
        self.resolver = dns.resolver.Resolver(configure=False)
        self.resolver.nameservers = [ip]
        self.resolver.timeout = 4
        self.resolver.lifetime = 8

    def query(self, qname: str, rdtype: str) -> set[str]:
        """Retourne l'ensemble normalisé des rdata, {} si NXDOMAIN/NoAnswer."""
        try:
            answer = self.resolver.resolve(qname, rdtype)
            return {norm(r.to_text()) for r in answer}
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return set()


def resolve_ips(qname: str) -> list[str]:
    res = dns.resolver.Resolver(configure=False)
    res.nameservers = [BOOTSTRAP_RESOLVER]
    res.timeout = 4
    res.lifetime = 8
    return [r.to_text() for r in res.resolve(qname, "A")]


def query_direct(server_ip: str, qname: str, rdtype: str) -> tuple[set[str], set[str]]:
    """Requête NON récursive directe (RD=0). Retourne (answer, authority)."""
    q = dns.message.make_query(qname, rdtype)
    q.flags &= ~dns.flags.RD
    resp = dns.query.udp(q, server_ip, timeout=6)
    answer, authority = set(), set()
    for section, bucket in ((resp.answer, answer), (resp.authority, authority)):
        for rrset in section:
            if rrset.rdtype == dns.rdatatype.from_text(rdtype):
                bucket.update(norm(r.to_text()) for r in rrset)
    return answer, authority


# ---------------------------------------------------------------- le moniteur

class Sentinel:
    def __init__(self):
        self.baseline = load_json(ROOT / "baseline.json", None)
        if not self.baseline:
            print("FATAL: baseline.json introuvable ou invalide")
            sys.exit(2)
        self.domain = self.baseline["domain"]
        self.state = load_json(STATE_PATH, {})
        self.state.setdefault("alerts", {})
        self.findings: list[tuple[str, str, str]] = []  # (severity, key, message)

    # ------------------------------------------------------------- findings

    def add(self, severity: str, key: str, message: str):
        self.findings.append((severity, key, message))
        print(f"[{severity}] {key}: {message}")

    # ------------------------------------------------------------ checks DNS

    def check_zone_from_vantages(self):
        exp = self.baseline["records"]
        vantages: list[Vantage] = []
        for name, ip in PUBLIC_RESOLVERS.items():
            vantages.append(Vantage(f"resolver:{name}", ip))
        for ns_name in self.baseline["authoritative_ns"]:
            try:
                ip = resolve_ips(ns_name)[0]
                vantages.append(Vantage(f"auth:{ns_name}", ip))
            except Exception as e:  # noqa: BLE001
                self.add(SEV_WARNING, f"auth-unreachable:{ns_name}",
                         f"Serveur autoritatif {ns_name} non résolu : {e}")

        public_failures = 0
        for v in vantages:
            is_public = v.name.startswith("resolver:")
            try:
                checks = [
                    ("A apex", self.domain, "A", norm_set(exp["apex_a"])),
                    ("NS zone", self.domain, "NS", norm_set(self.baseline["authoritative_ns"])),
                    ("CAA", self.domain, "CAA", norm_set(exp["caa"])),
                    ("MX", self.domain, "MX", norm_set(exp["mx"])),
                    ("CNAME www", f"www.{self.domain}", "CNAME", {norm(exp["www_cname"])}),
                ]
                for label, qname, rdtype, expected in checks:
                    got = v.query(qname, rdtype)
                    if got != expected:
                        self.add(SEV_CRITICAL, f"dns:{label}:{v.name}",
                                 f"{label} inattendu vu par {v.name} : {sorted(got) or 'VIDE'} "
                                 f"(attendu {sorted(expected)})")
                # DS : servi par le registre, interrogeable via résolveurs seulement
                if is_public:
                    got_ds = v.query(self.domain, "DS")
                    if got_ds != norm_set(exp["ds"]):
                        self.add(SEV_CRITICAL, f"dns:DS:{v.name}",
                                 f"DS inattendu vu par {v.name} : {sorted(got_ds) or 'ABSENT'} "
                                 f"(attendu {sorted(norm_set(exp['ds']))})")
            except Exception as e:  # noqa: BLE001
                if is_public:
                    public_failures += 1
                self.add(SEV_WARNING, f"vantage-error:{v.name}",
                         f"Point d'observation {v.name} injoignable : {e}")

        if public_failures == len(PUBLIC_RESOLVERS):
            self.add(SEV_CRITICAL, "dns:all-resolvers-down",
                     "AUCUN résolveur public ne répond — réseau runner ou domaine hors ligne")

    def check_parent_registry(self):
        """Vérité au registre .io : délégation NS + DS, en direct (RD=0)."""
        try:
            tld_ns = resolve_ips(self.baseline["parent_ns"])
        except Exception as e:  # noqa: BLE001
            self.add(SEV_WARNING, "parent:bootstrap",
                     f"Impossible de résoudre {self.baseline['parent_ns']} : {e}")
            return
        try:
            answer, authority = query_direct(tld_ns[0], self.domain, "NS")
            delegation = answer or authority
            if delegation != norm_set(self.baseline["authoritative_ns"]):
                self.add(SEV_CRITICAL, "parent:delegation",
                         f"Délégation NS au registre .io : {sorted(delegation)} "
                         f"(attendu {sorted(norm_set(self.baseline['authoritative_ns']))})")
            ds_answer, _ = query_direct(tld_ns[0], self.domain, "DS")
            if ds_answer != norm_set(self.baseline["records"]["ds"]):
                self.add(SEV_CRITICAL, "parent:ds",
                         f"DS au registre .io : {sorted(ds_answer) or 'ABSENT'} "
                         f"(attendu {sorted(norm_set(self.baseline['records']['ds']))})")
        except Exception as e:  # noqa: BLE001
            self.add(SEV_WARNING, "parent:query", f"Interrogation du registre .io en échec : {e}")

    # ----------------------------------------------------------------- RDAP

    def _flaky_source_failed(self, source: str, error: str, threshold: int = 6):
        """Source externe flaky (RDAP, crt.sh) : WARNING seulement après
        `threshold` échecs CONSÉCUTIFS (~30 min à la cadence 5 min)."""
        streaks = self.state.setdefault("fail_streaks", {})
        streaks[source] = streaks.get(source, 0) + 1
        msg = f"{source} injoignable ({streaks[source]}e échec consécutif) : {error}"
        if streaks[source] >= threshold:
            self.add(SEV_WARNING, f"{source}:down", msg)
        else:
            print(f"[transient] {msg}")

    def _flaky_source_ok(self, source: str):
        self.state.setdefault("fail_streaks", {}).pop(source, None)

    def check_rdap(self):
        exp = self.baseline["rdap"]
        data = None
        errors = []
        for url in (f"https://rdap.identitydigital.services/rdap/domain/{self.domain}",
                    f"https://rdap.org/domain/{self.domain}"):
            try:
                r = requests.get(url, headers={"Accept": "application/rdap+json"}, timeout=20)
                r.raise_for_status()
                data = r.json()
                break
            except Exception as e:  # noqa: BLE001
                errors.append(f"{url} → {e}")
        if data is None:
            self._flaky_source_failed("rdap", " ; ".join(errors))
            return
        self._flaky_source_ok("rdap")

        status = [s.lower() for s in data.get("status", [])]
        for expected_status in exp["expect_status"]:
            if expected_status not in status:
                self.add(SEV_CRITICAL, f"rdap:status:{expected_status}",
                         f"Statut registre « {expected_status} » ABSENT (statuts : {status}) — "
                         "verrou transfert levé ou transfert en cours ?")

        registrar = ""
        for ent in data.get("entities", []):
            if "registrar" in ent.get("roles", []):
                for item in ent.get("vcardArray", [None, []])[1]:
                    if item[0] == "fn":
                        registrar = item[3].lower()
        if exp["registrar_contains"] not in registrar:
            self.add(SEV_CRITICAL, "rdap:registrar",
                     f"Registrar inattendu au registre : « {registrar} » "
                     f"(attendu contenant « {exp['registrar_contains']} ») — TRANSFERT DE DOMAINE ?")

        registry_ns = {norm(ns.get("ldhName", "")) for ns in data.get("nameservers", [])}
        if registry_ns and registry_ns != norm_set(self.baseline["authoritative_ns"]):
            self.add(SEV_CRITICAL, "rdap:nameservers",
                     f"NS côté registre (RDAP) : {sorted(registry_ns)} "
                     f"(attendu {sorted(norm_set(self.baseline['authoritative_ns']))})")

        secure = data.get("secureDNS", {})
        if not secure.get("delegationSigned", False):
            self.add(SEV_CRITICAL, "rdap:dnssec",
                     "RDAP : délégation NON signée (DNSSEC désactivé au registre ?)")
        else:
            rdap_ds = {norm(f"{d.get('keyTag')} {d.get('algorithm')} {d.get('digestType')} {d.get('digest')}")
                       for d in secure.get("dsData", [])}
            if rdap_ds and rdap_ds != norm_set(self.baseline["records"]["ds"]):
                self.add(SEV_CRITICAL, "rdap:ds",
                         f"DS côté registre (RDAP) : {sorted(rdap_ds)} "
                         f"(attendu {sorted(norm_set(self.baseline['records']['ds']))})")

    # ---------------------------------------------------- Certificate Transparency

    def check_ct(self):
        exp = self.baseline["ct"]
        entries: dict[int, dict] = {}
        for q in (self.domain, f"%.{self.domain}"):
            data, last_error = None, None
            for attempt in range(2):  # crt.sh est notoirement flaky → 1 retry
                try:
                    r = requests.get("https://crt.sh/",
                                     params={"q": q, "output": "json"}, timeout=30)
                    r.raise_for_status()
                    data = r.json()
                    break
                except Exception as e:  # noqa: BLE001
                    last_error = e
                    time.sleep(3)
            if data is None:
                self._flaky_source_failed("crt.sh", f"({q}) {last_error}")
                return  # pas de conclusion sans données complètes
            for e in data:
                entries[int(e["id"])] = e
        self._flaky_source_ok("crt.sh")

        if not entries:
            return

        expected_names = norm_set(exp["expected_names"])
        expected_issuers = [i.lower() for i in exp["expected_issuers"]]

        last_id = self.state.get("ct_last_id")
        max_id = max(entries)
        if last_id is None:
            # Première exécution : on prend l'existant comme acquis, sans alerter.
            print(f"[init] crt.sh : baseline posée à l'entrée {max_id} ({len(entries)} certs historiques)")
        else:
            for cert_id in sorted(i for i in entries if i > last_id):
                e = entries[cert_id]
                names = norm_set(e.get("name_value", "").split("\n"))
                issuer = e.get("issuer_name", "").lower()
                issuer_ok = any(x in issuer for x in expected_issuers)
                names_ok = names <= expected_names
                desc = (f"crt.sh #{cert_id} · SAN {sorted(names)} · émetteur {e.get('issuer_name')} "
                        f"· loggé {e.get('entry_timestamp')}")
                if issuer_ok and names_ok:
                    self.add(SEV_INFO, f"ct:renewal:{cert_id}", f"Certificat attendu (renouvellement) — {desc}")
                else:
                    self.add(SEV_CRITICAL, f"ct:unexpected:{cert_id}",
                             f"CERTIFICAT INATTENDU dans les logs CT — {desc}")
        self.state["ct_last_id"] = max_id

        # Renouvellement en retard : NotAfter du cert le plus récent par nom attendu.
        # (Le runner ne peut PAS joindre l'apex en TLS : allowlist L3 sur la VM.)
        warn_days = self.baseline["cert_renewal_warn_days"]
        for name in expected_names:
            newest = None
            for e in entries.values():
                if name in norm_set(e.get("name_value", "").split("\n")):
                    na = dt.datetime.fromisoformat(e["not_after"]).replace(tzinfo=dt.timezone.utc)
                    newest = na if newest is None or na > newest else newest
            if newest is None:
                continue
            days_left = (newest - now_utc()).days
            if days_left < 0:
                self.add(SEV_CRITICAL, f"cert:expired:{name}",
                         f"Le cert le plus récent pour {name} est EXPIRÉ depuis {-days_left} j "
                         "et aucun successeur n'apparaît dans les logs CT")
            elif days_left < warn_days:
                self.add(SEV_CRITICAL, f"cert:renewal-late:{name}",
                         f"Renouvellement en retard pour {name} : le cert le plus récent expire "
                         f"dans {days_left} j et aucun successeur dans les logs CT "
                         "(panne Traefik/PAT Gandi ou GitHub Pages ?)")

    # ------------------------------------------------------------ PAT Gandi

    def check_bundle_integrity(self):
        """Item 5 (niveau 1) - integrite du bundle frontend SERVI.

        Compare ce que https://dodofinance.io sert (index.html + assets +
        sw.js...) au manifeste SIGNE publie au deploiement (integrity.json,
        genere par scripts/integrity-snapshot.py depuis le poste de dev - la
        cle de release ne touche JAMAIS la VM). Verifie d'abord la signature
        Ed25519 avec la pubkey EPINGLEE dans baseline.json (jamais celle du
        fichier). Divergence = bundle modifie hors deploiement legitime =
        possible compromission ACTIVE (un JS piege peut exfiltrer les cles
        utilisateur a la connexion) -> CRITICAL.

        Tant que l'allowlist L3 de la VM bloque le runner GitHub, le fetch
        echoue au niveau connexion -> le check se met en veille (note, pas
        d'alerte) et s'armera tout seul a l'ouverture publique. Un deploiement
        frontend legitime SANS re-snapshot fait crier ce check - c'est voulu
        (meme doctrine que la baseline DNS) : relancer integrity-snapshot.py
        + deploy-sentinel.sh apres chaque deploiement frontend.
        """
        integrity_path = ROOT / "integrity.json"
        pubkey_b64 = self.baseline.get("release_pubkey_b64")
        if not integrity_path.exists() or not pubkey_b64:
            print("[note] integrity.json / release_pubkey_b64 absents - check bundle desactive")
            return

        import base64
        import hashlib
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        except ImportError:
            self.add(SEV_WARNING, "bundle:no-cryptography",
                     "cryptography absent des requirements - check d'integrite du bundle inoperant")
            return

        doc = load_json(integrity_path, None)
        if not doc or "payload" not in doc or "signature_b64" not in doc:
            self.add(SEV_WARNING, "bundle:bad-manifest", "integrity.json illisible/incomplet")
            return

        # 1. Signature du manifeste (pubkey epinglee baseline - anti-faux manifeste)
        canonical = json.dumps(doc["payload"], sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(pubkey_b64)).verify(
                base64.b64decode(doc["signature_b64"]), canonical,
            )
        except Exception:
            self.add(SEV_CRITICAL, "bundle:bad-signature",
                     "Signature du manifeste d'integrite INVALIDE - manifeste altere ou mauvaise cle")
            return

        base_url = doc["payload"].get("base_url", f"https://{self.domain}")
        files = doc["payload"].get("files", {})

        # 2. Joignabilite (allowlist L3 -> veille silencieuse)
        try:
            r0 = requests.get(base_url + "/", timeout=15)
            r0.raise_for_status()
        except Exception as e:
            print(f"[note] app injoignable depuis le runner ({e}) - check bundle en veille (allowlist)")
            return

        # 3. Comparaison servi vs manifeste
        mismatches = []
        for path, expected in sorted(files.items()):
            try:
                content = r0.content if path == "/" else requests.get(base_url + path, timeout=15).content
            except Exception:
                mismatches.append(f"{path} (injoignable)")
                continue
            if hashlib.sha256(content).hexdigest() != expected:
                mismatches.append(path)
        if mismatches:
            self.add(SEV_CRITICAL, "bundle:mismatch",
                     f"BUNDLE SERVI != MANIFESTE SIGNE ({len(mismatches)} fichier(s) : "
                     f"{', '.join(mismatches[:5])}) - si deploiement recent : relancer "
                     "integrity-snapshot.py + deploy-sentinel.sh ; SINON possible compromission active")
        else:
            print(f"[ok] bundle servi conforme au manifeste signe ({len(files)} fichiers)")

    def check_bootstrap_files(self):
        """Epinglage des fichiers du SERVEUR A (bootstrap) — item 5 niveau 2,
        dernier morceau de N2-3.

        A est l'ANCRE de confiance : le SW verificateur qu'il sert ne peut pas
        se verifier lui-meme. Ce check compare les fichiers SERVIS par A aux
        hashes figes dans baseline.json["bootstrap"] (poses par
        scripts/pin-bootstrap.py apres chaque redeploiement legitime de A).
        Divergence -> CRITICAL : modification de l'ancre (compromission de A,
        hijack DNS vers un faux A, ou redeploiement legitime sans re-pin).
        A est PUBLIC (pas d'allowlist) -> le check est arme en permanence.
        """
        import hashlib
        boot = self.baseline.get("bootstrap")
        if not boot or not boot.get("files"):
            print("[note] baseline sans section bootstrap - check A desactive "
                  "(lancer scripts/pin-bootstrap.py)")
            return
        origin = boot.get("origin", f"https://{self.domain}")
        mismatches = []
        fetch_errors = []
        for path, expected in sorted(boot["files"].items()):
            try:
                # Redirections refusees : suivre un 301 = hasher un AUTRE
                # serveur (lecon de l'incident snapshot du 2026-07-21).
                r = requests.get(origin + path, timeout=15, allow_redirects=False)
                if r.status_code != 200:
                    fetch_errors.append(f"{path} (HTTP {r.status_code})")
                    continue
            except Exception as e:  # noqa: BLE001
                fetch_errors.append(f"{path} ({e})")
                continue
            if hashlib.sha256(r.content).hexdigest() != expected:
                mismatches.append(path)
        if mismatches:
            self.add(SEV_CRITICAL, "bootstrap:mismatch",
                     f"FICHIER(S) DU SERVEUR A MODIFIES ({', '.join(mismatches)}) - "
                     "si redeploiement recent de A : relancer pin-bootstrap.py + "
                     "deploy-sentinel.sh ; SINON compromission de l'ANCRE (A/DNS/CA) "
                     "- traiter en incident immediatement")
            self._flaky_source_ok("bootstrap-fetch")
        elif fetch_errors:
            # A injoignable = app down pour tout le monde -> seuil court.
            self._flaky_source_failed("bootstrap-fetch", ", ".join(fetch_errors), threshold=3)
        else:
            self._flaky_source_ok("bootstrap-fetch")
            print(f"[ok] serveur A conforme aux hashes epingles ({len(boot['files'])} fichiers)")

    def check_pat_expiry(self):
        expiry = self.baseline.get("gandi_pat_expiry")
        if not expiry:
            print("[note] gandi_pat_expiry non renseigné dans baseline.json — check désactivé")
            return
        days_left = (dt.date.fromisoformat(expiry) - now_utc().date()).days
        if days_left < 0:
            self.add(SEV_CRITICAL, "pat:expired",
                     f"PAT Gandi EXPIRÉ depuis {-days_left} j — le renouvellement des certs va échouer")
        elif days_left <= 14:
            self.add(SEV_WARNING, f"pat:expiry:{expiry}",
                     f"PAT Gandi expire dans {days_left} j ({expiry}) — le régénérer + màj .env VM "
                     "+ `docker compose up -d traefik` + màj baseline.json")

    # ------------------------------------------------------------- alerting

    def notify(self, title: str, message: str, priority: str, tags: str, email: bool):
        topic = os.environ.get("NTFY_TOPIC", "").strip()
        if not topic:
            print(f"[no-ntfy] {title} — {message}")
            return
        headers = {"Title": title, "Priority": priority, "Tags": tags}
        alert_email = os.environ.get("ALERT_EMAIL", "").strip()
        if email and alert_email:
            headers["X-Email"] = alert_email
        try:
            requests.post(f"https://ntfy.sh/{topic}", data=message.encode("utf-8"),
                          headers=headers, timeout=10)
        except Exception as e:  # noqa: BLE001
            print(f"[ntfy-error] {e}")

    def dispatch_alerts(self) -> bool:
        """Envoie les alertes (throttlées), purge les anomalies résolues.
        Retourne True s'il y a au moins un CRITICAL."""
        throttle = dt.timedelta(minutes=self.baseline.get("alert_throttle_minutes", 60))
        alerts_state: dict = self.state["alerts"]
        active_keys = set()
        has_critical = False

        for severity, key, message in self.findings:
            active_keys.add(key)
            if severity == SEV_CRITICAL:
                has_critical = True
            last = alerts_state.get(key)
            if last and now_utc() - dt.datetime.fromisoformat(last) < throttle:
                continue  # déjà alerté récemment
            if severity == SEV_CRITICAL:
                self.notify(f"🚨 {self.domain} — anomalie critique", message,
                            "urgent", "rotating_light", email=True)
            elif severity == SEV_WARNING:
                self.notify(f"⚠ {self.domain} — avertissement", message, "high", "warning", email=False)
            else:
                self.notify(f"{self.domain} — info", message, "default", "information_source", email=False)
            alerts_state[key] = now_utc().isoformat()

        # anomalies disparues → on nettoie (permet une ré-alerte si ça revient)
        for key in [k for k in alerts_state if k not in active_keys]:
            del alerts_state[key]
        return has_critical

    def heartbeat(self):
        last = self.state.get("last_heartbeat")
        if last and now_utc() - dt.datetime.fromisoformat(last) < dt.timedelta(days=7):
            return
        crit = sum(1 for s, _, _ in self.findings if s == SEV_CRITICAL)
        warn = sum(1 for s, _, _ in self.findings if s == SEV_WARNING)
        self.notify(f"💓 sentinel {self.domain}",
                    f"Preuve de vie hebdomadaire — {crit} critique(s), {warn} avertissement(s). "
                    "Le moniteur tourne.", "min", "green_heart", email=False)
        self.state["last_heartbeat"] = now_utc().isoformat()

    # ------------------------------------------------------------------ run

    def run(self) -> int:
        print(f"=== sentinel {self.domain} — {now_utc().isoformat()} ===")
        self.check_zone_from_vantages()
        self.check_parent_registry()
        self.check_rdap()
        self.check_ct()
        self.check_bundle_integrity()
        self.check_bootstrap_files()
        self.check_pat_expiry()
        has_critical = self.dispatch_alerts()
        self.heartbeat()

        STATE_PATH.parent.mkdir(exist_ok=True)
        STATE_PATH.write_text(json.dumps(self.state, indent=2, sort_keys=True) + "\n",
                              encoding="utf-8")
        if not self.findings:
            print("OK — aucune anomalie")
        return 1 if has_critical else 0


if __name__ == "__main__":
    sys.exit(Sentinel().run())
