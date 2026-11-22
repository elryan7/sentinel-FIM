# sentinel-fim

Petit moniteur d'intégrité de fichiers (FIM) en Python, **sans dépendance**, pour détecter des modifications suspectes sur un serveur, un site web ou un dossier de configuration.

Il enregistre une empreinte de référence (la *baseline*) puis signale tout fichier **ajouté, supprimé ou modifié** : contenu (SHA-256), permissions, propriétaire/groupe, cible des liens symboliques.

## Installation

```bash
git clone https://github.com/elryan7/sentinel-fim.git
cd sentinel-fim
python3 fim.py --help      # Python 3.9+
```

## Utilisation

```bash
# 1. Créer la baseline d'un dossier sain
python3 fim.py init /etc/nginx -b /root/nginx.baseline.json

# 2. Vérifier plus tard
python3 fim.py check /etc/nginx -b /root/nginx.baseline.json
```

Exemple de sortie :

```
[~] modifié   nginx.conf (contenu)
[+] ajouté    conf.d/backdoor.conf
[-] supprimé  snippets/ssl.conf

3 changement(s) : 1 ajout(s), 1 suppression(s), 1 modification(s).
```

| Option | Rôle |
|---|---|
| `-b, --baseline` | Fichier baseline (défaut : `.fim-baseline.json`) |
| `-e, --exclude` | Motif à ignorer, répétable : `-e '*.log' -e 'cache/*'` |
| `--json` | Sortie JSON (pour SIEM ou scripts) |
| `--update` | Met la baseline à jour après le rapport (après une modification légitime) |

**Codes de sortie :** `0` rien à signaler · `1` changements détectés · `2` erreur.

## Protéger la baseline (signature HMAC)

Un attaquant qui modifie vos fichiers peut aussi modifier la baseline. Pour s'en prémunir, signez-la avec une clé secrète :

```bash
export FIM_KEY='une-longue-phrase-secrète'
python3 fim.py init /var/www -b /root/www.baseline.json
python3 fim.py check /var/www -b /root/www.baseline.json   # refuse une baseline altérée
```

Si `FIM_KEY` est définie, une baseline non signée est refusée (empêche son remplacement par une version sans signature).

## Automatiser avec cron

```cron
0 * * * * FIM_KEY=... python3 /opt/sentinel-fim/fim.py check /var/www -b /root/www.baseline.json || logger -t fim "changements détectés"
```

## Limites (à connaître)

- Détection **a posteriori** : l'outil signale, il ne bloque rien.
- Un attaquant root qui a accès à la clé `FIM_KEY` peut recréer une baseline valide : gardez la clé et la baseline **hors de la machine surveillée** (stockage en lecture seule, autre serveur).
- Ne surveille que les fichiers réguliers et les liens symboliques (pas les sockets, périphériques, ni les attributs étendus/ACL).
- Pour une surveillance en temps réel à grande échelle, regardez des outils comme AIDE, Tripwire ou Wazuh. sentinel-fim vise la simplicité et la lisibilité.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## Licence

MIT, voir [LICENSE](LICENSE).
