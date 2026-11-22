#!/usr/bin/env python3
"""sentinel-fim : moniteur d'intégrité de fichiers (usage défensif).

Crée une empreinte de référence (SHA-256, permissions, propriétaire, liens
symboliques) d'une arborescence, puis détecte les fichiers ajoutés, supprimés
ou modifiés. Bibliothèque standard uniquement.

Codes de sortie : 0 = rien à signaler, 1 = changements détectés, 2 = erreur.
"""
import argparse
import fnmatch
import hashlib
import hmac
import json
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

VERSION = "1.0.0"
DEFAULT_BASELINE = ".fim-baseline.json"
CHUNK = 1024 * 1024
LABELS = {
    "type": "type", "sha256": "contenu", "target": "cible du lien",
    "mode": "permissions", "uid": "propriétaire", "gid": "groupe",
}


class FimError(Exception):
    """Erreur d'utilisation ou baseline invalide."""


# ---------- Calcul des empreintes ----------
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def is_excluded(rel, patterns):
    base = os.path.basename(rel)
    return any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(base, p) for p in patterns)


def scan(root, excludes, skip=()):
    """Parcourt root sans suivre les liens symboliques.

    Retourne (fichiers, erreurs). Les chemins sont relatifs à root, en '/'.
    """
    root = os.path.realpath(root)
    if not os.path.isdir(root):
        raise FimError(f"dossier introuvable : {root}")
    files, errors = {}, []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = os.path.relpath(dirpath, root)
        dirnames[:] = sorted(
            d for d in dirnames
            if not is_excluded(Path(os.path.join(rel_dir, d)).as_posix(), excludes)
        )
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = Path(os.path.relpath(full, root)).as_posix()
            if is_excluded(rel, excludes) or os.path.abspath(full) in skip:
                continue
            try:
                st = os.lstat(full)
                if stat.S_ISLNK(st.st_mode):
                    entry = {"type": "symlink", "target": os.readlink(full)}
                elif stat.S_ISREG(st.st_mode):
                    entry = {"type": "file", "sha256": sha256_file(full)}
                else:
                    continue  # sockets, fifos, périphériques
                entry.update(mode=oct(stat.S_IMODE(st.st_mode)), uid=st.st_uid, gid=st.st_gid)
                files[rel] = entry
            except OSError as exc:
                errors.append(f"{rel} : {exc.strerror or exc}")
    return files, errors


def diff(old, new):
    added = sorted(set(new) - set(old))
    removed = sorted(set(old) - set(new))
    modified = []
    for path in sorted(set(old) & set(new)):
        fields = [k for k in LABELS if old[path].get(k) != new[path].get(k)]
        if fields:
            modified.append({"path": path, "changes": fields})
    return {"added": added, "removed": removed, "modified": modified}


# ---------- Baseline (stockage + signature HMAC optionnelle) ----------
def sign(data, key):
    payload = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(key.encode(), payload, hashlib.sha256).hexdigest()


def save_baseline(path, data, key=None):
    doc = {"version": 1, "created": datetime.now(timezone.utc).isoformat(timespec="seconds"), "data": data}
    if key:
        doc["hmac"] = sign(data, key)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)  # lisible par le propriétaire seulement
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, sort_keys=True)
    os.replace(tmp, path)


def load_baseline(path, key=None):
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
        data = doc["data"]
        data["files"], data["excludes"]
    except FileNotFoundError:
        raise FimError(f"baseline introuvable : {path} (lancez d'abord « init »)")
    except (ValueError, KeyError, TypeError):
        raise FimError(f"baseline illisible ou corrompue : {path}")
    if doc.get("hmac"):
        if not key:
            raise FimError("baseline signée : définissez la variable d'environnement FIM_KEY")
        if not hmac.compare_digest(doc["hmac"], sign(data, key)):
            raise FimError("signature invalide : la baseline a été modifiée ou la clé est incorrecte")
    elif key:
        raise FimError("FIM_KEY est définie mais la baseline n'est pas signée (remplacement possible)")
    return data


def make_data(root, excludes, skip):
    files, errors = scan(root, excludes, skip)
    return {"root": os.path.realpath(root), "excludes": sorted(excludes), "files": files}, errors


# ---------- Interface en ligne de commande ----------
def print_report(result, errors):
    for p in result["added"]:
        print(f"[+] ajouté    {p}")
    for p in result["removed"]:
        print(f"[-] supprimé  {p}")
    for m in result["modified"]:
        print(f"[~] modifié   {m['path']} ({', '.join(LABELS[c] for c in m['changes'])})")
    for e in errors:
        print(f"[!] illisible {e}", file=sys.stderr)
    total = len(result["added"]) + len(result["removed"]) + len(result["modified"])
    print(f"\n{total} changement(s) : {len(result['added'])} ajout(s), "
          f"{len(result['removed'])} suppression(s), {len(result['modified'])} modification(s).")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="fim", description="Moniteur d'intégrité de fichiers.")
    parser.add_argument("--version", action="version", version=VERSION)
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name, help_ in (("init", "créer la baseline"), ("check", "comparer à la baseline")):
        s = sub.add_parser(name, help=help_)
        s.add_argument("path", help="dossier à surveiller")
        s.add_argument("-b", "--baseline", default=DEFAULT_BASELINE, help=f"fichier baseline (défaut : {DEFAULT_BASELINE})")
        s.add_argument("-e", "--exclude", action="append", default=[], metavar="MOTIF", help="motif à ignorer (répétable), ex. '*.log'")
        if name == "check":
            s.add_argument("--json", action="store_true", help="sortie JSON")
            s.add_argument("--update", action="store_true", help="mettre à jour la baseline après le rapport")
    args = parser.parse_args(argv)
    key = os.environ.get("FIM_KEY") or None
    baseline = os.path.realpath(args.baseline)
    skip = {baseline, baseline + ".tmp"}  # la baseline ne se surveille pas elle-même

    try:
        if args.cmd == "init":
            data, errors = make_data(args.path, args.exclude, skip)
            save_baseline(args.baseline, data, key)
            print(f"Baseline créée : {len(data['files'])} fichier(s) → {args.baseline}"
                  + (" (signée HMAC)" if key else " (non signée : définissez FIM_KEY pour la signer)"))
            for e in errors:
                print(f"[!] illisible {e}", file=sys.stderr)
            return 0

        old = load_baseline(args.baseline, key)
        excludes = sorted(set(old["excludes"]) | set(args.exclude))
        if os.path.realpath(args.path) != old["root"]:
            print(f"Attention : la baseline a été créée pour {old['root']}", file=sys.stderr)
        new, errors = make_data(args.path, excludes, skip)
        old_files = {p: e for p, e in old["files"].items() if not is_excluded(p, excludes)}
        result = diff(old_files, new["files"])
        changed = any(result.values())
        if args.json:
            print(json.dumps({**result, "errors": errors}, indent=2, ensure_ascii=False))
        else:
            print_report(result, errors)
        if args.update:
            save_baseline(args.baseline, new, key)
        return 1 if changed else 0
    except FimError as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
