#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Déchiffre les données de l'application Fitness Park et les convertit en CSV.

Installation (une fois) :
    pip install cryptography

Utilisation :
    python dechiffrer.py <dossier-du-depot>              # tout le dépôt
    python dechiffrer.py <dossier> -o ./analyse          # dossier de sortie
    python dechiffrer.py <dossier> --json                # JSON brut en plus

Le mot de passe est demandé à la saisie ; il n'est jamais écrit sur le disque.
"""

import argparse, base64, csv, getpass, json, sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
except ImportError:
    sys.exit("Module manquant. Lance d'abord :  pip install cryptography")

# ── paramètres du chiffrement, identiques à ceux de l'application ──
SALT = b"fp-taverny-2026-v1-salt"
SALT_REC = SALT + b"|rec"
ITERATIONS = 150_000


def derive(secret: str, salt: bytes = SALT) -> bytes:
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                      salt=salt, iterations=ITERATIONS).derive(secret.encode())


def open_wrap(wrap: dict, password: str = None, recovery: str = None) -> bytes:
    """Ouvre le coffre scellé et rend la clé de données."""
    if password:
        return base64.b64decode(decrypt(wrap["p"], derive(password)))
    rk = "".join(c for c in (recovery or "").upper() if c.isalnum())
    return base64.b64decode(decrypt(wrap["r"], derive(rk, SALT_REC)))


def decrypt(blob: str, key: bytes) -> str:
    """Format produit par l'application : base64(iv) + '.' + base64(chiffré)."""
    iv_b64, ct_b64 = blob.strip().split(".", 1)
    iv, ct = base64.b64decode(iv_b64), base64.b64decode(ct_b64)
    return AESGCM(key).decrypt(iv, ct, None).decode("utf-8")


# ── mise à plat des séances ──────────────────────────────────
def rows_sets(s):
    for e in s.get("entries", []):
        for i, x in enumerate(e.get("sets", []), 1):
            if not (x.get("w") or x.get("r")):
                continue
            charge = float(x["w"]) if x.get("w") else 0.0
            reps = int(x["r"]) if x.get("r") else 0
            yield dict(date=s.get("date"), seance=s.get("day"),
                       heure_debut=s.get("t1"), heure_fin=s.get("t2"),
                       exercice=e.get("k"), serie=i,
                       charge_kg=x.get("w"), repetitions=x.get("r"), rir=x.get("rir"),
                       volume_kg=round(charge * reps, 1),
                       poids_corps=s.get("bw"),
                       fc_moy=(s.get("hr") or {}).get("avg"),
                       fc_max=(s.get("hr") or {}).get("max"),
                       fc_min=(s.get("hr") or {}).get("min"))


def rows_cardio(s):
    for moment, key in (("debut", "c1"), ("fin", "c2")):
        c = s.get(key) or {}
        if not (c.get("mach") or c.get("min")):
            continue
        yield dict(date=s.get("date"), seance=s.get("day"), moment=moment,
                   machine=c.get("mach"), programme=c.get("prog"),
                   duree_min=c.get("min"), niveau=c.get("niv"),
                   distance_km=c.get("km"), calories=c.get("kcal"),
                   fc_moy=c.get("fc"), note=c.get("note"))


def rows_abs(s):
    for a in s.get("abs", []):
        for i, x in enumerate(a.get("sets", []), 1):
            if not (x.get("sec") or x.get("r")):
                continue
            yield dict(date=s.get("date"), seance=s.get("day"),
                       exercice=a.get("ex"), precision=a.get("note"), serie=i,
                       secondes=x.get("sec"), repetitions=x.get("r"), charge_kg=x.get("w"))


def rows_hr(s):
    for t, bpm in s.get("hrs", []):
        yield dict(date=s.get("date"), seance=s.get("day"),
                   seconde=t, minute=round(t / 60, 2), bpm=bpm)


def rows_sessions(s):
    vol = sum(float(x["w"]) * int(x["r"])
              for e in s.get("entries", []) for x in e.get("sets", [])
              if x.get("w") and x.get("r"))
    nsets = sum(1 for e in s.get("entries", []) for x in e.get("sets", [])
                if x.get("w") or x.get("r"))
    cmin = sum(float((s.get(k) or {}).get("min") or 0) for k in ("c1", "c2"))
    return dict(date=s.get("date"), seance=s.get("day"),
                heure_debut=s.get("t1"), heure_fin=s.get("t2"),
                volume_kg=round(vol, 1), series=nsets,
                cardio_min=cmin, poids_corps=s.get("bw"),
                fc_moy=(s.get("hr") or {}).get("avg"),
                fc_max=(s.get("hr") or {}).get("max"),
                fc_min=(s.get("hr") or {}).get("min"),
                points_fc=len(s.get("hrs", [])),
                interruptions=len(s.get("hrGaps", [])),
                note=s.get("note"))


def write_csv(path, rows):
    rows = list(rows)
    if not rows:
        return 0
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()), delimiter=";")
        w.writeheader()
        w.writerows(rows)
    return len(rows)


def main():
    ap = argparse.ArgumentParser(description="Déchiffre les données Fitness Park.")
    ap.add_argument("source", help="dossier du dépôt cloné, ou dossier contenant les .enc")
    ap.add_argument("-o", "--out", default="analyse", help="dossier de sortie")
    ap.add_argument("--json", action="store_true", help="écrire aussi le JSON brut")
    ap.add_argument("--password", help="mot de passe (déconseillé : reste dans l'historique du terminal)")
    ap.add_argument("--recovery", help="clé de secours, à la place du mot de passe")
    ap.add_argument("--wrap", help="fichier du coffre scellé (db/keys.json). Cherché automatiquement sinon.")
    a = ap.parse_args()

    src = Path(a.source)
    files = sorted(src.rglob("*.enc"))
    if not files:
        sys.exit("Aucun fichier .enc trouvé sous " + str(src))

    # coffre scellé : nouveau format à enveloppe
    wrap_path = Path(a.wrap) if a.wrap else None
    if wrap_path is None:
        found = list(src.rglob("keys.json"))
        wrap_path = found[0] if found else None

    if wrap_path and wrap_path.exists():
        wrap = json.loads(wrap_path.read_text(encoding="utf-8"))
        if a.recovery:
            key = open_wrap(wrap, recovery=a.recovery)
        else:
            pwd = a.password or getpass.getpass("Mot de passe de l'application : ")
            try:
                key = open_wrap(wrap, password=pwd)
            except Exception:
                sys.exit("Mot de passe refusé par le coffre.")
        print("Coffre scellé ouvert :", wrap_path.name)
    else:
        # ancien format : la clé dérive directement du mot de passe
        pwd = a.password or getpass.getpass("Mot de passe de l'application : ")
        key = derive(pwd)
        print("Aucun coffre trouvé — lecture à l'ancien format.")

    sessions, photos, erreurs = [], {}, 0
    for f in files:
        try:
            data = json.loads(decrypt(f.read_text(encoding="utf-8"), key))
        except Exception as e:
            erreurs += 1
            print("  ! illisible :", f.name, "—", type(e).__name__)
            continue
        if "sessions" in str(f.parent):
            sessions.append(data)
        elif "photos" in str(f.parent):
            photos[f.stem] = data

    if erreurs and not sessions:
        sys.exit("Rien n'a pu être déchiffré. Le mot de passe est probablement incorrect.")

    sessions.sort(key=lambda s: (s.get("date") or "", s.get("t1") or ""))
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)

    n1 = write_csv(out / "seances.csv", (rows_sessions(s) for s in sessions))
    n2 = write_csv(out / "series.csv", (r for s in sessions for r in rows_sets(s)))
    n3 = write_csv(out / "cardio.csv", (r for s in sessions for r in rows_cardio(s)))
    n4 = write_csv(out / "abdos.csv", (r for s in sessions for r in rows_abs(s)))
    n5 = write_csv(out / "frequence_cardiaque.csv", (r for s in sessions for r in rows_hr(s)))

    if a.json:
        (out / "donnees.json").write_text(
            json.dumps({"sessions": sessions}, ensure_ascii=False, indent=2), encoding="utf-8")

    print()
    print("Déchiffrement terminé —", len(sessions), "séance(s) lue(s)"
          + (", " + str(erreurs) + " fichier(s) illisible(s)" if erreurs else ""))
    print("  seances.csv               ", n1, "ligne(s)")
    print("  series.csv                ", n2)
    print("  cardio.csv                ", n3)
    print("  abdos.csv                 ", n4)
    print("  frequence_cardiaque.csv   ", n5)
    if photos:
        print("  photos ignorées :", len(photos), "machine(s) — images non exportées")
    print("\nFichiers écrits dans :", out.resolve())


if __name__ == "__main__":
    main()
