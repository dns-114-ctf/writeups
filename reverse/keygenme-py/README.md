# keygenme-py — Writeup

## Informations
- Plateforme : CyLab Security Academy / picoCTF 2021
- Catégorie : Reverse Engineering
- Difficulté : Medium
- Auteur du challenge : syreal

## Énoncé
Le challenge fournit un script Python, `keygenme-trial.py`, simulant la version d'essai d'un logiciel fictif ("Arcane Calculator"). Le programme demande une clé de licence pour débloquer sa version complète.

## Analyse initiale
La lecture du script révèle une fonction `intro_trial()` qui affiche un menu avec 4 options, dont l'option `(c) Enter License Key`. Le nom d'utilisateur codé en dur dans le script est visible directement :

```python
username_trial = "BENNETT"
b_username_trial = b"BENNETT"
```

Le format attendu de la clé est également présent en clair :

```python
key_part_static1_trial = "picoCTF{1n_7h3_kk3y_of_"
key_part_dynamic1_trial = "xxxxxxxx"
key_part_static2_trial = "}"
key_full_template_trial = key_part_static1_trial + key_part_dynamic1_trial + key_part_static2_trial
```

Le flag final a donc la forme : `picoCTF{1n_7h3_kk3y_of_XXXXXXXX}`, où les 8 `X` restent à déterminer.

## Identification de la vulnérabilité (logique du keygen)
La fonction `check_key(key, username_trial)` valide la clé caractère par caractère :

1. Elle vérifie d'abord que la partie statique (`picoCTF{1n_7h3_kk3y_of_`) correspond.
2. Pour chaque caractère dynamique, elle compare un caractère de la clé fournie à un caractère précis du hash SHA-256 du nom d'utilisateur (`hashlib.sha256(username_trial).hexdigest()`), mais **dans un ordre non séquentiel**.
3. En relisant le code source, l'ordre des index utilisés pour piocher dans le hash est : `4, 5, 3, 6, 2, 7, 1, 8`.

Cette permutation volontaire des indices est la seule "protection" du programme : sans lire le code source, il est impossible de deviner l'ordre de reconstruction.

## Exploitation
Un script Python reproduit exactement cette logique pour générer la clé valide :

```python
import hashlib

username = b"BENNETT"
digest = hashlib.sha256(username).hexdigest()

positions = [4, 5, 3, 6, 2, 7, 1, 8]
dynamic_part = "".join(digest[i] for i in positions)

print("SHA-256 :", digest)
print("Clé :", f"picoCTF{{1n_7h3_kk3y_of_{dynamic_part}}}")
```

Exécution :
```bash
python3 script.py
```

La clé générée est ensuite saisie directement dans le menu du programme (option `c`), ce qui valide la licence et débloque la version complète (écriture du fichier `keygenme.py`, non nécessaire pour l'obtention du flag).

## Récupération du flag
La clé de licence générée correspond directement au flag attendu par la plateforme :

```text
picoCTF{1n_7h3_kk3y_of_********}
```

## Ce que ça démontre
Ce challenge illustre une technique classique de reverse engineering : la lecture statique du code source (sans exécution ni désassemblage) suffit à extraire l'algorithme de vérification et à le reproduire pour forger une clé valide (technique de "keygenning").

## Correctif
- Ne jamais coder en dur dans un binaire ou script distribuable l'algorithme de génération/vérification de licence.
- Déporter la validation de licence côté serveur, avec un secret non exposé côté client.
- Utiliser une signature cryptographique asymétrique (ex : RSA) plutôt qu'un simple hash dérivable localement, pour empêcher toute reconstruction de clé sans le secret privé.
