# Application de Proxy Re-encryption

Cette application Flask permet l'échange sécurisé de messages en utilisant la technique de proxy re-encryption avec la bibliothèque Umbral.

## Fonctionnalités

- Création de compte avec génération de paires de clés
- Envoi de messages chiffrés à plusieurs destinataires
- Re-chiffrement des messages via un proxy
- Déchiffrement des messages par les destinataires autorisés
- Interface utilisateur intuitive et responsive

## Prérequis

- Python 3.7 ou supérieur
- pip (gestionnaire de paquets Python)

## Installation

1. Clonez ce dépôt :
```bash
git clone <url-du-repo>
cd <nom-du-dossier>
```

2. Créez un environnement virtuel et activez-le :
```bash
python -m venv venv
# Sur Windows
venv\Scripts\activate
# Sur Linux/Mac
source venv/bin/activate
```

3. Installez les dépendances :
```bash
pip install -r requirements.txt
```

## Utilisation

1. Lancez l'application :
```bash
python app.py
```

2. Ouvrez votre navigateur et accédez à `http://localhost:5000`

3. Créez un compte ou connectez-vous

4. Utilisez le tableau de bord pour :
   - Envoyer des messages chiffrés
   - Voir vos messages envoyés et reçus
   - Déchiffrer les messages que vous avez reçus

## Sécurité

- Les mots de passe sont stockés en clair dans cette version de démonstration. Dans un environnement de production, il faudrait les hasher.
- Les clés privées sont stockées dans la base de données. Dans un environnement de production, il faudrait les stocker de manière plus sécurisée.
- La clé secrète de l'application est générée aléatoirement à chaque démarrage. Dans un environnement de production, il faudrait utiliser une clé fixe et sécurisée.

## Structure du projet

```
.
├── app.py              # Application Flask principale
├── requirements.txt    # Dépendances Python
├── templates/         # Templates HTML
│   ├── base.html     # Template de base
│   ├── index.html    # Page d'accueil
│   ├── login.html    # Page de connexion
│   ├── register.html # Page d'inscription
│   ├── dashboard.html # Tableau de bord
│   └── decrypt.html  # Page de déchiffrement
└── README.md         # Ce fichier
```

## Licence

Ce projet est sous licence MIT. Voir le fichier LICENSE pour plus de détails. 