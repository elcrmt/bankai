# 🏦 Bankai - API Bancaire Moderne

[![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com/)
[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![SQLModel](https://img.shields.io/badge/SQLModel-FF1709?style=for-the-badge&logo=sqlite&logoColor=white)](https://sqlmodel.tiangolo.com/)

Une API bancaire moderne et sécurisée construite avec FastAPI, offrant des fonctionnalités complètes de gestion de comptes et de transactions.

## ✨ Fonctionnalités

- 🔐 **Authentification Sécurisée**
  - JWT (JSON Web Tokens)
  - Gestion des sessions utilisateur
  - Protection des endpoints sensibles

- 💳 **Gestion des Comptes**
  - Création de compte principal et secondaires
  - Consultation des soldes et transactions
  - Clôture de comptes secondaires avec transfert automatique

- 💸 **Transactions**
  - Dépôts instantanés
  - Transferts entre comptes
  - Annulation possible dans les 5 secondes
  - Historique complet des transactions

## 🚀 Installation

1. Clonez le repository :
```bash
git clone https://github.com/elcrmt/bankai
cd bankai
```

2. Créez un environnement virtuel et activez-le :
```bash
python -m venv .venv
source .venv/bin/activate  # Sur Unix/macOS
# ou
.venv\Scripts\activate  # Sur Windows
```

3. Installez les dépendances :
```bash
pip install -r requirements.txt
```

4. Lancez l'application :
```bash
uvicorn main:app --reload
```

L'API sera accessible à l'adresse : http://localhost:8000

## 📚 Documentation API

La documentation interactive de l'API est disponible aux endpoints suivants :
- Swagger UI : http://localhost:8000/docs
- ReDoc : http://localhost:8000/redoc

## 🔍 Endpoints Principaux

### Authentification
- `POST /register` : Création d'un nouveau compte utilisateur
- `POST /token` : Obtention d'un token JWT

### Gestion des Comptes
- `POST /account` : Création d'un nouveau compte bancaire
- `GET /me` : Consultation de ses informations et comptes
- `DELETE /account/{account_id}/close` : Clôture d'un compte secondaire

### Transactions
- `POST /deposit` : Dépôt d'argent
- `POST /transfer` : Transfert vers un autre compte
- `POST /cancel-transfer/{transaction_id}` : Annulation d'un transfert (dans les 5 secondes)

## 🔒 Sécurité

- Authentification JWT
- Hachage sécurisé des mots de passe
- Validation des emails
- Protection contre les injections SQL
- Gestion sécurisée des sessions

## 💻 Technologies Utilisées

- **FastAPI** : Framework web moderne et rapide
- **SQLModel** : ORM moderne pour Python
- **Pydantic** : Validation des données
- **JWT** : Authentification sécurisée
- **SQLite** : Base de données légère et performante

## 🤝 Contribution

Les contributions sont les bienvenues ! N'hésitez pas à :
1. Fork le projet
2. Créer une branche pour votre fonctionnalité
3. Commiter vos changements
4. Pousser vers la branche
5. Ouvrir une Pull Request

## 📝 Licence

Ce projet est sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.

## 📧 Contact

Pour toute question ou suggestion, n'hésitez pas à ouvrir une issue ou à me contacter directement.