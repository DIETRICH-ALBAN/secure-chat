# SecureChat Encryptor - Chiffrement de communications

Auteur : Jamein N. Dietrich A.
Contexte : Projet personnel en cyberscurite - Chiffrement et authentification des communications

## Description

SecureChat Encryptor est un outil educatif qui implemente les principes fondamentaux de la cryptographie appliquee aux communications securisees. Il demontre le chiffrement symetrique (AES-256-CTR), le chiffrement asymetrique (RSA) et la verification d'integrite (HMAC-SHA256) avec protection contre les attaques par chronometrage.

Fonctionnalites principales :
- Chiffrement AES-256 en mode CTR (simulation SHA-256 comme permutation de bloc)
- Implementation simplifiee de RSA avec test de primalite Miller-Rabin
- Generation de cles RSA (p, q, n, e, d)
- Chiffrement et dechiffrement RSA
- HMAC-SHA256 avec verification a temps constant (protection timing attack)
- Generation de cles cryptographiques
- Interface CLI complete avec sous-commandes
- Mode demonstration complet

## Competences cyberscurite demontrees

| Competence | Description |
|---|---|
| Chiffrement symetrique | AES-256 en mode CTR |
| Chiffrement asymetrique | RSA avec generation de cles |
| Test de primalite | Algorithme de Miller-Rabin |
| Integrite | HMAC-SHA256 |
| Timing attacks | Protection par comparaison a temps constant |
| Gestion des cles | Generation et manipulation de cles |

## Installation

```bash
git clone <url-du-depot>
cd securechat-encryptor
```

Aucune dependance externe necessaire - utilise uniquement la bibliotheque standard Python.

## Utilisation

Demonstration complete :
```bash
python3 securechat.py demo
```

Generer des cles :
```bash
python3 securechat.py gen-cle -t all
```

Chiffrer avec AES-256-CTR :
```bash
python3 securechat.py aes-chiffrer "Message secret"
python3 securechat.py aes-chiffrer "Message secret" -k <cle_base64>
```

Dechiffrer avec AES-256-CTR :
```bash
python3 securechat.py aes-dechiffrer <hex_chiffre> -k <cle_base64>
```

Generer des cles RSA :
```bash
python3 securechat.py rsa-generer -b 2048
```

Chiffrer avec RSA :
```bash
python3 securechat.py rsa-chiffrer "Secret" -e <exposant> -n <module>
```

Dechiffrer avec RSA :
```bash
python3 securechat.py rsa-dechiffrer <chiffre_int> -d <exposant_prive> -n <module>
```

Calculer un HMAC-SHA256 :
```bash
python3 securechat.py hmac-calculer "Message" -k <cle_base64>
```

Verifier un HMAC-SHA256 :
```bash
python3 securechat.py hmac-verifier "Message" -m <hmac_hex> -k <cle_base64>
```

## Structure du projet

```
securechat-encryptor/
  |-- securechat.py    # Script principal avec toutes les fonctionnalites
  |-- README.md        # Documentation du projet
```

## Avertissement ethique

Cet outil est strictement destine a un usage educatif. Les implementations cryptographiques presentees sont simplifiees a des fins pedagogiques et ne doivent PAS etre utilisees pour proteger des donnees reelles. Pour un usage en production, utilisez des bibliotheques cryptographiques certifiees comme la bibliotheque cryptography de Python. L'auteur decline toute responsabilite quant a l'utilisation de ce code dans un contexte de production.

## Licence

MIT License
