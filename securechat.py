#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecureChat Encryptor - Chiffrement de communications
Auteur : Jamein N. Dietrich A.

Outil educatif pour :
- Chiffrement AES-256 en mode CTR (simulation avec SHA-256)
- Chiffrement RSA simplifie (Miller-Rabin, generation de cles)
- Verification d'integrite HMAC-SHA256 avec protection contre les timing attacks
- Generation de cles
- Interface CLI avec sous-commandes
"""

import argparse
import hashlib
import hmac
import os
import random
import struct
import sys
import time
import base64


# ============================================================
# SECTION : Chiffrement AES-256 en mode CTR (simulation SHA-256)
# ============================================================

class AES256_CTR:
    """
    Simulation d'un chiffrement AES-256 en mode CTR.

    En mode educatif, on utilise SHA-256 comme fonction de permutation
    de bloc pour simuler le comportement d'AES-256-CTR.
    Le mode CTR (Compteur) genere un flux de cle (keystream) en
    chiffrant des valeurs de compteur successives.

    Note : Cette implementation est EDUCATIVE. Pour un usage reel,
    utilisez la bibliotheque cryptography ou PyCryptodome.
    """

    TAILLE_BLOC = 16  # 128 bits = 16 octets

    def __init__(self, cle):
        """
        Initialise le chiffreur avec une cle de 32 octets (256 bits).

        Args:
            cle (bytes): Cle de chiffrement (32 octets)
        """
        if len(cle) != 32:
            raise ValueError("La cle doit faire exactement 32 octets (256 bits)")
        self.cle = cle

    def _generer_bloc_keystream(self, compteur):
        """
        Genere un bloc du keystream en chiffrant la valeur du compteur.

        Args:
            compteur (int): Valeur du compteur

        Returns:
            bytes: Bloc de keystream de 16 octets
        """
        # Construction du bloc d'entree : cle + compteur
        # En mode CTR reel, AES chiffre (compteur || nonce)
        compteur_bytes = struct.pack('>QQ', 0, compteur)
        entree = self.cle + compteur_bytes
        # SHA-256 comme permutation de bloc
        hachage = hashlib.sha256(entree).digest()
        return hachage[:self.TAILLE_BLOC]

    def chiffrer(self, donnees):
        """
        Chiffre les donnees en mode CTR.

        Args:
            donnees (bytes): Donnees en clair a chiffrer

        Returns:
            bytes: Donnees chiffrees
        """
        resultat = bytearray()
        compteur = 0

        for i in range(0, len(donnees), self.TAILLE_BLOC):
            bloc_clair = donnees[i:i + self.TAILLE_BLOC]
            keystream = self._generer_bloc_keystream(compteur)
            # XOR entre le bloc clair et le keystream
            for j in range(len(bloc_clair)):
                resultat.append(bloc_clair[j] ^ keystream[j])
            compteur += 1

        return bytes(resultat)

    def dechiffrer(self, donnees_chiffrees):
        """
        Dechiffre les donnees en mode CTR.
        Le dechiffrement est identique au chiffrement en mode CTR.

        Args:
            donnees_chiffrees (bytes): Donnees chiffrees

        Returns:
            bytes: Donnees en clair
        """
        return self.chiffrer(donnees_chiffrees)


# ============================================================
# SECTION : Chiffrement RSA simplifie
# ============================================================

class RSA:
    """
    Implementation simplifiee du chiffrement RSA.

    Inclut :
    - Test de primalite Miller-Rabin
    - Generation de nombres premiers
    - Generation de paires de cles RSA
    - Chiffrement et dechiffrement

    Note : Cette implementation est EDUCATIVE. Pour un usage reel,
    utilisez la bibliotheque cryptography.
    """

    def __init__(self, taille_cle=2048):
        """
        Initialise les parametres RSA.

        Args:
            taille_cle (int): Taille de la cle en bits (defaut : 2048)
        """
        self.taille_cle = taille_cle
        self.cle_publique = None   # (e, n)
        self.cle_privee = None     # (d, n)
        self.p = None
        self.q = None

    @staticmethod
    def _test_miller_rabin(n, k=20):
        """
        Test de primalite de Miller-Rabin.

        Ce test probabiliste determine si un nombre est probablement premier.
        Le parametre k controle le nombre de temoins testes.
        Probabilite d'erreur : 4^(-k)

        Args:
            n (int): Nombre a tester
            k (int): Nombre de tours de test (defaut : 20)

        Returns:
            bool: True si n est probablement premier
        """
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False

        # Decomposition : n - 1 = 2^r * d
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2

        # Test avec k temoins
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)

            if x == 1 or x == n - 1:
                continue

            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False

        return True

    @staticmethod
    def _generer_premier(bits):
        """
        Genere un nombre premier de la taille specifiee.

        Args:
            bits (int): Taille en bits du nombre premier

        Returns:
            int: Nombre premier
        """
        while True:
            # Generer un nombre impair de la bonne taille
            n = random.getrandbits(bits)
            n |= (1 << (bits - 1)) | 1  # Bit de poids fort et impair
            if RSA._test_miller_rabin(n):
                return n

    @staticmethod
    def _pgcd_etendu(a, b):
        """
        Algorithme d'Euclide etendu.
        Calcule le PGCD et les coefficients de Bezout.

        Args:
            a, b (int): Nombres entiers

        Returns:
            tuple: (pgcd, x, y) tel que a*x + b*y = pgcd
        """
        if a == 0:
            return b, 0, 1
        pgcd, x1, y1 = RSA._pgcd_etendu(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return pgcd, x, y

    @staticmethod
    def _inverse_modulaire(e, phi):
        """
        Calcule l'inverse modulaire de e modulo phi.

        Args:
            e (int): Exposant
            phi (int): Indicatrice d'Euler

        Returns:
            int: Inverse modulaire d
        """
        pgcd, x, _ = RSA._pgcd_etendu(e, phi)
        if pgcd != 1:
            raise ValueError("L'inverse modulaire n'existe pas")
        return x % phi

    def generer_cles(self):
        """
        Genere une paire de cles RSA.

        Returns:
            tuple: (cle_publique, cle_privee) ou cle = (exposant, modulus)
        """
        bits_p = self.taille_cle // 2
        bits_q = self.taille_cle // 2

        print(f"[*] Generation de nombres premiers de {bits_p} bits...")

        self.p = self._generer_premier(bits_p)
        self.q = self._generer_premier(bits_q)

        # S'assurer que p != q
        while self.p == self.q:
            self.q = self._generer_premier(bits_q)

        n = self.p * self.q
        phi = (self.p - 1) * (self.q - 1)

        # Exposant public (standard : 65537)
        e = 65537

        # Verifier que e est premier avec phi
        if self._pgcd_etendu(e, phi)[0] != 1:
            e = 3
            while self._pgcd_etendu(e, phi)[0] != 1:
                e += 2

        # Exposant prive
        d = self._inverse_modulaire(e, phi)

        self.cle_publique = (e, n)
        self.cle_privee = (d, n)

        print(f"[+] Cle publique  (e, n) : ({e}, {n})")
        print(f"[+] Cle privee    (d, n) : ({d}, {n})")
        print(f"[+] Module n      : {n.bit_length()} bits")

        return self.cle_publique, self.cle_privee

    def chiffrer(self, message, cle_publique=None):
        """
        Chiffre un message avec RSA.

        Args:
            message (str or int): Message a chiffrer
            cle_publique (tuple): Cle publique (e, n)

        Returns:
            int: Message chiffre
        """
        if cle_publique is None:
            cle_publique = self.cle_publique

        if cle_publique is None:
            raise ValueError("Aucune cle publique definie")

        e, n = cle_publique

        # Conversion du message en entier
        if isinstance(message, str):
            message_bytes = message.encode('utf-8')
            m = int.from_bytes(message_bytes, 'big')
        else:
            m = message

        if m >= n:
            raise ValueError("Le message est trop long pour la taille de la cle")

        # Chiffrement : c = m^e mod n
        c = pow(m, e, n)
        return c

    def dechiffrer(self, message_chiffre, cle_privee=None):
        """
        Dechiffre un message avec RSA.

        Args:
            message_chiffre (int): Message chiffre
            cle_privee (tuple): Cle privee (d, n)

        Returns:
            str: Message dechiffre
        """
        if cle_privee is None:
            cle_privee = self.cle_privee

        if cle_privee is None:
            raise ValueError("Aucune cle privee definie")

        d, n = cle_privee

        # Dechiffrement : m = c^d mod n
        m = pow(message_chiffre, d, n)

        # Conversion de l'entier en chaine
        longueur_bytes = (m.bit_length() + 7) // 8
        message_bytes = m.to_bytes(longueur_bytes, 'big')
        return message_bytes.decode('utf-8', errors='ignore')


# ============================================================
# SECTION : HMAC-SHA256 avec protection contre les timing attacks
# ============================================================

class HMAC_SHA256:
    """
    Verification d'integrite HMAC-SHA256 avec protection contre les timing attacks.

    Le HMAC (Hash-based Message Authentication Code) permet de verifier
    l'integrite et l'authenticite d'un message. La protection contre les
    timing attacks empeche un attaquant de deviner le HMAC correct en
    mesurant le temps de comparaison.
    """

    TAILLE_HMAC = 32  # SHA-256 = 32 octets

    @staticmethod
    def calculer(cle, message):
        """
        Calcule le HMAC-SHA256 d'un message.

        Args:
            cle (bytes): Cle secrete
            message (bytes): Message a authentifier

        Returns:
            bytes: HMAC-SHA256 (32 octets)
        """
        return hmac.new(cle, message, hashlib.sha256).digest()

    @staticmethod
    def verifier(cle, message, hmac_attendu):
        """
        Verifie le HMAC-SHA256 d'un message avec protection contre les timing attacks.

        La comparaison a temps constant empeche un attaquant de determiner
        progressivement le HMAC correct en mesurant le temps de reponse.
        La fonction comparedigest de hmac est specifiquement concue pour cela.

        Args:
            cle (bytes): Cle secrete
            message (bytes): Message a verifier
            hmac_attendu (bytes): HMAC attendu

        Returns:
            bool: True si le HMAC est valide
        """
        hmac_calcule = hmac.new(cle, message, hashlib.sha256).digest()

        # Utilisation de hmac.compare_digest pour une comparaison a temps constant
        # Cette fonction est resistante aux timing attacks car elle prend
        # toujours le meme temps quelque soit la position de la premiere difference
        return hmac.compare_digest(hmac_calcule, hmac_attendu)

    @staticmethod
    def comparaison_naive(a, b):
        """
        Comparaison naive (VULNERABLE aux timing attacks).
        Montre pourquoi hmac.compare_digest est necessaire.

        Args:
            a (bytes): Premier HMAC
            b (bytes): Second HMAC

        Returns:
            bool: True si identiques
        """
        if len(a) != len(b):
            return False
        for x, y in zip(a, b):
            if x != y:
                return False  # Retour premature = fuite d'information
        return True

    @staticmethod
    def comparaison_temps_constant(a, b):
        """
        Comparaison manuelle a temps constant.
        Implementation alternative montrant le principe.

        Args:
            a (bytes): Premier HMAC
            b (bytes): Second HMAC

        Returns:
            bool: True si identiques
        """
        if len(a) != len(b):
            return False
        resultat = 0
        for x, y in zip(a, b):
            resultat |= x ^ y  # XOR : 0 si identiques
        return resultat == 0


# ============================================================
# SECTION : Generation de cles
# ============================================================

def generer_cle_aes256():
    """
    Genere une cle AES-256 aleatoire (32 octets).

    Returns:
        bytes: Cle de 32 octets
    """
    return os.urandom(32)


def generer_cle_hmac():
    """
    Genere une cle HMAC aleatoire (32 octets).

    Returns:
        bytes: Cle de 32 octets
    """
    return os.urandom(32)


def generer_nonce():
    """
    Genere un nonce aleatoire (16 octets) pour le mode CTR.

    Returns:
        bytes: Nonce de 16 octets
    """
    return os.urandom(16)


def formater_cle_base64(cle):
    """
    Formate une cle en base64 pour l'affichage.

    Args:
        cle (bytes): Cle a formater

    Returns:
        str: Cle encodee en base64
    """
    return base64.b64encode(cle).decode('ascii')


def charger_cle_base64(cle_str):
    """
    Charge une cle depuis sa representation base64.

    Args:
        cle_str (str): Cle encodee en base64

    Returns:
        bytes: Cle decodee
    """
    return base64.b64decode(cle_str)


# ============================================================
# SECTION : Chiffrement de messages complet
# ============================================================

def chiffrer_message(message, cle_aes=None, cle_hmac=None):
    """
    Chiffre un message avec AES-256-CTR et ajoute un HMAC-SHA256.

    Le processus complet :
    1. Generation d'un nonce aleatoire
    2. Chiffrement AES-256-CTR du message
    3. Calcul du HMAC-SHA256 sur (nonce + message chiffre)
    4. Concatenation : nonce + message chiffre + HMAC

    Args:
        message (str): Message en clair
        cle_aes (bytes): Cle AES-256 (32 octets)
        cle_hmac (bytes): Cle HMAC (32 octets)

    Returns:
        dict: Donnees chiffrees avec metadonnees
    """
    if cle_aes is None:
        cle_aes = generer_cle_aes256()
    if cle_hmac is None:
        cle_hmac = generer_cle_hmac()

    # Generation du nonce
    nonce = generer_nonce()

    # Chiffrement AES-256-CTR
    cipher = AES256_CTR(cle_aes)
    message_bytes = message.encode('utf-8')
    message_chiffre = cipher.chiffrer(message_bytes)

    # Calcul du HMAC sur nonce + message chiffre
    donnees_a_authentifier = nonce + message_chiffre
    hmac_calcule = HMAC_SHA256.calculer(cle_hmac, donnees_a_authentifier)

    return {
        "nonce": nonce,
        "message_chiffre": message_chiffre,
        "hmac": hmac_calcule,
        "cle_aes": cle_aes,
        "cle_hmac": cle_hmac,
        "taille_originale": len(message_bytes),
        "taille_chiffree": len(message_chiffre),
    }


def dechiffrer_message(donnees_chiffrees, cle_aes, cle_hmac):
    """
    Dechiffre un message en verifiant le HMAC-SHA256.

    Le processus complet :
    1. Verification du HMAC-SHA256
    2. Dechiffrement AES-256-CTR

    Args:
        donnees_chiffrees (dict): Donnees chiffrees
        cle_aes (bytes): Cle AES-256 (32 octets)
        cle_hmac (bytes): Cle HMAC (32 octets)

    Returns:
        dict: Resultat du dechiffrement
    """
    nonce = donnees_chiffrees["nonce"]
    message_chiffre = donnees_chiffrees["message_chiffre"]
    hmac_attendu = donnees_chiffrees["hmac"]

    # Verification du HMAC (protection contre les timing attacks)
    donnees_a_authentifier = nonce + message_chiffre
    hmac_valide = HMAC_SHA256.verifier(cle_hmac, donnees_a_authentifier, hmac_attendu)

    if not hmac_valide:
        return {
            "succes": False,
            "erreur": "HMAC invalide - integrite compromise !",
            "message": None
        }

    # Dechiffrement AES-256-CTR
    cipher = AES256_CTR(cle_aes)
    message_dechiffre = cipher.dechiffrer(message_chiffre)

    return {
        "succes": True,
        "erreur": None,
        "message": message_dechiffre.decode('utf-8', errors='ignore')
    }


# ============================================================
# SECTION : Demonstration interactive
# ============================================================

def executer_demo():
    """Execute une demonstration complete des fonctionnalites."""
    print("\n" + "=" * 65)
    print("  SecureChat Encryptor - Demonstration")
    print("  Auteur : Jamein N. Dietrich A.")
    print("=" * 65)

    # --- Partie 1 : AES-256-CTR ---
    print("\n\n--- PARTIE 1 : Chiffrement AES-256-CTR ---\n")

    message_test = "Bonjour, ceci est un message secret pour SecureChat !"
    print(f"[*] Message original : {message_test}")

    # Generation de la cle
    cle_aes = generer_cle_aes256()
    print(f"[*] Cle AES-256 generee : {formater_cle_base64(cle_aes)[:40]}...")

    # Chiffrement
    cipher = AES256_CTR(cle_aes)
    message_bytes = message_test.encode('utf-8')
    message_chiffre = cipher.chiffrer(message_bytes)
    print(f"[*] Message chiffre (hex) : {message_chiffre.hex()[:60]}...")
    print(f"[*] Taille originale : {len(message_bytes)} octets")
    print(f"[*] Taille chiffree : {len(message_chiffre)} octets")

    # Dechiffrement
    message_dechiffre = cipher.dechiffrer(message_chiffre)
    print(f"[+] Message dechiffre : {message_dechiffre.decode('utf-8')}")
    print(f"[+] Verification : {'OK' if message_dechiffre == message_bytes else 'ERREUR'}")

    # --- Partie 2 : RSA ---
    print("\n\n--- PARTIE 2 : Chiffrement RSA simplifie ---\n")

    print("[*] Generation d'une paire de cles RSA-512 (rapide pour la demo)...")
    rsa = RSA(taille_cle=512)
    rsa.generer_cles()

    message_rsa = "Secret RSA!"
    print(f"\n[*] Message a chiffrer : {message_rsa}")

    chiffre = rsa.chiffrer(message_rsa)
    print(f"[*] Message chiffre (int) : {chiffre}")

    dechiffre = rsa.dechiffrer(chiffre)
    print(f"[+] Message dechiffre : {dechiffre}")
    print(f"[+] Verification : {'OK' if dechiffre == message_rsa else 'ERREUR'}")

    # --- Partie 3 : HMAC-SHA256 ---
    print("\n\n--- PARTIE 3 : HMAC-SHA256 avec protection timing attack ---\n")

    cle_hmac = generer_cle_hmac()
    message_hmac = b"Message important a authentifier"

    hmac_calcule = HMAC_SHA256.calculer(cle_hmac, message_hmac)
    print(f"[*] Message : {message_hmac.decode()}")
    print(f"[*] HMAC-SHA256 : {hmac_calcule.hex()}")

    # Verification avec le bon HMAC
    est_valide = HMAC_SHA256.verifier(cle_hmac, message_hmac, hmac_calcule)
    print(f"[+] Verification (HMAC correct) : {'VALIDE' if est_valide else 'INVALIDE'}")

    # Verification avec un HMAC modifie
    hmac_modifie = bytearray(hmac_calcule)
    hmac_modifie[0] ^= 0xFF
    est_valide_modifie = HMAC_SHA256.verifier(
        cle_hmac, message_hmac, bytes(hmac_modifie)
    )
    print(f"[+] Verification (HMAC modifie) : {'VALIDE' if est_valide_modifie else 'INVALIDE'}")

    # Demonstration de la protection contre les timing attacks
    print(f"\n[*] Demonstration protection timing attack :")
    print(f"    - Comparaison naive : vulnerable (retour premature sur difference)")
    print(f"    - Comparaison temps constant : securisee (temps fixe)")
    print(f"    - hmac.compare_digest : fonction standard securisee")

    # --- Partie 4 : Chiffrement complet ---
    print("\n\n--- PARTIE 4 : Chiffrement complet (AES + HMAC) ---\n")

    message_complet = "Ceci est un message confidentiel transmis via SecureChat."
    print(f"[*] Message : {message_complet}")

    resultat = chiffrer_message(message_complet)
    print(f"[*] Nonce : {resultat['nonce'].hex()}")
    print(f"[*] Message chiffre : {resultat['message_chiffre'].hex()[:60]}...")
    print(f"[*] HMAC : {resultat['hmac'].hex()}")

    # Dechiffrement
    resultat_dechiffrement = dechiffrer_message(
        resultat,
        resultat["cle_aes"],
        resultat["cle_hmac"]
    )
    print(f"[+] Dechiffrement : {resultat_dechiffrement['message']}")
    print(f"[+] Integrite HMAC : {'VALIDE' if resultat_dechiffrement['succes'] else 'INVALIDE'}")

    # Test avec modification du message chiffre
    donnees_modifiees = resultat.copy()
    msg_mod = bytearray(donnees_modifiees["message_chiffre"])
    msg_mod[0] ^= 0x01
    donnees_modifiees["message_chiffre"] = bytes(msg_mod)

    resultat_modifie = dechiffrer_message(
        donnees_modifiees,
        resultat["cle_aes"],
        resultat["cle_hmac"]
    )
    print(f"\n[*] Test avec message modifie :")
    if not resultat_modifie["succes"]:
        print(f"[+] HMAC invalide detecte : {resultat_modifie['erreur']}")
    else:
        print(f"[!] ERREUR : Le message modifie n'a pas ete detecte !")

    print("\n" + "=" * 65)
    print("  Fin de la demonstration")
    print("=" * 65)


# ============================================================
# SECTION : Interface CLI
# ============================================================

def main():
    """Point d'entree principal du programme."""
    parser = argparse.ArgumentParser(
        description="SecureChat Encryptor - Chiffrement de communications",
        epilog="Auteur : Jamein N. Dietrich A. | Usage educatif uniquement"
    )

    subparsers = parser.add_subparsers(dest="commande", help="Commandes disponibles")

    # Commande : demo
    subparsers.add_parser(
        "demo", help="Executer la demonstration complete"
    )

    # Commande : aes-chiffrer
    parser_aes_enc = subparsers.add_parser(
        "aes-chiffrer", help="Chiffrer un message avec AES-256-CTR"
    )
    parser_aes_enc.add_argument(
        "message", type=str, help="Message a chiffrer"
    )
    parser_aes_enc.add_argument(
        "-k", "--cle", type=str, default=None,
        help="Cle AES-256 en base64 (generee si non fournie)"
    )

    # Commande : aes-dechiffrer
    parser_aes_dec = subparsers.add_parser(
        "aes-dechiffrer", help="Dechiffrer un message avec AES-256-CTR"
    )
    parser_aes_dec.add_argument(
        "message_hex", type=str, help="Message chiffre en hexadecimal"
    )
    parser_aes_dec.add_argument(
        "-k", "--cle", type=str, required=True,
        help="Cle AES-256 en base64"
    )

    # Commande : rsa-generer
    parser_rsa_gen = subparsers.add_parser(
        "rsa-generer", help="Generer une paire de cles RSA"
    )
    parser_rsa_gen.add_argument(
        "-b", "--bits", type=int, default=2048,
        help="Taille de la cle en bits (defaut : 2048)"
    )

    # Commande : rsa-chiffrer
    parser_rsa_enc = subparsers.add_parser(
        "rsa-chiffrer", help="Chiffrer un message avec RSA"
    )
    parser_rsa_enc.add_argument(
        "message", type=str, help="Message a chiffrer"
    )
    parser_rsa_enc.add_argument(
        "-e", "--exposant", type=int, required=True,
        help="Exposant public e"
    )
    parser_rsa_enc.add_argument(
        "-n", "--module", type=int, required=True,
        help="Module n"
    )

    # Commande : rsa-dechiffrer
    parser_rsa_dec = subparsers.add_parser(
        "rsa-dechiffrer", help="Dechiffrer un message avec RSA"
    )
    parser_rsa_dec.add_argument(
        "chiffre", type=int, help="Message chiffre (entier)"
    )
    parser_rsa_dec.add_argument(
        "-d", "--exposant-prive", type=int, required=True,
        help="Exposant prive d"
    )
    parser_rsa_dec.add_argument(
        "-n", "--module", type=int, required=True,
        help="Module n"
    )

    # Commande : hmac-calculer
    parser_hmac_calc = subparsers.add_parser(
        "hmac-calculer", help="Calculer le HMAC-SHA256 d'un message"
    )
    parser_hmac_calc.add_argument(
        "message", type=str, help="Message a authentifier"
    )
    parser_hmac_calc.add_argument(
        "-k", "--cle", type=str, default=None,
        help="Cle HMAC en base64 (generee si non fournie)"
    )

    # Commande : hmac-verifier
    parser_hmac_ver = subparsers.add_parser(
        "hmac-verifier", help="Verifier le HMAC-SHA256 d'un message"
    )
    parser_hmac_ver.add_argument(
        "message", type=str, help="Message a verifier"
    )
    parser_hmac_ver.add_argument(
        "-m", "--hmac", type=str, required=True,
        help="HMAC attendu en hexadecimal"
    )
    parser_hmac_ver.add_argument(
        "-k", "--cle", type=str, required=True,
        help="Cle HMAC en base64"
    )

    # Commande : gen-cle
    parser_gen = subparsers.add_parser(
        "gen-cle", help="Generer des cles cryptographiques"
    )
    parser_gen.add_argument(
        "-t", "--type", type=str, default="aes",
        choices=["aes", "hmac", "all"],
        help="Type de cle a generer (defaut : aes)"
    )

    args = parser.parse_args()

    if not args.commande:
        parser.print_help()
        return

    if args.commande == "demo":
        executer_demo()

    elif args.commande == "aes-chiffrer":
        cle = charger_cle_base64(args.cle) if args.cle else generer_cle_aes256()
        cipher = AES256_CTR(cle)
        message_bytes = args.message.encode('utf-8')
        chiffre = cipher.chiffrer(message_bytes)
        print(f"[*] Message chiffre (hex) : {chiffre.hex()}")
        print(f"[*] Cle AES-256 (base64) : {formater_cle_base64(cle)}")

    elif args.commande == "aes-dechiffrer":
        cle = charger_cle_base64(args.cle)
        cipher = AES256_CTR(cle)
        chiffre = bytes.fromhex(args.message_hex)
        clair = cipher.dechiffrer(chiffre)
        print(f"[+] Message dechiffre : {clair.decode('utf-8', errors='ignore')}")

    elif args.commande == "rsa-generer":
        rsa = RSA(taille_cle=args.bits)
        rsa.generer_cles()

    elif args.commande == "rsa-chiffrer":
        rsa = RSA()
        cle_pub = (args.exposant, args.module)
        chiffre = rsa.chiffrer(args.message, cle_pub)
        print(f"[*] Message chiffre : {chiffre}")

    elif args.commande == "rsa-dechiffrer":
        rsa = RSA()
        cle_priv = (args.exposant_prive, args.module)
        clair = rsa.dechiffrer(args.chiffre, cle_priv)
        print(f"[+] Message dechiffre : {clair}")

    elif args.commande == "hmac-calculer":
        cle = charger_cle_base64(args.cle) if args.cle else generer_cle_hmac()
        message_bytes = args.message.encode('utf-8')
        hmac_calc = HMAC_SHA256.calculer(cle, message_bytes)
        print(f"[*] HMAC-SHA256 : {hmac_calc.hex()}")
        print(f"[*] Cle HMAC (base64) : {formater_cle_base64(cle)}")

    elif args.commande == "hmac-verifier":
        cle = charger_cle_base64(args.cle)
        message_bytes = args.message.encode('utf-8')
        hmac_attendu = bytes.fromhex(args.hmac)
        est_valide = HMAC_SHA256.verifier(cle, message_bytes, hmac_attendu)
        print(f"[+] Resultat : {'HMAC VALIDE' if est_valide else 'HMAC INVALIDE'}")

    elif args.commande == "gen-cle":
        if args.type in ("aes", "all"):
            cle_aes = generer_cle_aes256()
            print(f"Cle AES-256 (base64) : {formater_cle_base64(cle_aes)}")
        if args.type in ("hmac", "all"):
            cle_hmac = generer_cle_hmac()
            print(f"Cle HMAC (base64) : {formater_cle_base64(cle_hmac)}")


if __name__ == "__main__":
    main()
