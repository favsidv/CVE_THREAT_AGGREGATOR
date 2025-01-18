# ====================================
# CVE_THREAT_AGGREGATOR
# Module de récupération et traitement des CVE (Common Vulnerabilities and Exposures)
# Optimisé pour les performances I/O avec gestion asynchrone des requêtes
# Auteur: Non spécifié
# Version: 0.6
# ====================================

"""
CVE_THREAT_AGGREGATOR
====================

Un agrégateur de vulnérabilités CVE optimisé pour les performances I/O avec gestion asynchrone.

Description détaillée
--------------------
Ce module implémente un agrégateur complet de vulnérabilités CVE avec :

* Récupération asynchrone des flux RSS de l'ANSSI
* Enrichissement via les APIs MITRE et EPSS 
* Cache mémoire avec TTL (Time To Live)
* Interface web Flask pour la visualisation
* Build automatisé des assets front-end

:Auteur: Non spécifié
:Version: 0.6
"""

# ====================================
# BIBLIOTHÈQUES
# ====================================

"""
Dépendances
===========

Bibliothèques standard Python
----------------------------
* os
    Opérations système et variables d'environnement
* re  
    Expressions régulières pour le traitement de texte
* asyncio
    Gestion de l'asynchrone
* datetime
    Manipulation des dates/durées via datetime, timedelta
* pathlib
    Manipulation avancée des chemins via Path
* typing
    Support du typage statique (List, Dict)

Gestion HTTP asynchrone
----------------------
* aiohttp
    Client HTTP asynchrone complet incluant :
    - ClientTimeout : Configuration des timeouts
    - ClientSession : Gestion des sessions HTTP

Analyse de données
-----------------
* pandas 
    Manipulation de données via DataFrame
* feedparser
    Parser pour flux RSS/Atom 

Framework web
------------
* flask
    Framework web léger avec :
    - Flask : Application WSGI
    - jsonify : Conversion JSON
    - render_template : Moteur de templates

Utilitaires
-----------
* subprocess
    Exécution de commandes système
* tqdm
    Barres de progression avec versions :
    - tqdm : Synchrone 
    - tqdm_async, tqdm_asyncio : Asynchrones
"""

# --- Bibliothèques standard Python ---
import os                                # Opérations sur le système de fichiers et variables d'environnement
import re                                # Expressions régulières pour le traitement de texte
import asyncio                           # Gestion de l'asynchrone en Python
from datetime import datetime, timedelta # Manipulation des dates et durées
from pathlib import Path                 # Manipulation avancée des chemins de fichiers
from typing import List, Dict            # Types pour le typage statique

# --- Gestion des requêtes HTTP asynchrones ---
import aiohttp                           # Client HTTP asynchrone
from aiohttp import ClientTimeout        # Gestion des timeouts pour les requêtes
from aiohttp.client import ClientSession # Session cliente HTTP

# --- Manipulation et analyse de données ---
import pandas as pd # Manipulation de données tabulaires avec DataFrame
import feedparser   # Parser pour les flux RSS

# --- Framework web ---
from flask import Flask, jsonify, render_template # Framework web léger
    # - Flask: classe principale;
    # - jsonify: conversion en JSON;
    # - render_template: rendu des templates HTML.

# --- Utilitaires système ---
import subprocess # Exécution de commandes système

# --- Barres de progression ---
from tqdm import tqdm                       # Barre de progression pour les boucles classiques
from tqdm.asyncio import tqdm as tqdm_async # Version asynchrone de tqdm
from tqdm.asyncio import tqdm_asyncio       # Autre version asynchrone de tqdm

# ====================================
# CONSTANTES SYSTÈME
# ====================================

_MAX_THREAD_POOL_SIZE = 500              # Limite maximale de connexions HTTP simultanées
_IO_TIMEOUT_MS = ClientTimeout(total=10) # Timeout des requêtes HTTP en secondes
_MEM_CHUNK_SIZE = 100                    # Taille des lots pour le traitement par batch

def _compute_threat_vector(raw_cvss_ptr: str) -> str:
    """
    Convertit un score CVSS en niveau de menace qualitatif.
    
    Le CVSS est un score numérique de 0 à 10 évaluant la gravité d'une vulnérabilité.
    Traduit ce score en catégories de risque standardisées.
    
    Paramètres
    ----------
    ``raw_cvss_ptr`` (str): Score CVSS brut à convertir
    
    Retourne
    --------
    str: Niveau de menace ('Faible', 'Moyenne', 'Élevée', 'Critique', ou 'n/a')
    
    Mapping des scores
    ----------------
        - 0.0 à 3.9  -> Faible   (0x01)
        - 4.0 à 6.9  -> Moyenne  (0x02)
        - 7.0 à 8.9  -> Élevée   (0x03)
        - 9.0 à 10.0 -> Critique (0x04)
        - Erreur     -> n/a      (0xFF)
            
    Exemple d'utilisation
    --------------------
    ::
    
        result = _compute_threat_vector('7.5') # Retourne 'Élevée'
        result = _compute_threat_vector('9.1') # Retourne 'Critique'
        result = _compute_threat_vector('err') # Retourne 'n/a'
    """
    try:
        _threat_level_reg = float(raw_cvss_ptr)
        if _threat_level_reg >= 0 and _threat_level_reg <= 3:
            # Risque faible (0x01)
            return "Faible"
        elif 4 <= _threat_level_reg <= 6:
            # Risque moyen (0x02)
            return "Moyenne"
        elif 7 <= _threat_level_reg <= 8:
            # Risque élevé (0x03)
            return "Élevée"
        elif 9 <= _threat_level_reg <= 10:
            # Risque critique (0x04)
            return "Critique"
        else:
            # Valeur hors plage (0x00)
            return "n/a"
    except (ValueError, TypeError):
        # Erreur de conversion (0xFF)
        return "n/a"

class CVE_DataProcessor_Engine:
    """
    Moteur de traitement des CVE avec architecture pipeline et cache.
    
    Architecture asynchrone optimisée pour les performances avec pattern Context Manager
    pour la gestion automatique des ressources réseau et système de cache multi-niveaux.
    
    Attributs
    ---------
        ``_net_io_handler`` (ClientSession): Gestionnaire de sessions HTTP asynchrones
        ``_thread_mutex`` (asyncio.Semaphore): Sémaphore limitant les connexions simultanées
        ``_l1_mitre_cache`` (dict): Cache niveau 1 pour données MITRE
        ``_l1_epss_cache`` (dict): Cache niveau 1 pour scores EPSS
        ``_net_sock`` (aiohttp.TCPConnector): Connecteur TCP avec cache DNS
        
    Architecture technique
    ----------------------
    Le moteur implémente plusieurs optimisations:
        - Cache DNS avec TTL de 5 minutes 
        - Pooling de connexions HTTP limité à 500 connexions
        - Traitement par lots des CVEs (100 par batch)
        - Cache L1 pour les données MITRE et EPSS
        - Timeouts configurables pour les requêtes HTTP
        
    Pipeline de traitement
    ----------------------
    1. Récupération asynchrone des flux RSS ANSSI
    2. Extraction et parsing des CVEs mentionnées
    3. Enrichissement parallèle via MITRE et EPSS
    4. Mise en cache des données fréquemment accédées
        
    Exemple d'utilisation
    ---------------------
    ::

        async with CVE_DataProcessor_Engine() as engine:
            # Traitement d'un lot de CVEs
            cve_data = await engine._process_cve_batch(feed_entries)
            # Enrichissement via MITRE
            mitre_data = await engine._fetch_mitre_metadata(cve_ids)
            # Récupération des scores EPSS
            epss_scores = await engine._fetch_epss_scores(cve_ids)
            
    Format des caches
    -----------------
        Cache MITRE::

            {
                'CVE-2024-1234': {
                    'cvss_score': '7.5',
                    'description': '...',
                    'cwe_desc': 'CWE-119'
                }
            }

        Cache EPSS::

            {
                'CVE-2024-1234': 0.75,
                'CVE-2024-5678': 0.32
            }
            
    Voir aussi
    ----------
        - ``MemCache``: Système de cache avec TTL
        - ``aiohttp.ClientSession``: Gestion des sessions HTTP
        - ``asyncio.Semaphore``: Limitation des connexions
    """

    def __init__(self):
        """
        Initialise une nouvelle instance du moteur de traitement CVE.
        
        Configure les registres système pour le traitement asynchrone des données
        et initialise les différents caches avec leurs valeurs par défaut.
        
        Attributs initialisés
        --------------------
        ``_net_io_handler`` : None
            Gestionnaire de sessions HTTP, initialisé lors du context enter

        ``_thread_mutex`` : asyncio.Semaphore
            Sémaphore limitant à 500 connexions simultanées
        
        ``_l1_mitre_cache`` : dict
            Cache vide pour les métadonnées MITRE
        
        ``_l1_epss_cache`` : dict
            Cache vide pour les scores EPSS
        
        ``_net_sock`` : None
            Socket réseau, initialisé lors du context enter

        Exemple d'utilisation
        --------------------
        ::

            # Création d'une nouvelle instance
            engine = CVE_DataProcessor_Engine()
            # Les ressources réseau ne sont pas encore initialisées
            # Utiliser avec un context manager pour l'initialisation
            async with engine as initialized_engine:
                await initialized_engine._process_cve_batch(entries)
        
        Note
        ----
        Cette classe doit être utilisée avec un context manager.
        """
        # Initialisation des registres système
        self._net_io_handler: ClientSession = None
        self._thread_mutex = asyncio.Semaphore(_MAX_THREAD_POOL_SIZE)
        self._l1_mitre_cache = {} # Cache des métadonnées MITRE
        self._l1_epss_cache = {}  # Cache des scores EPSS
        self._net_sock = None     # Socket réseau réutilisable

    async def __aenter__(self):
        """
        Initialise la session HTTP asynchrone et les ressources réseau.
        
        Configure et établit une session HTTP optimisée pour les performances
        avec gestion du cache DNS et du pooling de connexions.
        
        Configuration
        ------------
        Session HTTP :
            - Cache DNS activé avec TTL de 5 minutes
            - Pool de connexions limité à 500
            - SSL désactivé pour les performances
            - Headers HTTP standards
        
        Connecteur TCP
        -------------
            - ``limit``: 500 connexions maximum
            - ``ttl_dns_cache``: 300 secondes
            - ``use_dns_cache``: Activé
            - ``ssl``: Désactivé
        
        Headers HTTP
        -----------
        ::
        
            {
                'User-Agent': 'Mozilla/5.0',
                'Accept': 'application/json'
            }
        
        Exemple d'utilisation
        --------------------
        ::

            async with CVE_DataProcessor_Engine() as engine:
                # La session HTTP est maintenant initialisée
                # avec la configuration optimale
                await engine._process_cve_batch(entries)
        
        Retourne
        --------
        self: L'instance configurée pour une utilisation dans le context manager
        
        Note
        ----
        Le SSL est désactivé pour les performances. À adapter en production.
        """
        if not self._net_sock:
            self._net_sock = aiohttp.TCPConnector(
                limit=_MAX_THREAD_POOL_SIZE, 
                ttl_dns_cache=300,  # Cache DNS de 5 minutes
                use_dns_cache=True, # Activation du cache DNS
                ssl=False           # SSL désactivé
            )
        self._net_io_handler = ClientSession(
            timeout=_IO_TIMEOUT_MS,
            connector=self._net_sock,
            headers={
                'User-Agent': 'Mozilla/5.0',
                'Accept': 'application/json'
            }
        )
        return self

    async def __aexit__(self, _exc_type, _exc_val, _exc_tb):
        """
        Nettoie les ressources réseau à la sortie du context manager.
        
        Assure la fermeture propre de la session HTTP et la libération
        des ressources réseau pour éviter les fuites mémoire.
        
        Paramètres
        ----------
        ``_exc_type`` (Type[BaseException]): Type de l'exception si elle existe
        ``_exc_val`` (BaseException): Instance de l'exception si elle existe
        ``_exc_tb`` (TracebackType): Traceback de l'exception si elle existe
        
        Actions réalisées
        ----------------
        - Fermeture de la session HTTP si elle existe
        - Libération des connexions du pool
        - Nettoyage du cache DNS
        
        Exemple d'utilisation
        --------------------
        ::

            async with CVE_DataProcessor_Engine() as engine:
                # Le context manager gère automatiquement les ressources
                await engine._process_cve_batch(entries)
            # À la sortie du bloc, __aexit__ est appelé automatiquement
            # pour nettoyer les ressources
        
        Note
        ----
        Les paramètres d'exception ne sont pas utilisés car toutes les 
        exceptions sont propagées au code appelant.
        """
        if self._net_io_handler:
            await self._net_io_handler.close()

    def _decode_rss_stream(self, feed_addr: str) -> List[Dict]:
        """
        Décode et analyse un flux RSS pour en extraire les CVEs.
        
        Parse un flux RSS de l'ANSSI et extrait les informations pertinentes
        en nettoyant et standardisant les données.

        Paramètres
        ----------
        ``feed_addr`` (str): URL du flux RSS à analyser

        Retourne
        --------
        List[Dict]: Liste des entrées RSS normalisées contenant:
            - title: Titre nettoyé (parenthèses retirées)
            - link: URL du bulletin
            - type: "Alerte" ou "Avis" selon l'URL
            - date: Date de publication (format ISO)

        Traitement effectué
        ------------------
        1. Parse du flux RSS avec feedparser
        2. Nettoyage des titres (retrait des parenthèses)
        3. Détection du type selon l'URL
        4. Standardisation des dates au format ISO
        
        Format de sortie
        ---------------
        ::

            [
                {
                    'title': 'CERTFR-2024-ALE-001 Python vulnerability',
                    'link': 'https://cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-001',
                    'type': 'Alerte',
                    'date': '2024-01-18'
                },
                { ... }
            ]
        
        Exemple d'utilisation
        --------------------
        ::

            feed_url = "https://www.cert.ssi.gouv.fr/alerte/feed"
            engine = CVE_DataProcessor_Engine()
            entries = engine._decode_rss_stream(feed_url)
            for entry in entries:
                print(f"Title: {entry['title']}, Type: {entry['type']}")

        Note
        ----
        Le type est déterminé automatiquement selon la présence du mot "alerte"
        dans l'URL du bulletin.
        """
        _raw_feed_buf = feedparser.parse(feed_addr)
        return [{
            'title': re.sub(r'\(.*?\)', '', _entry_ptr.title), # Retire les parenthèses du titre
            'link': _entry_ptr.link,
            'type': "Alerte" if "alerte" in _entry_ptr.link.lower() else "Avis",
            'date': datetime.strptime(_entry_ptr.published, '%a, %d %b %Y %H:%M:%S %z').date().isoformat()
        } for _entry_ptr in _raw_feed_buf.entries]

    async def _fetch_remote_data(self, target_addr: str) -> Dict:
        """
        Récupère des données depuis une API distante de manière asynchrone.
        
        Effectue une requête HTTP GET avec gestion des erreurs et des timeouts.
        Utilise un sémaphore pour limiter le nombre de connexions simultanées.
        
        Paramètres
        ----------
        ``target_addr`` (str): URL de l'API à interroger
        
        Retourne
        --------
        Dict: Réponse JSON de l'API ou dictionnaire vide en cas d'erreur
        
        Gestion des erreurs
        ------------------
        - Timeout de connexion : retourne {}
        - Erreur HTTP : retourne {} si status != 200
        - Erreur JSON : retourne {}
        - Autres erreurs : retourne {}
        
        Exemple d'utilisation
        --------------------
        ::

            url = "https://cveawg.mitre.org/api/cve/CVE-2024-1234"
            data = await engine._fetch_remote_data(url)
            if data:
                print(f"Description: {data.get('descriptions', [{}])[0].get('value')}")
        
        Note
        ----
        Utilise le sémaphore ``_thread_mutex`` pour limiter à 500 connexions simultanées.
        """
        async with self._thread_mutex:
            try:
                async with self._net_io_handler.get(target_addr) as _resp_buf:
                    return await _resp_buf.json() if _resp_buf.status == 200 else {}
            except:
                return {}

    async def _process_cve_batch(self, feed_entries: List[Dict]) -> List[Dict]:
        """
        Traite un lot de CVEs en parallèle avec enrichissement des données.
        
        Implémente un pipeline de traitement asynchrone pour optimiser les performances
        et enrichir les données CVE avec les informations MITRE et EPSS.
        
        Paramètres
        ----------
        ``feed_entries`` (List[Dict]): Liste des entrées RSS contenant :
            - title: Titre du bulletin 
            - link: URL du bulletin
            - type: Type de bulletin (Alerte/Avis)
            - date: Date de publication

        Retourne
        --------
        List[Dict]: Liste des CVEs enrichies contenant : 
            - cve_id: Identifiant CVE
            - title: Titre du bulletin
            - type: Type de bulletin
            - date: Date de publication
            - link: URL du bulletin
        
        Pipeline de traitement
        ---------------------
        1. Création des tâches asynchrones pour chaque entrée
        2. Récupération parallèle des données JSON
        3. Validation et nettoyage des données
        4. Extraction des CVEs et métadonnées
        
        Validation des données
        --------------------
        - Vérification de la présence des données JSON
        - Validation des champs 'cves' et 'name'
        - Nettoyage des données manquantes
        
        Exemple d'utilisation
        --------------------
        ::

            feed_entries = [
                {
                    'title': 'CERTFR-2024-ALE-001',
                    'link': 'https://cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-001',
                    'type': 'Alerte',
                    'date': '2024-01-18'
                }
            ]
            
            async with CVE_DataProcessor_Engine() as engine:
                cves = await engine._process_cve_batch(feed_entries)
                for cve in cves:
                    print(f"CVE: {cve['cve_id']}, Type: {cve['type']}")
        
        Note
        ----
        Utilise ``asyncio.gather`` pour le traitement parallèle optimal.
        """
        # Création des tâches asynchrones pour chaque entrée
        _task_queue = [self._fetch_remote_data(f"{_entry_ptr['link']}json") 
                      for _entry_ptr in feed_entries]
        _result_buf = await asyncio.gather(*_task_queue)
        
        _cve_buf = []
        for _entry_ptr, _data_block in zip(feed_entries, _result_buf):
            # Validation des données et extraction des CVEs
            if not _data_block or 'cves' not in _data_block:
                continue
            for _cve_block in _data_block['cves']:
                if 'name' not in _cve_block:
                    continue
                _cve_buf.append({
                    'cve_id': _cve_block['name'],
                    'title': _entry_ptr['title'],
                    'type': _entry_ptr['type'],
                    'date': _entry_ptr['date'],
                    'link': _entry_ptr['link']
                })
        return _cve_buf

    async def _fetch_mitre_metadata(self, cve_id_array: List[str]) -> Dict:
        """
        Récupère les métadonnées MITRE pour une liste de CVEs.
        
        Optimise la récupération des données en utilisant un cache L1 et un traitement par lots
        pour réduire la charge sur l'API MITRE et améliorer les performances.
        
        Paramètres
        ----------
        ``cve_id_array`` (List[str]): Liste d'identifiants CVE à enrichir
            
        Retourne
        --------
        Dict: Métadonnées pour chaque CVE avec la structure :
            - cvss_score: Score CVSS v3.1
            - description: Description de la vulnérabilité
            - cwe_desc: Type de vulnérabilité (CWE)
            - vendor: Éditeur affecté
            - product: Produit affecté
            - versions: Versions vulnérables
        
        Pipeline de traitement
        --------------------
        1. Vérification des données en cache L1
        2. Identification des CVEs manquantes
        3. Récupération par lots des données manquantes
        4. Mise à jour du cache avec les nouvelles données
        5. Fusion des données (cache + nouvelles)
        
        Format de retour
        ---------------
        ::

            {
                'CVE-2024-1234': {
                    'cvss_score': '7.5',
                    'description': 'Buffer overflow...',
                    'cwe_desc': 'CWE-119',
                    'vendor': 'Example Corp',
                    'product': 'ExampleApp',
                    'versions': '1.0, 1.1, 1.2'
                },
                'CVE-2024-5678': { ... }
            }
        
        Exemple d'utilisation
        --------------------
        ::

            cve_ids = ['CVE-2024-1234', 'CVE-2024-5678']
            async with CVE_DataProcessor_Engine() as engine:
                metadata = await engine._fetch_mitre_metadata(cve_ids)
                for cve_id, data in metadata.items():
                    print(f"{cve_id}: CVSS={data['cvss_score']}")
        
        Note
        ----
        Le cache L1 est persistant pendant toute la durée de vie de l'instance.
        """
        # Identification des CVEs non présentes en cache
        _uncached_cve_ptrs = [_cve_id for _cve_id in cve_id_array 
                             if _cve_id not in self._l1_mitre_cache]
        
        if _uncached_cve_ptrs:
            _task_buf = []
            # Traitement par lots pour éviter la surcharge
            for i in range(0, len(_uncached_cve_ptrs), _MEM_CHUNK_SIZE):
                _chunk_ptr = _uncached_cve_ptrs[i:i + _MEM_CHUNK_SIZE]
                _task_buf.extend([self._fetch_remote_data(
                    f"https://cveawg.mitre.org/api/cve/{_cve_id}"
                ) for _cve_id in _chunk_ptr])
            
            _result_buf = await asyncio.gather(*_task_buf)
            
            # Mise à jour du cache avec les nouvelles données
            for _cve_id, _data_block in zip(_uncached_cve_ptrs, _result_buf):
                if _data_block and 'containers' in _data_block:
                    self._l1_mitre_cache[_cve_id] = self._process_mitre_block(_data_block)
        
        # Retourne toutes les données (cache + nouvelles)
        return {_cve_id: self._l1_mitre_cache.get(_cve_id, {}) 
                for _cve_id in cve_id_array}
    
    def _process_mitre_block(self, data_block: Dict) -> Dict:
        """
        Parse et normalise un bloc de données MITRE.

        Extrait et structure les informations importantes d'un bloc de données
        brutes MITRE en un format standardisé et cohérent.
        
        Paramètres
        ----------
        ``data_block`` (Dict): Données brutes de l'API MITRE contenant :
            - containers: Conteneur principal des données
            - descriptions: Description textuelle
            - metrics: Scores et métriques
            - affected: Informations sur les systèmes affectés
            
        Retourne
        --------
        Dict: Données normalisées contenant :
            - cvss_score: Score CVSS de base
            - description: Description de la vulnérabilité
            - cwe_desc: Type de vulnérabilité (CWE)
            - vendor: Éditeur du produit
            - product: Nom du produit
            - versions: Liste des versions affectées
        
        Structure de données
        ------------------
        Entrée::

            {
                'containers': {
                    'cna': {
                        'metrics': [{'cvssV3_1': {...}}],
                        'descriptions': [{'value': '...'}],
                        'affected': [{
                            'vendor': '...',
                            'product': '...',
                            'versions': [...]
                        }]
                    }
                }
            }

        Exemple d'utilisation
        --------------------
        ::

            raw_data = await self._fetch_remote_data(mitre_url)
            if raw_data:
                processed = self._process_mitre_block(raw_data)
                print(f"CVSS Score: {processed['cvss_score']}")
        
        Note
        ----
        Retourne 'n/a' pour les champs non trouvés ou invalides.
        """
        # Extraction des pointeurs vers les différentes sections
        _cna_ptr = data_block['containers'].get('cna', {})
        _metrics_ptr = _cna_ptr.get('metrics', [{}])[0].get('cvssV3_1', {})
        _affected_ptr = _cna_ptr.get('affected', [{}])[0]
        _problem_ptr = _cna_ptr.get('problemTypes', [{}])[0].get('descriptions', [{}])[0]
        
        return {
            'cvss_score': _metrics_ptr.get('baseScore', 'n/a'),
            'description': _cna_ptr.get('descriptions', [{}])[0].get('value', 'n/a'),
            'cwe_desc': _problem_ptr.get('description', 'n/a'),
            'vendor': _affected_ptr.get('vendor', 'n/a'),
            'product': _affected_ptr.get('product', 'n/a'),
            'versions': ', '.join(v.get('version', '') 
                        for v in _affected_ptr.get('versions', []))
        }

    async def _fetch_epss_scores(self, cve_id_array: List[str]) -> Dict:
        """
        Récupère les scores EPSS pour une liste de CVEs.
        
        L'EPSS (Exploit Prediction Scoring System) prédit la probabilité 
        d'exploitation active d'une vulnérabilité dans les 30 jours.
        
        Paramètres
        ----------
        ``cve_id_array`` (List[str]): Liste des identifiants CVE à évaluer
        
        Retourne
        --------
        Dict: Scores EPSS normalisés entre 0 et 1 pour chaque CVE
            - Clé: Identifiant CVE
            - Valeur: Score float ou 'n/a' si non disponible
        
        Traitement des données
        --------------------
        1. Vérification du cache L1
        2. Construction de la requête pour les CVEs manquantes
        3. Appel à l'API FIRST.org
        4. Mise à jour du cache avec les nouveaux scores
        5. Fusion des données (cache + nouvelles)
        
        Format de retour
        ---------------
        ::

            {
                'CVE-2024-1234': 0.75,  # 75% de chance d'exploitation
                'CVE-2024-5678': 0.32,  # 32% de chance d'exploitation
                'CVE-2024-9012': 'n/a'  # Score non disponible
            }
        
        Exemple d'utilisation
        --------------------
        ::

            cve_ids = ['CVE-2024-1234', 'CVE-2024-5678']
            async with CVE_DataProcessor_Engine() as engine:
                scores = await engine._fetch_epss_scores(cve_ids)
                for cve_id, score in scores.items():
                    if score != 'n/a':
                        print(f"{cve_id}: {score*100:.1f}% risk")
        
        Note
        ----
        Le cache L1 est persistant durant toute la durée de vie de l'instance.
        Les scores sont normalisés entre 0 (risque minimal) et 1 (risque maximal).
        """
        # Vérification du cache
        _uncached_cve_ptrs = [_cve_id for _cve_id in cve_id_array 
                             if _cve_id not in self._l1_epss_cache]
        if not _uncached_cve_ptrs:
            return {_cve_id: self._l1_epss_cache.get(_cve_id, 'n/a') 
                    for _cve_id in cve_id_array}

        _epss_score_buf = {}
        try:
            # Requête à l'API EPSS avec tous les CVEs non cachés
            _params_block = {"cve[]": _uncached_cve_ptrs}
            async with self._net_io_handler.get(
                "https://api.first.org/data/v1/epss",
                params=_params_block,
                ssl=False # SSL désactivé pour les performances
            ) as _resp_buf:
                if _resp_buf.status == 200:
                    _data_block = await _resp_buf.json()
                    if 'data' in _data_block:
                        # Mise à jour du cache avec les nouveaux scores
                        for _item_ptr in _data_block['data']:
                            if 'cve' in _item_ptr and 'epss' in _item_ptr:
                                self._l1_epss_cache[_item_ptr['cve']] = float(_item_ptr['epss'])
                                _epss_score_buf[_item_ptr['cve']] = float(_item_ptr['epss'])
        except Exception as _err_ptr:
            print(f"EPSS_ERROR: {_err_ptr}")
        
        # Retour des données combinées (cache + nouvelles)
        return {_cve_id: self._l1_epss_cache.get(_cve_id, 'n/a') 
                for _cve_id in cve_id_array}

class MemCache:
    """
    Gestionnaire de cache mémoire avec système de Time-To-Live (TTL).
    
    Implémente un cache en mémoire thread-safe avec expiration automatique
    des données basée sur un TTL configurable.
    
    Attributs
    ---------
    ``_data_ptr`` (Any): 
        Données stockées en cache
    ``_timestamp`` (datetime): 
        Horodatage de dernière mise à jour
    ``_ttl`` (timedelta): 
        Durée de vie des données en cache
    ``_mutex`` (asyncio.Lock):
        Verrou pour l'accès concurrent
    
    Fonctionnalités
    --------------
    - Stockage en mémoire avec durée de vie limitée
    - Vérification automatique de la validité
    - Thread-safe via verrous asyncio
    - Interface _get_or_fetch pour récupération/actualisation
    
    Algorithme
    ---------
    1. Vérification de la validité des données
    2. Si invalide ou expirées :
        - Appel de la fonction de récupération
        - Mise à jour du timestamp
        - Stockage des nouvelles données
    3. Sinon : retour des données du cache
    
    Exemple d'utilisation
    --------------------
    ::

        # Création d'un cache avec TTL de 60 minutes
        cache = MemCache(ttl_min=60)
        
        # Définition de la fonction de récupération
        async def fetch_data():
            return {'key': 'value'}
        
        # Utilisation du cache
        data = await cache._get_or_fetch(fetch_data)
    
    Note
    ----
    Les données sont considérées périmées quand:
        - Le cache est vide
        - Le timestamp est None
        - Le TTL est dépassé
    """
    def __init__(self, ttl_min=60):
        """
        Initialise une nouvelle instance du cache mémoire.
        
        Crée un cache avec une durée de vie configurable pour les données.
        Le cache est initialement vide jusqu'à la première récupération.
        
        Paramètres
        ----------
        ``ttl_min`` (int): Durée de vie des données en minutes (défaut: 60)
            
        Attributs initialisés
        -------------------
        - ``_data_ptr``: None - Données en cache
        - ``_timestamp``: None - Horodatage dernière mise à jour
        - ``_ttl``: timedelta - Durée de vie configurée
        - ``_mutex``: asyncio.Lock() - Verrou pour l'accès concurrent
        
        Exemple d'utilisation
        --------------------
        ::

            # Cache avec TTL de 30 minutes
            cache_court = MemCache(ttl_min=30)
            
            # Cache avec TTL par défaut (60 minutes)
            cache_defaut = MemCache()
        
        Note
        ----
        Le TTL est converti en timedelta lors de l'initialisation.
        """
        self._data_ptr = None
        self._timestamp = None
        self._ttl = timedelta(minutes=ttl_min)
        self._mutex = asyncio.Lock()

    def _check_validity(self):
        """
        Vérifie si les données en cache sont valides.
        
        Détermine si les données actuellement en cache peuvent être utilisées
        en vérifiant leur existence et leur durée de vie.
        
        Retourne
        --------
        bool: État de validité du cache
            - True: Données valides et utilisables
            - False: Cache vide ou données expirées
        
        Tests effectués
        --------------
        1. Présence des données (_data_ptr not None)
        2. Présence du timestamp (_timestamp not None)
        3. TTL non dépassé (now - _timestamp < _ttl)
        
        Exemple d'utilisation
        --------------------
        ::

            if self._check_validity():
                return self._data_ptr
            else:
                # Récupérer de nouvelles données
                return await self._update_cache()
        
        Note
        ----
        Les données sont considérées invalides si l'un des tests échoue.
        """
        if not self._data_ptr or not self._timestamp:
            return False
        return datetime.now() - self._timestamp < self._ttl

    def _update_cache(self, new_data):
        """
        Met à jour le cache avec de nouvelles données.
        
        Actualise le contenu du cache avec les nouvelles données fournies
        et met à jour l'horodatage au moment de l'écriture.
        
        Paramètres
        ----------
        ``new_data`` (Any): Nouvelles données à mettre en cache
            
        Opérations réalisées
        -------------------
        1. Remplacement des données précédentes
        2. Mise à jour de l'horodatage
        
        Exemple d'utilisation
        --------------------
        ::

            data = await fetch_new_data()
            self._update_cache(data)
            # Le TTL est remis à zéro à partir de maintenant
        
        Note
        ----
        L'appel à cette méthode réinitialise le TTL des données.
        """
        self._data_ptr = new_data
        self._timestamp = datetime.now()

    def _get_cache(self):
        """
        Récupère les données actuellement en cache.
        
        Retourne les données brutes du cache sans vérification de validité.
        Cette méthode interne est utilisée après la validation du TTL.
        
        Retourne
        --------
        Any: Données stockées dans le cache ou None si vide
        
        Exemple d'utilisation
        --------------------
        ::

            if self._check_validity():
                return self._get_cache()
            else:
                return None
        
        Note
        ----
        Cette méthode ne vérifie pas la validité des données,
        cela doit être fait avant l'appel avec _check_validity().
        """
        return self._data_ptr

    async def _get_or_fetch(self, fetch_func):
        """
        Récupère les données du cache ou les actualise si nécessaire.
        
        Vérifie la validité du cache et soit retourne les données existantes,
        soit appelle la fonction de récupération pour actualiser le cache.
        
        Paramètres
        ----------
        ``fetch_func`` (Callable): Fonction asynchrone de récupération des données
            Doit être une coroutine sans paramètres retournant les nouvelles données
        
        Retourne
        --------
        Any: Données du cache (existantes ou nouvellement récupérées)
        
        Processus de récupération
        ----------------------
        1. Acquisition du verrou (_mutex)
        2. Vérification de la validité du cache
        3. Si valide : retour des données existantes
        4. Si invalide :
            - Appel de fetch_func()
            - Mise à jour du cache
            - Retour des nouvelles données
        
        Exemple d'utilisation
        --------------------
        ::

            async def fetch_data():
                return await api.get_latest_data()
                
            cache = MemCache(ttl_min=30)
            data = await cache._get_or_fetch(fetch_data)
        
        Note
        ----
        Thread-safe grâce au verrou asyncio.Lock pour les accès concurrents.
        """
        async with self._mutex:
            if self._check_validity():
                return self._get_cache()
            
            _new_data = await fetch_func()
            self._update_cache(_new_data)
            return _new_data

# Initialisation du cache système global
_SYS_CACHE = MemCache()

def _check_build_status():
    """
    Vérifie si une reconstruction des assets front-end est nécessaire.
    
    Compare les timestamps des fichiers sources et du bundle pour déterminer
    si une reconstruction est requise suite à des modifications.
    
    Retourne
    --------
    bool: État de la reconstruction
        - True: Reconstruction nécessaire
        - False: Bundle à jour
    
    Critères de vérification
    ----------------------
    1. Existence de bundle.js
    2. Comparaison des timestamps:
        - Fichiers sources (src/)
        - Bundle (static/dist/bundle.js)
    
    Exemple d'utilisation
    --------------------
    ::

        if _check_build_status():
            _execute_build_process()
        else:
            print("Assets up-to-date")
    
    Note
    ----
    Le bundle est considéré périmé si :
        - Il n'existe pas
        - Un fichier source est plus récent
    """
    if not os.path.exists('static/dist/bundle.js'):
        return True
        
    _bundle_timestamp = os.path.getmtime('static/dist/bundle.js')
    _src_timestamp = _get_latest_modification_time('src')
    
    return _src_timestamp > _bundle_timestamp

def _execute_build_process():
    """
    Exécute le processus de build des assets front-end.
    
    Gère l'installation des dépendances npm et le build des assets
    avec gestion des erreurs et logging du processus.
    
    Processus de build
    -----------------
    1. Vérification si build nécessaire
    2. Installation npm si node_modules absent
    3. Exécution du build avec npm run build
    4. Logging des résultats et erreurs
    
    Actions exécutées
    ----------------
    - Installation npm: ``npm install``
    - Build process: ``npm run build``
    
    Exemple d'utilisation
    --------------------
    ::

        # Build automatique au démarrage
        _execute_build_process()
        
        # Build manuel si nécessaire
        if _check_build_status():
            _execute_build_process()
    
    Messages de statut
    -----------------
    - "[BUILD_STATUS]: Up-to-date"
    - "[NPM_INIT]: Installing dependencies"
    - "[BUILD_PROCESS]: Starting"
    - "[BUILD_PROCESS]: Success"
    - "[BUILD_ERROR]: {error}"
    - "[SYSTEM_ERROR]: {error}"
    
    Note
    ----
    Les erreurs sont capturées et loggées sans arrêter l'application.
    """
    try:
        if not _check_build_status():
            print("\n[BUILD_STATUS]: Up-to-date")
            return

        if not os.path.exists('node_modules'):
            print("\n[NPM_INIT]: Installing dependencies")
            subprocess.run(['npm', 'install'], check=True)

        print("\n[BUILD_PROCESS]: Starting")
        subprocess.run(['npm', 'run', 'build'], check=True)
        print("\n[BUILD_PROCESS]: Success")
    except subprocess.CalledProcessError as _err_ptr:
        print(f"\n[BUILD_ERROR]: {_err_ptr}")
    except Exception as _err_ptr:
        print(f"\n[SYSTEM_ERROR]: {_err_ptr}")

# Initialisation de l'application Flask
_APP = Flask(__name__, static_folder='static')

@_APP.before_request
def _init_system():
    """
    Middleware d'initialisation du système Flask.
    
    S'exécute avant chaque requête pour s'assurer que le système
    est correctement initialisé et que les assets sont à jour.
    
    Opérations réalisées
    -------------------
    - Vérification du flag d'initialisation
    - Build des assets front-end si nécessaire
    - Marquage du système comme initialisé
    
    Processus d'initialisation
    -------------------------
    1. Vérification de _sys_initialized sur l'app
    2. Si non initialisé :
        - Exécution du build process
        - Définition du flag d'initialisation
    
    Exemple d'utilisation
    --------------------
    ::

        @_APP.before_request
        def _init_system():
            if not hasattr(_APP, '_sys_initialized'):
                _execute_build_process()
                _APP._sys_initialized = True
    
    Note
    ----
    Utilise un flag sur l'objet app pour éviter les initialisations multiples.
    """
    if not hasattr(_APP, '_sys_initialized'):
        _execute_build_process()
        _APP._sys_initialized = True

@_APP.route('/')
def _serve_index():
    """
    Route principale servant la page d'accueil de l'application.
    
    Génère et retourne la page HTML principale à partir du template index.html.
    Cette route est le point d'entrée de l'interface utilisateur.
    
    Route
    -----
    GET /
        Point d'accès principal de l'application web
    
    Retourne
    --------
    str: Page HTML générée à partir du template index.html
    
    Template utilisé
    --------------
    - Fichier: index.html
    - Dossier: templates/
    
    Exemple d'utilisation
    --------------------
    ::

        @_APP.route('/')
        def _serve_index():
            return render_template('index.html')
    
    Note
    ----
    Aucune donnée n'est passée au template, le chargement des données
    se fait via des appels API JavaScript côté client.
    """
    return render_template('index.html')

@_APP.route('/fetch_data')
async def _handle_data_request():
    """
    Endpoint API pour la récupération des données CVE.
    
    Retourne les données CVE enrichies en utilisant le cache système.
    En cas d'erreur, retourne les dernières données valides du cache.
    
    Route
    -----
    GET /fetch_data
        Endpoint pour récupérer les CVEs enrichies
    
    Retourne
    --------
    Response: Réponse HTTP JSON contenant :
        - Liste des CVEs avec métadonnées
        - Données enrichies MITRE et EPSS
        - Scores et classifications
    
    Processus de traitement
    ----------------------
    1. Tentative de récupération via le cache
    2. Si échec du cache :
        - Nouvelle récupération avec _fetch_all_data
        - Mise en cache des nouvelles données
    3. En cas d'erreur :
        - Retour des dernières données valides
        - Si cache vide, retour liste vide
    
    Exemple d'utilisation
    --------------------
    ::

        # Appel API côté client
        fetch('/fetch_data')
            .then(response => response.json())
            .then(data => console.log(data))
    
    Note
    ----
    Les erreurs sont gérées silencieusement pour assurer
    la continuité du service même en cas de problème.
    """
    try:
        return jsonify(await _SYS_CACHE._get_or_fetch(_fetch_all_data))
    except Exception as _err_ptr:
        print(f"[DATA_ERROR]: {_err_ptr}")
        return jsonify(_SYS_CACHE._get_cache() or [])

async def _fetch_all_data():
    """
    Pipeline principal de récupération et traitement des données CVE.
    
    Implémente le pipeline complet de collecte, enrichissement et 
    normalisation des données CVE depuis les sources ANSSI.
    
    Retourne
    --------
    List[Dict]: Données CVE enrichies et normalisées contenant :
        - Métadonnées du bulletin ANSSI
        - Données MITRE (CVSS, CWE)
        - Scores EPSS
        - Classifications et métriques
    
    Sources de données
    ----------------
    Flux RSS ANSSI :
        - ``https://www.cert.ssi.gouv.fr/avis/feed``
        - ``https://www.cert.ssi.gouv.fr/alerte/feed``
    
    Pipeline de traitement
    --------------------
    1. Pré-calcul du nombre total de CVEs
    2. Allocation mémoire optimisée
    3. Pour chaque flux RSS:
        - Décodage et parsing du flux
        - Traitement des CVEs par lots
        - Enrichissement via MITRE et EPSS
    4. Consolidation et normalisation finale
    
    Exemple d'utilisation
    --------------------
    ::

        data = await _fetch_all_data()
        df = pd.DataFrame(data)
        print(f"Nombre de CVEs: {len(df)}")
    
    Note
    ----
    - Utilise une barre de progression pour le monitoring
    - Sauvegarde le DataFrame final en CSV pour analyse offline
    - Optimise la mémoire avec un traitement par chunks
    """
    # URLs des flux RSS de l'ANSSI
    _RSS_ADDR_ARRAY = [
        "https://www.cert.ssi.gouv.fr/avis/feed",
        "https://www.cert.ssi.gouv.fr/alerte/feed"
    ]
    
    # Pré-calcul du nombre total de CVEs pour allocation mémoire
    _total_cve_count = 0
    async with CVE_DataProcessor_Engine() as _engine_ptr:
        for _feed_addr in _RSS_ADDR_ARRAY:
            _feed_entries = _engine_ptr._decode_rss_stream(_feed_addr)
            _cve_blocks = await _engine_ptr._process_cve_batch(_feed_entries)
            _total_cve_count += len(_cve_blocks)
    
    print(f"\n[MEM_ALLOC]: Allocating for {_total_cve_count} CVEs\n")
    
    # Traitement principal avec barre de progression
    with tqdm(total=_total_cve_count, desc="[PROGRESS]") as _prog_bar:
        _task_queue = []
        for _feed_addr in _RSS_ADDR_ARRAY:
            _task_queue.append(_process_data_chunk(_feed_addr, _prog_bar))
        
        _df_chunks = await asyncio.gather(*_task_queue)
        _df_chunks = [_chunk for _chunk in _df_chunks if not _chunk.empty]
    
    if not _df_chunks:
        return []
    
    # Construction et optimisation du DataFrame final
    _result_df = pd.concat(_df_chunks, ignore_index=True)
    _result_df['Date de publication'] = pd.to_datetime(_result_df['Date de publication'])
    _result_df = _result_df.sort_values('Date de publication', ascending=False)
    _result_df['Date de publication'] = _result_df['Date de publication'].dt.strftime('%Y-%m-%d')
    
    # Nettoyage et standardisation des données
    for _col_ptr in ['Score CVSS', 'Type CWE', 'Base Severity', 'Score EPSS']:
        if _col_ptr not in _result_df.columns:
            _result_df[_col_ptr] = 'n/a'
    
    _result_df = _result_df.fillna('n/a')
    
    print("\n[DATA_FETCH]: Complete")
    # Sauvegarde pour analyse offline
    _result_df.to_csv('dataframe.csv', encoding='utf-8-sig')
    return _result_df.to_dict(orient='records')

async def _process_data_chunk(feed_addr: str, prog_monitor) -> pd.DataFrame:
    """
    Traite un chunk de données RSS et enrichit les CVEs associées.
    
    Implémente un pipeline de traitement multi-étages pour transformer
    et enrichir les données CVE d'un flux RSS spécifique.
    
    Paramètres
    ----------
    ``feed_addr`` (str): URL du flux RSS ANSSI à traiter
    ``prog_monitor`` (tqdm): Instance de la barre de progression
    
    Retourne
    --------
    pd.DataFrame: DataFrame enrichi contenant :
        - Métadonnées du bulletin
        - Données MITRE et EPSS
        - Scores et classifications
    
    Pipeline de traitement
    --------------------
    1. Décodage et parsing du flux RSS source
    2. Extraction des CVEs mentionnées
    3. Enrichissement parallèle :
        - Métadonnées MITRE
        - Scores EPSS
    4. Construction du DataFrame normalisé
    
    Structure de sortie
    -----------------
    ::

        DataFrame[
            "Titre du bulletin (ANSSI)",
            "Type de bulletin",
            "Date de publication",
            "Identifiant CVE",
            "Score CVSS",
            "Base Severity",
            "Type CWE",
            "Score EPSS",
            "Lien du bulletin (ANSSI)",
            "Description",
            "Éditeur",
            "Produit",
            "Versions affectées"
        ]
    
    Exemple d'utilisation
    -------------------
    ::

        with tqdm(total=total_cves) as progress:
            df = await _process_data_chunk(
                "https://www.cert.ssi.gouv.fr/avis/feed",
                progress
            )
            print(f"CVEs traitées: {len(df)}")
    
    Note
    ----
    Retourne un DataFrame vide en cas d'erreur ou si aucune CVE n'est trouvée.
    """
    async with CVE_DataProcessor_Engine() as _engine_ptr:
        # Stage 1: Décodage initial du flux RSS
        _feed_entries = _engine_ptr._decode_rss_stream(feed_addr)
        
        # Stage 2: Extraction des CVEs mentionnées
        _cve_blocks = await _engine_ptr._process_cve_batch(_feed_entries)
        if not _cve_blocks:
            return pd.DataFrame()
            
        # Stage 3: Préparation de l'enrichissement
        _cve_id_array = [_block['cve_id'] for _block in _cve_blocks]
        
        # Stage 3.1: Enrichissement parallèle MITRE/EPSS
        _mitre_data, _epss_data = await asyncio.gather(
            _engine_ptr._fetch_mitre_metadata(_cve_id_array),
            _engine_ptr._fetch_epss_scores(_cve_id_array)
        )
        
        # Stage 4: Construction du DataFrame enrichi
        _enriched_data = []
        for _cve_block in _cve_blocks:
            prog_monitor.update(1)  # Mise à jour de la barre de progression
            _cve_id = _cve_block['cve_id']
            _mitre_block = _mitre_data.get(_cve_id, {})
            
            # Construction de la ligne de données normalisée
            _data_row = {
                "Titre du bulletin (ANSSI)": _cve_block['title'],
                "Type de bulletin": _cve_block['type'],
                "Date de publication": _cve_block['date'],
                "Identifiant CVE": _cve_id,
                "Score CVSS": _mitre_block.get("cvss_score", "n/a"),
                "Base Severity": _compute_threat_vector(_mitre_block.get("cvss_score")),
                "Type CWE": _mitre_block.get("cwe_desc", "n/a"),
                "Score EPSS": str(_epss_data.get(_cve_id, "n/a")),
                "Lien du bulletin (ANSSI)": _cve_block['link'],
                "Description": _mitre_block.get("description", "n/a"),
                "Éditeur": _mitre_block.get("vendor", "n/a"),
                "Produit": _mitre_block.get("product", "n/a"),
                "Versions affectées": _mitre_block.get("versions", "n/a")
            }
            _enriched_data.append(_data_row)
        
        return pd.DataFrame(_enriched_data)

def _get_latest_modification_time(dir_path, ext=None):
    """
    Analyse récursive des timestamps de modification d'un répertoire.
    
    Parcourt un répertoire et ses sous-dossiers pour trouver le fichier 
    modifié le plus récemment, avec filtrage optionnel par extension.
    
    Paramètres
    ----------
    ``dir_path`` (str): Chemin du répertoire à analyser
    ``ext`` (str, optional): Extension de fichier à filtrer (ex: '.js')
    
    Retourne
    --------
    float: Timestamp Unix de la modification la plus récente
    
    Processus d'analyse
    -----------------
    1. Parcours récursif du répertoire (via Path.rglob)
    2. Filtrage optionnel par extension
    3. Extraction des timestamps de modification
    4. Sélection du timestamp le plus récent
    
    Exemple d'utilisation
    --------------------
    ::

        # Tous les fichiers
        ts = get_latest_modification_time('src/')
        
        # Uniquement les .js
        ts = get_latest_modification_time('src/', ext='.js')
    
    Note
    ----
    Retourne 0 si le répertoire est vide ou si aucun fichier
    ne correspond à l'extension demandée.
    """
    _latest_ts = 0
    for _path_ptr in Path(dir_path).rglob('*'):
        if ext is None or _path_ptr.suffix == ext:
            _latest_ts = max(_latest_ts, _path_ptr.stat().st_mtime)
    return _latest_ts

if __name__ == "__main__":
    """
    Point d'entrée principal de l'application web.
    
    Pour démarrer l'application en local, décommentez l'ensemble du bloc.
    Lance le build initial des assets et démarre le serveur Flask.
    
    Configuration serveur
    -------------------
    - Mode debug activé
    - Écoute sur toutes les interfaces (0.0.0.0)
    - Port 5000
    
    Pour utiliser
    ------------
    1. Décommentez ce bloc (retirez les "##")
    2. Exécutez le script : python main.py
    3. Accédez à http://localhost:5000
    
    Exemple d'utilisation
    --------------------
    Décommentez ces lignes pour lancer l'application en local::

        ## _execute_build_process() # Build initial des assets
        ^^
        ||
        ## _APP.run(debug=True, host="0.0.0.0", port=5000) # Démarrage du serveur
        ^^
        ||
    Sinon, décommentez cette ligne pour enregistrer l'ensemble des données dans un dataframe au format CSV::
        ## syncio.run(_fetch_all_data()) # Fichier de données consolidées
        ^^
        ||
    Note
    ----
    Le mode debug ne doit pas être activé en production.
    """
    ## _execute_build_process() # Build initial des assets
    ## _APP.run(debug=True, host="0.0.0.0", port=5000) # Démarrage du serveur

    ## asyncio.run(_fetch_all_data()) # Fichier de données consolidées