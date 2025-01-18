# ====================================
# CVE_THREAT_AGGREGATOR
# Module de récupération et traitement des CVE (Common Vulnerabilities and Exposures)
# Optimisé pour les performances I/O avec gestion asynchrone des requêtes
# Auteur: Non spécifié
# Version: 0.6
# ====================================

"""
Ce module implémente un agrégateur de vulnérabilités CVE avec les fonctionnalités suivantes:
    - Récupération asynchrone des flux RSS de l'ANSSI;
    - Enrichissement des données via les APIs MITRE et EPSS;
    - Mise en cache des données avec TTL (Time To Live);
    - Interface web Flask pour la visualisation;
    - Système de build automatisé pour les assets front-end.
"""

# ====================================
# BIBLIOTHÈQUES
# ====================================

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

_MAX_THREAD_POOL_SIZE = 500               # Limite maximale de connexions HTTP simultanées
_IO_TIMEOUT_MS = ClientTimeout(total=10)  # Timeout des requêtes HTTP en secondes
_MEM_CHUNK_SIZE = 100                     # Taille des lots pour le traitement par batch

def _compute_threat_vector(raw_cvss_ptr: str) -> str:
    """
    Convertit un score CVSS (Common Vulnerability Scoring System) en niveau de menace qualitatif.
    
    Le CVSS est un score numérique de 0 à 10 qui évalue la gravité d'une vulnérabilité.
    Cette fonction le traduit en catégories de risque plus facilement compréhensibles.
    
    Arguments:
        raw_cvss_ptr (str): Score CVSS brut à convertir
    
    Returns:
        str: Niveau de menace ('Faible', 'Moyenne', 'Élevée', 'Critique', ou 'n/a' en cas d'absence de score CVSS)
    
    Mapping des scores:
        - 0.0 à 3.9  -> Faible   (0x01)
        - 4.0 à 6.9  -> Moyenne  (0x02)
        - 7.0 à 8.9  -> Élevée   (0x03)
        - 9.0 à 10.0 -> Critique (0x04)
        - Erreur     -> n/a      (0xFF)
    """
    try:
        _threat_level_reg = float(raw_cvss_ptr)
        if _threat_level_reg <= 3:
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
    Moteur principal de traitement des CVE avec architecture pipeline et système de cache.
    
    Cette classe gère:
        - La récupération asynchrone des données CVE;
        - Le parsing des flux RSS de l'ANSSI;
        - L'enrichissement via les APIs MITRE et EPSS;
        - La mise en cache des données fréquemment accédées.
    
    Attributs:
        _net_io_handler (ClientSession): Gestionnaire de sessions HTTP;
        _thread_mutex (asyncio.Semaphore): Sémaphore pour limiter les connexions simultanées;
        _l1_mitre_cache (dict): Cache niveau 1 pour les données MITRE;
        _l1_epss_cache (dict): Cache niveau 1 pour les scores EPSS;
        _net_sock (aiohttp.TCPConnector): Connecteur TCP avec cache DNS.
    """

    def __init__(self):
        # Initialisation des registres système
        self._net_io_handler: ClientSession = None
        self._thread_mutex = asyncio.Semaphore(_MAX_THREAD_POOL_SIZE)
        self._l1_mitre_cache = {} # Cache des métadonnées MITRE
        self._l1_epss_cache = {}  # Cache des scores EPSS
        self._net_sock = None     # Socket réseau réutilisable

    async def __aenter__(self):
        """
        Initialise la session HTTP avec les paramètres optimaux:
            - Cache DNS activé pour réduire la latence;
            - Pool de connexions limité;
            - Headers HTTP standards;
            - SSL désactivé pour les performances (attention en production).
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
        Nettoyage des ressources réseau à la sortie du context manager.
        Ferme proprement la session HTTP pour éviter les fuites de ressources.
        """
        if self._net_io_handler:
            await self._net_io_handler.close()

    def _decode_rss_stream(self, feed_addr: str) -> List[Dict]:
        """
        Décode et parse un flux RSS pour en extraire les informations pertinentes.
        
        Cette méthode:
        1. Parse le flux RSS avec feedparser;
        2. Nettoie les titres en retirant les parenthèses;
        3. Extrait les métadonnées essentielles (titre, lien, type, date);
        4. Standardise le format des dates.
        
        Arguments:
            feed_addr (str): URL du flux RSS à parser
            
        Returns:
            List[Dict]: Liste de dictionnaires contenant les entrées du flux
                        avec les champs: title, link, type, date
        
        Note:
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
        Récupère des données depuis une API distante avec gestion des erreurs.
        
        Cette méthode implémente:
            - Limitation du nombre de requêtes simultanées via un sémaphore;
            - Gestion des timeouts et des erreurs réseau;
            - Décodage automatique du JSON.
        
        Arguments:
            target_addr (str): URL de l'API à interroger
            
        Returns:
            Dict: Données JSON récupérées ou dictionnaire vide en cas d'erreur
            
        Note:
            Utilise le sémaphore _thread_mutex pour éviter la surcharge du serveur distant
        """
        async with self._thread_mutex:
            try:
                async with self._net_io_handler.get(target_addr) as _resp_buf:
                    return await _resp_buf.json() if _resp_buf.status == 200 else {}
            except:
                return {}

    async def process_cve_batch(self, feed_entries: List[Dict]) -> List[Dict]:
        """
        Traite un lot de CVEs en parallèle en suivant une architecture pipeline.
        
        Pipeline de traitement:
        1. Extraction parallèle des CVEs depuis les URLs;
        2. Validation des données reçues;
        3. Enrichissement et normalisation des informations.
        
        Arguments:
            feed_entries (List[Dict]): Liste des entrées RSS à traiter
            
        Returns:
            List[Dict]: Liste des CVEs traitées avec leurs métadonnées
            
        Note:
            Utilise asyncio.gather pour le traitement parallèle optimal
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

    async def fetch_mitre_metadata(self, cve_id_array: List[str]) -> Dict:
        """
        Récupère les métadonnées MITRE pour une liste de CVEs avec système de cache.
        
        Fonctionnement:
        1. Vérifie les données présentes dans le cache L1;
        2. Récupère en parallèle les données manquantes;
        3. Met à jour le cache avec les nouvelles données;
        4. Retourne l'ensemble des données (cache + nouvelles).
        
        Arguments:
            cve_id_array (List[str]): Liste des identifiants CVE à rechercher
            
        Returns:
            Dict: Dictionnaire {cve_id: metadata} pour chaque CVE
            
        Optimisations:
            - Traitement par lots pour réduire la charge serveur;
            - Cache L1 pour éviter les requêtes redondantes;
            - Récupération parallèle des données manquantes.
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
        Traite et normalise un bloc de données MITRE.
        
        Cette méthode extrait les informations importantes d'un bloc de données MITRE:
            - Score CVSS et métriques associées;
            - Description de la vulnérabilité;
            - Type de vulnérabilité (CWE);
            - Informations sur le vendeur et le produit;
            - Versions affectées.
        
        Arguments:
            data_block (Dict): Bloc de données MITRE brut
            
        Returns:
            Dict: Données normalisées avec les champs standards
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

    async def fetch_epss_scores(self, cve_id_array: List[str]) -> Dict:
        """
        Récupère les scores EPSS (Exploit Prediction Scoring System) pour une liste de CVEs.
        
        L'EPSS est un système qui prédit la probabilité d'exploitation d'une vulnérabilité.
        
        Fonctionnalités:
            - Utilisation du cache L1 pour optimiser les requêtes;
            - Gestion des erreurs réseau;
            - Traitement en lot des CVEs.
        
        Arguments:
            cve_id_array (List[str]): Liste des identifiants CVE
            
        Returns:
            Dict: Dictionnaire {cve_id: epss_score} pour chaque CVE
            
        Note:
            Les scores sont normalisés entre 0 et 1, 'n/a' en cas d'absence de score EPSS ou d'erreur
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
    
    Fonctionnalités:
        - Stockage en mémoire avec durée de vie limitée;
        - Thread-safe avec verrous asyncio;
        - Validation automatique des données périmées.
    
    Attributs:
        _data_ptr: Données en cache
        _timestamp: Horodatage de dernière mise à jour
        _ttl: Durée de vie des données
        _mutex: Verrou pour accès concurrent
    """
    def __init__(self, ttl_min=60):
        """
        Initialise le cache avec une durée de vie en minutes.
        
        Arguments:
            ttl_min (int): Durée de vie en minutes (défaut: 60)
        """
        self._data_ptr = None
        self._timestamp = None
        self._ttl = timedelta(minutes=ttl_min)
        self._mutex = asyncio.Lock()

    def _check_validity(self):
        """
        Vérifie si les données en cache sont toujours valides.
        
        Returns:
            bool: True si les données sont valides, False sinon
        """
        if not self._data_ptr or not self._timestamp:
            return False
        return datetime.now() - self._timestamp < self._ttl

    def _update_cache(self, new_data):
        """
        Met à jour le cache avec de nouvelles données.
        
        Arguments:
            new_data: Nouvelles données à mettre en cache
        """
        self._data_ptr = new_data
        self._timestamp = datetime.now()

    def _get_cache(self):
        """
        Récupère les données du cache.
        
        Returns:
            Les données en cache ou None si vide
        """
        return self._data_ptr

    async def get_or_fetch(self, fetch_func):
        """
        Récupère les données du cache ou les actualise si nécessaire.
        
        Cette méthode est thread-safe grâce au mutex asyncio.
        
        Arguments:
            fetch_func: Fonction asynchrone à appeler pour actualiser les données
            
        Returns:
            Les données du cache (existantes ou nouvellement récupérées)
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
    
    Cette fonction compare les timestamps des fichiers sources et du bundle
    pour déterminer si une reconstruction est requise.
    
    Returns:
        bool: True si une reconstruction est nécessaire, False sinon
    """
    if not os.path.exists('static/dist/bundle.js'):
        return True
        
    _bundle_timestamp = os.path.getmtime('static/dist/bundle.js')
    _src_timestamp = get_latest_modification_time('src')
    
    return _src_timestamp > _bundle_timestamp

def _execute_build_process():
    """
    Exécute le processus de build des assets front-end.
    
    Cette fonction:
    1. Vérifie si une reconstruction est nécessaire;
    2. Installe les dépendances npm si nécessaire;
    3. Lance le processus de build;
    4. Gère les erreurs potentielles.
    
    Les erreurs sont capturées et loggées pour le debugging.
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
    Middleware d'initialisation du système.
    
    Cette fonction est exécutée avant chaque requête et assure:
        - L'initialisation unique du système au premier démarrage;
        - La reconstruction des assets si nécessaire.
    
    Note:
        Utilise un flag sur l'objet app pour éviter les initialisations multiples
    """
    if not hasattr(_APP, '_sys_initialized'):
        _execute_build_process()
        _APP._sys_initialized = True

@_APP.route('/')
def _serve_index():
    """
    Route principale servant la page d'accueil.
    
    Returns:
        str: Page HTML générée à partir du template index.html
    """
    return render_template('index.html')

@_APP.route('/fetch_data')
async def _handle_data_request():
    """
    Endpoint API pour la récupération des données CVE.
    
    Cette route:
    1. Utilise le cache système pour optimiser les performances;
    2. Déclenche la récupération des données si nécessaire;
    3. Gère les erreurs de manière gracieuse.
    
    Returns:
        Response: Données JSON contenant les CVEs
        
    Note:
        En cas d'erreur, retourne les dernières données valides du cache
    """
    try:
        return jsonify(await _SYS_CACHE.get_or_fetch(_fetch_all_data))
    except Exception as _err_ptr:
        print(f"[DATA_ERROR]: {_err_ptr}")
        return jsonify(_SYS_CACHE._get_cache() or [])

async def _fetch_all_data():
    """
    Pipeline principal de récupération et traitement des données CVE.
    
    Ce pipeline:
    1. Parse les flux RSS de l'ANSSI;
    2. Extrait les CVEs pertinentes;
    3. Enrichit les données via MITRE et EPSS;
    4. Construit un DataFrame normalisé.
    
    Architecture:
        - Traitement asynchrone pour optimiser les performances;
        - Gestion de la mémoire par chunks;
        - Monitoring de la progression.
    
    Returns:
        list: Liste des CVEs enrichies au format dictionnaire
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
            _cve_blocks = await _engine_ptr.process_cve_batch(_feed_entries)
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
    _result_df.to_csv('dataframe.csv')
    return _result_df.to_dict(orient='records')

async def _process_data_chunk(feed_addr: str, prog_monitor) -> pd.DataFrame:
    """
    Traite un chunk de données RSS et enrichit les CVEs associées.
    
    Cette fonction implémente un pipeline de traitement en plusieurs étages:
    1. Décodage du flux RSS source;
    2. Extraction des CVEs mentionnées;
    3. Enrichissement parallèle via MITRE et EPSS;
    4. Construction d'un DataFrame normalisé.
    
    Arguments:
        feed_addr (str): URL du flux RSS à traiter
        prog_monitor: Instance de tqdm pour le suivi de progression
        
    Returns:
        pd.DataFrame: DataFrame contenant les CVEs enrichies
    """
    async with CVE_DataProcessor_Engine() as _engine_ptr:
        # Stage 1: Décodage initial du flux RSS
        _feed_entries = _engine_ptr._decode_rss_stream(feed_addr)
        
        # Stage 2: Extraction des CVEs mentionnées
        _cve_blocks = await _engine_ptr.process_cve_batch(_feed_entries)
        if not _cve_blocks:
            return pd.DataFrame()
            
        # Stage 3: Préparation de l'enrichissement
        _cve_id_array = [_block['cve_id'] for _block in _cve_blocks]
        
        # Stage 3.1: Enrichissement parallèle MITRE/EPSS
        _mitre_data, _epss_data = await asyncio.gather(
            _engine_ptr.fetch_mitre_metadata(_cve_id_array),
            _engine_ptr.fetch_epss_scores(_cve_id_array)
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

def get_latest_modification_time(dir_path, ext=None):
    """
    Analyse récursive des timestamps de modification d'un répertoire.
    
    Cette fonction parcourt récursivement un répertoire pour trouver
    le fichier modifié le plus récemment, avec filtrage optionnel par extension.
    
    Arguments:
        dir_path (str): Chemin du répertoire à analyser
        ext (str, optional): Extension de fichier à filtrer
        
    Returns:
        float: Timestamp de la modification la plus récente
    """
    _latest_ts = 0
    for _path_ptr in Path(dir_path).rglob('*'):
        if ext is None or _path_ptr.suffix == ext:
            _latest_ts = max(_latest_ts, _path_ptr.stat().st_mtime)
    return _latest_ts

if __name__ == "__main__":
    # Point d'entrée principal de l'application
    _execute_build_process() # Build initial des assets
    _APP.run(debug=True, host="0.0.0.0", port=5000) # Démarrage du serveur