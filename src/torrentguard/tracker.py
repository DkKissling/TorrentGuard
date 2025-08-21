"""
Módulo para verificar la reputación de trackers.
"""
import re
import json
import aiohttp
import asyncio
from typing import Dict, List, Any, Set
from urllib.parse import urlparse
from datetime import datetime, timedelta
import os

class TrackerChecker:
    def __init__(self):
        self.cache_file = "tracker_cache.json"
        self.cache_duration = timedelta(days=7)  # Actualizar la cache cada 7 días
        
        # Constantes para el sistema de puntuación
        self.RISK_SCORES = {
            'NO_SSL': 30,              # Sin HTTPS
            'SUSPICIOUS_TLD': 40,      # TLDs sospechosos
            'BLACKLISTED': 100,        # En lista negra
            'SUSPICIOUS_KEYWORDS': 50,  # Palabras clave sospechosas
            'NOT_IN_WHITELIST': 20,    # No está en listas blancas conocidas
            'POOR_UPTIME': 15,         # Baja disponibilidad
        }
        
        self.SUSPICIOUS_TLDS = {
            'su', 'ru', 'cc', 'ws', 'biz', 'download', 'party', 'gdn', 'bid'
        }
        
        self.SUSPICIOUS_KEYWORDS = {
            'warez', 'crack', 'hack', 'pirate', 'malware', 'trojan',
            'keygen', 'adware', 'spyware', 'virus', 'botnet'
        }
        
        # Inicializar las listas base
        self._init_default_lists()
        
        # Intentar cargar la caché o actualizar desde fuentes en línea
        self._load_cache()
        
    def _init_default_lists(self):
        """Inicializa las listas por defecto de trackers"""
        # Lista blanca de trackers confiables
        self.trusted_trackers = set([
            'tracker.opentrackr.org', 'exodus.desync.com', 'open.stealth.si',
            'tracker.torrent.eu.org', 'tracker.openbittorrent.com', 'tracker.publicbt.com',
            'tracker.internetwarriors.net', 'academictorrents.com', 'bt.archlinux.org',
            'tracker.debian.org', 'tracker.ubuntu.com', 'linuxtracker.org',
            'tracker.legittorrents.info', 'bt.etree.org', 'tracker.wikimedia.org',
            'tracker.documentfoundation.org', 'torrent.fedoraproject.org',
            'tracker.gnome.org', 'tracker.kde.org', 'tracker.apache.org'
        ])
        
        # Lista negra de trackers conocidos como maliciosos
        self.blacklisted_trackers = set([
            'malware-tracker.com', 'suspicious-tracker.com', 'warez-tracker.net',
            'pirate-tracker.org', 'hack-tracker.com', 'trojan-tracker.net',
            'adware-tracker.com', 'spyware-tracker.net', 'malicious-tracker.org'
        ])
        
        # Diccionario para almacenar métricas de trackers
        self.tracker_metrics = {}

    def _load_cache(self) -> None:
        """Carga la cache de trackers o la inicializa si no existe."""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    cache_data = json.load(f)
                    if datetime.fromisoformat(cache_data['last_update']) + self.cache_duration > datetime.now():
                        self.trusted_trackers = set(cache_data['trusted'])
                        self.suspicious_trackers = set(cache_data['suspicious'])
                        return
        except Exception:
            pass
            
        # Si la cache está expirada o no existe, intentar actualizar desde fuentes en línea
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Si ya hay un event loop corriendo, usarlo
                loop.create_task(self._update_tracker_lists())
            else:
                # Si no hay event loop, crear uno nuevo
                asyncio.run(self._update_tracker_lists())
        except Exception as e:
            print(f"Error al actualizar listas de trackers online: {e}")
            
    async def _update_tracker_lists(self) -> None:
        """Actualiza las listas de trackers desde fuentes en línea."""
        sources = [
            'https://newtrackon.com/api/stable',  # Lista de trackers estables
            'https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_best.txt',  # Lista de mejores trackers
            'https://raw.githubusercontent.com/XIU2/TrackersListCollection/master/best.txt'  # Otra lista curada
        ]

        async with aiohttp.ClientSession() as session:
            for source in sources:
                try:
                    async with session.get(source) as response:
                        if response.status == 200:
                            content = await response.text()
                            # Procesar según el formato de la fuente
                            if source.endswith('.txt'):
                                trackers = {self._extract_domain(t) for t in content.split('\n') if t.strip()}
                            else:  # API JSON
                                data = await response.json()
                                trackers = {self._extract_domain(t['url']) for t in data if t.get('url')}
                            
                            self.trusted_trackers.update(trackers)
                except Exception as e:
                    print(f"Error al actualizar lista de trackers desde {source}: {e}")

        # Guardar en cache
        cache_data = {
            'last_update': datetime.now().isoformat(),
            'trusted': list(self.trusted_trackers),
            'suspicious': list(self.suspicious_trackers)
        }
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(cache_data, f)
        except Exception as e:
            print(f"Error al guardar cache de trackers: {e}")
            
    async def check_tracker_safety(self, tracker_url: str) -> dict:
        """
        Analiza la seguridad de un tracker y retorna un informe detallado.
        
        Returns:
            dict: {
                'is_safe': bool,
                'risk_score': int,
                'risk_level': str,
                'reasons': list,
                'recommendations': list
            }
        """
        from .tracker_risk import check_domain_reputation, calculate_risk_score
        
        domain = self._extract_domain(tracker_url)
        if not domain:
            return {
                'is_safe': False,
                'risk_score': 100,
                'risk_level': 'Alto',
                'reasons': ['URL de tracker inválida'],
                'recommendations': ['Verificar la URL del tracker']
            }
        
        # Verificar si está en la lista negra
        if domain in self.blacklisted_trackers:
            return {
                'is_safe': False,
                'risk_score': 100,
                'risk_level': 'Crítico',
                'reasons': ['Tracker en lista negra conocida'],
                'recommendations': ['Evitar el uso de este tracker']
            }
        
        # Verificar si está en la lista blanca
        if domain in self.trusted_trackers:
            return {
                'is_safe': True,
                'risk_score': 0,
                'risk_level': 'Bajo',
                'reasons': ['Tracker en lista blanca verificada'],
                'recommendations': []
            }
        
        # Obtener métricas del tracker
        if domain not in self.tracker_metrics:
            self.tracker_metrics[domain] = await check_domain_reputation(domain)
        
        # Calcular puntuación de riesgo
        risk_score, reasons = calculate_risk_score(
            domain,
            self.tracker_metrics[domain],
            {
                'NO_SSL': self.RISK_SCORES['NO_SSL'],
                'SUSPICIOUS_TLD': self.RISK_SCORES['SUSPICIOUS_TLD'],
                'SUSPICIOUS_KEYWORDS': self.RISK_SCORES['SUSPICIOUS_KEYWORDS'],
                'POOR_UPTIME': self.RISK_SCORES['POOR_UPTIME'],
                'SUSPICIOUS_TLDS': self.SUSPICIOUS_TLDS,
                'SUSPICIOUS_KEYWORDS': self.SUSPICIOUS_KEYWORDS
            }
        )
        
        # Determinar nivel de riesgo
        risk_level = 'Bajo' if risk_score < 30 else 'Medio' if risk_score < 60 else 'Alto'
        
        # Generar recomendaciones
        recommendations = []
        if risk_score >= 30:
            recommendations.append('Investigar la reputación del tracker antes de usar')
        if not self.tracker_metrics[domain].get('ssl_valid'):
            recommendations.append('Preferir trackers que usen HTTPS')
        if risk_score >= 60:
            recommendations.append('Considerar usar un tracker alternativo de la lista de confianza')
        
        return {
            'is_safe': risk_score < 50,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'reasons': reasons,
            'recommendations': recommendations
        }

    def check_trackers(self, trackers: List[str]) -> Dict[str, Any]:
        """
        Analiza la reputación de los trackers proporcionados.
        """
        results = {
            'trusted_trackers': [],
            'unknown_trackers': [],
            'suspicious_trackers': [],
            'overall_risk': 'bajo',
            'recommendations': []
        }

        if not trackers:
            results['recommendations'].append('No se encontraron trackers. Esto podría ser un DHT torrent.')
            results['overall_risk'] = 'medio'
            return results

        for tracker in trackers:
            try:
                domain = self._extract_domain(tracker)
                if domain in self.trusted_trackers:
                    results['trusted_trackers'].append(tracker)
                elif domain in self.suspicious_trackers:
                    results['suspicious_trackers'].append(tracker)
                else:
                    results['unknown_trackers'].append(tracker)
            except Exception:
                results['unknown_trackers'].append(tracker)

        # Evaluar el riesgo general
        self._evaluate_overall_risk(results)
        
        return results

    def _extract_domain(self, url: str) -> str:
        """
        Extrae el dominio de una URL de tracker.
        """
        try:
            # Limpiar la URL
            url = url.strip().lower()
            if not url.startswith(('http://', 'https://', 'udp://')):
                url = 'http://' + url

            parsed = urlparse(url)
            domain = parsed.netloc

            # Remover el puerto si existe
            if ':' in domain:
                domain = domain.split(':')[0]

            return domain
        except Exception as e:
            raise ValueError(f"URL de tracker inválida: {url}")

    def _evaluate_overall_risk(self, results: Dict[str, Any]) -> None:
        """
        Evalúa el nivel general de riesgo basado en los trackers encontrados.
        """
        total_trackers = len(results['trusted_trackers']) + \
                        len(results['unknown_trackers']) + \
                        len(results['suspicious_trackers'])

        if len(results['suspicious_trackers']) > 0:
            results['overall_risk'] = 'alto'
            results['recommendations'].append(
                'Se detectaron trackers sospechosos conocidos por distribuir malware.'
            )
        elif len(results['trusted_trackers']) == 0:
            if total_trackers > 0:
                results['overall_risk'] = 'medio'
                results['recommendations'].append(
                    'No se encontraron trackers confiables conocidos en la lista.'
                )
        elif len(results['unknown_trackers']) > 3 * len(results['trusted_trackers']):
            results['overall_risk'] = 'medio'
            results['recommendations'].append(
                'La mayoría de los trackers no están en nuestra base de datos de trackers confiables.'
            )

        if total_trackers > 20:
            results['recommendations'].append(
                'Se detectó una cantidad inusualmente alta de trackers. Esto podría indicar un intento de maximizar la distribución.'
            )

        # Agregar recomendaciones específicas
        if results['trusted_trackers']:
            tracker_list = '\n- ' + '\n- '.join(results['trusted_trackers'][:3])
            results['recommendations'].append(
                f'Trackers confiables detectados (top 3):{tracker_list}'
            )

    async def check_tracker_status(self, tracker: str) -> Dict[str, Any]:
        """
        Verifica si un tracker está en línea y responde.
        """
        try:
            if tracker.startswith('udp://'):
                return {'status': 'unknown', 'message': 'UDP trackers requieren un protocolo específico para verificación'}

            async with aiohttp.ClientSession() as session:
                try:
                    async with session.head(tracker, timeout=5) as response:
                        return {
                            'status': 'online' if response.status < 400 else 'offline',
                            'response_code': response.status
                        }
                except asyncio.TimeoutError:
                    return {'status': 'offline', 'message': 'Timeout al conectar con el tracker'}
                except Exception as e:
                    return {'status': 'offline', 'message': f'Error al conectar: {str(e)}'}
        except Exception as e:
            return {'status': 'error', 'message': f'Error al verificar tracker: {str(e)}'}