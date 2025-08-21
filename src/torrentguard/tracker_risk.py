"""
Módulo para evaluar el riesgo de trackers
"""
import ssl
import socket
from urllib.parse import urlparse
import aiohttp
import asyncio
from typing import Tuple, Dict, Any

async def check_ssl(domain: str) -> bool:
    """Verifica si el dominio soporta SSL/TLS."""
    try:
        context = ssl.create_default_context()
        async with aiohttp.ClientSession() as session:
            async with session.get(f'https://{domain}', ssl=context, timeout=5) as response:
                return True
    except:
        return False

async def check_domain_reputation(domain: str) -> Dict[str, Any]:
    """
    Verifica la reputación del dominio usando servicios externos.
    Retorna un diccionario con métricas de reputación.
    """
    metrics = {
        'age_days': 0,
        'ssl_valid': False,
        'response_time': 0,
        'last_checked': None,
        'uptime_percentage': 0
    }
    
    try:
        # Verificar SSL
        metrics['ssl_valid'] = await check_ssl(domain)
        
        # Verificar tiempo de respuesta
        start_time = asyncio.get_event_loop().time()
        async with aiohttp.ClientSession() as session:
            async with session.get(f'http://{domain}', timeout=5) as response:
                metrics['response_time'] = asyncio.get_event_loop().time() - start_time
                metrics['last_checked'] = response.headers.get('date')
    except:
        pass
    
    return metrics

def calculate_risk_score(domain: str, metrics: Dict[str, Any], risk_config: Dict[str, int]) -> Tuple[int, list]:
    """
    Calcula una puntuación de riesgo para un tracker basado en varios factores.
    Retorna una tupla con (puntuación, lista_de_razones).
    """
    score = 0
    reasons = []
    
    # Verificar SSL
    if not metrics.get('ssl_valid', False):
        score += risk_config['NO_SSL']
        reasons.append("No usa HTTPS")
    
    # Verificar TLD sospechoso
    tld = domain.split('.')[-1]
    if tld in risk_config.get('SUSPICIOUS_TLDS', []):
        score += risk_config['SUSPICIOUS_TLD']
        reasons.append(f"TLD sospechoso (.{tld})")
    
    # Verificar palabras clave sospechosas
    for keyword in risk_config.get('SUSPICIOUS_KEYWORDS', []):
        if keyword in domain:
            score += risk_config['SUSPICIOUS_KEYWORDS']
            reasons.append(f"Palabra clave sospechosa ({keyword})")
            break
    
    # Verificar tiempo de respuesta
    response_time = metrics.get('response_time', float('inf'))
    if response_time > 2.0:  # más de 2 segundos
        score += risk_config['POOR_UPTIME']
        reasons.append("Tiempo de respuesta alto")
    
    return score, reasons
