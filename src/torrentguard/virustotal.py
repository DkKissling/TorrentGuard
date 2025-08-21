"""
Módulo para la integración con VirusTotal.
"""
import vt
import hashlib
import os
import asyncio
from typing import Dict, Any, Optional
from datetime import datetime

class VirusTotalChecker:
    def __init__(self, api_key: Optional[str] = None):
        """
        Inicializa el checker de VirusTotal.
        Si no se proporciona api_key, intentará obtenerla de la variable de entorno VIRUSTOTAL_API_KEY
        """
        self.api_key = api_key or os.getenv('VIRUSTOTAL_API_KEY')
        if not self.api_key:
            raise ValueError("Se requiere una API key de VirusTotal. Configúrala en la variable de entorno VIRUSTOTAL_API_KEY")
        self._client = None

    @property
    def client(self):
        if self._client is None:
            self._client = vt.Client(self.api_key)
        return self._client

    async def close(self):
        """Cierra el cliente de forma segura."""
        if self._client is not None:
            await self._client.close_async()
            self._client = None

    async def check_file(self, file_path: str) -> Dict[str, Any]:
        """
        Verifica un archivo usando VirusTotal.
        """
        try:
            # Calcular el hash SHA-256 del archivo
            sha256_hash = self._calculate_file_hash(file_path)
            
            try:
                # Primero intentamos buscar el archivo por su hash
                file_report = await self.client.get_object_async(f"/files/{sha256_hash}")
                return self._process_report(file_report)
            except vt.error.NotFoundError:
                # Si el archivo no está en VT, lo subimos
                with open(file_path, 'rb') as f:
                    analysis = await self.client.scan_file_async(f)
                    return {
                        'status': 'pending',
                        'message': 'Archivo enviado para análisis',
                        'analysis_id': analysis.id
                    }
        except Exception as e:
            return {
                'status': 'error',
                'message': f'Error al verificar con VirusTotal: {str(e)}',
                'error': str(e)
            }
        finally:
            await self.close()

    async def check_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Verifica un hash en VirusTotal.
        """
        try:
            try:
                file_report = await self.client.get_object_async(f"/files/{file_hash}")
                return self._process_report(file_report)
            except vt.error.NotFoundError:
                return {
                    'status': 'not_found',
                    'message': 'Hash no encontrado en VirusTotal'
                }
        except Exception as e:
            return {
                'status': 'error',
                'message': f'Error al verificar con VirusTotal: {str(e)}',
                'error': str(e)
            }
        finally:
            await self.close()

    def _calculate_file_hash(self, file_path: str) -> str:
        """
        Calcula el hash SHA-256 de un archivo.
        """
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def _process_report(self, report: Any) -> Dict[str, Any]:
        """
        Procesa el reporte de VirusTotal.
        """
        try:
            stats = report.last_analysis_stats
            total_scans = sum(stats.values())
            malicious = stats.get('malicious', 0)

            result = {
                'status': 'completed',
                'analysis_stats': stats,
                'scan_date': report.last_analysis_date,
                'community_reputation': report.reputation if hasattr(report, 'reputation') else None,
                'file_type': report.type_description if hasattr(report, 'type_description') else None,
                'names': report.names if hasattr(report, 'names') else [],
                'analysis_results': {},
                'risk_level': 'bajo'
            }

            # Procesar resultados individuales
            if hasattr(report, 'last_analysis_results'):
                for vendor, analysis in report.last_analysis_results.items():
                    result['analysis_results'][vendor] = {
                        'category': analysis.get('category', 'unknown'),
                        'result': analysis.get('result', 'N/A')
                    }

            # Evaluar nivel de riesgo
            if malicious > 0:
                percentage = (malicious / total_scans) * 100
                if percentage > 30:
                    result['risk_level'] = 'alto'
                elif percentage > 10:
                    result['risk_level'] = 'medio'

            return result
        except Exception as e:
            return {
                'status': 'error',
                'message': f'Error al procesar el reporte: {str(e)}',
                'error': str(e)
            }
