"""
Módulo para la verificación de seguridad de torrents.
"""
import os
from typing import Dict, List, Any, Optional
from .virustotal import VirusTotalChecker

class SecurityChecker:
    def __init__(self):
        # Lista básica de extensiones potencialmente peligrosas
        self.dangerous_extensions = {'.exe', '.bat', '.cmd', '.msi', '.vbs', '.scr'}
        # Inicializar VirusTotal checker
        self.vt_enabled = bool(os.getenv('VIRUSTOTAL_API_KEY'))

    async def check_security(self, torrent_info: Dict[str, Any], torrent_path: str) -> Dict[str, Any]:
        """
        Realiza verificaciones básicas de seguridad en la información del torrent.
        """
        security_report = {
            'risk_level': 'bajo',
            'warnings': [],
            'recommendations': [],
            'virustotal_results': None,
            'content_analysis': []
        }

        # Verificar el tamaño del archivo
        if torrent_info['file_size'] > 100_000_000:  # 100MB
            security_report['warnings'].append('Archivo torrent grande detectado')
            security_report['risk_level'] = 'medio'

        # Verificar extensiones peligrosas y analizar piezas
        piece_analysis = []
        for file_info in torrent_info['content_info']['files']:
            file_extension = self._get_file_extension(file_info['path'])
            
            piece_info = {
                'file_path': file_info['path'],
                'size': file_info['size'],
                'extension': file_extension,
                'risk_level': 'bajo',
                'warnings': [],
                'vt_results': []
            }

            if file_extension in self.dangerous_extensions:
                piece_info['warnings'].append('Extensión de archivo potencialmente peligrosa')
                piece_info['risk_level'] = 'alto'
                security_report['recommendations'].append(
                    f'Verificar cuidadosamente el origen del archivo: {file_info["path"]}'
                )

            # Verificar los hashes de las piezas con VirusTotal si están disponibles
            if self.vt_enabled and 'piece_hashes' in file_info and file_info['piece_hashes']:
                try:
                    vt_checker = VirusTotalChecker()
                    hashes_to_check = file_info['piece_hashes']
                    
                    # Limitar la cantidad de hashes a verificar para no sobrecargar la API
                    sample_size = min(len(hashes_to_check), 5)
                    sample_hashes = hashes_to_check[:sample_size]
                    
                    for piece_hash in sample_hashes:
                        vt_result = await vt_checker.check_hash(piece_hash)
                        if vt_result['status'] == 'completed':
                            piece_info['vt_results'].append(vt_result)
                            
                            if vt_result['risk_level'] == 'alto':
                                piece_info['risk_level'] = 'alto'
                                piece_info['warnings'].append(
                                    f'Pieza detectada como maliciosa por VirusTotal'
                                )
                            elif vt_result['risk_level'] == 'medio':
                                if piece_info['risk_level'] != 'alto':
                                    piece_info['risk_level'] = 'medio'
                                piece_info['warnings'].append(
                                    f'Pieza marcada como sospechosa por algunos antivirus'
                                )
                except Exception as e:
                    piece_info['warnings'].append(f'Error al verificar piezas con VirusTotal: {str(e)}')

            security_report['content_analysis'].append(piece_info)
            
            # Actualizar el nivel de riesgo general
            if piece_info['risk_level'] == 'alto' and security_report['risk_level'] != 'alto':
                security_report['risk_level'] = 'alto'
                security_report['warnings'].append(f'Contenido de alto riesgo detectado en: {file_info["path"]}')
            elif piece_info['risk_level'] == 'medio' and security_report['risk_level'] == 'bajo':
                security_report['risk_level'] = 'medio'

        # Verificar el archivo torrent completo con VirusTotal
        if self.vt_enabled:
            try:
                vt_checker = VirusTotalChecker()
                vt_results = await vt_checker.check_file(torrent_path)
                security_report['virustotal_results'] = vt_results

                if vt_results['status'] == 'completed':
                    if vt_results['risk_level'] == 'alto':
                        security_report['risk_level'] = 'alto'
                        security_report['warnings'].append(
                            f'El archivo torrent ha sido marcado como malicioso por múltiples antivirus'
                        )
                    elif vt_results['risk_level'] == 'medio' and security_report['risk_level'] == 'bajo':
                        security_report['risk_level'] = 'medio'
                        security_report['warnings'].append(
                            'El archivo torrent tiene algunas detecciones en VirusTotal'
                        )
                elif vt_results['status'] == 'pending':
                    security_report['warnings'].append('Archivo enviado a VirusTotal para análisis')
                    security_report['recommendations'].append(
                        f'Verificar resultados más tarde con el ID: {vt_results.get("analysis_id")}'
                    )
            except Exception as e:
                security_report['warnings'].append(f'Error al verificar con VirusTotal: {str(e)}')
                security_report['recommendations'].append('No se pudo completar la verificación de VirusTotal')

        return security_report

    def _get_file_extension(self, filename: str) -> str:
        """
        Obtiene la extensión de un archivo en minúsculas.
        """
        return filename[filename.rfind('.'):].lower() if '.' in filename else ''
