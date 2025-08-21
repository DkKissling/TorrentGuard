"""
TorrentGuard main module.
"""
import sys
import asyncio
import os
from typing import Any, Dict
from torrentguard.env_loader import load_env
from torrentguard.analyzer import TorrentAnalyzer
from torrentguard.security import SecurityChecker
from torrentguard.tracker import TrackerChecker

# Cargar variables de entorno desde .env
if not load_env():
    print("\n⚠️ No se encontró el archivo .env con la API key de VirusTotal")
    print("Por favor, sigue las instrucciones en README.txt para configurar tu API key\n")

def format_size(size_bytes: float) -> str:
    """Convierte bytes a una forma legible."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"

async def analyze_torrent(torrent_path: str) -> Dict[str, Any]:
    """Analiza un archivo torrent y retorna la información completa."""
    print("Analizando archivo torrent...")
    analyzer = TorrentAnalyzer(torrent_path)
    result = analyzer.analyze_file()
    print("Análisis básico completado.")
    return result

async def check_security(torrent_info: Dict[str, Any], torrent_path: str) -> Dict[str, Any]:
    """Realiza verificaciones de seguridad en el torrent."""
    print("Iniciando verificaciones de seguridad...")
    checker = SecurityChecker()
    result = await checker.check_security(torrent_info, torrent_path)
    print("Verificaciones de seguridad completadas.")
    return result

async def analyze_trackers(trackers: list) -> Dict[str, Any]:
    """Analiza los trackers del torrent y su nivel de riesgo."""
    print("\nAnalizando trackers...")
    checker = TrackerChecker()
    results = []
    
    for tracker in trackers:
        print(f"Analizando tracker: {tracker}")
        result = await checker.check_tracker_safety(tracker)
        results.append({
            'url': tracker,
            'safety_info': result
        })
    
    print("Análisis de trackers completado.")
    return {'trackers': results}

async def main():
    """Main entry point for the application."""
    print("\n=== TorrentGuard v1.0.0 ===\n")
    
    if len(sys.argv) < 2:
        print("Uso: python main.py <ruta_del_torrent>")
        sys.exit(1)
    
    torrent_path = sys.argv[1]
    print(f"Analizando: {torrent_path}")

    if not os.path.exists(torrent_path):
        print(f"Error: El archivo {torrent_path} no existe")
        sys.exit(1)

    try:
        # Analizar el archivo torrent
        print("\nIniciando análisis completo...")
        torrent_info = await analyze_torrent(torrent_path)
        
        print("\n=== Información del Archivo ===")
        print(f"Nombre: {torrent_info['file_name']}")
        print(f"Tamaño del archivo .torrent: {format_size(torrent_info['file_size'])}")
        print(f"Hash SHA-256: {torrent_info['file_hash']}")
        
        # Mostrar información del contenido
        content_info = torrent_info['content_info']
        print(f"\nNombre del contenido: {content_info['name']}")
        print(f"Tamaño total del contenido: {format_size(content_info['total_size'])}")
        print(f"Número de archivos: {len(content_info['files'])}")
        
        if len(content_info['files']) <= 5:
            print("\nArchivos:")
            for file in content_info['files']:
                print(f"- {file['path']} ({format_size(file['size'])})")
        else:
            print(f"\nPrimeros 5 archivos de {len(content_info['files'])}:")
            for file in content_info['files'][:5]:
                print(f"- {file['path']} ({format_size(file['size'])})")
        
        # Mostrar información de creación
        creation_info = torrent_info['creation_info']
        print("\n=== Información de Creación ===")
        if creation_info['created_by']:
            print(f"Creado por: {creation_info['created_by']}")
        if creation_info['creation_date']:
            print(f"Fecha de creación: {creation_info['creation_date']}")
        if creation_info['comment']:
            print(f"Comentario: {creation_info['comment']}")
        
        # Verificar trackers
        tracker_report = await analyze_trackers(torrent_info['tracker_info'])
        
        print("\n=== Análisis de Trackers ===")
        for tracker_info in tracker_report['trackers']:
            safety = tracker_info['safety_info']
            print(f"\nTracker: {tracker_info['url']}")
            print(f"Nivel de riesgo: {safety['risk_level']}")
            print(f"Puntuación de riesgo: {safety['risk_score']}/100")
            
            if safety['reasons']:
                print("Razones:")
                for reason in safety['reasons']:
                    print(f"- {reason}")
            
            if safety['recommendations']:
                print("Recomendaciones:")
                for rec in safety['recommendations']:
                    print(f"- {rec}")
        
        # Verificar la seguridad general
        print("\nIniciando verificación de seguridad...")
        security_report = await check_security(torrent_info, torrent_path)
        
        print("\n=== Reporte de Seguridad ===")
        print(f"Nivel de riesgo general: {security_report['risk_level'].upper()}")
        
        if security_report['warnings']:
            print("\nAdvertencias:")
            for warning in security_report['warnings']:
                print(f"- {warning}")
        
        if security_report['recommendations']:
            print("\nRecomendaciones de seguridad:")
            for rec in security_report['recommendations']:
                print(f"- {rec}")
        
        # Mostrar resultados de VirusTotal si están disponibles
        if security_report.get('virustotal_results'):
            vt_results = security_report['virustotal_results']
            if vt_results['status'] == 'completed':
                print("\n=== Resultados de VirusTotal ===")
                stats = vt_results.get('analysis_stats', {})
                total = sum(stats.values()) if stats else 0
                malicious = stats.get('malicious', 0) if stats else 0
                print(f"Detecciones: {malicious}/{total} antivirus")
                
                if vt_results.get('community_reputation') is not None:
                    print(f"Puntuación de la comunidad: {vt_results['community_reputation']}")
                if vt_results.get('file_type'):
                    print(f"Tipo de archivo: {vt_results['file_type']}")
                
                if vt_results.get('analysis_results'):
                    print("\nDetecciones principales:")
                    shown = 0
                    for vendor, result in vt_results['analysis_results'].items():
                        if result['category'] in ['malicious', 'suspicious']:
                            print(f"- {vendor}: {result['result']}")
                            shown += 1
                            if shown >= 5:  # Mostrar solo las 5 primeras detecciones
                                break
            elif vt_results['status'] == 'pending':
                print("\n=== VirusTotal ===")
                print("El archivo ha sido enviado para análisis. Verifica más tarde con el ID:", vt_results.get('analysis_id'))

        # Mostrar conclusión
        print("\n=== Conclusión ===")
        if security_report['risk_level'] == 'alto':
            print("⚠️  ¡PRECAUCIÓN! Se han detectado riesgos significativos.")
            print("     Se recomienda NO descargar este torrent.")
        elif security_report['risk_level'] == 'medio':
            print("⚠️  Se han detectado algunos riesgos potenciales.")
            print("     Proceda con precaución y revise todas las advertencias.")
        else:
            print("✅ No se han detectado riesgos significativos.")
            print("   Sin embargo, siempre descargue contenido bajo su propia responsabilidad.")
                
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except ValueError as e:
        print(f"Error al procesar el archivo: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error inesperado: {e}")
        print(f"Detalles del error: {str(e)}")
        sys.exit(1)

def pause_console():
    """Pausa la consola y espera input del usuario."""
    print("\nPresiona Enter para cerrar...")
    try:
        input()
    except:
        pass

if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(main())
    finally:
        # Siempre pausar al final, sin importar si hubo error o no
        pause_console()
