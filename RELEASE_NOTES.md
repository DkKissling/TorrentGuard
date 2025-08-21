# TorrentGuard v1.0.0 - Release Inicial

## 📦 Archivos Incluidos
- `TorrentGuard.exe` - Ejecutable para Windows
- `TorrentGuard-v1.0.0.zip` - Paquete completo con código fuente y ejecutable

## ✨ Características Principales
- Análisis profundo de archivos .torrent
- Sistema avanzado de verificación de trackers:
  - Evaluación individual de cada tracker
  - Sistema de puntuación de riesgo (0-100)
  - Detección de protocolos inseguros
  - Identificación de dominios sospechosos
- Integración con VirusTotal para detección de malware
- Base de datos actualizada de trackers seguros y maliciosos
- Sistema de caché para funcionamiento offline
- Reportes detallados de seguridad

## 🔧 Requisitos
- Windows 10/11
- Conexión a Internet para:
  - Análisis de VirusTotal
  - Actualización de base de datos de trackers
- API Key de VirusTotal (gratuita)

## 📝 Instrucciones de Instalación
1. Descarga `TorrentGuard.exe`
2. Crea un archivo `.env` en la misma carpeta que el ejecutable
3. Añade tu API key de VirusTotal en el archivo `.env`:
   ```
   VIRUSTOTAL_API_KEY=tu_api_key_aqui
   ```
4. Ejecuta el programa pasando un archivo torrent como argumento:
   ```
   TorrentGuard.exe "ruta/al/archivo.torrent"
   ```

## 🌟 Novedades en esta Versión
- Sistema avanzado de puntuación de riesgo para trackers
- Base de datos ampliada de trackers confiables
- Detección mejorada de trackers maliciosos
- Interfaz de usuario mejorada con información detallada
- Sistema de caché para funcionamiento offline

## ⚠️ Notas Importantes
- Algunos antivirus pueden mostrar falsos positivos debido a la naturaleza del programa
- El ejecutable está firmado digitalmente para garantizar su autenticidad
- Se recomienda descargar siempre desde la página oficial de releases

## 🐛 Problemas Conocidos
- Ninguno reportado hasta el momento

## 📜 Licencia
Este software se distribuye bajo la licencia GPL-2.0
