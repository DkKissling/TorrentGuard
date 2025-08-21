"""
Módulo para cargar variables de entorno.
"""
import os
from pathlib import Path

def load_env():
    """
    Carga las variables de entorno desde el archivo .env
    Busca el archivo .env en:
    1. La carpeta del ejecutable
    2. La carpeta actual
    3. La carpeta del script
    """
    env_locations = [
        # Carpeta del ejecutable (cuando se usa como .exe)
        os.path.dirname(os.path.abspath(os.sys.executable)),
        # Carpeta actual
        os.getcwd(),
        # Carpeta del script
        os.path.dirname(os.path.abspath(__file__))
    ]

    for location in env_locations:
        env_path = os.path.join(location, '.env')
        if os.path.exists(env_path):
            try:
                with open(env_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            key, value = line.split('=', 1)
                            os.environ[key.strip()] = value.strip()
                return True
            except Exception as e:
                print(f"Error al cargar .env: {e}")
    return False
