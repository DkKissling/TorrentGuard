"""
Módulo para el análisis de archivos torrent.
"""
import os
import hashlib
from torrentool.api import Torrent
from typing import Dict, Any, List, Union
from datetime import datetime

class TorrentAnalyzer:
    def __init__(self, torrent_path: str):
        self.torrent_path = torrent_path
        self.torrent_data = None

    def analyze_file(self) -> Dict[str, Any]:
        """
        Analiza un archivo torrent y retorna información detallada sobre él.
        """
        if not os.path.exists(self.torrent_path):
            raise FileNotFoundError(f"El archivo {self.torrent_path} no existe")

        try:
            self.torrent_data = Torrent.from_file(self.torrent_path)
        except Exception as e:
            raise ValueError(f"Error al decodificar el archivo torrent: {str(e)}")

        file_info = {
            'file_size': os.path.getsize(self.torrent_path),
            'file_name': os.path.basename(self.torrent_path),
            'file_hash': self._calculate_file_hash(),
            'content_info': self._analyze_content(),
            'tracker_info': self._analyze_trackers(),
            'creation_info': self._get_creation_info(),
            'piece_info': self._analyze_pieces()
        }
        
        return file_info

    def _calculate_file_hash(self) -> str:
        """
        Calcula el hash SHA-256 del archivo torrent.
        """
        sha256_hash = hashlib.sha256()
        with open(self.torrent_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def _analyze_pieces(self) -> Dict[str, Any]:
        """
        Analiza la información de las piezas del torrent y genera hashes.
        """
        piece_info = {
            'piece_length': self.torrent_data.piece_length if hasattr(self.torrent_data, 'piece_length') else 0,
            'num_pieces': len(self.torrent_data.pieces) if hasattr(self.torrent_data, 'pieces') else 0,
            'piece_hashes': []
        }

        if hasattr(self.torrent_data, 'pieces'):
            # Convertir los bytes de las piezas en hashes individuales
            pieces = self.torrent_data.pieces
            for i in range(0, len(pieces), 20):  # SHA1 hash es de 20 bytes
                piece_hash = pieces[i:i+20].hex()
                piece_info['piece_hashes'].append(piece_hash)

        return piece_info

    def _analyze_content(self) -> Dict[str, Any]:
        """
        Analiza la información del contenido del torrent.
        """
        content_info = {
            'name': self.torrent_data.name,
            'total_size': self.torrent_data.total_size,
            'files': []
        }

        try:
            if hasattr(self.torrent_data, 'files_list') and self.torrent_data.files_list:
                total_offset = 0
                for file_info in self.torrent_data.files_list:
                    file_size = file_info.length if hasattr(file_info, 'length') else 0
                    file_path = str(file_info)
                    
                    # Calcular los índices de las piezas que contienen este archivo
                    start_piece = total_offset // self.torrent_data.piece_length
                    end_piece = (total_offset + file_size - 1) // self.torrent_data.piece_length
                    piece_hashes = []
                    
                    if hasattr(self.torrent_data, 'pieces'):
                        for i in range(start_piece, end_piece + 1):
                            if i * 20 < len(self.torrent_data.pieces):
                                piece_hash = self.torrent_data.pieces[i*20:(i+1)*20].hex()
                                piece_hashes.append(piece_hash)

                    content_info['files'].append({
                        'path': file_path,
                        'size': file_size,
                        'offset': total_offset,
                        'piece_range': {
                            'start': start_piece,
                            'end': end_piece
                        },
                        'piece_hashes': piece_hashes
                    })
                    total_offset += file_size
            else:
                piece_hashes = []
                if hasattr(self.torrent_data, 'pieces'):
                    for i in range(0, len(self.torrent_data.pieces), 20):
                        piece_hash = self.torrent_data.pieces[i:i+20].hex()
                        piece_hashes.append(piece_hash)
                
                content_info['files'].append({
                    'path': self.torrent_data.name,
                    'size': self.torrent_data.total_size,
                    'offset': 0,
                    'piece_range': {
                        'start': 0,
                        'end': len(piece_hashes) - 1 if piece_hashes else 0
                    },
                    'piece_hashes': piece_hashes
                })
        except Exception as e:
            content_info['files'].append({
                'path': self.torrent_data.name if hasattr(self.torrent_data, 'name') else 'Unknown',
                'size': self.torrent_data.total_size if hasattr(self.torrent_data, 'total_size') else 0,
                'offset': 0,
                'piece_range': {'start': 0, 'end': 0},
                'piece_hashes': []
            })
            print(f"Advertencia: Error al procesar información de archivos: {e}")

        return content_info

    def _analyze_trackers(self) -> List[str]:
        """
        Extrae y analiza la información de los trackers.
        """
        trackers = []
        
        try:
            # Obtener tracker principal y lista de trackers
            if hasattr(self.torrent_data, 'announce_urls'):
                for tracker in self.torrent_data.announce_urls:
                    if isinstance(tracker, (list, tuple)):
                        trackers.extend([str(t) for t in tracker])
                    else:
                        trackers.append(str(tracker))
            elif hasattr(self.torrent_data, 'announce'):
                trackers.append(str(self.torrent_data.announce))
        except Exception as e:
            print(f"Advertencia: Error al procesar trackers: {e}")
        
        # Eliminar duplicados manteniendo el orden
        trackers = list(dict.fromkeys(trackers))
        
        return trackers

    def _get_creation_info(self) -> Dict[str, Any]:
        """
        Obtiene información sobre la creación del torrent.
        """
        creation_info = {
            'created_by': None,
            'creation_date': None,
            'comment': None
        }

        try:
            creation_info['created_by'] = str(self.torrent_data.created_by) if hasattr(self.torrent_data, 'created_by') and self.torrent_data.created_by else None
            if hasattr(self.torrent_data, 'created_at') and self.torrent_data.created_at:
                try:
                    creation_info['creation_date'] = self.torrent_data.created_at.isoformat()
                except AttributeError:
                    creation_info['creation_date'] = str(self.torrent_data.created_at)
            creation_info['comment'] = str(self.torrent_data.comment) if hasattr(self.torrent_data, 'comment') and self.torrent_data.comment else None
        except Exception as e:
            print(f"Advertencia: Error al procesar información de creación: {e}")

        return creation_info
