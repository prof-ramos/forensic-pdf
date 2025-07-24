"""
Analisador Forense de PDF.

Este script é uma ferramenta de linha de comando para realizar uma análise forense
em arquivos PDF. Ele extrai metadados, verifica a integridade do arquivo e analisa
datas de modificação.

Requer a dependência de linha de comando `exiftool` e a biblioteca Python `pypdf`.

Uso:
    pip install -r requirements.txt
    python3 forensic_analyzer.py /caminho/para/seu/arquivo.pdf
"""
import argparse
import json
import logging
import os
import subprocess
import hashlib
import shutil
from datetime import datetime, timezone
from typing import List, Dict, Any

# Importa a nova dependência
import pypdf

# Configuração do logger
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ToolExecutionError(Exception):
    """Exceção customizada para erros na execução de ferramentas externas."""
    pass

def check_dependencies():
    """
    Verifica se a ferramenta de linha de comando `exiftool` está instalada.
    """
    if not shutil.which('exiftool'):
        logger.error("Dependência faltando: exiftool. Por favor, instale-a e tente novamente.")
        raise SystemExit(1)
    logger.info("Dependência externa (exiftool) encontrada.")

def validate_file_path(file_path: str) -> str:
    """
    Valida o caminho do arquivo fornecido.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Arquivo não encontrado: {file_path}")
    if not file_path.lower().endswith('.pdf'):
        raise ValueError("O arquivo fornecido não parece ser um PDF.")
    return file_path

def compute_hash(file_path: str) -> str:
    """
    Calcula o hash SHA-256 de um arquivo.
    """
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def run_command(cmd: List[str]) -> str:
    """
    Executa um comando de shell e retorna sua saída.
    """
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, encoding='utf-8')
        return result.stdout.strip()
    except FileNotFoundError:
        raise ToolExecutionError(f"Ferramenta não encontrada: {cmd[0]}")
    except subprocess.CalledProcessError as e:
        raise ToolExecutionError(f"Falha na execução de: {' '.join(cmd)} - {e.stderr.strip()}")

def extract_data_pypdf(file_path: str) -> Dict[str, Any]:
    """
    Extrai metadados, informações estruturais e de segurança usando pypdf.

    Args:
        file_path: O caminho para o arquivo PDF.

    Returns:
        Um dicionário contendo os dados extraídos.
    """
    try:
        with open(file_path, "rb") as f:
            reader = pypdf.PdfReader(f)
            metadata = reader.metadata
            
            # Converte o objeto de metadados para um dicionário simples
            pypdf_meta = {
                "Author": metadata.author,
                "Creator": metadata.creator,
                "Producer": metadata.producer,
                "Subject": metadata.subject,
                "Title": metadata.title,
                "CreationDate": metadata.creation_date,
                "ModificationDate": metadata.modification_date,
            }

            # Remove chaves com valores None para um relatório mais limpo
            pypdf_meta = {k: v for k, v in pypdf_meta.items() if v is not None}

            return {
                "metadata": pypdf_meta,
                "structural_info": {
                    "pdf_version": f"{reader.pdf_header}",
                    "pages": len(reader.pages),
                    "encrypted": reader.is_encrypted,
                },
                "security_info": {
                    # Verifica a presença de assinaturas digitais
                    "has_digital_signatures": "/Sig" in reader.trailer.keys(),
                    # Verifica a presença de JavaScript
                    "contains_javascript": reader.get_fields() is not None and any(
                        field.get("/AA", {}).get("/JS") for field in reader.get_fields().values()
                    )
                }
            }
    except pypdf.errors.PdfReadError as e:
        logger.error(f"Erro ao ler o PDF com pypdf: {e}")
        return {}

def analyze_modifications(metadata_exif: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analisa as datas de criação e modificação para detectar alterações.
    """
    creation = metadata_exif.get('CreateDate')
    modified = metadata_exif.get('ModifyDate')
    return {
        'altered': creation != modified if creation and modified else "Data missing",
        'creation_date': creation,
        'modified_date': modified
    }

def generate_report(file_path: str, output_path: str):
    """
    Orquestra a análise forense e gera o relatório JSON final.
    """
    try:
        validated_path = validate_file_path(file_path)
        integrity_hash = compute_hash(validated_path)
        logger.info(f"Hash SHA-256 calculado para '{os.path.basename(validated_path)}'.")

        # 1. Extração com ExifTool (ainda valioso por sua abrangência)
        logger.info("Extraindo metadados com ExifTool...")
        exif_output = run_command(['exiftool', '-j', '-d', '%Y-%m-%dT%H:%M:%S%z', validated_path])
        metadata_exif = json.loads(exif_output)[0] if exif_output else {}

        # 2. Extração com pypdf
        logger.info("Extraindo dados com pypdf...")
        pypdf_data = extract_data_pypdf(validated_path)

        # 3. Análise e Compilação
        modifications = analyze_modifications(metadata_exif)
        
        report = {
            'file_information': {
                'file_name': os.path.basename(validated_path),
                'full_path': validated_path,
                'sha256_hash': integrity_hash,
            },
            'metadata': {
                'exiftool': metadata_exif,
                'pypdf': pypdf_data.get('metadata', {}),
            },
            'analysis_summary': {
                'modification_analysis': modifications,
                'has_digital_signatures': pypdf_data.get('security_info', {}).get('has_digital_signatures', False),
                'structural_info': pypdf_data.get('structural_info', {}),
                'potential_vulnerabilities': {
                    'contains_javascript': pypdf_data.get('security_info', {}).get('contains_javascript', False)
                }
            },
            'audit_trail': {
                'analysis_date_utc': datetime.now(timezone.utc).isoformat()
            }
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=4, ensure_ascii=False)
        
        logger.info(f"Relatório forense gerado com sucesso: {output_path}")

    except (FileNotFoundError, ValueError, ToolExecutionError, SystemExit, json.JSONDecodeError) as e:
        logger.error(f"Falha na análise: {e}")
    except Exception as e:
        logger.error(f"Ocorreu um erro inesperado: {e}", exc_info=True)

def main():
    """
    Ponto de entrada principal para o script.
    """
    check_dependencies()

    parser = argparse.ArgumentParser(
        description="Análise Forense de PDF",
        epilog="Exemplo: python3 forensic_analyzer.py meu_doc.pdf"
    )
    parser.add_argument('file_path', type=str, help="Caminho do arquivo PDF a ser analisado.")
    parser.add_argument(
        '-o', '--output',
        type=str,
        help="Caminho do arquivo de relatório JSON. Padrão: <arquivo_original>.report.json"
    )
    args = parser.parse_args()
    
    output_file = args.output or f"{os.path.splitext(args.file_path)[0]}.report.json"
    
    generate_report(args.file_path, output_file)

if __name__ == "__main__":
    main()
