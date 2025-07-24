"""
Analisador Forense de PDF.

Este script é uma ferramenta de linha de comando para realizar uma análise forense
em arquivos PDF. Ele extrai metadados, verifica a integridade do arquivo, analisa
datas de modificação e verifica a presença de assinaturas digitais e
vulnerabilidades potenciais.

Requer as seguintes dependências de linha de comando:
- exiftool
- pdftk
- pdfinfo (parte do pacote poppler)

Uso:
    python forensic_analyzer.py /caminho/para/seu/arquivo.pdf [--output /caminho/para/relatorio.json]
"""
import argparse
import json
import logging
import os
import subprocess
import hashlib
import shutil
from datetime import datetime
from typing import List, Dict, Any, Optional

# Configuração do logger para fornecer feedback claro ao usuário.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ToolExecutionError(Exception):
    """Exceção customizada para erros na execução de ferramentas externas."""
    pass

def check_dependencies():
    """
    Verifica se todas as ferramentas de linha de comando necessárias estão instaladas.
    
    Levanta:
        SystemExit: Se uma dependência estiver faltando.
    """
    dependencies = ['exiftool', 'pdftk', 'pdfinfo']
    missing = [dep for dep in dependencies if not shutil.which(dep)]
    if missing:
        logger.error(f"Dependências faltando: {', '.join(missing)}. Por favor, instale-as e tente novamente.")
        raise SystemExit(1)
    logger.info("Todas as dependências foram encontradas.")

def validate_file_path(file_path: str) -> str:
    """
    Valida o caminho do arquivo fornecido.

    Args:
        file_path: O caminho para o arquivo PDF.

    Returns:
        O caminho do arquivo validado.

    Raises:
        FileNotFoundError: Se o arquivo não for encontrado.
        ValueError: Se o arquivo não for um PDF.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Arquivo não encontrado: {file_path}")
    if not file_path.lower().endswith('.pdf'):
        raise ValueError("O arquivo fornecido não parece ser um PDF.")
    return file_path

def compute_hash(file_path: str) -> str:
    """
    Calcula o hash SHA-256 de um arquivo.

    Args:
        file_path: O caminho para o arquivo.

    Returns:
        O hash SHA-256 em formato hexadecimal.
    """
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        # Lê o arquivo em blocos para ser eficiente em termos de memória.
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def run_command(cmd: List[str]) -> str:
    """
    Executa um comando de shell e retorna sua saída.

    Args:
        cmd: O comando e seus argumentos como uma lista de strings.

    Returns:
        A saída padrão (stdout) do comando.

    Raises:
        ToolExecutionError: Se o comando falhar.
    """
    try:
        # O uso de `check=True` garante que uma exceção seja levantada se o comando retornar um código de erro.
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, encoding='utf-8')
        return result.stdout.strip()
    except FileNotFoundError:
        logger.error(f"Comando não encontrado: {cmd[0]}. Verifique se está instalado e no PATH.")
        raise ToolExecutionError(f"Ferramenta não encontrada: {cmd[0]}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Erro ao executar '{' '.join(cmd)}': {e.stderr.strip()}")
        raise ToolExecutionError(f"Falha na execução de: {' '.join(cmd)}")

def _parse_key_value_output(output: str) -> Dict[str, str]:
    """
    Função auxiliar para parsear saídas no formato 'Chave: Valor'.

    Args:
        output: A string de saída de uma ferramenta como pdftk ou pdfinfo.

    Returns:
        Um dicionário com os pares chave-valor extraídos.
    """
    metadata = {}
    for line in output.splitlines():
        if ':' in line:
            key, value = line.split(':', 1)
            metadata[key.strip()] = value.strip()
    return metadata

def analyze_modifications(metadata_exif: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analisa as datas de criação e modificação para detectar alterações.

    Args:
        metadata_exif: Dicionário de metadados extraído pelo ExifTool.

    Returns:
        Um dicionário contendo o status da alteração e as datas.
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

    Args:
        file_path: O caminho para o arquivo PDF a ser analisado.
        output_path: O caminho para salvar o relatório JSON.
    """
    try:
        # --- 1. Validação e Coleta Inicial ---
        validated_path = validate_file_path(file_path)
        integrity_hash = compute_hash(validated_path)
        logger.info(f"Hash SHA-256 calculado para '{os.path.basename(validated_path)}'.")

        # --- 2. Execução das Ferramentas Externas (uma vez por ferramenta) ---
        logger.info("Extraindo metadados com as ferramentas externas...")
        exif_output = run_command(['exiftool', '-j', validated_path])
        pdftk_output = run_command(['pdftk', validated_path, 'dump_data'])
        pdfinfo_output = run_command(['pdfinfo', validated_path])
        logger.info("Extração de metadados concluída.")

        # --- 3. Parsing e Análise dos Resultados ---
        metadata_exif = json.loads(exif_output)[0] if exif_output else {}
        metadata_pdftk = _parse_key_value_output(pdftk_output)
        metadata_poppler = _parse_key_value_output(pdfinfo_output)

        modifications = analyze_modifications(metadata_exif)
        
        # A verificação de assinatura agora reutiliza a saída do pdftk.
        has_signatures = 'Signature' in pdftk_output
        
        # A verificação estrutural reutiliza a saída do pdfinfo.
        pdf_version = metadata_poppler.get('PDF version')
        
        # A verificação de vulnerabilidade é mais específica e reutiliza a saída do pdfinfo.
        # Procura por tags que indicam conteúdo ativo ou ações de lançamento.
        has_js = 'JavaScript' in pdfinfo_output or '/JS' in pdfinfo_output or '/Launch' in pdfinfo_output
        
        # --- 4. Compilação do Relatório Final ---
        report = {
            'file_information': {
                'file_name': os.path.basename(validated_path),
                'full_path': validated_path,
                'sha256_hash': integrity_hash,
            },
            'metadata': {
                'exiftool': metadata_exif,
                'pdftk': metadata_pdftk,
                'poppler': metadata_poppler
            },
            'analysis_summary': {
                'modification_analysis': modifications,
                'has_digital_signatures': has_signatures,
                'structural_info': {'pdf_version': pdf_version},
                'potential_vulnerabilities': {'contains_active_content': has_js}
            },
            'audit_trail': {
                'analysis_date_utc': datetime.utcnow().isoformat()
            }
        }
        
        # --- 5. Salvando o Relatório ---
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=4, ensure_ascii=False)
        
        logger.info(f"Relatório forense gerado com sucesso: {output_path}")

    except (FileNotFoundError, ValueError, ToolExecutionError, SystemExit) as e:
        # Captura exceções esperadas e registra o erro sem gerar um relatório parcial.
        logger.error(f"Falha na análise: {e}")
    except Exception as e:
        # Captura qualquer outra exceção inesperada.
        logger.error(f"Ocorreu um erro inesperado: {e}", exc_info=True)

def main():
    """
    Ponto de entrada principal para o script.
    Parseia argumentos da linha de comando e inicia a geração do relatório.
    """
    # Verifica as dependências antes de fazer qualquer outra coisa.
    check_dependencies()

    parser = argparse.ArgumentParser(
        description="Análise Forense de PDF",
        epilog="Exemplo: python forensic_analyzer.py meu_doc.pdf -o relatorio_doc.json"
    )
    parser.add_argument('file_path', type=str, help="Caminho do arquivo PDF a ser analisado.")
    parser.add_argument(
        '-o', '--output',
        type=str,
        help="Caminho do arquivo de relatório JSON de saída. Padrão: <arquivo_original>.report.json"
    )
    args = parser.parse_args()
    
    # Define o nome do arquivo de saída padrão se não for fornecido.
    output_file = args.output or f"{os.path.splitext(args.file_path)[0]}.report.json"
    
    generate_report(args.file_path, output_file)

if __name__ == "__main__":
    main()