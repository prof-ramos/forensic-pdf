# Análise Forense de PDF

Este projeto é uma ferramenta de linha de comando para realizar uma análise forense em arquivos PDF. Ele extrai metadados, verifica a integridade do arquivo, analisa datas de modificação e verifica a presença de assinaturas digitais e vulnerabilidades potenciais.

## Requisitos

- Python 3.x
- A biblioteca `pypdf` (instalada via pip).
- A ferramenta de linha de comando `exiftool`.

## Instalação

1.  **Instale as dependências do Python:**

    Clone o repositório e instale a biblioteca `pypdf` usando o `requirements.txt`.
    ```bash
    git clone https://github.com/prof-ramos/forensic-pdf.git
    cd forensic-pdf
    pip install -r requirements.txt
    ```

2.  **Instale o ExifTool:**

    A única dependência externa agora é o `ExifTool`.

    -   **macOS (com Homebrew):**
        ```bash
        brew install exiftool
        ```

    -   **Linux (Debian/Ubuntu):**
        ```bash
        sudo apt-get update
        sudo apt-get install -y libimage-exiftool-perl
        ```

    -   **Windows (com Chocolatey):**
        ```powershell
        choco install exiftool
        ```

## Uso

Para analisar um arquivo PDF, execute o script a partir da linha de comando:

```bash
python3 forensic_analyzer.py /caminho/para/seu/arquivo.pdf
```

Por padrão, o relatório será salvo como `<nome_do_arquivo>.report.json` no mesmo diretório do arquivo original.

## Fluxo de Trabalho da Análise

O fluxo de trabalho foi simplificado para reduzir as dependências externas. O `pypdf` agora lida com a maior parte da análise interna do PDF, enquanto o `exiftool` ainda é usado por sua capacidade inigualável de extrair metadados detalhados.

```mermaid
graph TD
    A[Início] --> B{Valida Caminho do PDF};
    B --> |Arquivo Válido| C{Calcula Hash SHA-256};
    B --> |Arquivo Inválido| Z[Encerra com Erro];
    
    C --> D{Extração de Dados};
    D --> E[Executa exiftool];
    D --> F[Executa pypdf (na memória)];
    
    subgraph "Análise dos Dados"
        E --> G[Parse Metadados EXIF];
        F --> H[Parse Metadados, Assinaturas, etc.];
        G --> I{Analisa Datas de Modificação};
    end
    
    subgraph "Geração do Relatório"
        C --> J[Integridade do Arquivo];
        I --> K[Análise de Modificação];
        H --> L[Dados Estruturais e de Segurança];
    end

    J & K & L --> M{Compila Relatório JSON};
    M --> N[Salva report.json];
    N --> O[Fim];
```