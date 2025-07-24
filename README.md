# Análise Forense de PDF

Este projeto é uma ferramenta de linha de comando para realizar uma análise forense em arquivos PDF. Ele extrai metadados, verifica a integridade do arquivo, analisa datas de modificação e verifica a presença de assinaturas digitais e vulnerabilidades potenciais.

## Requisitos

- Python 3.x
- As seguintes ferramentas de linha de comando devem estar instaladas e acessíveis no `PATH` do sistema:
  - `exiftool`
  - `pdftk`
  - `pdfinfo` (parte do pacote `poppler`)

### Instalação (macOS com Homebrew)

```bash
brew install exiftool poppler pdftk-java
```

## Uso

Para analisar um arquivo PDF, execute o script a partir da linha de comando:

```bash
python3 forensic_analyzer.py /caminho/para/seu/arquivo.pdf
```

Por padrão, o relatório será salvo como `<nome_do_arquivo>.report.json` no mesmo diretório do arquivo original.

Você pode especificar um local de saída diferente com a flag `-o` ou `--output`:

```bash
python3 forensic_analyzer.py meu_doc.pdf -o /caminho/para/relatorio.json
```

## Fluxo de Trabalho da Análise

O script segue um fluxo de trabalho claro para garantir uma análise consistente e completa. O diagrama abaixo ilustra as etapas principais, desde a validação inicial do arquivo até a geração do relatório final.

```mermaid
graph TD
    A[Início] --> B{Valida Caminho do PDF};
    B --> |Arquivo Válido| C{Calcula Hash SHA-256};
    B --> |Arquivo Inválido| Z[Encerra com Erro];
    
    C --> D[Executa Ferramentas Externas];
    D --> E[exiftool -j <arquivo>];
    D --> F[pdftk <arquivo> dump_data];
    D --> G[pdfinfo <arquivo>];
    
    subgraph "Análise dos Dados"
        E --> H[Parse Metadados EXIF];
        F --> I[Parse Metadados PDFTk];
        G --> J[Parse Metadados Poppler];
        
        H --> K{Analisa Datas de Modificação};
        I --> L{Verifica Assinaturas Digitais};
        J --> M{Verifica Versão do PDF};
        J --> N{Verifica Vulnerabilidades (JS)};
    end
    
    subgraph "Geração do Relatório"
        C --> O[Integridade do Arquivo];
        K --> P[Análise de Modificação];
        L --> Q[Assinaturas];
        M --> R[Info Estrutural];
        N --> S[Vulnerabilidades];
    end

    O & P & Q & R & S --> T{Compila Relatório JSON};
    T --> U[Salva report.json];
    U --> V[Fim];
```
