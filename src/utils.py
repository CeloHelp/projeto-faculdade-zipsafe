#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ZIPSafe - Sistema de IA para Detecção Preventiva de Arquivos Maliciosos
Módulo de funções auxiliares.

Este módulo contém funções utilitárias reutilizáveis para o projeto ZIPSafe.
"""

import os
import math
import hashlib
import logging
import csv
import json
from datetime import datetime

try:
    import streamlit as st
except Exception:
    st = None

try:
    from supabase import create_client
except Exception:
    create_client = None

def configurar_logging(nivel=logging.INFO):
    """
    Configura o sistema de logging para o projeto.
    
    Args:
        nivel: Nível de logging (default: logging.INFO)
        
    Returns:
        logging.Logger: Logger configurado
    """
    # Criar diretório de logs se não existir
    os.makedirs('logs', exist_ok=True)
    
    # Configurar logger
    logger = logging.getLogger('zipsafe')
    logger.setLevel(nivel)
    
    # Evitar duplicação de handlers
    if not logger.handlers:
        # Handler para console
        console_handler = logging.StreamHandler()
        console_handler.setLevel(nivel)
        console_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(console_format)
        logger.addHandler(console_handler)
        
        # Handler para arquivo
        log_file = os.path.join('logs', f'zipsafe_{datetime.now().strftime("%Y%m%d")}.log')
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(nivel)
        file_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(file_format)
        logger.addHandler(file_handler)
    
    return logger

def calcular_hash(caminho_arquivo, algoritmo='sha256', tamanho_bloco=65536):
    """
    Calcula o hash de um arquivo.
    
    Args:
        caminho_arquivo (str): Caminho para o arquivo
        algoritmo (str): Algoritmo de hash (default: 'sha256')
        tamanho_bloco (int): Tamanho do bloco para leitura (default: 65536)
        
    Returns:
        str: Hash do arquivo em formato hexadecimal
    """
    if algoritmo == 'sha256':
        hash_obj = hashlib.sha256()
    elif algoritmo == 'md5':
        hash_obj = hashlib.md5()
    else:
        raise ValueError(f"Algoritmo de hash não suportado: {algoritmo}")
    
    with open(caminho_arquivo, 'rb') as arquivo:
        for bloco in iter(lambda: arquivo.read(tamanho_bloco), b''):
            hash_obj.update(bloco)
    
    return hash_obj.hexdigest()

def calcular_entropia(caminho_arquivo, tamanho_bloco=65536):
    """
    Calcula a entropia de Shannon de um arquivo.
    Valores altos (próximos de 8.0) podem indicar compressão, criptografia ou ofuscação.
    
    Args:
        caminho_arquivo (str): Caminho para o arquivo
        tamanho_bloco (int): Tamanho do bloco para leitura (default: 65536)
        
    Returns:
        float: Valor da entropia (entre 0.0 e 8.0)
    """
    # Inicializar contadores
    contagem_bytes = [0] * 256
    tamanho_total = 0
    
    # Ler arquivo em blocos
    with open(caminho_arquivo, 'rb') as arquivo:
        for bloco in iter(lambda: arquivo.read(tamanho_bloco), b''):
            for byte in bloco:
                contagem_bytes[byte] += 1
            tamanho_total += len(bloco)
    
    # Calcular entropia
    entropia = 0.0
    for contagem in contagem_bytes:
        if contagem > 0:
            probabilidade = contagem / tamanho_total
            entropia -= probabilidade * math.log2(probabilidade)
    
    return entropia

def salvar_relatorio(resultado, nome_base):
    """
    Salva o resultado da análise em formatos CSV e HTML.
    
    Args:
        resultado (dict): Resultado da análise
        nome_base (str): Nome base para os arquivos de saída
    """
    # Criar diretório de relatórios se não existir
    diretorio_relatorios = os.path.join('output', 'relatorios')
    os.makedirs(diretorio_relatorios, exist_ok=True)
    
    # Salvar como CSV
    caminho_csv = os.path.join(diretorio_relatorios, f"{nome_base}.csv")
    _salvar_csv(resultado, caminho_csv)
    
    # Salvar como HTML
    caminho_html = os.path.join(diretorio_relatorios, f"{nome_base}.html")
    _salvar_html(resultado, caminho_html)
    
    # Salvar como JSON (para referência)
    caminho_json = os.path.join(diretorio_relatorios, f"{nome_base}.json")
    with open(caminho_json, 'w', encoding='utf-8') as arquivo_json:
        json.dump(resultado, arquivo_json, indent=2, ensure_ascii=False)

    # Se Supabase estiver configurado, enviar artefatos ao Storage e registrar em reports
    urls = None
    if supabase_available():
        try:
            urls = supabase_upload_artifacts(nome_base, caminho_html, caminho_csv, caminho_json)
            uploaded_any = bool(urls) and any(urls.values())
            if uploaded_any:
                payload = {
                    'nome': nome_base,
                    'arquivo': resultado.get('nome_arquivo', ''),
                    'risco': resultado.get('nivel_risco', 'não classificado'),
                    'resumo': resultado,
                    'html_url': (urls or {}).get('html'),
                    'csv_url': (urls or {}).get('csv'),
                    'json_url': (urls or {}).get('json'),
                    'created_at': datetime.now().isoformat()
                }
                supabase_insert_report(payload)
                # Remover cópias locais somente se o upload ocorreu com sucesso
                for p in (caminho_html, caminho_csv, caminho_json):
                    try:
                        os.remove(p)
                    except Exception:
                        pass
            # Caso uploads falhem, mantém cópias locais para fallback
        except Exception:
            # Se falhar, mantém cópias locais
            pass

    # Retorna informação para UI (compatível com chamadas antigas que ignoram retorno)
    return {
        'local': {
            'html': caminho_html,
            'csv': caminho_csv,
            'json': caminho_json
        },
        'urls': urls
    }

def _salvar_csv(resultado, caminho_saida):
    """
    Salva o resultado da análise em formato CSV.
    
    Args:
        resultado (dict): Resultado da análise
        caminho_saida (str): Caminho para o arquivo CSV de saída
    """
    # Preparar dados para CSV (aplanar o dicionário)
    dados_csv = {}
    for chave, valor in resultado.items():
        if isinstance(valor, (str, int, float, bool)) or valor is None:
            dados_csv[chave] = valor
        elif isinstance(valor, list):
            dados_csv[chave] = '; '.join(str(item) for item in valor)
        elif isinstance(valor, dict):
            for sub_chave, sub_valor in valor.items():
                dados_csv[f"{chave}_{sub_chave}"] = sub_valor
    
    # Escrever CSV
    with open(caminho_saida, 'w', newline='', encoding='utf-8') as arquivo_csv:
        writer = csv.writer(arquivo_csv)
        writer.writerow(dados_csv.keys())
        writer.writerow(dados_csv.values())

def _salvar_html(resultado, caminho_saida):
    """
    Salva o resultado da análise em formato HTML.
    
    Args:
        resultado (dict): Resultado da análise
        caminho_saida (str): Caminho para o arquivo HTML de saída
    """
    # Determinar classe CSS baseada no nível de risco
    nivel_risco = resultado.get('nivel_risco', 'não classificado')
    if nivel_risco == 'alto':
        classe_risco = 'danger'
    elif nivel_risco == 'medio':
        classe_risco = 'warning'
    elif nivel_risco == 'baixo':
        classe_risco = 'success'
    else:
        classe_risco = 'secondary'
    
    # Gerar HTML
    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZIPSafe - Relatório de Análise</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {{ padding: 20px; }}
        .header {{ margin-bottom: 30px; }}
        .flag-item {{ margin-bottom: 5px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>ZIPSafe - Relatório de Análise</h1>
            <p class="text-muted">Gerado em: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</p>
        </div>
        
        <div class="card mb-4">
            <div class="card-header bg-{classe_risco} text-white">
                <h3>Resumo da Análise</h3>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-6">
                        <h4>Informações do Arquivo</h4>
                        <ul class="list-group">
                            <li class="list-group-item"><strong>Nome:</strong> {resultado.get('nome_arquivo', 'N/A')}</li>
                            <li class="list-group-item"><strong>Caminho:</strong> {resultado.get('caminho', 'N/A')}</li>
                            <li class="list-group-item"><strong>Tamanho:</strong> {resultado.get('tamanho_bytes', 0)} bytes</li>
                            <li class="list-group-item"><strong>Extensão:</strong> {resultado.get('extensao', 'N/A')}</li>
                            <li class="list-group-item"><strong>MIME Type:</strong> {resultado.get('mime_type', 'N/A')}</li>
                            <li class="list-group-item"><strong>Data de Modificação:</strong> {resultado.get('data_modificacao', 'N/A')}</li>
                        </ul>
                    </div>
                    <div class="col-md-6">
                        <h4>Análise de Segurança</h4>
                        <ul class="list-group">
                            <li class="list-group-item"><strong>Nível de Risco:</strong> <span class="badge bg-{classe_risco}">{nivel_risco.upper()}</span></li>
                            <li class="list-group-item"><strong>Entropia:</strong> {resultado.get('entropia', 0):.2f}/8.0</li>
                            <li class="list-group-item"><strong>Hash SHA256:</strong> {resultado.get('hash_sha256', 'N/A')}</li>
                            <li class="list-group-item"><strong>Contém Macros:</strong> {'Sim' if resultado.get('tem_macros', False) else 'Não'}</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
"""
    
    # Adicionar seção de flags suspeitas se existirem
    flags = resultado.get('flags_suspeitas', [])
    if flags:
        html += f"""
        <div class="card mb-4">
            <div class="card-header bg-danger text-white">
                <h3>Flags de Suspeita ({len(flags)})</h3>
            </div>
            <div class="card-body">
                <ul class="list-group">
"""
        for flag in flags:
            html += f'                    <li class="list-group-item flag-item">{flag}</li>\n'
        
        html += """
                </ul>
            </div>
        </div>
"""
    
    # Adicionar conteúdo ZIP se existir
    conteudo_zip = resultado.get('conteudo_zip', [])
    if conteudo_zip:
        html += f"""
        <div class="card mb-4">
            <div class="card-header bg-info text-white">
                <h3>Conteúdo do Arquivo ZIP ({len(conteudo_zip)} itens)</h3>
            </div>
            <div class="card-body">
                <ul class="list-group">
"""
        for item in conteudo_zip:
            html += f'                    <li class="list-group-item">{item}</li>\n'
        
        html += """
                </ul>
            </div>
        </div>
"""
    
    # Fechar HTML
    html += """
        <footer class="mt-5 text-center text-muted">
            <p>ZIPSafe - Sistema de IA para Detecção Preventiva de Arquivos Maliciosos</p>
        </footer>
    </div>
</body>
</html>
"""
    
    # Salvar arquivo HTML
    with open(caminho_saida, 'w', encoding='utf-8') as arquivo_html:
        arquivo_html.write(html)

# ===== Integração Supabase =====

def supabase_available():
    """Verifica se Supabase está configurado via secrets e SDK importável."""
    try:
        return bool(
            st and hasattr(st, 'secrets') and 'supabase' in st.secrets
            and st.secrets['supabase'].get('url')
            and (st.secrets['supabase'].get('service_role') or st.secrets['supabase'].get('anon_key'))
            and create_client
        )
    except Exception:
        return False

def _get_supabase_client():
    """Cria cliente Supabase usando secrets (service_role preferencial para escrita)."""
    if not supabase_available():
        return None
    url = st.secrets['supabase'].get('url')
    key = st.secrets['supabase'].get('service_role') or st.secrets['supabase'].get('anon_key')
    try:
        return create_client(url, key)
    except Exception:
        return None

def supabase_upload_artifacts(nome_base, caminho_html, caminho_csv, caminho_json, bucket=None):
    """Envia HTML/CSV/JSON ao Storage e retorna URLs públicas."""
    client = _get_supabase_client()
    if not client:
        return None
    bucket = bucket or st.secrets['supabase'].get('bucket', 'relatorios')
    store = client.storage.from_(bucket)

    def _upload(local_path, ext, content_type):
        try:
            remote_path = f"relatorios/{nome_base}.{ext}"
            with open(local_path, 'rb') as f:
                data = f.read()
            store.upload(remote_path, data, {"contentType": content_type, "upsert": "true"})
            url = store.get_public_url(remote_path)
            return url
        except Exception:
            return None

    return {
        'html': _upload(caminho_html, 'html', 'text/html'),
        'csv': _upload(caminho_csv, 'csv', 'text/csv'),
        'json': _upload(caminho_json, 'json', 'application/json'),
    }

def supabase_insert_report(payload: dict):
    """Insere registro na tabela reports."""
    client = _get_supabase_client()
    if not client:
        return None
    try:
        return client.table('reports').insert(payload).execute()
    except Exception:
        return None

def supabase_list_reports(n=50):
    """Lista últimos relatórios da tabela reports em formato compatível com a UI."""
    client = _get_supabase_client()
    if not client:
        return []
    try:
        resp = client.table('reports').select('*').order('created_at', desc=True).limit(n).execute()
        rows = getattr(resp, 'data', resp)
        entries = []
        for r in rows or []:
            created = r.get('created_at')
            try:
                # Normaliza timestamps ISO
                created_fmt = datetime.fromisoformat((created or '').replace('Z','')).strftime('%d/%m/%Y %H:%M:%S') if created else ''
            except Exception:
                created_fmt = created or ''
            entries.append({
                'relatorio': r.get('nome') or str(r.get('id') or ''),
                'criado_em': created_fmt,
                'risco': r.get('risco', 'não classificado'),
                'arquivo': r.get('arquivo', ''),
                'html_url': r.get('html_url'),
                'csv_url': r.get('csv_url'),
                'json_url': r.get('json_url'),
            })
        return entries
    except Exception:
        return []