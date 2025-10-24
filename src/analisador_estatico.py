#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ZIPSafe - Sistema de IA para Detecção Preventiva de Arquivos Maliciosos
Módulo de análise estática de arquivos.

Este módulo contém funções para análise segura de arquivos, extraindo metadados
e características sem executar o conteúdo dos arquivos.
"""

import os
import zipfile
import magic
import logging
from datetime import datetime
from oletools import olevba
from utils import calcular_entropia, calcular_hash

# Lista de extensões potencialmente perigosas
EXTENSOES_PERIGOSAS = {
    # Executáveis e scripts
    'exe', 'dll', 'com', 'bat', 'cmd', 'ps1', 'vbs', 'js', 'jse', 'wsf', 'wsh', 'msi', 'scr',
    # Macros e documentos potencialmente perigosos
    'docm', 'xlsm', 'pptm', 'xls', 'doc', 'ppt',
    # Outros formatos potencialmente perigosos
    'hta', 'jar', 'lnk', 'reg', 'vbe', 'vba', 'pif'
}

# Configuração de logging
logger = logging.getLogger(__name__)

def analisar_estaticamente(caminho_arquivo):
    """
    Realiza análise estática do arquivo, extraindo metadados e características
    sem executar o conteúdo.
    
    Args:
        caminho_arquivo (str): Caminho para o arquivo a ser analisado
        
    Returns:
        dict: Dicionário contendo os metadados e características do arquivo
    """
    logger.info(f"Iniciando análise estática de: {caminho_arquivo}")
    
    # Informações básicas do arquivo
    nome_arquivo = os.path.basename(caminho_arquivo)
    tamanho_bytes = os.path.getsize(caminho_arquivo)
    data_modificacao = datetime.fromtimestamp(os.path.getmtime(caminho_arquivo)).isoformat()
    extensao = os.path.splitext(nome_arquivo)[1].lower().lstrip('.')
    
    # Detectar tipo MIME
    mime_type = magic.Magic(mime=True).from_file(caminho_arquivo)
    
    # Calcular hash e entropia
    hash_sha256 = calcular_hash(caminho_arquivo)
    entropia = calcular_entropia(caminho_arquivo)
    
    # Inicializar resultado
    resultado = {
        'nome_arquivo': nome_arquivo,
        'caminho': caminho_arquivo,
        'tamanho_bytes': tamanho_bytes,
        'data_modificacao': data_modificacao,
        'extensao': extensao,
        'mime_type': mime_type,
        'hash_sha256': hash_sha256,
        'entropia': entropia,
        'flags_suspeitas': [],
        'conteudo_zip': [],
        'tem_macros': False
    }
    
    # Verificar extensão suspeita
    if extensao in EXTENSOES_PERIGOSAS:
        resultado['flags_suspeitas'].append(f"Extensão potencialmente perigosa: {extensao}")
    
    # Análise específica por tipo de arquivo
    if mime_type.startswith('application/zip') or extensao == 'zip':
        _analisar_zip(caminho_arquivo, resultado)
    
    elif mime_type.startswith(('application/vnd.ms-office', 'application/vnd.openxmlformats-officedocument')):
        _analisar_office(caminho_arquivo, resultado)
    
    # Verificar entropia (valores altos podem indicar criptografia/compressão/ofuscação)
    if entropia > 7.0:
        resultado['flags_suspeitas'].append(f"Alta entropia ({entropia:.2f}): possível criptografia/ofuscação")
    
    # Adicionar nível de suspeita baseado em heurísticas simples
    resultado['nivel_suspeita'] = _calcular_nivel_suspeita(resultado)
    
    logger.info(f"Análise estática concluída para: {nome_arquivo}")
    return resultado

def _analisar_zip(caminho_arquivo, resultado):
    """
    Analisa o conteúdo de um arquivo ZIP sem extraí-lo.
    
    Args:
        caminho_arquivo (str): Caminho para o arquivo ZIP
        resultado (dict): Dicionário de resultado para atualizar
    """
    try:
        with zipfile.ZipFile(caminho_arquivo, 'r') as zip_ref:
            # Listar arquivos no ZIP
            arquivos_zip = zip_ref.namelist()
            resultado['conteudo_zip'] = arquivos_zip
            
            # Verificar arquivos suspeitos dentro do ZIP
            for arquivo in arquivos_zip:
                nome_base = os.path.basename(arquivo)
                ext = os.path.splitext(nome_base)[1].lower().lstrip('.')
                
                if ext in EXTENSOES_PERIGOSAS:
                    resultado['flags_suspeitas'].append(
                        f"Arquivo potencialmente perigoso no ZIP: {arquivo}"
                    )
                
                # Verificar nomes suspeitos (ex: "invoice", "urgent", etc.)
                nome_lower = nome_base.lower()
                palavras_suspeitas = ['invoice', 'urgent', 'payment', 'bank', 'password', 
                                     'confidential', 'private', 'account', 'update', 'verify']
                
                for palavra in palavras_suspeitas:
                    if palavra in nome_lower:
                        resultado['flags_suspeitas'].append(
                            f"Nome potencialmente enganoso no ZIP: {arquivo} (contém '{palavra}')"
                        )
    
    except zipfile.BadZipFile:
        resultado['flags_suspeitas'].append("Arquivo ZIP corrompido ou inválido")
    except Exception as e:
        logger.error(f"Erro ao analisar ZIP: {str(e)}")
        resultado['flags_suspeitas'].append(f"Erro na análise do ZIP: {str(e)}")

def _analisar_office(caminho_arquivo, resultado):
    """
    Analisa documentos do Office em busca de macros e conteúdo suspeito.
    
    Args:
        caminho_arquivo (str): Caminho para o arquivo do Office
        resultado (dict): Dicionário de resultado para atualizar
    """
    try:
        # Verificar presença de macros usando oletools
        vba_parser = olevba.VBA_Parser(caminho_arquivo)
        
        if vba_parser.detect_vba_macros():
            resultado['tem_macros'] = True
            resultado['flags_suspeitas'].append("Documento contém macros")
            
            # Analisar macros em busca de comportamentos suspeitos
            macros = vba_parser.extract_macros()
            for _, _, _, macro_code in macros:
                if macro_code:
                    # Verificar padrões suspeitos em macros
                    padroes_suspeitos = [
                        'Shell', 'WScript.Shell', 'CreateObject', 
                        'powershell', 'cmd.exe', 'ActiveXObject',
                        'ExecuteExcel4Macro', 'URLDownloadToFile',
                        'Process.Start', 'System.Diagnostics'
                    ]
                    
                    for padrao in padroes_suspeitos:
                        if padrao in macro_code:
                            resultado['flags_suspeitas'].append(
                                f"Macro contém código potencialmente malicioso: {padrao}"
                            )
        
        vba_parser.close()
    
    except Exception as e:
        logger.error(f"Erro ao analisar documento Office: {str(e)}")
        resultado['flags_suspeitas'].append(f"Erro na análise do documento: {str(e)}")

def _calcular_nivel_suspeita(resultado):
    """
    Calcula um nível de suspeita baseado nas flags encontradas.
    
    Args:
        resultado (dict): Resultado da análise
        
    Returns:
        str: Nível de suspeita ('baixo', 'medio', 'alto')
    """
    num_flags = len(resultado['flags_suspeitas'])
    
    # Verificar flags críticas que automaticamente elevam o nível
    for flag in resultado['flags_suspeitas']:
        if any(termo in flag.lower() for termo in ['macro', 'malicioso', 'powershell', 'cmd.exe']):
            return 'alto'
    
    # Classificação baseada no número de flags
    if num_flags == 0:
        return 'baixo'
    elif num_flags <= 2:
        return 'medio'
    else:
        return 'alto'