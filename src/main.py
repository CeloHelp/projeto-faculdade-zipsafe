#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ZIPSafe - Sistema de IA para Detecção Preventiva de Arquivos Maliciosos
Módulo principal que contém o ponto de entrada da aplicação.

Este módulo expõe a função analisar_arquivo que coordena a análise estática
e a classificação de risco de arquivos potencialmente maliciosos.
"""

import os
import sys
import json
import argparse
import logging
from datetime import datetime
import joblib

# Importações locais
from analisador_estatico import analisar_estaticamente
from utils import configurar_logging, salvar_relatorio

# Configuração de logging
logger = configurar_logging()

def analisar_arquivo(caminho_arquivo):
    """
    Função principal para análise de arquivos.
    
    Args:
        caminho_arquivo (str): Caminho para o arquivo a ser analisado
        
    Returns:
        dict: Resultado da análise contendo metadados e classificação de risco
    """
    logger.info(f"Iniciando análise do arquivo: {caminho_arquivo}")
    
    # Validar se o arquivo existe
    if not os.path.exists(caminho_arquivo):
        logger.error(f"Arquivo não encontrado: {caminho_arquivo}")
        return {"erro": "Arquivo não encontrado", "caminho": caminho_arquivo}
    
    # Realizar análise estática (sem executar o arquivo)
    try:
        resultado_analise = analisar_estaticamente(caminho_arquivo)
        logger.info(f"Análise estática concluída para: {caminho_arquivo}")
    except Exception as e:
        logger.error(f"Erro na análise estática: {str(e)}")
        return {"erro": f"Erro na análise: {str(e)}", "caminho": caminho_arquivo}
    
    # Tentar classificar o risco usando modelo (se existir)
    modelo_path = os.path.join("output", "modelo", "model.pkl")
    vectorizer_path = os.path.join("output", "modelo", "vectorizer.pkl")
    
    if os.path.exists(modelo_path) and os.path.exists(vectorizer_path):
        try:
            # Carregar modelo e vetorizador
            modelo = joblib.load(modelo_path)
            vectorizer = joblib.load(vectorizer_path)
            
            # Preparar dados para classificação
            features = [
                resultado_analise.get('nome_arquivo', ''),
                resultado_analise.get('extensao', ''),
                resultado_analise.get('mime_type', ''),
                str(resultado_analise.get('tamanho_bytes', 0)),
                str(resultado_analise.get('entropia', 0)),
                'tem_macros:' + str(resultado_analise.get('tem_macros', False)),
                'nivel_suspeita:' + str(resultado_analise.get('nivel_suspeita', 'baixo'))
            ]
            
            # Adicionar flags suspeitas
            for flag in resultado_analise.get('flags_suspeitas', []):
                features.append(flag)
                
            # Adicionar conteúdo ZIP se disponível
            for arquivo in resultado_analise.get('conteudo_zip', []):
                features.append('contem:' + arquivo)
            
            # Transformar dados e prever
            X = vectorizer.transform([' '.join(features)])
            
            # Verificar se o número de características é compatível com o modelo
            if X.shape[1] != modelo.n_features_in_:
                logger.warning(f"Incompatibilidade de características: modelo espera {modelo.n_features_in_}, mas recebeu {X.shape[1]}")
                # Ajustar para o número correto de características (padding com zeros)
                from scipy import sparse
                if X.shape[1] < modelo.n_features_in_:
                    padding = sparse.csr_matrix((1, modelo.n_features_in_ - X.shape[1]))
                    X = sparse.hstack([X, padding])
                else:
                    X = X[:, :modelo.n_features_in_]
                    
            nivel_risco_pred = modelo.predict(X)[0]
            prob_classes = modelo.predict_proba(X)[0]
            
            # Converter numpy.int64 para int padrão do Python
            if hasattr(nivel_risco_pred, 'item'):
                nivel_risco_pred = nivel_risco_pred.item()
                
            # Mapear valores numéricos para níveis de risco
            mapa_risco = {0: 'baixo', 1: 'medio', 2: 'alto'}
            nivel_risco_texto = mapa_risco.get(nivel_risco_pred, 'desconhecido')
            
            # Adicionar resultado da classificação
            resultado_analise['nivel_risco'] = nivel_risco_texto
            resultado_analise['probabilidades'] = {
                'baixo': float(prob_classes[0]),
                'medio': float(prob_classes[1]),
                'alto': float(prob_classes[2]) if len(prob_classes) > 2 else 0.0
            }
            
            logger.info(f"Classificação de risco: {nivel_risco_pred}")
        except Exception as e:
            logger.warning(f"Não foi possível classificar o risco: {str(e)}")
            resultado_analise['nivel_risco'] = "não classificado"
    else:
        logger.info("Modelo de classificação não encontrado. Executando apenas análise estática.")
        resultado_analise['nivel_risco'] = "não classificado"
    
    # Salvar relatório
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    nome_relatorio = f"relatorio_{timestamp}"
    
    try:
        salvar_relatorio(resultado_analise, nome_relatorio)
        logger.info(f"Relatório salvo como: {nome_relatorio}")
    except Exception as e:
        logger.error(f"Erro ao salvar relatório: {str(e)}")
    
    return resultado_analise

def main():
    """Função principal para execução via linha de comando"""
    parser = argparse.ArgumentParser(
        description="ZIPSafe - Sistema de IA para Detecção Preventiva de Arquivos Maliciosos"
    )
    parser.add_argument("arquivo", help="Caminho para o arquivo a ser analisado")
    args = parser.parse_args()
    
    resultado = analisar_arquivo(args.arquivo)
    print(json.dumps(resultado, indent=2, ensure_ascii=False))
    
    return 0

if __name__ == "__main__":
    sys.exit(main())