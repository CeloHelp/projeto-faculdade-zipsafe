#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ZIPSafe - Sistema de IA para Detecção Preventiva de Arquivos Maliciosos
Módulo de treinamento do modelo de IA.

Este módulo gera um dataset sintético e treina um modelo de classificação
para detectar arquivos potencialmente maliciosos.
"""

import os
import pandas as pd
import numpy as np
import joblib
import random
from faker import Faker
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import LabelEncoder
import matplotlib.pyplot as plt
import seaborn as sns

# Configurar o gerador de dados sintéticos
fake = Faker()
Faker.seed(42)
random.seed(42)
np.random.seed(42)

# Extensões comuns por categoria
EXTENSOES = {
    'documentos': ['pdf', 'doc', 'docx', 'txt', 'rtf', 'odt'],
    'planilhas': ['xls', 'xlsx', 'csv', 'ods'],
    'apresentacoes': ['ppt', 'pptx', 'odp'],
    'imagens': ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg'],
    'compactados': ['zip', 'rar', '7z', 'tar', 'gz'],
    'executaveis': ['exe', 'msi', 'bat', 'cmd', 'ps1', 'vbs', 'js'],
    'macros': ['docm', 'xlsm', 'pptm']
}

# Palavras comuns em nomes de arquivos maliciosos
PALAVRAS_SUSPEITAS = [
    'invoice', 'payment', 'urgent', 'confidential', 'bank', 'account',
    'password', 'update', 'verify', 'document', 'statement', 'receipt',
    'tax', 'refund', 'order', 'shipping', 'tracking', 'delivery'
]

def gerar_dataset_sintetico(num_amostras=1000, caminho_saida=None):
    """
    Gera um dataset sintético para treinamento do modelo.
    
    Args:
        num_amostras (int): Número de amostras a serem geradas
        caminho_saida (str): Caminho para salvar o dataset (opcional)
        
    Returns:
        pandas.DataFrame: Dataset gerado
    """
    print(f"Gerando dataset sintético com {num_amostras} amostras...")
    
    dados = []
    
    # Distribuição de classes (60% seguro, 40% malicioso)
    classes = ['seguro'] * int(num_amostras * 0.6) + ['malicioso'] * int(num_amostras * 0.4)
    random.shuffle(classes)
    
    for i in range(num_amostras):
        classe = classes[i] if i < len(classes) else 'seguro'
        
        # Gerar características diferentes com base na classe
        if classe == 'seguro':
            # Arquivos seguros: nomes comuns, extensões comuns, entropia normal
            categoria = random.choice(['documentos', 'planilhas', 'apresentacoes', 'imagens'])
            extensao = random.choice(EXTENSOES[categoria])
            
            if random.random() < 0.7:  # 70% dos arquivos seguros têm nomes comuns
                nome_base = fake.word()
                if random.random() < 0.3:  # 30% têm dois componentes no nome
                    nome_base += '_' + fake.word()
            else:
                # Alguns arquivos seguros podem ter nomes que parecem suspeitos
                nome_base = random.choice(PALAVRAS_SUSPEITAS)
            
            # Metadados para arquivos seguros
            tamanho = random.randint(10, 5000)  # KB
            entropia = random.uniform(3.5, 6.5)
            tem_macros = False
            nivel_risco = 'baixo'
            
        else:  # malicioso
            # Arquivos maliciosos: mais propensos a ter extensões executáveis ou macros
            if random.random() < 0.6:  # 60% dos maliciosos são executáveis ou têm macros
                categoria = random.choice(['executaveis', 'macros', 'compactados'])
            else:
                # Alguns maliciosos se disfarçam como arquivos comuns
                categoria = random.choice(['documentos', 'planilhas', 'apresentacoes'])
            
            extensao = random.choice(EXTENSOES[categoria])
            
            # Nomes mais propensos a usar palavras suspeitas
            if random.random() < 0.8:  # 80% usam palavras suspeitas
                nome_base = random.choice(PALAVRAS_SUSPEITAS)
                if random.random() < 0.4:  # 40% combinam duas palavras suspeitas
                    nome_base += '_' + random.choice(PALAVRAS_SUSPEITAS)
            else:
                nome_base = fake.word()
            
            # Metadados para arquivos maliciosos
            tamanho = random.randint(50, 10000)  # KB
            entropia = random.uniform(6.0, 7.9)  # Maior entropia (possível ofuscação)
            tem_macros = categoria == 'macros' or random.random() < 0.4
            
            # Determinar nível de risco
            if categoria in ['executaveis', 'macros'] or tem_macros:
                nivel_risco = 'alto'
            elif extensao in ['zip', 'rar'] and random.random() < 0.7:
                nivel_risco = 'alto'
            else:
                nivel_risco = 'medio'
        
        # Gerar nome de arquivo completo
        nome_arquivo = f"{nome_base}.{extensao}"
        
        # Adicionar à lista de dados
        dados.append({
            'nome_arquivo': nome_arquivo,
            'extensao': extensao,
            'tamanho_kb': tamanho,
            'entropia': entropia,
            'tem_macros': tem_macros,
            'categoria': categoria,
            'nivel_risco': nivel_risco,
            'classe': classe
        })
    
    # Criar DataFrame
    df = pd.DataFrame(dados)
    
    # Salvar dataset se caminho fornecido
    if caminho_saida:
        os.makedirs(os.path.dirname(caminho_saida), exist_ok=True)
        df.to_csv(caminho_saida, index=False)
        print(f"Dataset salvo em: {caminho_saida}")
    
    return df

def preprocessar_dados(df):
    """
    Pré-processa os dados para treinamento.
    
    Args:
        df (pandas.DataFrame): Dataset a ser pré-processado
        
    Returns:
        tuple: (X_train, X_test, y_train, y_test, vectorizer, label_encoder)
    """
    print("Pré-processando dados...")
    
    # Preparar features textuais (combinação de nome e extensão)
    df['texto_features'] = df['nome_arquivo'] + ' ' + df['extensao']
    
    # Codificar variáveis categóricas
    label_encoder = LabelEncoder()
    df['nivel_risco_encoded'] = label_encoder.fit_transform(df['nivel_risco'])
    
    # Vetorizar características textuais
    vectorizer = CountVectorizer(analyzer='char', ngram_range=(2, 4))
    X_text = vectorizer.fit_transform(df['texto_features'])
    
    # Combinar com outras características numéricas
    X_numeric = df[['tamanho_kb', 'entropia']].values
    X_binary = df[['tem_macros']].astype(int).values
    
    # Converter para array denso para concatenação
    X_text_dense = X_text.toarray()
    X_combined = np.hstack((X_text_dense, X_numeric, X_binary))
    
    # Dividir em conjuntos de treino e teste
    X_train, X_test, y_train, y_test = train_test_split(
        X_combined, 
        df['nivel_risco_encoded'],
        test_size=0.2,
        random_state=42
    )
    
    return X_train, X_test, y_train, y_test, vectorizer, label_encoder

def treinar_modelo(X_train, y_train, tipo_modelo='naive_bayes'):
    """
    Treina o modelo de classificação.
    
    Args:
        X_train: Features de treinamento
        y_train: Labels de treinamento
        tipo_modelo (str): Tipo de modelo ('naive_bayes' ou 'decision_tree')
        
    Returns:
        object: Modelo treinado
    """
    print(f"Treinando modelo ({tipo_modelo})...")
    
    if tipo_modelo == 'naive_bayes':
        modelo = MultinomialNB()
    elif tipo_modelo == 'decision_tree':
        modelo = DecisionTreeClassifier(max_depth=10, random_state=42)
    else:
        raise ValueError(f"Tipo de modelo não suportado: {tipo_modelo}")
    
    modelo.fit(X_train, y_train)
    return modelo

def avaliar_modelo(modelo, X_test, y_test, label_encoder):
    """
    Avalia o desempenho do modelo.
    
    Args:
        modelo: Modelo treinado
        X_test: Features de teste
        y_test: Labels de teste
        label_encoder: Codificador de labels
        
    Returns:
        dict: Métricas de avaliação
    """
    print("Avaliando modelo...")
    
    # Fazer previsões
    y_pred = modelo.predict(X_test)
    
    # Calcular métricas
    acuracia = accuracy_score(y_test, y_pred)
    relatorio = classification_report(y_test, y_pred, target_names=label_encoder.classes_, output_dict=True)
    matriz_confusao = confusion_matrix(y_test, y_pred)
    
    print(f"Acurácia: {acuracia:.4f}")
    print("\nRelatório de Classificação:")
    print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))
    
    # Plotar matriz de confusão
    plt.figure(figsize=(8, 6))
    sns.heatmap(matriz_confusao, annot=True, fmt='d', cmap='Blues',
                xticklabels=label_encoder.classes_,
                yticklabels=label_encoder.classes_)
    plt.xlabel('Predito')
    plt.ylabel('Real')
    plt.title('Matriz de Confusão')
    
    # Salvar gráfico
    os.makedirs(os.path.join('output', 'relatorios'), exist_ok=True)
    plt.savefig(os.path.join('output', 'relatorios', 'matriz_confusao.png'))
    
    return {
        'acuracia': acuracia,
        'relatorio': relatorio,
        'matriz_confusao': matriz_confusao
    }

def salvar_modelo(modelo, vectorizer, label_encoder):
    """
    Salva o modelo treinado e componentes relacionados.
    
    Args:
        modelo: Modelo treinado
        vectorizer: Vetorizador de features
        label_encoder: Codificador de labels
    """
    print("Salvando modelo e componentes...")
    
    # Criar diretório se não existir
    diretorio_modelo = os.path.join('output', 'modelo')
    os.makedirs(diretorio_modelo, exist_ok=True)
    
    # Salvar componentes
    joblib.dump(modelo, os.path.join(diretorio_modelo, 'model.pkl'))
    joblib.dump(vectorizer, os.path.join(diretorio_modelo, 'vectorizer.pkl'))
    joblib.dump(label_encoder, os.path.join(diretorio_modelo, 'label_encoder.pkl'))
    
    print(f"Modelo e componentes salvos em: {diretorio_modelo}")

def main():
    """Função principal para execução do treinamento"""
    print("ZIPSafe - Treinamento do Modelo de Detecção")
    print("=" * 50)
    
    # Definir caminhos
    dataset_path = os.path.join('data', 'dataset_exemplo.csv')
    
    # Gerar dataset sintético
    df = gerar_dataset_sintetico(num_amostras=1000, caminho_saida=dataset_path)
    
    # Pré-processar dados
    X_train, X_test, y_train, y_test, vectorizer, label_encoder = preprocessar_dados(df)
    
    # Treinar modelo (escolher entre 'naive_bayes' ou 'decision_tree')
    modelo = treinar_modelo(X_train, y_train, tipo_modelo='decision_tree')
    
    # Avaliar modelo
    metricas = avaliar_modelo(modelo, X_test, y_test, label_encoder)
    
    # Salvar modelo e componentes
    salvar_modelo(modelo, vectorizer, label_encoder)
    
    print("\nTreinamento concluído com sucesso!")
    return 0

if __name__ == "__main__":
    main()