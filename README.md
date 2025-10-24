# ZIPSafe — Detecção Preventiva de Arquivos Maliciosos

ZIPSafe é uma aplicação de análise estática de arquivos com classificação de risco assistida por IA. Foca em uso cotidiano (e-mail, WhatsApp, downloads) para ajudar pessoas e equipes a identificar arquivos potencialmente perigosos antes de abrir, com um fluxo simples de upload, análise e geração de relatório. 

## Motivação
- Ataques por engenharia social continuam sendo uma das maiores portas de entrada (ZIPs, executáveis, documentos Office com macros). 
- Usuários não técnicos precisam de respostas simples: "posso abrir?" e "por que é arriscado?".
- Equipes precisam de rastreabilidade (relatórios) e acesso centralizado (Supabase), mas com fallback local quando internet/credenciais não estão disponíveis.

## Principais funcionalidades
- Upload de arquivos: `zip`, executáveis, scripts, documentos Office, PDF e texto.
- Análise estática segura (sem executar o conteúdo):
  - Metadados (tamanho, MIME, extensão).
  - Entropia (sinais de ofuscação).
  - Detecção de macros via `oletools/olevba`.
  - Inspeção de conteúdo de ZIP (lista de arquivos internos).
  - Amostra dos primeiros bytes (hex/ascii) para diagnóstico.
- Classificação de risco com IA (quando o modelo está disponível): `baixo`, `medio`, `alto`.
- Relatório com links públicos (Supabase) ou salvamento local como fallback.
- Histórico com filtros e links clicáveis (HTML/CSV/JSON) e botão "Abrir relatório".
- Manutenção: limpeza de relatórios antigos e auditorias legadas.

## Arquitetura do projeto
- `src/app_streamlit.py`: UI em Streamlit, fluxo de upload/análise/relatório, histórico e manutenção.
- `src/analisador_estatico.py`: funções de análise estática e extração de sinais/flags.
- `src/main.py`: orquestra análise, classificação (quando o modelo existe) e salva relatório.
- `src/utils.py`: utilitários, integração com Supabase (Storage + tabela `public.reports`) e lógica de fallback local.
- `src/treino_modelo.py`: pipeline de treinamento da IA (dataset sintético + modelos clássicos).
- `scripts/storage_upload_probe.py`: script de diagnóstico para upload no Storage.
- `scripts/check_supabase.py`: verificação rápida de credenciais e acessos.
- Saídas:
  - `output/relatorios/`: relatórios e artefatos (inclui gráficos, ex.: matriz de confusão).
  - `output/modelo/`: artefatos do modelo (`model.pkl`, `vectorizer.pkl`, `label_encoder.pkl`).

## Como a IA foi treinada
O treinamento está em `src/treino_modelo.py` e segue esta pipeline:
1. Geração de dataset sintético com `Faker` e regras heurísticas:
   - Classes: `seguro` (≈60%) e `malicioso` (≈40%).
   - Extensões por categoria (documentos, planilhas, executáveis, macros, compactados).
   - Nomes de arquivo com probabilidade de conter palavras suspeitas (ex.: `invoice`, `urgent`, `payment`).
   - Metadados simulados: tamanho (KB), entropia, presença de macros, categoria e nível de risco esperado.
2. Pré-processamento:
   - Combinação textual do nome do arquivo e extensão.
   - Vetorização de caracteres com `CountVectorizer` e n-grams de 2 a 4.
   - Junção com features numéricas (tamanho, entropia) e binária (tem_macros).
   - Split treino/teste com `train_test_split` (20% teste, `random_state=42`).
3. Modelagem:
   - Opções: `MultinomialNB` (Naive Bayes) ou `DecisionTreeClassifier` (max_depth=10).
   - Treinamento em `X_train`/`y_train` e avaliação em `X_test`/`y_test`.
4. Avaliação e artefatos:
   - Métricas: acurácia e relatório de classificação por nível de risco.
   - Matriz de confusão salva em `output/relatorios/matriz_confusao.png`.
   - Componentes salvos com `joblib`: `model.pkl`, `vectorizer.pkl`, `label_encoder.pkl` em `output/modelo/`.

### Executando o treinamento
1. Instale dependências:
   ```bash
   pip install -r requirements.txt
   ```
2. Treine e gere o dataset + artefatos:
   ```bash
   python src/treino_modelo.py
   ```
3. Artefatos gerados:
   - Dataset: `data/dataset_exemplo.csv`.
   - Modelo e componentes: `output/modelo/`.
   - Gráfico: `output/relatorios/matriz_confusao.png`.

## Executando a aplicação
1. Configure as credenciais do Supabase em `.streamlit/secrets.toml`:
   ```toml
   supabase_url = "https://<YOUR-PROJECT>.supabase.co"
   supabase_key = "<SERVICE_ROLE_OR_ANON_KEY>"
   supabase_bucket = "relatorios"
   supabase_table = "reports"  # schema público
   ```
   - Use uma chave com permissão de gravação no Storage e na tabela `public.reports`.
   - Ajuste o bucket/tabela conforme seu projeto.
2. Execute o Streamlit:
   ```bash
   streamlit run src/app_streamlit.py
   ```
3. Fluxo esperado:
   - Upload do arquivo → análise → classificação (se modelo disponível) → salvar relatório.
   - Com Supabase ativo: toast "Relatório salvo no Supabase" + links públicos.
   - Sem Supabase ou falha: toast "Relatório salvo localmente" + botões de download locais.

## Integração com Supabase
- Storage: arquivos ficam em `relatorios/relatorios/<nome>.<ext>`.
- Tabela `public.reports`: histórico dos relatórios gerados, com URLs públicos.
- Cabeçalhos de upload: `{"contentType": "text/plain", "upsert": "true"}`.
  - Observação: `upsert` deve ser string (`"true"`), não booleano — caso contrário, erro "Header value must be str or bytes".
- Fallback seguro: só removemos arquivos locais se ao menos um upload para o Storage tiver sucesso.

## Funcionalidades de UI
- Histórico com filtros de busca e por risco.
- Tabela com colunas de link (HTML, CSV, JSON) e botão "Abrir relatório" para o HTML.
- Painéis de diagnóstico (bytes iniciais, flags suspeitas, conteúdo ZIP).
- Ações de manutenção: limpeza de relatórios antigos e auditorias.

## Estrutura de pastas (resumo)
```
├── src/
│   ├── app_streamlit.py        # UI e fluxo
│   ├── analisador_estatico.py  # análise estática
│   ├── main.py                 # orquestração e persistência
│   ├── treino_modelo.py        # treinamento da IA
│   └── utils.py                # utilitários e Supabase
├── scripts/
│   ├── storage_upload_probe.py # diagnóstico Storage
│   └── check_supabase.py       # verificação de credenciais
├── output/
│   ├── modelo/                 # modelo e vetorizadores
│   └── relatorios/             # relatórios e gráficos
├── data/
│   └── dataset_exemplo.csv     # gerado pelo treino
└── .streamlit/secrets.toml     # credenciais locais
```

## Troubleshooting
- Upload falha com erro de cabeçalho: valide `upsert = "true"` em `src/utils.py` e nos scripts.
- Links não aparecem no histórico: verifique se Supabase está disponível e se `utils.py` populou `html_url`, `csv_url`, `json_url`.
- Sem modelo de IA: a classificação fica como "não classificado"; rode o treinamento para gerar `output/modelo/`.
- Permissões no Storage: bucket `relatorios` deve permitir `insert` e `select` para o token usado.

## Como contribuir
- Commits semânticos sugeridos: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`.
- Pull requests com descrição das mudanças e impacto.

## Roadmap
- Melhorar explicabilidade da classificação (feature importance / SHAP).
- Adicionar análise dinâmica sandbox (opcional, isolada).
- Suporte a mais formatos e regras de detecção.
