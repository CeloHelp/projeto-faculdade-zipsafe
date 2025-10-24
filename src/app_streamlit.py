#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
from datetime import datetime
import streamlit as st
import pandas as pd

# Garantir que o diretório do projeto esteja no sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Importar funções principais do projeto
from src.main import analisar_arquivo
from src.utils import salvar_relatorio, supabase_available, supabase_list_reports

import re
import uuid

def sanitize_filename(name, max_len=120):
    base = os.path.basename(name)
    safe = re.sub(r'[^A-Za-z0-9._-]+', '_', base)
    return safe[:max_len]

MAX_UPLOAD_MB = 50

from collections import deque
import time
import json
import tempfile
import shutil

MAX_ANALYSES_PER_MINUTE = 10
SESSION_MAX_PER_MINUTE = 5
ANALYSIS_TIMESTAMPS = deque()

def _purge_old(ts_deque, window_sec=60):
    now = time.time()
    while ts_deque and now - ts_deque[0] > window_sec:
        ts_deque.popleft()

def analysis_allowed():
    global ANALYSIS_TIMESTAMPS
    _purge_old(ANALYSIS_TIMESTAMPS)
    if len(ANALYSIS_TIMESTAMPS) >= MAX_ANALYSES_PER_MINUTE:
        return False, f"Limite global de {MAX_ANALYSES_PER_MINUTE}/min atingido. Aguarde."
    if 'analysis_timestamps' not in st.session_state:
        st.session_state.analysis_timestamps = deque()
    _purge_old(st.session_state.analysis_timestamps)
    if len(st.session_state.analysis_timestamps) >= SESSION_MAX_PER_MINUTE:
        return False, f"Limite por sessão de {SESSION_MAX_PER_MINUTE}/min atingido. Aguarde."
    return True, None

def register_analysis():
    ANALYSIS_TIMESTAMPS.append(time.time())
    st.session_state.analysis_timestamps.append(time.time())


def preview_bytes(path, num_bytes=256):
    try:
        with open(path, 'rb') as f:
            data = f.read(num_bytes)
        hex_str = ' '.join(f'{b:02X}' for b in data)
        ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data)
        return hex_str, ascii_str
    except Exception as e:
        return "", f"Erro ao ler bytes: {e}"


def extract_strings(path, min_len=4, max_bytes=1024*1024):
    try:
        with open(path, 'rb') as f:
            data = f.read(max_bytes)
        printable = set(range(32, 127))
        result = []
        buf = []
        for b in data:
            if b in printable:
                buf.append(chr(b))
            else:
                if len(buf) >= min_len:
                    result.append(''.join(buf))
                buf = []
        if len(buf) >= min_len:
            result.append(''.join(buf))
        # UTF-16LE
        try:
            text_utf16 = data.decode('utf-16le', errors='ignore')
            cur = []
            parts = []
            for ch in text_utf16:
                if 32 <= ord(ch) <= 126:
                    cur.append(ch)
                else:
                    if len(cur) >= min_len:
                        parts.append(''.join(cur))
                    cur = []
            if len(cur) >= min_len:
                parts.append(''.join(cur))
            for s in parts:
                if s not in result:
                    result.append(s)
        except Exception:
            pass
        return result[:50]
    except Exception as e:
        return [f"Erro ao extrair strings: {e}"]


def append_audit_entry(relatorio_id, resultado, user, created_at):
    """
    Registra uma entrada de auditoria usando o caminho padrão de auditoria.
    Mantém a assinatura original e delega para um gravador genérico.
    """
    audit_dir = os.path.join(PROJECT_ROOT, "output", "auditoria")
    os.makedirs(audit_dir, exist_ok=True)
    audit_csv = os.path.join(audit_dir, "auditoria.csv")
    entry = {
        "relatorio_id": relatorio_id,
        "arquivo": resultado.get("nome_arquivo", ""),
        "sha256": resultado.get("hash_sha256", ""),
        "risco": resultado.get("nivel_risco", "não classificado"),
        "analisado_por": user,
        "analisado_em": created_at,
    }
    _append_audit_entry_csv(audit_csv, entry)


def _append_audit_entry_csv(csv_path: str, entry: dict):
    os.makedirs(os.path.dirname(csv_path), exist_ok=True)
    import csv
    header = ["relatorio_id","arquivo","sha256","risco","analisado_por","analisado_em"]
    file_exists = os.path.exists(csv_path)
    mode = "a" if file_exists else "w"
    with open(csv_path, mode, newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(header)
        writer.writerow([
            entry.get("relatorio_id", ""),
            entry.get("arquivo", ""),
            entry.get("sha256", ""),
            entry.get("risco", ""),
            entry.get("analisado_por", ""),
            entry.get("analisado_em", ""),
        ])


def cleanup_uploads(dir_path: str, max_age_minutes: int = 60):
    try:
        os.makedirs(dir_path, exist_ok=True)
        now = time.time()
        for name in os.listdir(dir_path):
            p = os.path.join(dir_path, name)
            if not os.path.isfile(p):
                continue
            age_min = (now - os.path.getmtime(p)) / 60.0
            if age_min > max_age_minutes:
                try:
                    os.remove(p)
                except Exception:
                    pass
    except Exception:
        pass


def retro_cleanup_audit():
    """Remove auditoria CSV e campo analisado_por dos JSON antigos."""
    audit_csv = os.path.join(PROJECT_ROOT, "output", "auditoria", "auditoria.csv")
    removed_csv = False
    try:
        if os.path.exists(audit_csv):
            os.remove(audit_csv)
            removed_csv = True
    except Exception:
        pass

    rel_dir = os.path.join(PROJECT_ROOT, "output", "relatorios")
    updated_json = 0
    if os.path.isdir(rel_dir):
        for fname in os.listdir(rel_dir):
            if not fname.endswith(".json"):
                continue
            json_path = os.path.join(rel_dir, fname)
            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if "analisado_por" in data:
                    data.pop("analisado_por", None)
                    with open(json_path, "w", encoding="utf-8") as f:
                        json.dump(data, f, ensure_ascii=False, indent=2)
                    updated_json += 1
            except Exception:
                continue
    return removed_csv, updated_json


def cleanup_reports_by_age(max_age_days: int = 30):
    """Apaga arquivos de relatório (html/csv/json) mais antigos que max_age_days."""
    rel_dir = os.path.join(PROJECT_ROOT, "output", "relatorios")
    removed = 0
    now = time.time()
    if os.path.isdir(rel_dir):
        for fname in os.listdir(rel_dir):
            path = os.path.join(rel_dir, fname)
            if not os.path.isfile(path):
                continue
            age_days = (now - os.path.getmtime(path)) / 86400.0
            if age_days > max_age_days:
                try:
                    os.remove(path)
                    removed += 1
                except Exception:
                    pass
    return removed


def list_recent_reports(n=10):
    rel_dir = os.path.join(PROJECT_ROOT, "output", "relatorios")
    if not os.path.isdir(rel_dir):
        return []
    files = [f for f in os.listdir(rel_dir) if f.endswith(".json")]
    entries = []
    for fname in files:
        json_path = os.path.join(rel_dir, fname)
        try:
            mtime = os.path.getmtime(json_path)
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            entries.append({
                "relatorio": os.path.splitext(fname)[0],
                "mtime": mtime,
                "criado_em": datetime.fromtimestamp(mtime).strftime("%d/%m/%Y %H:%M:%S"),
                "risco": data.get("nivel_risco", "não classificado"),
                "arquivo": data.get("nome_arquivo", ""),
                "analisado_por": data.get("analisado_por", ""),
                "analisado_em": data.get("analisado_em", ""),
                "html": os.path.join(rel_dir, os.path.splitext(fname)[0] + ".html"),
                "csv": os.path.join(rel_dir, os.path.splitext(fname)[0] + ".csv"),
                "json": json_path
            })
        except Exception:
            continue
    entries.sort(key=lambda e: e["mtime"], reverse=True)
    return entries[:n]

st.set_page_config(page_title="ZIPSafe", page_icon="🛡️", layout="wide")
st.title("ZIPSafe - Analisador de Arquivos")
st.write("Faça upload de um arquivo para análise estática e classificação de risco.")
STYLE_REPORT = """
<style>
.risk-card { padding: 0.75rem 1rem; border-radius: 8px; color: #fff; font-weight: 600; margin-bottom: 0.5rem; }
.risk-low { background: #2e7d32; }
.risk-medium { background: #ed6c02; }
.risk-high { background: #d32f2f; }
.chips { display: flex; flex-wrap: wrap; gap: 6px; }
.chip { padding: 6px 10px; border-radius: 999px; font-size: 0.85rem; background: #eee; }
.chip-danger { background: #ffebee; color: #b71c1c; border: 1px solid #ffcdd2; }
.chip-warning { background: #fff3e0; color: #e65100; border: 1px solid #ffe0b2; }
.file-bad { color: #d32f2f; font-weight: 600; }
.file-ok { color: #2e7d32; }
</style>
"""

def risk_class(nivel_risco):
    s = str(nivel_risco or "").strip().lower()
    if s.startswith("alto"):
        return "risk-high"
    if s.startswith("medio") or s.startswith("médio"):
        return "risk-medium"
    if s.startswith("baixo"):
        return "risk-low"
    return "risk-medium"


def render_analysis_summary(resultado, file_path=None):
    try:
        risco = resultado.get("nivel_risco", "não classificado")
        klass = risk_class(risco)
        flags = resultado.get("flags_suspeitas", []) or []
        entropy = resultado.get("entropia")
        tem_macros = resultado.get("tem_macros")

        html_parts = []
        html_parts.append(f'<div class="risk-card {klass}">Nível de risco: {risco}</div>')
        chips = []
        if tem_macros:
            chips.append('<span class="chip chip-warning">Macros detectadas</span>')
        if isinstance(entropy, (int, float)):
            chips.append(f'<span class="chip">Entropia {entropy:.2f}/8.00</span>')
        for f in flags[:12]:
            chips.append(f'<span class="chip chip-danger">{f}</span>')
        if chips:
            html_parts.append('<div class="chips">' + ' '.join(chips) + '</div>')

        st.markdown(''.join(html_parts), unsafe_allow_html=True)
    except Exception:
        # Se algo falhar, não quebra a página
        pass

def inject_report_styles():
    try:
        st.markdown(STYLE_REPORT, unsafe_allow_html=True)
    except Exception:
        pass

inject_report_styles()

# Preparar dados de histórico e filtros
if supabase_available():
    recent = supabase_list_reports(50)
else:
    recent = list_recent_reports(50)
risk_options = sorted(list({e['risco'] for e in recent})) or ["baixo","medio","alto","não classificado"]

with st.sidebar:
    st.header("Filtros")
    search_query = st.text_input("Buscar por nome", key="hist_search", placeholder="nome do arquivo ou relatório")
    risk_filter = st.multiselect("Filtrar por risco", options=risk_options, default=risk_options, key="hist_risk_filter")
    st.caption("Arquivos enviados são removidos após a análise. Relatórios são mantidos.")

    st.header("Manutenção")
    cleanup_days = st.number_input("Apagar relatórios mais antigos que (dias)", min_value=1, max_value=3650, value=30, step=1, key="cleanup_days")
    if st.button("Executar limpeza de relatórios", key="btn_cleanup_reports"):
        removed = cleanup_reports_by_age(int(cleanup_days))
        st.toast(f"Relatórios apagados: {removed}")
    if st.button("Remover auditoria antiga", key="btn_cleanup_audit"):
        removed_csv, updated_json = retro_cleanup_audit()
        st.toast(f"Auditoria CSV removido: {'sim' if removed_csv else 'não'}. JSONs atualizados: {updated_json}")

uploaded_file = st.file_uploader(
    "Selecione um arquivo",
    type=[
        "zip", "exe", "dll", "com", "bat", "cmd", "ps1", "vbs", "js", "jse", "wsf", "wsh", "msi", "scr",
        "doc", "docm", "xls", "xlsm", "ppt", "pptm", "pdf", "rar", "txt"
    ],
    help=f"Suporta ZIP, executáveis, documentos Office e texto. Limite: {MAX_UPLOAD_MB} MB."
)

# Tabela de histórico com filtros
filtered = [e for e in recent if (
    (not search_query) or (search_query.lower() in (os.path.basename(e['arquivo']) or '').lower()) or (search_query.lower() in e['relatorio'].lower())
) and (e['risco'] in (risk_filter or risk_options))]

st.subheader("Histórico de relatórios")
if filtered:
    if supabase_available():
        df = pd.DataFrame([
            {
                "Data": e["criado_em"],
                "Risco": e["risco"],
                "Arquivo": os.path.basename(e["arquivo"]) if e["arquivo"] else "",
                "Relatório": e["relatorio"],
                "HTML": e.get("html_url"),
                "CSV": e.get("csv_url"),
                "JSON": e.get("json_url"),
            }
            for e in filtered
        ])
        st.dataframe(
            df,
            width='stretch',
            height=300,
            column_config={
                "HTML": st.column_config.LinkColumn("HTML", help="Abrir relatório HTML", display_text="Abrir"),
                "CSV": st.column_config.LinkColumn("CSV", help="Baixar CSV", display_text="Baixar"),
                "JSON": st.column_config.LinkColumn("JSON", help="Baixar JSON", display_text="Baixar"),
            }
        )
    else:
        df = pd.DataFrame([
            {
                "Data": e["criado_em"],
                "Risco": e["risco"],
                "Arquivo": os.path.basename(e["arquivo"]) if e["arquivo"] else "",
                "Relatório": e["relatorio"],
            }
            for e in filtered
        ])
        st.dataframe(df, width='stretch', height=300)

    selected_relatorio = st.selectbox(
        "Selecionar relatório para download",
        options=[e["relatorio"] for e in filtered],
        key="history_select_relatorio"
    )
    selected_entry = next((e for e in filtered if e["relatorio"] == selected_relatorio), None)
    if selected_entry:
        if supabase_available():
            col1, col2, col3 = st.columns(3)
            if selected_entry.get('html_url'):
                col1.link_button('Abrir relatório', selected_entry['html_url'])
            else:
                col1.write('HTML indisponível')
            if selected_entry.get('csv_url'):
                col2.link_button('Baixar CSV', selected_entry['csv_url'])
            else:
                col2.write('CSV indisponível')
            if selected_entry.get('json_url'):
                col3.link_button('Baixar JSON', selected_entry['json_url'])
            else:
                col3.write('JSON indisponível')
        else:
            sdl1, sdl2, sdl3 = st.columns(3)
            try:
                with open(selected_entry["html"], "rb") as fh:
                    sdl1.download_button("HTML", fh.read(), file_name=os.path.basename(selected_entry["html"]), mime="text/html", key="dl_html_hist")
            except Exception:
                sdl1.write("HTML indisponível")
            try:
                with open(selected_entry["csv"], "rb") as fc:
                    sdl2.download_button("CSV", fc.read(), file_name=os.path.basename(selected_entry["csv"]), mime="text/csv", key="dl_csv_hist")
            except Exception:
                sdl2.write("CSV indisponível")
            try:
                with open(selected_entry["json"], "rb") as fj:
                    sdl3.download_button("JSON", fj.read(), file_name=os.path.basename(selected_entry["json"]), mime="application/json", key="dl_json_hist")
            except Exception:
                sdl3.write("JSON indisponível")
else:
    st.caption("Sem relatórios ainda.")

if uploaded_file:
    allowed, msg = analysis_allowed()
    if not allowed:
        st.error(msg)
    elif uploaded_file.size > MAX_UPLOAD_MB * 1024 * 1024:
        st.error(f"O arquivo excede {MAX_UPLOAD_MB} MB. Selecione um menor.")
    else:
        # Força armazenamento temporário (auto-excluir) para maior segurança
        use_temp = True
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = sanitize_filename(uploaded_file.name)
        unique_suffix = uuid.uuid4().hex[:8]

        if use_temp:
            tmp_dir = tempfile.mkdtemp(prefix="zipsafe_")
            save_path = os.path.join(tmp_dir, f"{timestamp}_{unique_suffix}_{safe_name}")
            try:
                with open(save_path, "wb") as f:
                    f.write(uploaded_file.getbuffer())
                st.info(f"Arquivo armazenado temporariamente em `{save_path}`")

                register_analysis()
                with st.spinner("Analisando arquivo..."):
                    resultado = analisar_arquivo(save_path)

                if "erro" in resultado:
                    st.error(f"Erro: {resultado['erro']}")
                else:
                    risco = resultado.get("nivel_risco", "não classificado")
                    st.subheader(f"Nível de risco: {risco}")
                    render_analysis_summary(resultado, save_path)

                    # Informações principais
                    col1, col2 = st.columns(2)
                    with col1:
                        st.markdown("**Informações do arquivo**")
                        st.code(
                            f"Nome: {resultado.get('nome_arquivo')}\n"
                            f"Tamanho: {resultado.get('tamanho_bytes')} bytes\n"\
                            f"MIME: {resultado.get('mime_type')}\n"\
                            f"Extensão: {resultado.get('extensao')}\n"\
                            f"SHA256: {resultado.get('hash_sha256')}"
                        )
                    with col2:
                        st.markdown("**Análise**")
                        st.code(
                            f"Entropia: {resultado.get('entropia', 0):.2f}/8.0\n"\
                            f"Macros: {'Sim' if resultado.get('tem_macros') else 'Não'}\n"\
                            f"Flags: {len(resultado.get('flags_suspeitas', []))}"
                        )

                    # Flags suspeitas
                    flags = resultado.get("flags_suspeitas", [])
                    if flags:
                        st.markdown("**Flags suspeitas**")
                        for flag in flags:
                            st.write(f"- {flag}")

                    # Conteúdo ZIP
                    conteudo_zip = resultado.get("conteudo_zip", [])
                    if conteudo_zip:
                        st.markdown("**Conteúdo do ZIP**")
                        st.write("\n".join(conteudo_zip))

                    # Probabilidades, se presentes
                    if "probabilidades" in resultado:
                        st.markdown("**Probabilidades de risco**")
                        probs = {k: round(v, 3) for k, v in resultado["probabilidades"].items()}
                        st.json(probs)

                    # Amostras do arquivo para diagnóstico
                    with st.expander("Amostra dos primeiros bytes (hex/ascii)"):
                        hex_str, ascii_str = preview_bytes(save_path, num_bytes=256)
                        if hex_str:
                            st.code(hex_str, language="text")
                            st.code(ascii_str, language="text")
                        else:
                            st.caption(ascii_str or "Não foi possível ler bytes.")

                    with st.expander("Strings legíveis (amostra)"):
                        strings = extract_strings(save_path, min_len=4, max_bytes=1024*1024)
                        if strings:
                            st.write("\n".join(strings))
                        else:
                            st.caption("Nenhuma string legível encontrada.")

                    # Gerar relatório dedicado com nome conhecido
                    nome_relatorio = f"ui_relatorio_{timestamp}"
                    try:
                        resultado['analisado_em'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                        info = salvar_relatorio(resultado, nome_relatorio)
                        urls = (info or {}).get('urls')
                        if urls and any(urls.values()):
                            st.toast("Relatório salvo no Supabase", icon='✅')
                            col_dl1, col_dl2, col_dl3 = st.columns(3)
                            if urls.get('html'):
                                col_dl1.link_button("Abrir relatório HTML", urls['html'])
                            if urls.get('csv'):
                                col_dl2.link_button("Baixar relatório CSV", urls['csv'])
                            if urls.get('json'):
                                col_dl3.link_button("Baixar relatório JSON", urls['json'])
                        else:
                            rel_dir = os.path.join(PROJECT_ROOT, "output", "relatorios")
                            html_path = os.path.join(rel_dir, f"{nome_relatorio}.html")
                            csv_path = os.path.join(rel_dir, f"{nome_relatorio}.csv")
                            json_path = os.path.join(rel_dir, f"{nome_relatorio}.json")
                            st.toast("Relatório salvo localmente", icon='✅')
                            st.write(f"HTML: `{html_path}`")
                            st.write(f"CSV: `{csv_path}`")

                            # Auditoria desativada por enquanto

                            # Botões de download
                            col_dl1, col_dl2, col_dl3 = st.columns(3)
                            with open(html_path, "rb") as fh:
                                col_dl1.download_button(
                                    "Baixar relatório HTML",
                                    fh.read(),
                                    file_name=os.path.basename(html_path),
                                    mime="text/html"
                                )
                            with open(csv_path, "rb") as fc:
                                col_dl2.download_button(
                                    "Baixar relatório CSV",
                                    fc.read(),
                                    file_name=os.path.basename(csv_path),
                                    mime="text/csv"
                                )
                            with open(json_path, "rb") as fj:
                                col_dl3.download_button(
                                    "Baixar relatório JSON",
                                    fj.read(),
                                    file_name=os.path.basename(json_path),
                                    mime="application/json"
                                )
                    except Exception as e:
                        st.warning(f"Não foi possível salvar relatório: {e}")
            except Exception as e:
                st.error(f"Erro ao processar análise: {e}")
            finally:
                try:
                    shutil.rmtree(tmp_dir)
                    st.toast("Arquivo temporário excluído.")
                except Exception:
                    st.toast("Falha ao excluir arquivo temporário.", icon="⚠️")
# Cleanup: duplicatas de estilos e funções removidas do final do arquivo

def render_history_table():
    # Lista histórico do Supabase se disponível, caso contrário usa função local existente
    try:
        if supabase_available():
            entries = supabase_list_reports(100)
            if entries:
                import pandas as pd
                df = pd.DataFrame(entries)
                st.dataframe(df, width='stretch')
                st.caption('Links públicos são exibidos quando disponíveis.')
            else:
                st.info('Nenhum relatório disponível no Supabase ainda.')
        else:
            # Fallback: mantém comportamento anterior
            if 'list_recent_reports' in globals():
                try:
                    df = list_recent_reports(limit=100)
                    st.dataframe(df, width='stretch')
                except Exception:
                    st.warning('Histórico local indisponível.')
            else:
                st.info('Histórico local não configurado.')
    except Exception:
        st.warning('Falha ao renderizar histórico.')

def on_analysis_complete(resultado, nome_base):
    info = salvar_relatorio(resultado, nome_base)
    urls = (info or {}).get('urls')
    if urls and any(urls.values()):
        st.toast('Relatório salvo no Supabase', icon='✅')
        col1, col2, col3 = st.columns(3)
        if urls.get('html'):
            col1.link_button('Abrir HTML', urls['html'])
        if urls.get('csv'):
            col2.link_button('Baixar CSV', urls['csv'])
        if urls.get('json'):
            col3.link_button('Baixar JSON', urls['json'])
    else:
        st.toast('Relatório salvo localmente', icon='✅')