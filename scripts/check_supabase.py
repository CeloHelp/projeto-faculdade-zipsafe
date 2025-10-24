import os
import sys

try:
    import tomllib  # Python 3.11+
except Exception:  # Fallback if needed
    import tomli as tomllib  # type: ignore

try:
    from supabase import create_client, Client
except Exception as e:
    print("ERROR: supabase SDK não instalado ou indisponível:", e)
    sys.exit(2)

SECRETS_PATH = os.path.join(os.getcwd(), ".streamlit", "secrets.toml")
if not os.path.exists(SECRETS_PATH):
    print("ERROR: secrets.toml não encontrado:", SECRETS_PATH)
    sys.exit(2)

with open(SECRETS_PATH, "rb") as f:
    data = tomllib.load(f)

sup = data.get("supabase", {})
url = sup.get("url")
key = sup.get("service_role") or sup.get("anon_key")
bucket = sup.get("bucket")

if not url or not key or not bucket:
    print("ERROR: Faltam campos em [supabase]: url, chave (service_role/anon_key) ou bucket")
    sys.exit(2)

try:
    client: Client = create_client(url, key)
    # Tenta listar poucos itens para validar acesso ao bucket
    res = client.storage.from_(bucket).list(path="", options={"limit": 5})
    # Normaliza tamanho do resultado (pode ser lista ou dict dependendo da versão)
    try:
        count = len(res)  # v2 costuma retornar lista
    except TypeError:
        try:
            count = len(res.get("data", []) if isinstance(res, dict) else [])
        except Exception:
            count = -1
    print("OK: conexão Supabase e acesso ao bucket funcionou; itens:", count)
    # Gera uma URL pública de exemplo (não garante que o arquivo exista)
    pub = client.storage.from_(bucket).get_public_url("teste_conexao.txt")
    print("Public URL exemplo:", pub)
    sys.exit(0)
except Exception as e:
    print("ERROR: falha ao acessar bucket '", bucket, "':", e)
    sys.exit(1)
