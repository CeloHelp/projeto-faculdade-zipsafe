import os
import sys

try:
    import tomllib
except Exception:
    import tomli as tomllib  # type: ignore

from supabase import create_client

SECRETS_PATH = os.path.join(os.getcwd(), ".streamlit", "secrets.toml")
with open(SECRETS_PATH, "rb") as f:
    data = tomllib.load(f)

sup = data.get("supabase", {})
url = sup.get("url")
key = sup.get("service_role") or sup.get("anon_key")
bucket = sup.get("bucket") or "relatorios"

client = create_client(url, key)
store = client.storage.from_(bucket)

print("Bucket:", bucket)

try:
    # Tenta upload usando opções atuais (contentType camelCase)
    resp = store.upload("relatorios/probe_upload.txt", b"hello from python", {"contentType": "text/plain", "upsert": "true"})
    print("Upload (contentType) OK:", resp)
except Exception as e:
    print("Upload (contentType) FAIL:", e)
    try:
        # Tenta upload com snake_case como fallback
        resp2 = store.upload("relatorios/probe_upload_snake.txt", b"hello from python (snake)", {"content_type": "text/plain", "upsert": "true"})
        print("Upload (content_type) OK:", resp2)
    except Exception as e2:
        print("Upload (content_type) FAIL:", e2)
        sys.exit(1)

sys.exit(0)
