#!/usr/bin/env python3
"""サービスアカウント JSON から Streamlit 用 secrets.toml を生成する。

基本の使い方:
  1. GCP からダウンロードした JSON を .streamlit/service_account.json に保存
  2. .streamlit/secrets.toml.example の値を編集（または既存 secrets.toml を用意）
  3. python scripts/build_streamlit_secrets.py --write

Streamlit Cloud 用（改行問題を避ける Base64 1行・推奨）:
  python scripts/build_streamlit_secrets.py --cloud --print

JSON ファイルを直接指定:
  python scripts/build_streamlit_secrets.py --json ~/Downloads/key.json --write
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
from pathlib import Path

import gspread
from google.auth.transport.requests import Request
from google.oauth2 import service_account

REPO_ROOT = Path(__file__).resolve().parents[1]
STREAMLIT_DIR = REPO_ROOT / ".streamlit"
DEFAULT_JSON = STREAMLIT_DIR / "service_account.json"
DEFAULT_TEMPLATE = STREAMLIT_DIR / "secrets.toml.example"
DEFAULT_OUTPUT = STREAMLIT_DIR / "secrets.toml"


def _toml_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def format_service_account_section(info: dict) -> str:
    """[google_service_account] セクション（Streamlit TOML 向け）。"""
    order = (
        "type",
        "project_id",
        "private_key_id",
        "private_key",
        "client_email",
        "client_id",
        "auth_uri",
        "token_uri",
        "auth_provider_x509_cert_url",
        "client_x509_cert_url",
        "universe_domain",
    )
    lines: list[str] = ["[google_service_account]"]
    for key in order:
        if key not in info:
            continue
        val = info[key]
        if key == "private_key":
            pem = str(val).replace("\\n", "\n").strip()
            lines.append('private_key = """')
            lines.extend(pem.splitlines())
            lines.append('"""')
        else:
            lines.append(f'{key} = "{_toml_escape(str(val))}"')
    return "\n".join(lines)


def load_service_account_json(
    json_path: Path | None, *, use_stdin: bool
) -> dict:
    if use_stdin:
        raw = sys.stdin.read()
        if not raw.strip():
            raise ValueError("標準入力が空です。JSON を貼り付けて Enter → Ctrl+D で終了してください。")
        return json.loads(raw)

    path = json_path or DEFAULT_JSON
    if not path.is_file():
        raise FileNotFoundError(
            f"JSON が見つかりません: {path}\n"
            f"GCP からダウンロードした JSON を {DEFAULT_JSON} に保存するか、"
            f"--json パス を指定してください。"
        )
    return json.loads(path.read_text(encoding="utf-8"))


def strip_service_account_blocks(text: str) -> str:
    """既存 TOML から [google_service_account] と GOOGLE_SERVICE_ACCOUNT_JSON を除去。"""
    lines = text.splitlines()
    out: list[str] = []
    in_sa = False
    in_json_secret = False

    for line in lines:
        stripped = line.strip()

        if stripped == "[google_service_account]":
            in_sa = True
            continue
        if in_sa:
            if stripped.startswith("[") and stripped.endswith("]"):
                in_sa = False
                out.append(line)
            continue

        if stripped.startswith("GOOGLE_SERVICE_ACCOUNT_JSON_B64"):
            continue

        if stripped.startswith("GOOGLE_SERVICE_ACCOUNT_JSON"):
            if "'''" in line:
                if line.count("'''") >= 2:
                    continue
                in_json_secret = True
                continue
            if line.rstrip().endswith("'") and "GOOGLE_SERVICE_ACCOUNT_JSON = '" in line:
                continue
            in_json_secret = True
            continue
        if in_json_secret:
            if "'''" in line or (line.rstrip().endswith("'") and not line.strip().startswith("#")):
                in_json_secret = False
            continue

        out.append(line)

    return re.sub(r"\n{3,}", "\n\n", "\n".join(out)).rstrip() + "\n"


def encode_service_account_b64(info: dict) -> str:
    raw = json.dumps(info, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def build_cloud_secrets_toml(template_text: str, info: dict, *, minimal: bool = False) -> str:
    base = strip_service_account_blocks(template_text).rstrip()
    b64 = encode_service_account_b64(info)
    if minimal:
        lines = [
            ln
            for ln in base.splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        base = "\n".join(lines).rstrip()
    comment = ""
    if not minimal:
        comment = (
            "# Streamlit Cloud 推奨: JSON を Base64 1行で渡す（private_key 改行問題を回避）\n"
        )
    return (
        f"{base}\n\n"
        f"{comment}"
        f'GOOGLE_SERVICE_ACCOUNT_JSON_B64 = "{b64}"\n'
    )


def build_secrets_toml(
    template_text: str, info: dict, *, cloud: bool = False, minimal: bool = False
) -> str:
    if cloud:
        return build_cloud_secrets_toml(template_text, info, minimal=minimal)
    base = strip_service_account_blocks(template_text).rstrip()
    sa = format_service_account_section(info)
    return f"{base}\n\n{sa}\n"


def validate_credentials(info: dict, sheet_id: str | None) -> list[str]:
    """検証結果メッセージのリスト（エラー時は例外）。"""
    required = ("type", "private_key", "client_email", "private_key_id")
    missing = [k for k in required if not info.get(k)]
    if missing:
        raise ValueError(f"JSON に必須キーがありません: {', '.join(missing)}")

    messages = [
        f"project_id     : {info.get('project_id', '')}",
        f"private_key_id : {info.get('private_key_id', '')}",
        f"client_email   : {info.get('client_email', '')}",
    ]

    pk = str(info.get("private_key", "")).replace("\\n", "\n")
    if "BEGIN PRIVATE KEY" not in pk or "END PRIVATE KEY" not in pk:
        raise ValueError("private_key が PEM 形式ではありません。JSON ファイルを確認してください。")

    creds = service_account.Credentials.from_service_account_info(
        info, scopes=["https://www.googleapis.com/auth/spreadsheets"]
    )
    creds.refresh(Request())
    messages.append("JWT 署名       : OK")

    if sheet_id:
        sh = gspread.authorize(creds).open_by_key(sheet_id)
        messages.append(f"スプレッドシート : OK（{sh.title}）")
    return messages


def resolve_template(path: Path | None) -> Path:
    if path and path.is_file():
        return path
    if DEFAULT_OUTPUT.is_file():
        return DEFAULT_OUTPUT
    if DEFAULT_TEMPLATE.is_file():
        return DEFAULT_TEMPLATE
    raise FileNotFoundError(
        f"テンプレートが見つかりません。{DEFAULT_TEMPLATE} を作成してください。"
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="サービスアカウント JSON から Streamlit secrets.toml を生成"
    )
    parser.add_argument(
        "--json",
        type=Path,
        default=None,
        help=f"JSON ファイル（省略時は {DEFAULT_JSON}）",
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="標準入力から JSON を読み込む（貼り付け → Ctrl+D）",
    )
    parser.add_argument(
        "--template",
        type=Path,
        default=None,
        help="ベース TOML（省略時: secrets.toml または secrets.toml.example）",
    )
    parser.add_argument(
        "--sheet-id",
        default=None,
        help="接続テスト用スプレッドシート ID",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help=f"{DEFAULT_OUTPUT} に書き出す",
    )
    parser.add_argument(
        "--print",
        action="store_true",
        help="生成した secrets.toml 全文を標準出力（Streamlit Cloud 用コピペ）",
    )
    parser.add_argument(
        "--cloud",
        action="store_true",
        help="Streamlit Cloud 向けに GOOGLE_SERVICE_ACCOUNT_JSON_B64（1行）を出力",
    )
    parser.add_argument(
        "--minimal",
        action="store_true",
        help="コメント行を除いた最小構成（Cloud 貼り付け向け）",
    )
    parser.add_argument(
        "--skip-test",
        action="store_true",
        help="JWT / スプレッドシート接続テストをスキップ",
    )
    args = parser.parse_args()

    if not args.write and not args.print:
        args.write = True

    sheet_id = args.sheet_id or os.environ.get("GOOGLE_SPREADSHEET_ID")
    info: dict = {}

    try:
        info = load_service_account_json(args.json, use_stdin=args.stdin)
        template_path = resolve_template(args.template)
        template_text = template_path.read_text(encoding="utf-8")
        secrets_toml = build_secrets_toml(
            template_text, info, cloud=args.cloud, minimal=args.minimal
        )

        if not args.skip_test:
            print("=== 検証 ===", file=sys.stderr)
            for msg in validate_credentials(info, sheet_id):
                print(f"  {msg}", file=sys.stderr)
            if args.cloud:
                print(
                    "  Cloud 形式  : GOOGLE_SERVICE_ACCOUNT_JSON_B64（1行）",
                    file=sys.stderr,
                )
            print(file=sys.stderr)

        if args.write:
            STREAMLIT_DIR.mkdir(parents=True, exist_ok=True)
            DEFAULT_OUTPUT.write_text(secrets_toml, encoding="utf-8")
            print(f"書き出しました: {DEFAULT_OUTPUT}", file=sys.stderr)
            print("ローカル実行: streamlit run app.py", file=sys.stderr)

        if args.print:
            print(secrets_toml)

        if args.print and args.cloud:
            print(
                "\n--- 上記全文を Streamlit Cloud Secrets に貼り付け（"
                "[google_service_account] は不要） ---",
                file=sys.stderr,
            )
        elif args.write and args.print:
            print(
                "\n--- 上記の === 検証 === 以降を Streamlit Cloud Secrets に貼り付け ---",
                file=sys.stderr,
            )
    except Exception as e:
        print(f"エラー: {e}", file=sys.stderr)
        if "Invalid JWT Signature" in str(e) or "invalid_grant" in str(e):
            print(
                "GCP で鍵が無効です。サービス アカウント → キー で新しい JSON を作成してください。",
                file=sys.stderr,
            )
        elif sheet_id and "403" in str(e):
            print(
                f"スプレッドシートに {info.get('client_email')} を編集者で共有してください。",
                file=sys.stderr,
            )
        sys.exit(1)


if __name__ == "__main__":
    main()
