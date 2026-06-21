#!/usr/bin/env python3
"""cloud-secrets.toml が Streamlit Cloud 向けに正しいか検証する（鍵本体は表示しない）。"""

from __future__ import annotations

import argparse
import base64
import json
import re
import sys
from pathlib import Path

from google.auth.transport.requests import Request
from google.oauth2 import service_account

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PATH = REPO_ROOT / "cloud-secrets.toml"

FORBIDDEN = (
    "[google_service_account]",
    "GOOGLE_SERVICE_ACCOUNT_JSON =",
    "GOOGLE_SERVICE_ACCOUNT_JSON='",
)
PLACEHOLDERS = ("変更してください", "YOUR_DEPLOYMENT_ID")


def _non_comment_lines(text: str) -> str:
    return "\n".join(
        ln for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")
    )


def check(path: Path) -> int:
    text = path.read_text(encoding="utf-8")
    body = _non_comment_lines(text)
    issues: list[str] = []
    ok: list[str] = []

    for bad in FORBIDDEN:
        if bad in body:
            issues.append(f"削除が必要: {bad}")

    for ph in PLACEHOLDERS:
        if ph in body:
            issues.append(f"プレースホルダが残っています: {ph}")

    m = re.search(r'GOOGLE_SERVICE_ACCOUNT_JSON_B64\s*=\s*"([^"]+)"', body)
    if not m:
        issues.append("GOOGLE_SERVICE_ACCOUNT_JSON_B64 行がありません")
        b64 = ""
    else:
        b64 = m.group(1)
        ok.append(f"B64 文字数: {len(b64)}")
        if len(b64) < 500:
            issues.append("B64 が短すぎます（途中で切れている可能性）")

    if "GOOGLE_SPREADSHEET_ID" not in body:
        issues.append("GOOGLE_SPREADSHEET_ID がありません")

    if b64:
        try:
            info = json.loads(base64.b64decode(b64).decode("utf-8"))
            ok.append(f"private_key_id: {info.get('private_key_id', '?')}")
            ok.append(f"client_email  : {info.get('client_email', '?')}")
            creds = service_account.Credentials.from_service_account_info(
                info, scopes=["https://www.googleapis.com/auth/spreadsheets"]
            )
            creds.refresh(Request())
            ok.append("JWT 署名       : OK")
        except Exception as e:
            issues.append(f"B64 / JWT 検証失敗: {e}")

    print(f"=== {path} ===")
    for line in ok:
        print(f"  OK  {line}")
    for line in issues:
        print(f"  NG  {line}")

    if issues:
        print("\nCloud Secrets に貼る前に上記 NG を直してください。", file=sys.stderr)
        return 1

    print("\nこのファイル全文を Cloud Secrets に貼り付け → Save → Reboot app", file=sys.stderr)
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="cloud-secrets.toml を検証")
    parser.add_argument(
        "path",
        nargs="?",
        type=Path,
        default=DEFAULT_PATH,
        help=f"検証する TOML（既定: {DEFAULT_PATH.name}）",
    )
    args = parser.parse_args()
    if not args.path.is_file():
        print(f"ファイルがありません: {args.path}", file=sys.stderr)
        sys.exit(1)
    sys.exit(check(args.path))


if __name__ == "__main__":
    main()
