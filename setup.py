import os
import secrets
import json

def get_input(prompt, default=None):
    """ユーザー入力を取得するヘルパー関数"""
    if default:
        user_input = input(f"{prompt} [{default}]: ")
        return user_input if user_input else default
    else:
        return input(f"{prompt}: ")

def generate_secret_key():
    return secrets.token_hex(32)

def main():
    print("=== コミュニティアプリ セットアップウィザード ===")
    print("このスクリプトは .env (機密情報) と config.json (サイト設定) を生成します。")
    print("-" * 50)

    # --- 1. サイト設定 (config.json) ---
    print("\n[Step 1: サイト外観設定]")
    community_name = get_input("コミュニティ名 (前半)")
    community_subname = get_input("コミュニティ名 (後半)")
    primary_color = get_input("メインテーマカラー (Hex)", "#ffac30")

    config_data = {
        "community_name": community_name,
        "community_subname": community_subname,
        "primary_color": primary_color
    }

    # --- 2. 機密情報設定 (.env) ---
    print("\n[Step 2: サーバー・機密情報設定]")
    
    # シークレットキーの生成
    secret_key = generate_secret_key()
    print(f"Secret Keyを自動生成しました: {secret_key[:8]}...")
    
    # 初期管理者
    admin_email = get_input("初期管理者メールアドレス", "admin@example.com")
    
    # メール設定
    print("\n-- メールサーバー設定 (SMTP) --")
    print("Gmail等の場合、アプリパスワードが必要です。")
    mail_server = get_input("SMTPサーバー", "smtp.gmail.com")
    mail_port = get_input("SMTPポート", "587")
    mail_use_tls = get_input("TLSを使用しますか? (True/False)", "True")
    mail_username = get_input("メールアドレス(Username)", "your-email@gmail.com")
    mail_password = get_input("メールパスワード", "your-app-password")
    mail_sender = get_input("送信元アドレス(Default Sender)", mail_username)

    # Canva設定 (任意)
    print("\n-- Canva連携設定 (任意: Enterでスキップ可) --")
    canva_client_id = get_input("Canva Client ID", "")
    canva_client_secret = get_input("Canva Client Secret", "")

    # .env ファイルの内容を作成
    env_content = f"""# Flask Settings
SECRET_KEY={secret_key}
SQLALCHEMY_DATABASE_URI=sqlite:///database.db

# Initial Admin
INITIAL_ADMIN_EMAIL={admin_email}

# Mail Settings
MAIL_SERVER={mail_server}
MAIL_PORT={mail_port}
MAIL_USE_TLS={mail_use_tls}
MAIL_USERNAME={mail_username}
MAIL_PASSWORD={mail_password}
MAIL_DEFAULT_SENDER={mail_sender}

# Canva Settings
CANVA_CLIENT_ID={canva_client_id}
CANVA_CLIENT_SECRET={canva_client_secret}
"""

    # --- ファイル書き出し ---
    print("\n[Step 3: 設定ファイルの生成]")
    
    # config.json 書き出し
    with open('config.json', 'w', encoding='utf-8') as f:
        json.dump(config_data, f, indent=4, ensure_ascii=False)
    print("✔ config.json を作成しました。")

    # .env 書き出し
    with open('.env', 'w', encoding='utf-8') as f:
        f.write(env_content)
    print("✔ .env を作成しました。")

    print("-" * 50)
    print("セットアップが完了しました！")
    print("\n以下のコマンドでアプリケーションを起動できます:")
    print("  python app.py")

if __name__ == "__main__":
    main()