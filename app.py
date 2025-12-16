import base64
import os
import hashlib
import random
import string
import uuid
import json
import time
from datetime import datetime, timedelta

# 外部ライブラリ
from flask import Flask, render_template, request, redirect, session, url_for, flash, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
from flask_talisman import Talisman
import requests
import markdown
from dotenv import load_dotenv

# --- 環境変数の読み込み---
load_dotenv()
# setup.py で生成されるファイルを読み込みます。ない場合はデフォルト値を使用します。
try:
    with open('config.json', 'r', encoding='utf-8') as f:
        SITE_CONFIG = json.load(f)
except FileNotFoundError:
    SITE_CONFIG = {
        "community_name": "コミュニティー",
        "community_subname": "Default",
        "primary_color": "#ffac30"
    }

app = Flask(__name__)

# --- アプリケーション設定 (環境変数から取得) ---
# キーがない場合のデフォルト値も設定していますが、基本は .env に記述します
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default-insecure-key-change-me')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ファイルアップロード設定
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip', 'py', 'js', 'html'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# メール設定 
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

# Canva設定
app.config['CANVA_CLIENT_ID'] = os.getenv('CANVA_CLIENT_ID')
app.config['CANVA_CLIENT_SECRET'] = os.getenv('CANVA_CLIENT_SECRET')
app.config['CANVA_AUTH_URL'] = 'https://www.canva.com/api/oauth/authorize'
app.config['CANVA_TOKEN_URL'] = 'https://api.canva.com/rest/v1/oauth/token'
app.config['CANVA_API_BASE'] = 'https://api.canva.com/rest/v1'

# 拡張機能の初期化
db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- Talismanによるセキュリティヘッダー ---
Talisman(app, 
         content_security_policy=None, # CSPを無効化
         strict_transport_security=True, # HSTS (HTTPS強制) を有効化
         frame_options='DENY') # クリックジャッキング対策

# --- テンプレートへの共通変数注入 ---
@app.context_processor
def inject_config():
    """テンプレート(base.html等)で site_config 変数を使えるようにする"""
    return dict(site_config=SITE_CONFIG)

# --- モデル定義 ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    otp = db.Column(db.String(6), nullable=True)
    otp_created_at = db.Column(db.DateTime, nullable=True)
    
    # Canva連携用カラム
    canva_access_token = db.Column(db.String(500), nullable=True)
    canva_refresh_token = db.Column(db.String(500), nullable=True)
    canva_token_expires_at = db.Column(db.Float, nullable=True)

class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    tags = db.Column(db.String(200)) # カンマ区切り
    filename = db.Column(db.String(200)) # 添付ファイル名 
    date_posted = db.Column(db.DateTime, default=datetime.now)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('articles', lazy=True))

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    due_date = db.Column(db.Date, nullable=True)
    priority = db.Column(db.String(20), default='Medium') # High, Medium, Low
    assignee = db.Column(db.String(100), nullable=True)
    is_team = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(20), default='Pending') # Pending, Done
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    article_id = db.Column(db.Integer, db.ForeignKey('article.id'), nullable=False)
    __table_args__ = (db.UniqueConstraint('user_id', 'article_id', name='_user_article_uc'),)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.now)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    article_id = db.Column(db.Integer, db.ForeignKey('article.id'), nullable=False)
    
    # リレーションシップ
    user = db.relationship('User', backref=db.backref('comments', lazy=True))
    article = db.relationship('Article', backref=db.backref('comments', lazy=True))

# --- ヘルパー関数 ---
def generate_unique_filename(original_filename):
    """
    元のファイル名に基づいて、安全かつユニークなファイル名を生成する。
    """
    ext = original_filename.rsplit('.', 1)[1].lower() if '.' in original_filename else ''
    safe_original_name = secure_filename(original_filename.rsplit('.', 1)[0] if '.' in original_filename else original_filename)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    unique_id = str(uuid.uuid4())[:8]
    unique_filename = f"{timestamp}_{unique_id}_{safe_original_name}.{ext}"
    return unique_filename

def generate_code_verifier():
    return base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode('utf-8')

def generate_code_challenge(verifier):
    digest = hashlib.sha256(verifier.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b'=').decode('utf-8')

def markdown_to_html(md_text):
    """MarkdownテキストをHTMLに変換する"""
    if md_text is None:
        return ""
    return markdown.markdown(md_text, extensions=['nl2br'])

# テンプレート内でこの関数を使えるようにする
app.jinja_env.globals.update(markdown_to_html=markdown_to_html)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def send_otp_email(user):
    otp = ''.join(random.choices(string.digits, k=6))
    user.otp = otp
    user.otp_created_at = datetime.utcnow()
    
    try:
        db.session.commit()
        
        # 設定ファイルからコミュニティ名を取得してメール件名・本文に使用
        comm_name = SITE_CONFIG.get('community_name', 'Community')
        
        msg = Message(f'{comm_name} Login Code', recipients=[user.email])
        msg.body = f'あなたのログインコードは: {otp} です。'
        msg.html = f'<h3>{comm_name} Login</h3><p>ログインコード: <b>{otp}</b></p>'
        mail.send(msg)
        return True
    except Exception as e:
        db.session.rollback()
        print(f"Mail Error: {e}")
        flash('ログインコードのメール送信に失敗しました。サーバー設定を確認してください。', 'danger')
        return False

# --- ルート定義 ---

@app.route('/')
@login_required
def index():
    # 1. 記事とタスクの取得
    articles = Article.query.order_by(Article.date_posted.desc()).limit(5).all()
    todos = Todo.query.filter_by(status='Pending').order_by(Todo.due_date).limit(5).all()
    
    # 2. 記事にいいね数を追加する処理
    articles_with_likes_and_comments = []
    
    for article in articles:
        like_count = Like.query.filter_by(article_id=article.id).count()
        article.like_count = like_count
        articles_with_likes_and_comments.append(article)
    
    return render_template('dashboard.html', 
                           articles=articles_with_likes_and_comments, 
                           todos=todos)

@app.route('/article/<int:article_id>')
@login_required
def article_detail(article_id):
    """記事詳細表示ルート"""
    article = Article.query.get_or_404(article_id)
    is_liked = Like.query.filter_by(user_id=current_user.id, article_id=article_id).first() is not None
    like_count = Like.query.filter_by(article_id=article_id).count()
    comments = Comment.query.filter_by(article_id=article_id).order_by(Comment.date_posted.asc()).all()
    
    return render_template('article_detail.html', 
                           article=article, 
                           is_liked=is_liked, 
                           like_count=like_count,
                           comments=comments)

@app.route('/like_article/<int:article_id>', methods=['POST'])
@login_required
def like_article(article_id):
    """いいね機能のトグル"""
    like = Like.query.filter_by(user_id=current_user.id, article_id=article_id).first()
    
    if like:
        db.session.delete(like)
        flash('いいねを解除しました', 'warning')
    else:
        new_like = Like(user_id=current_user.id, article_id=article_id)
        db.session.add(new_like)
        flash('いいねしました！', 'success')
        
    db.session.commit()
    return redirect(url_for('article_detail', article_id=article_id))

@app.route('/comment_article/<int:article_id>', methods=['POST'])
@login_required
def comment_article(article_id):
    """コメント投稿機能"""
    content = request.form.get('content')
    
    if content:
        new_comment = Comment(
            content=content,
            user_id=current_user.id,
            article_id=article_id
        )
        db.session.add(new_comment)
        db.session.commit()
        flash('コメントを投稿しました', 'success')
    else:
        flash('コメント内容が空です', 'danger')
        
    return redirect(url_for('article_detail', article_id=article_id))

@app.route('/delete_article/<int:article_id>', methods=['POST'])
@login_required
def delete_article(article_id):
    """記事の削除ルート（管理者または投稿者のみ実行可能）"""
    article = Article.query.get_or_404(article_id)
    
    is_author = article.user_id == current_user.id
    is_admin = current_user.is_admin 
    
    if is_author or is_admin:
        try:
            if article.filename:
                # 記事に添付ファイルがある場合
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], article.filename)
                
                # 絶対パスを取得
                abs_filepath = os.path.abspath(filepath)
                abs_upload_dir = os.path.abspath(app.config['UPLOAD_FOLDER'])
                
                # ファイルパスが必ずアップロードディレクトリ内にあることを確認
                if abs_filepath.startswith(abs_upload_dir) and os.path.exists(abs_filepath):
                    os.remove(abs_filepath)
                else:
                    print(f"Warning: Attempted to delete file outside upload folder or file not found: {article.filename}")

            # 関連レコードを削除
            Like.query.filter_by(article_id=article_id).delete()
            Comment.query.filter_by(article_id=article_id).delete()
            
            # 記事本体を削除
            db.session.delete(article)
            db.session.commit()
            
            flash('記事「{}」を削除しました。'.format(article.title), 'success')
            return redirect(url_for('articles'))
        
        except Exception as e:
            db.session.rollback()
            print(f"Error during article deletion: {e}") 
            flash(f'記事の削除中にエラーが発生しました。', 'danger')
            return redirect(url_for('article_detail', article_id=article_id))

    else:
        flash('この記事を削除する権限がありません。', 'danger')
        return redirect(url_for('article_detail', article_id=article_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            # send_otp_email内部でメール送信失敗時のflashとdb.session.rollbackを処理
            if send_otp_email(user):
                return redirect(url_for('verify', email=email))
        else:
            flash('登録されていないメールアドレスです。', 'warning')
    return render_template('login.html')

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    email = request.args.get('email')
    
    if request.method == 'POST':
        email = request.form.get('email')
        code = request.form.get('code')
        user = User.query.filter_by(email=email).first()

        if user:
            if user.otp and user.otp_created_at and datetime.utcnow() <= user.otp_created_at + timedelta(minutes=5):
                if user.otp == code:
                    user.otp = None 
                    user.otp_created_at = None
                    db.session.commit()
                    login_user(user)
                    return redirect(url_for('index'))
                else:
                    flash('無効なコードです。', 'danger')
            else:
                flash('OTPの有効期限が切れました。再送信してください。', 'danger')
        else:
            flash('ユーザーが存在しません。', 'danger')

    return render_template('verify.html', email=email)

def get_valid_canva_token(user):
    if not user.canva_access_token:
        return None
    
    if user.canva_token_expires_at and time.time() > user.canva_token_expires_at:
        payload = {
            'grant_type': 'refresh_token',
            'refresh_token': user.canva_refresh_token,
        }
        auth = (app.config['CANVA_CLIENT_ID'], app.config['CANVA_CLIENT_SECRET'])
        response = requests.post(app.config['CANVA_TOKEN_URL'], data=payload, auth=auth)
        
        if response.status_code == 200:
            tokens = response.json()
            user.canva_access_token = tokens['access_token']
            user.canva_refresh_token = tokens.get('refresh_token', user.canva_refresh_token)
            user.canva_token_expires_at = time.time() + tokens['expires_in']
            db.session.commit()
            return user.canva_access_token
        else:
            return None
            
    return user.canva_access_token

@app.route('/connect/canva')
@login_required
def connect_canva():
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    state = base64.urlsafe_b64encode(os.urandom(16)).rstrip(b'=').decode('utf-8')
    
    session['canva_code_verifier'] = code_verifier
    session['canva_state'] = state
    
    params = {
        'response_type': 'code',
        'client_id': app.config['CANVA_CLIENT_ID'],
        'redirect_uri': url_for('callback_canva', _external=True),
        'scope': 'design:meta:read design:content:read',
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256',
        'state': state,
    }
    auth_url = requests.Request('GET', app.config['CANVA_AUTH_URL'], params=params).prepare().url
    return redirect(auth_url)

@app.route('/callback/canva')
@login_required
def callback_canva():
    code = request.args.get('code')
    state = request.args.get('state')

    if not code:
        flash('Canvaとの連携をキャンセルしました。', 'warning')
        return redirect(url_for('articles'))

    if state != session.get('canva_state'):
        flash('不正なリクエストです（state不一致）', 'danger')
        return redirect(url_for('articles'))

    code_verifier = session.get('canva_code_verifier')
    if not code_verifier:
        flash('PKCEコードが見つかりません。再連携してください。', 'danger')
        return redirect(url_for('articles'))

    data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': url_for('callback_canva', _external=True),
        'code_verifier': code_verifier,
    }

    auth = (app.config['CANVA_CLIENT_ID'], app.config['CANVA_CLIENT_SECRET'])
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    response = requests.post(app.config['CANVA_TOKEN_URL'], data=data, auth=auth, headers=headers)

    if response.status_code == 200:
        tokens = response.json()
        current_user.canva_access_token = tokens['access_token']
        current_user.canva_refresh_token = tokens.get('refresh_token')
        current_user.canva_token_expires_at = time.time() + tokens['expires_in']
        db.session.commit()

        session.pop('canva_code_verifier', None)
        session.pop('canva_state', None)

        flash('Canvaと連携しました！', 'success')
        return render_template('canva_success.html')

    flash(f'Canva連携エラー: {response.text}', 'danger')
    return redirect(url_for('articles'))
    
@app.route('/api/canva/designs')
@login_required
def api_canva_designs():
    token = get_valid_canva_token(current_user)
    if not token:
        return {'error': 'not_connected'}, 401
        
    headers = {'Authorization': f'Bearer {token}'}
    try:
        response = requests.get(f"{app.config['CANVA_API_BASE']}/designs", headers=headers)
        if response.status_code == 200:
            data = response.json()
            return {'designs': data.get('items', [])}
        return {'error': 'failed_to_fetch'}, response.status_code
    except Exception as e:
        return {'error': str(e)}, 500
    
@app.route('/api/canva/upload', methods=['POST'])
@login_required
def api_canva_upload():
    token = get_valid_canva_token(current_user)
    if not token:
        return {'error': 'not_connected'}, 401
    
    design_id = request.json.get('design_id')
    if not design_id:
        return {'error': 'no_design_id'}, 400
        
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    
    export_payload = {
        'design_id': design_id,
        'format': {'type': 'jpg', 'quality': 80}
    }
    
    try:
        resp = requests.post(f"{app.config['CANVA_API_BASE']}/exports", json=export_payload, headers=headers)
        if resp.status_code != 200:
            return {'error': 'export_start_failed', 'details': resp.text}, 500
            
        job_id = resp.json()['job']['id']
        
        download_url = None
        for _ in range(10): 
            time.sleep(2)
            check_resp = requests.get(f"{app.config['CANVA_API_BASE']}/exports/{job_id}", headers=headers)
            if check_resp.status_code == 200:
                job_data = check_resp.json()['job']
                status = job_data['status']
                if status == 'success':
                    download_url = job_data['urls'][0]
                    break
                elif status == 'failed':
                    return {'error': 'export_job_failed'}, 500
            else:
                 return {'error': 'polling_failed'}, 500
        
        if not download_url:
            return {'error': 'timeout'}, 500
            
        img_resp = requests.get(download_url)
        if img_resp.status_code == 200:
            filename = f"canva_{uuid.uuid4().hex[:8]}.jpg"
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            with open(save_path, 'wb') as f:
                f.write(img_resp.content)
            
            return {'filename': filename, 'url': url_for('uploaded_file', filename=filename)}
            
    except Exception as e:
        return {'error': str(e)}, 500
        
    return {'error': 'unknown_error'}, 500

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if not current_user.is_admin:
        abort(403)
    if request.method == 'POST':
        email = request.form.get('email')
        if User.query.filter_by(email=email).first():
            flash('既に登録されています。', 'warning')
        else:
            new_user = User(email=email, is_admin=False)
            db.session.add(new_user)
            db.session.commit()
            flash(f'ユーザー {email} を追加しました。', 'success')
    users = User.query.all()
    return render_template('admin.html', users=users)

@app.route('/articles', methods=['GET', 'POST'])
@login_required
def articles():
    # POSTリクエスト処理（新規記事投稿）
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        tags = request.form.get('tags')
        file = request.files.get('file')
        unique_filename = None
        
        if file and allowed_file(file.filename):
            unique_filename = generate_unique_filename(file.filename)
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(save_path)
            
        new_article = Article(title=title, content=content, tags=tags, filename=unique_filename, user_id=current_user.id)
        db.session.add(new_article)
        db.session.commit()
        flash('記事を投稿しました', 'success')
        return redirect(url_for('articles'))
    
    # GETリクエスト処理（記事一覧表示）
    search = request.args.get('search', '')
    if search:
        all_articles = Article.query.filter(
            (Article.title.contains(search)) | 
            (Article.tags.contains(search))
        ).order_by(Article.date_posted.desc()).all()
    else:
        all_articles = Article.query.order_by(Article.date_posted.desc()).all()

    articles_with_likes = []
    
    for article in all_articles:
        like_count = Like.query.filter_by(article_id=article.id).count()
        article.like_count = like_count
        articles_with_likes.append(article)
        
    return render_template('articles.html', articles=articles_with_likes)

@app.route('/todos', methods=['GET', 'POST'])
@login_required
def todos():
    if request.method == 'POST':
        title = request.form.get('title')
        due_date_str = request.form.get('due_date')
        due_date = datetime.strptime(due_date_str, '%Y-%m-%d').date() if due_date_str else None
        priority = request.form.get('priority')
        is_team = True if request.form.get('is_team') else False
        assignee = request.form.get('assignee')
        
        new_todo = Todo(title=title, due_date=due_date, priority=priority, is_team=is_team, assignee=assignee, user_id=current_user.id)
        db.session.add(new_todo)
        db.session.commit()
        flash('Todoを追加しました', 'success')
        return redirect(url_for('todos'))
        
    my_todos = Todo.query.filter_by(user_id=current_user.id, status='Pending').all()
    team_todos = Todo.query.filter_by(is_team=True, status='Pending').all()
    return render_template('todos.html', my_todos=my_todos, team_todos=team_todos)

@app.route('/complete_todo/<int:id>')
@login_required
def complete_todo(id):
    todo = Todo.query.get_or_404(id)
    todo.status = 'Done'
    db.session.commit()
    flash('タスクを完了しました', 'success')
    return redirect(url_for('todos'))

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    try:
        safe_filename = secure_filename(filename)
        return send_from_directory(app.config['UPLOAD_FOLDER'], safe_filename)
    except Exception:
        abort(404)

def create_initial_data(app):
    """データベースのテーブルを作成し、初期管理者ユーザーを設定する"""
    with app.app_context():
        # データベース内の全てのテーブルを作成
        db.create_all()
        
        # .env から初期管理者のメールアドレスを取得
        ADMIN_EMAIL = os.getenv('INITIAL_ADMIN_EMAIL')
        
        if ADMIN_EMAIL:
            if not User.query.filter_by(email=ADMIN_EMAIL).first():
                admin_user = User(email=ADMIN_EMAIL, is_admin=True)
                db.session.add(admin_user)
                db.session.commit()
                print(f"INFO: Initial Admin User ({ADMIN_EMAIL}) created.")
            else:
                print("INFO: Admin User already exists.")
        else:
            print("WARNING: INITIAL_ADMIN_EMAIL not set in .env. No admin created.")

if __name__ == '__main__':
    # アプリケーション起動前に初期データ投入関数を呼び出す
    create_initial_data(app)
    
    app.run(debug=True, port=8000)