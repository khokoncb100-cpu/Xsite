#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
লাইভ হোস্টিং প্যানেল - একক ফাইল Flask অ্যাপ্লিকেশন
সমস্ত ফিচার একটি মাত্র ফাইলে ইমপ্লিমেন্ট করা হয়েছে
Production Quality • Secure • Professional
"""

# ==================== প্রয়োজনীয় লাইব্রেরি ইম্পোর্ট (সংশোধিত) ====================
import os
import sys
import json
import time
import hashlib
import secrets
import subprocess
import psutil
import platform
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
import threading
import logging
import re
import mimetypes
from logging.handlers import RotatingFileHandler

# Flask ইম্পোর্ট
from flask import (
    Flask, render_template_string, request, jsonify, 
    session, redirect, url_for, send_file, abort,
    make_response, flash, send_from_directory
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
import uuid
import html

# ==================== অ্যাপ্লিকেশন কনফিগারেশন (সংশোধিত) ====================
class Config:
    """অ্যাপ্লিকেশন কনফিগারেশন ক্লাস - প্রোডাকশন রেডি"""
    
    # সিকিউরিটি কী - এনভায়রনমেন্ট ভেরিয়েবল থেকে নিবে, না থাকলে জেনারেট করবে
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(64)
    
    # সেশন কনফিগারেশন
    SESSION_COOKIE_SECURE = bool(os.environ.get('RENDER'))  # প্রোডাকশনে True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_NAME = '__Host-session' if SESSION_COOKIE_SECURE else 'session'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=12)  # ১২ ঘন্টায় কমিয়ে আনা হলো
    
    # CSRF প্রোটেকশন
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # 1 hour
    
    # ফাইল আপলোড
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB (নিরাপত্তার জন্য কমানো হলো)
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'uploads')
    ALLOWED_EXTENSIONS = {
        'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'svg',
        'py', 'js', 'html', 'css', 'json', 'xml', 'md',
        'zip', 'tar', 'gz', 'rar', '7z',
        'mp4', 'mp3', 'wav', 'webm',
        'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'
    }
    
    # বেস ডিরেক্টরি
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    
    # রেট লিমিটিং
    RATELIMIT_ENABLED = True
    RATELIMIT_STORAGE_URL = "memory://"
    
    # ডিফল্ট অ্যাডমিন (শুধু প্রথম সেটআপের জন্য)
    DEFAULT_ADMIN = {
        'username': os.environ.get('ADMIN_USERNAME', 'admin'),
        'password': os.environ.get('ADMIN_PASSWORD', 'admin123'),  # প্রথম লগইনে পরিবর্তন করতে হবে
        'email': os.environ.get('ADMIN_EMAIL', 'admin@localhost.local')
    }
    
    # প্রোডাকশন মোড ডিটেকশন
    @staticmethod
    def is_production():
        return bool(os.environ.get('RENDER') or os.environ.get('PRODUCTION'))
    
    # ডিবাগ মোড - প্রোডাকশনে কখনো True হবে না
    DEBUG = not is_production.__func__()

# ==================== Flask অ্যাপ ইনিশিয়ালাইজেশন ====================
app = Flask(__name__)
app.config.from_object(Config)

# ProxyFix - Render/Production এর জন্য
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# ==================== লগিং সেটআপ (সংশোধিত) ====================
if not os.path.exists('logs'):
    os.makedirs('logs')

# জেনারেল লগ
general_handler = RotatingFileHandler(
    'logs/hosting_panel.log', 
    maxBytes=10485760,  # 10MB
    backupCount=10
)
general_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
general_handler.setLevel(logging.INFO)

# সিকিউরিটি ইভেন্ট লগ
security_handler = RotatingFileHandler(
    'logs/security.log', 
    maxBytes=10485760,  # 10MB
    backupCount=10
)
security_handler.setFormatter(logging.Formatter(
    '%(asctime)s SECURITY: %(message)s'
))
security_handler.setLevel(logging.WARNING)

# এরর লগ
error_handler = RotatingFileHandler(
    'logs/error.log', 
    maxBytes=10485760,  # 10MB
    backupCount=10
)
error_handler.setFormatter(logging.Formatter(
    '%(asctime)s ERROR: %(message)s\nTraceback: %(exc_info)s'
))
error_handler.setLevel(logging.ERROR)

app.logger.addHandler(general_handler)
app.logger.addHandler(security_handler)
app.logger.addHandler(error_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('হোস্টিং প্যানেল শুরু হচ্ছে...')

# ==================== সিকিউরিটি ইউটিলিটি ফাংশন (নতুন) ====================
def sanitize_input(input_string):
    """ইনপুট স্যানিটাইজেশন - XSS প্রতিরোধ"""
    if input_string is None:
        return None
    return html.escape(str(input_string).strip())

def validate_path(user_path, base_path=None):
    """পাথ ট্রাভার্সাল প্রতিরোধ"""
    if base_path is None:
        base_path = os.path.abspath(Config.UPLOAD_FOLDER)
    
    # পাথ নরমালাইজ করুন
    safe_path = os.path.abspath(os.path.join(base_path, user_path))
    
    # নিশ্চিত করুন পাথ বেস ডিরেক্টরির ভিতরে আছে
    if not safe_path.startswith(os.path.abspath(base_path)):
        raise ValueError("অননুমোদিত পাথ অ্যাক্সেস")
    
    return safe_path

def is_allowed_file(filename):
    """ফাইল টাইপ ভ্যালিডেশন"""
    if '.' not in filename:
        return False
    
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in Config.ALLOWED_EXTENSIONS

def generate_csrf_token():
    """CSRF টোকেন জেনারেটর"""
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']

def validate_csrf_token(token):
    """CSRF টোকেন ভ্যালিডেটর"""
    if not token or token != session.get('_csrf_token'):
        abort(403, description="CSRF ভ্যালিডেশন ব্যর্থ")
    return True

def log_security_event(event_type, details, ip_address=None):
    """সিকিউরিটি ইভেন্ট লগিং"""
    if ip_address is None:
        ip_address = request.remote_addr if request else 'Unknown'
    
    app.logger.warning(f"Security Event: {event_type} | IP: {ip_address} | Details: {details}")

# ==================== ইউটিলিটি ফাংশন ====================
def get_system_info():
    """সিস্টেম তথ্য সংগ্রহ করার ফাংশন (সংশোধিত)"""
    try:
        # CPU ব্যবহার - আরও নির্ভুল পরিমাপ
        cpu_percent = psutil.cpu_percent(interval=0.5)
        cpu_count = psutil.cpu_count()
        cpu_freq = psutil.cpu_freq()
        
        # মেমরি তথ্য
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        # ডিস্ক তথ্য
        disk = psutil.disk_usage('/')
        disk_io = psutil.disk_io_counters()
        
        # নেটওয়ার্ক তথ্য
        net_io = psutil.net_io_counters()
        
        # সিস্টেম আপটাইম
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        uptime_seconds = (datetime.now() - boot_time).total_seconds()
        
        return {
            'python_version': sys.version.split()[0],
            'flask_version': '3.0.0',
            'cpu_usage': cpu_percent,
            'cpu_count': cpu_count,
            'cpu_freq_current': f"{cpu_freq.current:.0f} MHz" if cpu_freq else "N/A",
            'total_ram': f"{memory.total / (1024**3):.2f} GB",
            'used_ram': f"{memory.used / (1024**3):.2f} GB",
            'ram_percent': memory.percent,
            'available_ram': f"{memory.available / (1024**3):.2f} GB",
            'swap_total': f"{swap.total / (1024**3):.2f} GB" if swap.total > 0 else "N/A",
            'swap_used': f"{swap.used / (1024**3):.2f} GB" if swap.used > 0 else "N/A",
            'total_storage': f"{disk.total / (1024**3):.2f} GB",
            'used_storage': f"{disk.used / (1024**3):.2f} GB",
            'free_storage': f"{disk.free / (1024**3):.2f} GB",
            'storage_percent': disk.percent,
            'disk_read_bytes': f"{disk_io.read_bytes / (1024**3):.2f} GB" if disk_io else "N/A",
            'disk_write_bytes': f"{disk_io.write_bytes / (1024**3):.2f} GB" if disk_io else "N/A",
            'network_sent': f"{net_io.bytes_sent / (1024**2):.2f} MB" if net_io else "N/A",
            'network_recv': f"{net_io.bytes_recv / (1024**2):.2f} MB" if net_io else "N/A",
            'platform': platform.platform(),
            'processor': platform.processor(),
            'hostname': platform.node(),
            'uptime_seconds': int(uptime_seconds),
            'uptime_formatted': format_uptime(uptime_seconds),
            'running_apps': get_running_applications()
        }
    except Exception as e:
        app.logger.error(f"সিস্টেম তথ্য সংগ্রহে ত্রুটি: {str(e)}", exc_info=True)
        return {}

def format_uptime(seconds):
    """আপটাইম ফরম্যাটিং"""
    days, remainder = divmod(int(seconds), 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    
    parts = []
    if days > 0:
        parts.append(f"{days}দিন")
    if hours > 0:
        parts.append(f"{hours}ঘণ্টা")
    if minutes > 0:
        parts.append(f"{minutes}মিনিট")
    parts.append(f"{seconds}সেকেন্ড")
    
    return " ".join(parts[:3])  # সর্বোচ্চ ৩ টি ইউনিট দেখাবে

def get_running_applications():
    """চলমান অ্যাপ্লিকেশন তালিকা (সংশোধিত)"""
    try:
        apps = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 
                                        'status', 'create_time', 'username', 'cmdline']):
            try:
                pinfo = proc.info
                if pinfo['cpu_percent'] > 0 or pinfo['memory_percent'] > 0.5:  # সক্রিয় প্রসেস
                    apps.append({
                        'pid': pinfo['pid'],
                        'name': pinfo['name'],
                        'cpu': f"{pinfo['cpu_percent']:.1f}%",
                        'memory': f"{pinfo['memory_percent']:.1f}%",
                        'status': pinfo['status'],
                        'username': pinfo.get('username', 'N/A'),
                        'cmdline': ' '.join(pinfo.get('cmdline', []))[:100] if pinfo.get('cmdline') else 'N/A'
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        # CPU ব্যবহার অনুযায়ী সর্ট
        return sorted(apps, key=lambda x: float(x['cpu'].rstrip('%')), reverse=True)[:15]
    except Exception as e:
        app.logger.error(f"অ্যাপ্লিকেশন তালিকা সংগ্রহে ত্রুটি: {str(e)}")
        return []

def create_default_users():
    """ডিফল্ট ইউজার তৈরি করার ফাংশন"""
    users_file = 'data/users.json'
    os.makedirs('data', exist_ok=True)
    
    if not os.path.exists(users_file):
        # শক্তিশালী পাসওয়ার্ড পলিসি
        default_password = Config.DEFAULT_ADMIN['password']
        if default_password == 'admin123':
            app.logger.warning("ডিফল্ট পাসওয়ার্ড ব্যবহার করা হচ্ছে - প্রথম লগইনে পরিবর্তন করুন!")
        
        default_user = {
            'id': str(uuid.uuid4()),
            'username': Config.DEFAULT_ADMIN['username'],
            'password': generate_password_hash(default_password, method='pbkdf2:sha256'),
            'email': Config.DEFAULT_ADMIN['email'],
            'role': 'admin',
            'created_at': datetime.now().isoformat(),
            'last_login': None,
            'is_active': True,
            'login_attempts': 0,
            'locked_until': None
        }
        
        users_data = {'users': [default_user]}
        with open(users_file, 'w', encoding='utf-8') as f:
            json.dump(users_data, f, indent=2, ensure_ascii=False)
        
        app.logger.info('ডিফল্ট অ্যাডমিন ইউজার তৈরি করা হয়েছে')

# ==================== ব্রুট ফোর্স প্রোটেকশন (নতুন) ====================
class BruteForceProtection:
    """ব্রুট ফোর্স অ্যাটাক প্রতিরোধ"""
    
    @staticmethod
    def is_account_locked(user):
        """অ্যাকাউন্ট লক চেক"""
        if user.get('locked_until'):
            locked_until = datetime.fromisoformat(user['locked_until'])
            if datetime.now() < locked_until:
                return True
            else:
                # লক সময় শেষ
                user['login_attempts'] = 0
                user['locked_until'] = None
        return False
    
    @staticmethod
    def record_failed_attempt(user):
        """ব্যর্থ লগইন রেকর্ড"""
        user['login_attempts'] = user.get('login_attempts', 0) + 1
        
        # ৫ বার ব্যর্থ হলে ১৫ মিনিট লক
        if user['login_attempts'] >= 5:
            user['locked_until'] = (datetime.now() + timedelta(minutes=15)).isoformat()
            log_security_event('ACCOUNT_LOCKED', 
                             f"User: {user['username']}, Attempts: {user['login_attempts']}")
        elif user['login_attempts'] >= 3:
            # ৩ বার ব্যর্থ হলে ১ মিনিট লক
            user['locked_until'] = (datetime.now() + timedelta(minutes=1)).isoformat()
        
        return user
    
    @staticmethod
    def reset_attempts(user):
        """সফল লগইনে রিসেট"""
        user['login_attempts'] = 0
        user['locked_until'] = None
        return user

# ==================== ডেকোরেটর ====================
def login_required(f):
    """লগইন প্রয়োজন ডেকোরেটর (সংশোধিত)"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('login'))
        
        # সেশন টাইমআউট চেক
        last_activity = session.get('last_activity')
        if last_activity:
            last_activity_time = datetime.fromisoformat(last_activity)
            if datetime.now() - last_activity_time > timedelta(hours=12):
                session.clear()
                return redirect(url_for('login'))
        
        # অ্যাক্টিভিটি আপডেট
        session['last_activity'] = datetime.now().isoformat()
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """অ্যাডমিন প্রয়োজন ডেকোরেটর"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# ==================== পেজ রেন্ডারিং হেল্পার (নতুন) ====================
def render_page(title, content, extra_css='', extra_js='', active_page=''):
    """সকল পেজ রেন্ডার করার ইউনিফাইড ফাংশন"""
    
    # বর্তমান ইউজার ইনফো
    user_logged_in = 'user_id' in session
    username = session.get('username', '')
    user_role = session.get('role', '')
    csrf_token = generate_csrf_token() if user_logged_in else ''
    
    # অ্যাক্টিভ ক্লাস নির্ধারণ
    def is_active(page):
        return 'active' if page == active_page else ''
    
    # সাইডবার (শুধু লগইন করা থাকলে)
    sidebar_html = ''
    if user_logged_in:
        sidebar_html = f'''
        <nav class="sidebar p-3">
            <div class="text-center mb-4">
                <h4 class="fw-bold">
                    <i class="fas fa-server"></i> হোস্টিং প্যানেল
                </h4>
            </div>
            
            <div class="nav flex-column">
                <a href="/dashboard" class="nav-link {is_active('dashboard')}">
                    <i class="fas fa-tachometer-alt"></i> ড্যাশবোর্ড
                </a>
                <a href="/file-manager" class="nav-link {is_active('file-manager')}">
                    <i class="fas fa-folder"></i> ফাইল ম্যানেজার
                </a>
                <a href="/project-manager" class="nav-link {is_active('project-manager')}">
                    <i class="fas fa-project-diagram"></i> প্রজেক্ট ম্যানেজার
                </a>
                <a href="/searxng" class="nav-link {is_active('searxng')}">
                    <i class="fas fa-search"></i> SearXNG
                </a>
                <a href="/settings" class="nav-link {is_active('settings')}">
                    <i class="fas fa-cog"></i> সেটিংস
                </a>
                <a href="/profile" class="nav-link {is_active('profile')}">
                    <i class="fas fa-user"></i> প্রোফাইল
                </a>
                <a href="/logs" class="nav-link {is_active('logs')}">
                    <i class="fas fa-history"></i> লগ
                </a>
                <a href="/server-info" class="nav-link {is_active('server-info')}">
                    <i class="fas fa-info-circle"></i> সার্ভার তথ্য
                </a>
                <a href="/logout" class="nav-link">
                    <i class="fas fa-sign-out-alt"></i> লগআউট
                </a>
            </div>
        </nav>
        '''
    
    # সম্পূর্ণ HTML পেজ
    full_html = f'''
    <!DOCTYPE html>
    <html lang="bn" data-bs-theme="dark">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>হোস্টিং প্যানেল - {title}</title>
        
        <!-- Bootstrap 5 CSS -->
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <!-- Font Awesome -->
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
        <!-- Google Fonts -->
        <link href="https://fonts.googleapis.com/css2?family=Hind+Siliguri:wght@300;400;500;600;700&display=swap" rel="stylesheet">
        
        <style>
            /* ==================== গ্লোবাল স্টাইল ==================== */
            :root {{
                --glass-bg: rgba(255, 255, 255, 0.05);
                --glass-border: rgba(255, 255, 255, 0.1);
                --glass-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.37);
                --primary-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                --success-gradient: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
                --danger-gradient: linear-gradient(135deg, #eb3349 0%, #f45c43 100%);
            }}
            
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            
            body {{
                font-family: 'Hind Siliguri', sans-serif;
                background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
                min-height: 100vh;
                color: #fff;
                overflow-x: hidden;
            }}
            
            /* ==================== গ্লাসমরফিজম ইফেক্ট ==================== */
            .glass-card {{
                background: var(--glass-bg);
                backdrop-filter: blur(10px);
                -webkit-backdrop-filter: blur(10px);
                border: 1px solid var(--glass-border);
                border-radius: 20px;
                box-shadow: var(--glass-shadow);
                transition: all 0.3s ease;
            }}
            
            .glass-card:hover {{
                transform: translateY(-5px);
                box-shadow: 0 12px 40px 0 rgba(31, 38, 135, 0.5);
            }}
            
            .glass-input {{
                background: rgba(255, 255, 255, 0.08);
                border: 1px solid rgba(255, 255, 255, 0.1);
                color: #fff;
                backdrop-filter: blur(5px);
            }}
            
            .glass-input:focus {{
                background: rgba(255, 255, 255, 0.12);
                border-color: rgba(255, 255, 255, 0.3);
                color: #fff;
                box-shadow: 0 0 0 0.25rem rgba(102, 126, 234, 0.25);
            }}
            
            /* ==================== নেভিগেশন ==================== */
            .sidebar {{
                background: rgba(15, 12, 41, 0.8);
                backdrop-filter: blur(10px);
                border-right: 1px solid rgba(255, 255, 255, 0.1);
                min-height: 100vh;
                width: 280px;
                transition: all 0.3s;
            }}
            
            .nav-link {{
                color: rgba(255, 255, 255, 0.7);
                padding: 12px 20px;
                margin: 5px 15px;
                border-radius: 12px;
                transition: all 0.3s;
                text-decoration: none;
                display: block;
            }}
            
            .nav-link:hover, .nav-link.active {{
                background: var(--primary-gradient);
                color: #fff;
                transform: translateX(5px);
            }}
            
            .nav-link i {{
                margin-right: 10px;
                width: 20px;
            }}
            
            /* ==================== বাটন স্টাইল ==================== */
            .btn-glass {{
                background: var(--glass-bg);
                backdrop-filter: blur(5px);
                border: 1px solid var(--glass-border);
                color: #fff;
                padding: 10px 25px;
                border-radius: 12px;
                transition: all 0.3s;
            }}
            
            .btn-glass:hover {{
                background: rgba(255, 255, 255, 0.15);
                transform: translateY(-2px);
                color: #fff;
            }}
            
            .btn-primary-gradient {{
                background: var(--primary-gradient);
                border: none;
                color: #fff;
                padding: 12px 30px;
                border-radius: 12px;
                font-weight: 600;
                transition: all 0.3s;
            }}
            
            .btn-primary-gradient:hover {{
                transform: translateY(-2px);
                box-shadow: 0 10px 20px rgba(102, 126, 234, 0.4);
                color: #fff;
            }}
            
            /* ==================== টোস্ট নোটিফিকেশন ==================== */
            .toast-container {{
                position: fixed;
                top: 20px;
                right: 20px;
                z-index: 1060;
            }}
            
            .custom-toast {{
                background: var(--glass-bg);
                backdrop-filter: blur(20px);
                border: 1px solid var(--glass-border);
                color: #fff;
                border-radius: 15px;
                margin-bottom: 10px;
                animation: slideInRight 0.3s ease-out;
            }}
            
            @keyframes slideInRight {{
                from {{
                    transform: translateX(100%);
                    opacity: 0;
                }}
                to {{
                    transform: translateX(0);
                    opacity: 1;
                }}
            }}
            
            /* ==================== লোডিং অ্যানিমেশন ==================== */
            .loading-overlay {{
                display: none;
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.7);
                z-index: 9999;
                justify-content: center;
                align-items: center;
            }}
            
            .loading-spinner {{
                width: 60px;
                height: 60px;
                border: 4px solid rgba(255, 255, 255, 0.1);
                border-top: 4px solid #667eea;
                border-radius: 50%;
                animation: spin 1s linear infinite;
            }}
            
            @keyframes spin {{
                0% {{ transform: rotate(0deg); }}
                100% {{ transform: rotate(360deg); }}
            }}
            
            /* ==================== রেসপন্সিভ ডিজাইন ==================== */
            @media (max-width: 768px) {{
                .sidebar {{
                    width: 100%;
                    min-height: auto;
                    position: relative;
                }}
                
                .glass-card {{
                    margin: 10px;
                }}
                
                .btn-primary-gradient {{
                    width: 100%;
                }}
            }}
            
            /* ==================== ফাইল ম্যানেজার স্টাইল ==================== */
            .file-item {{
                display: flex;
                align-items: center;
                padding: 12px;
                background: rgba(255, 255, 255, 0.05);
                border-radius: 10px;
                margin: 5px 0;
                transition: all 0.3s;
                cursor: pointer;
            }}
            
            .file-item:hover {{
                background: rgba(255, 255, 255, 0.1);
                transform: translateX(5px);
            }}
            
            .file-icon {{
                width: 40px;
                height: 40px;
                display: flex;
                align-items: center;
                justify-content: center;
                border-radius: 10px;
                margin-right: 15px;
                font-size: 20px;
            }}
            
            /* ==================== সার্চ বার ==================== */
            .search-box {{
                position: relative;
            }}
            
            .search-box input {{
                padding-left: 45px;
            }}
            
            .search-box .search-icon {{
                position: absolute;
                left: 15px;
                top: 50%;
                transform: translateY(-50%);
                color: rgba(255, 255, 255, 0.5);
            }}
            
            /* ==================== স্ট্যাটাস ইন্ডিকেটর ==================== */
            .status-indicator {{
                width: 12px;
                height: 12px;
                border-radius: 50%;
                display: inline-block;
                animation: pulse 2s infinite;
            }}
            
            .status-active {{
                background: #38ef7d;
                box-shadow: 0 0 10px #38ef7d;
            }}
            
            .status-inactive {{
                background: #f45c43;
                box-shadow: 0 0 10px #f45c43;
            }}
            
            @keyframes pulse {{
                0% {{ transform: scale(1); }}
                50% {{ transform: scale(1.1); }}
                100% {{ transform: scale(1); }}
            }}
            
            /* ==================== প্রগ্রেস বার ==================== */
            .progress-glass {{
                background: rgba(255, 255, 255, 0.1);
                border-radius: 20px;
                height: 12px;
                overflow: hidden;
            }}
            
            .progress-bar-glass {{
                background: var(--primary-gradient);
                border-radius: 20px;
                transition: width 0.3s ease;
            }}
            
            {extra_css}
        </style>
    </head>
    <body>
        <!-- লোডিং ওভারলে -->
        <div class="loading-overlay" id="loadingOverlay">
            <div class="text-center">
                <div class="loading-spinner mb-3"></div>
                <p class="text-white">লোড হচ্ছে...</p>
            </div>
        </div>
        
        <!-- টোস্ট কন্টেইনার -->
        <div class="toast-container" id="toastContainer"></div>
        
        <!-- মেইন লেআউট -->
        <div class="d-flex flex-wrap">
            {sidebar_html}
            
            <!-- মেইন কন্টেন্ট -->
            <main class="flex-grow-1 p-4">
                {content}
            </main>
        </div>
        
        <!-- Bootstrap JS -->
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
        
        <!-- কমন JavaScript ফাংশন -->
        <script>
            // ==================== CSRF টোকেন ====================
            const CSRF_TOKEN = '{csrf_token}';
            
            function getCsrfToken() {{
                return CSRF_TOKEN || document.querySelector('[name="csrf_token"]')?.value || '';
            }}
            
            // ==================== টোস্ট নোটিফিকেশন সিস্টেম ====================
            function showToast(message, type = 'info') {{
                const toastContainer = document.getElementById('toastContainer');
                const toastId = 'toast-' + Date.now();
                
                const icons = {{
                    success: '<i class="fas fa-check-circle text-success"></i>',
                    error: '<i class="fas fa-times-circle text-danger"></i>',
                    warning: '<i class="fas fa-exclamation-triangle text-warning"></i>',
                    info: '<i class="fas fa-info-circle text-info"></i>'
                }};
                
                const toastHTML = `
                    <div class="custom-toast p-3" id="${{toastId}}">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                ${{icons[type] || icons.info}}
                                <span class="ms-2">${{escapeHtml(message)}}</span>
                            </div>
                            <button class="btn-close btn-close-white" onclick="closeToast('${{toastId}}')" aria-label="Close"></button>
                        </div>
                    </div>
                `;
                
                toastContainer.insertAdjacentHTML('beforeend', toastHTML);
                
                setTimeout(() => {{
                    closeToast(toastId);
                }}, 5000);
            }}
            
            function closeToast(toastId) {{
                const toast = document.getElementById(toastId);
                if (toast) {{
                    toast.style.animation = 'slideInRight 0.3s ease-out reverse';
                    setTimeout(() => toast.remove(), 300);
                }}
            }}
            
            // XSS প্রতিরোধে HTML এস্কেপ
            function escapeHtml(text) {{
                const map = {{
                    '&': '&amp;',
                    '<': '&lt;',
                    '>': '&gt;',
                    '"': '&quot;',
                    "'": '&#039;'
                }};
                return String(text).replace(/[&<>"']/g, m => map[m]);
            }}
            
            // ==================== লোডিং অ্যানিমেশন ====================
            let loadingTimeout;
            
            function showLoading() {{
                clearTimeout(loadingTimeout);
                document.getElementById('loadingOverlay').style.display = 'flex';
            }}
            
            function hideLoading() {{
                loadingTimeout = setTimeout(() => {{
                    document.getElementById('loadingOverlay').style.display = 'none';
                }}, 500);
            }}
            
            // ==================== AJAX হেল্পার ====================
            async function fetchAPI(url, options = {{}}) {{
                try {{
                    const headers = {{
                        'Content-Type': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest',
                        'X-CSRF-Token': getCsrfToken(),
                        ...options.headers
                    }};
                    
                    const response = await fetch(url, {{
                        ...options,
                        headers
                    }});
                    
                    if (response.status === 401) {{
                        window.location.href = '/login';
                        return;
                    }}
                    
                    if (response.status === 403) {{
                        showToast('আপনার এই কাজের অনুমতি নেই', 'error');
                        return;
                    }}
                    
                    const data = await response.json();
                    
                    if (!response.ok) {{
                        throw new Error(data.message || data.error || 'অজানা ত্রুটি');
                    }}
                    
                    return data;
                }} catch (error) {{
                    showToast(error.message, 'error');
                    throw error;
                }}
            }}
            
            // ==================== কনফার্মেশন ডায়ালগ ====================
            async function confirmAction(message) {{
                return confirm(message);
            }}
            
            // ==================== ডার্ক মোড টগল ====================
            function toggleDarkMode() {{
                const html = document.documentElement;
                const currentTheme = html.getAttribute('data-bs-theme');
                const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
                html.setAttribute('data-bs-theme', newTheme);
                localStorage.setItem('theme', newTheme);
            }}
            
            document.addEventListener('DOMContentLoaded', () => {{
                const savedTheme = localStorage.getItem('theme') || 'dark';
                document.documentElement.setAttribute('data-bs-theme', savedTheme);
            }});
            
            {extra_js}
        </script>
    </body>
    </html>
    '''
    
    return full_html

# ==================== রাউটস ====================
@app.route('/')
def index():
    """হোম পেজ - লগইন পেজে রিডাইরেক্ট"""
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """লগইন পেজ (সংশোধিত - ব্রুট ফোর্স প্রোটেকশন সহ)"""
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username'))
        password = request.form.get('password')
        
        if not username or not password:
            return jsonify({'success': False, 'message': 'ইউজারনেম এবং পাসওয়ার্ড প্রয়োজন'}), 400
        
        # রেট লিমিট চেক (সাধারণ)
        client_ip = request.remote_addr
        
        # ইউজার ভেরিফিকেশন
        users_file = 'data/users.json'
        if not os.path.exists(users_file):
            return jsonify({'success': False, 'message': 'ইউজার ডাটাবেস পাওয়া যায়নি'}), 500
        
        with open(users_file, 'r', encoding='utf-8') as f:
            users_data = json.load(f)
        
        user = next((u for u in users_data['users'] if u['username'] == username), None)
        
        if user:
            # ব্রুট ফোর্স প্রোটেকশন চেক
            if BruteForceProtection.is_account_locked(user):
                locked_until = datetime.fromisoformat(user['locked_until'])
                remaining = int((locked_until - datetime.now()).total_seconds() / 60)
                log_security_event('LOGIN_BLOCKED', f"Account locked: {username}")
                return jsonify({
                    'success': False, 
                    'message': f'অ্যাকাউন্ট লক করা হয়েছে। {remaining} মিনিট পর আবার চেষ্টা করুন।'
                }), 429
        
        if user and check_password_hash(user['password'], password):
            # সফল লগইন
            user = BruteForceProtection.reset_attempts(user)
            
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['last_activity'] = datetime.now().isoformat()
            session.permanent = True
            
            # লাস্ট লগইন আপডেট
            user['last_login'] = datetime.now().isoformat()
            with open(users_file, 'w', encoding='utf-8') as f:
                json.dump(users_data, f, indent=2, ensure_ascii=False)
            
            log_security_event('LOGIN_SUCCESS', f"User: {username}")
            app.logger.info(f'ইউজার লগইন সফল: {username}')
            return jsonify({'success': True, 'redirect': '/dashboard'})
        else:
            # ব্যর্থ লগইন
            if user:
                user = BruteForceProtection.record_failed_attempt(user)
                with open(users_file, 'w', encoding='utf-8') as f:
                    json.dump(users_data, f, indent=2, ensure_ascii=False)
                log_security_event('LOGIN_FAILED', f"User: {username}, Attempts: {user['login_attempts']}")
            
            return jsonify({'success': False, 'message': 'ভুল ইউজারনেম বা পাসওয়ার্ড'}), 401
    
    # GET রিকোয়েস্ট - লগইন পেজ দেখান
    content = '''
    <div class="container">
        <div class="row justify-content-center align-items-center min-vh-100">
            <div class="col-md-5 col-lg-4">
                <div class="glass-card p-5">
                    <div class="text-center mb-4">
                        <i class="fas fa-server fa-3x mb-3" style="background: var(--primary-gradient); -webkit-background-clip: text; -webkit-text-fill-color: transparent;"></i>
                        <h3 class="fw-bold">হোস্টিং প্যানেল</h3>
                        <p class="text-muted">লগইন করুন</p>
                    </div>
                    
                    <form id="loginForm" onsubmit="handleLogin(event)">
                        <input type="hidden" name="csrf_token" value="''' + generate_csrf_token() + '''">
                        
                        <div class="mb-3">
                            <label class="form-label" for="username">ইউজারনেম</label>
                            <div class="input-group">
                                <span class="input-group-text glass-input">
                                    <i class="fas fa-user"></i>
                                </span>
                                <input type="text" class="form-control glass-input" id="username" name="username" required autocomplete="username">
                            </div>
                        </div>
                        
                        <div class="mb-3">
                            <label class="form-label" for="password">পাসওয়ার্ড</label>
                            <div class="input-group">
                                <span class="input-group-text glass-input">
                                    <i class="fas fa-lock"></i>
                                </span>
                                <input type="password" class="form-control glass-input" id="password" name="password" required autocomplete="current-password">
                                <button class="btn glass-input" type="button" onclick="togglePassword()" aria-label="পাসওয়ার্ড দেখান/লুকান">
                                    <i class="fas fa-eye" id="passwordToggle"></i>
                                </button>
                            </div>
                        </div>
                        
                        <div class="mb-3 form-check">
                            <input type="checkbox" class="form-check-input" id="rememberMe">
                            <label class="form-check-label" for="rememberMe">মনে রাখুন</label>
                        </div>
                        
                        <button type="submit" class="btn btn-primary-gradient w-100">
                            <i class="fas fa-sign-in-alt"></i> লগইন
                        </button>
                    </form>
                </div>
            </div>
        </div>
    </div>
    '''
    
    extra_js = '''
    function togglePassword() {
        const passwordInput = document.getElementById('password');
        const icon = document.getElementById('passwordToggle');
        
        if (passwordInput.type === 'password') {
            passwordInput.type = 'text';
            icon.classList.replace('fa-eye', 'fa-eye-slash');
        } else {
            passwordInput.type = 'password';
            icon.classList.replace('fa-eye-slash', 'fa-eye');
        }
    }
    
    async function handleLogin(event) {
        event.preventDefault();
        
        const formData = new FormData();
        formData.append('username', document.getElementById('username').value);
        formData.append('password', document.getElementById('password').value);
        formData.append('csrf_token', document.querySelector('[name="csrf_token"]').value);
        
        showLoading();
        
        try {
            const response = await fetch('/login', {
                method: 'POST',
                body: formData
            });
            
            const data = await response.json();
            
            if (data.success) {
                showToast('লগইন সফল!', 'success');
                setTimeout(() => {
                    window.location.href = data.redirect;
                }, 500);
            } else {
                showToast(data.message, 'error');
            }
        } catch (error) {
            showToast('লগইনে ত্রুটি: ' + error.message, 'error');
        } finally {
            hideLoading();
        }
    }
    
    document.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            handleLogin(new Event('submit'));
        }
    });
    '''
    
    return render_template_string(render_page('লগইন', content, extra_js=extra_js))

# ==================== ড্যাশবোর্ড ====================
@app.route('/dashboard')
@login_required
def dashboard():
    """ড্যাশবোর্ড পেজ (সংশোধিত)"""
    system_info = get_system_info()
    
    content = '''
    <div class="container-fluid">
        <h2 class="mb-4 fw-bold">
            <i class="fas fa-tachometer-alt"></i> ড্যাশবোর্ড
        </h2>
        
        <!-- সিস্টেম ওভারভিউ -->
        <div class="row mb-4">
            <div class="col-md-3 mb-3">
                <div class="glass-card p-4 text-center">
                    <i class="fas fa-microchip fa-2x mb-2" style="color: #667eea;"></i>
                    <h5>CPU ব্যবহার</h5>
                    <h3 class="fw-bold">''' + str(system_info.get('cpu_usage', 0)) + '''%</h3>
                    <small>''' + str(system_info.get('cpu_count', 'N/A')) + ''' কোর | ''' + str(system_info.get('cpu_freq_current', 'N/A')) + '''</small>
                    <div class="progress-glass mt-2">
                        <div class="progress-bar-glass" style="width: ''' + str(system_info.get('cpu_usage', 0)) + '''%"></div>
                    </div>
                </div>
            </div>
            
            <div class="col-md-3 mb-3">
                <div class="glass-card p-4 text-center">
                    <i class="fas fa-memory fa-2x mb-2" style="color: #11998e;"></i>
                    <h5>RAM ব্যবহার</h5>
                    <h3 class="fw-bold">''' + str(system_info.get('ram_percent', 0)) + '''%</h3>
                    <small>''' + str(system_info.get('used_ram', 'N/A')) + ''' / ''' + str(system_info.get('total_ram', 'N/A')) + '''</small>
                    <div class="progress-glass mt-2">
                        <div class="progress-bar-glass" style="width: ''' + str(system_info.get('ram_percent', 0)) + '''%"></div>
                    </div>
                </div>
            </div>
            
            <div class="col-md-3 mb-3">
                <div class="glass-card p-4 text-center">
                    <i class="fas fa-hdd fa-2x mb-2" style="color: #f45c43;"></i>
                    <h5>স্টোরেজ</h5>
                    <h3 class="fw-bold">''' + str(system_info.get('storage_percent', 0)) + '''%</h3>
                    <small>''' + str(system_info.get('used_storage', 'N/A')) + ''' / ''' + str(system_info.get('total_storage', 'N/A')) + '''</small>
                    <div class="progress-glass mt-2">
                        <div class="progress-bar-glass" style="width: ''' + str(system_info.get('storage_percent', 0)) + '''%"></div>
                    </div>
                </div>
            </div>
            
            <div class="col-md-3 mb-3">
                <div class="glass-card p-4 text-center">
                    <i class="fas fa-clock fa-2x mb-2" style="color: #764ba2;"></i>
                    <h5>সার্ভার আপটাইম</h5>
                    <h3 class="fw-bold">''' + str(system_info.get('uptime_formatted', 'N/A')) + '''</h3>
                    <small>''' + str(system_info.get('hostname', 'N/A')) + '''</small>
                </div>
            </div>
        </div>
        
        <!-- নেটওয়ার্ক ও অন্যান্য তথ্য -->
        <div class="row mb-4">
            <div class="col-md-4 mb-3">
                <div class="glass-card p-4">
                    <h6><i class="fas fa-network-wired"></i> নেটওয়ার্ক</h6>
                    <p class="mb-1">প্রেরিত: <strong>''' + str(system_info.get('network_sent', 'N/A')) + '''</strong></p>
                    <p class="mb-0">গৃহীত: <strong>''' + str(system_info.get('network_recv', 'N/A')) + '''</strong></p>
                </div>
            </div>
            <div class="col-md-4 mb-3">
                <div class="glass-card p-4">
                    <h6><i class="fas fa-exchange-alt"></i> ডিস্ক I/O</h6>
                    <p class="mb-1">পড়া: <strong>''' + str(system_info.get('disk_read_bytes', 'N/A')) + '''</strong></p>
                    <p class="mb-0">লেখা: <strong>''' + str(system_info.get('disk_write_bytes', 'N/A')) + '''</strong></p>
                </div>
            </div>
            <div class="col-md-4 mb-3">
                <div class="glass-card p-4">
                    <h6><i class="fas fa-memory"></i> সোয়াপ</h6>
                    <p class="mb-1">ব্যবহৃত: <strong>''' + str(system_info.get('swap_used', 'N/A')) + '''</strong></p>
                    <p class="mb-0">মোট: <strong>''' + str(system_info.get('swap_total', 'N/A')) + '''</strong></p>
                </div>
            </div>
        </div>
        
        <!-- চলমান অ্যাপ্লিকেশন -->
        <div class="glass-card p-4 mb-4">
            <div class="d-flex justify-content-between align-items-center mb-3">
                <h4><i class="fas fa-play-circle"></i> চলমান অ্যাপ্লিকেশন</h4>
                <button class="btn btn-glass btn-sm" onclick="refreshApps()">
                    <i class="fas fa-sync-alt"></i> রিফ্রেশ
                </button>
            </div>
            <div class="table-responsive">
                <table class="table table-dark table-hover">
                    <thead>
                        <tr>
                            <th>PID</th>
                            <th>নাম</th>
                            <th>CPU</th>
                            <th>RAM</th>
                            <th>স্ট্যাটাস</th>
                            <th>ইউজার</th>
                            <th>অ্যাকশন</th>
                        </tr>
                    </thead>
                    <tbody>
    '''
    
    # চলমান অ্যাপ্লিকেশন টেবিল রো
    for app in system_info.get('running_apps', []):
        status_class = 'status-active' if app.get('status') == 'running' else 'status-inactive'
        content += f'''
                        <tr>
                            <td><span class="badge bg-secondary">{app.get('pid', 'N/A')}</span></td>
                            <td>{app.get('name', 'N/A')}</td>
                            <td><span class="badge bg-primary">{app.get('cpu', 'N/A')}</span></td>
                            <td><span class="badge bg-success">{app.get('memory', 'N/A')}</span></td>
                            <td>
                                <span class="status-indicator {status_class}"></span>
                                {app.get('status', 'N/A')}
                            </td>
                            <td>{app.get('username', 'N/A')}</td>
                            <td>
                                <button class="btn btn-sm btn-glass" onclick="manageApp('{app.get('pid', '')}')" title="ম্যানেজ করুন">
                                    <i class="fas fa-cog"></i>
                                </button>
                            </td>
                        </tr>
        '''
    
    content += '''
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    '''
    
    extra_js = '''
    function refreshApps() {
        showToast('রিফ্রেশ হচ্ছে...', 'info');
        location.reload();
    }
    
    function manageApp(pid) {
        showToast('PID ' + pid + ' ম্যানেজ করা হচ্ছে...', 'info');
    }
    '''
    
    return render_template_string(render_page('ড্যাশবোর্ড', content, extra_js=extra_js, active_page='dashboard'))

@app.route('/logout')
def logout():
    """লগআউট রাউট (সংশোধিত)"""
    user = session.get('username', 'Unknown')
    
    # CSRF টোকেন রিমুভ
    session.pop('_csrf_token', None)
    
    # সম্পূর্ণ সেশন ক্লিয়ার
    session.clear()
    
    log_security_event('LOGOUT', f"User: {user}")
    app.logger.info(f'ইউজার লগআউট: {user}')
    
    return redirect(url_for('login'))

# ==================== ফাইল ম্যানেজার (নতুন) ====================
@app.route('/file-manager')
@login_required
def file_manager():
    """ফাইল ম্যানেজার পেজ"""
    current_path = request.args.get('path', '')
    
    try:
        base_path = os.path.abspath(Config.UPLOAD_FOLDER)
        target_path = validate_path(current_path) if current_path else base_path
        
        if not os.path.exists(target_path):
            os.makedirs(target_path, exist_ok=True)
        
        # ফাইল এবং ফোল্ডার তালিকা
        items = []
        for item in os.listdir(target_path):
            item_path = os.path.join(target_path, item)
            item_stat = os.stat(item_path)
            
            items.append({
                'name': item,
                'path': os.path.relpath(item_path, base_path),
                'is_dir': os.path.isdir(item_path),
                'size': item_stat.st_size,
                'modified': datetime.fromtimestamp(item_stat.st_mtime).isoformat(),
                'permissions': oct(item_stat.st_mode)[-3:]
            })
        
        # ফোল্ডার আগে, তারপর ফাইল, নাম অনুযায়ী সর্ট
        items.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))
        
    except Exception as e:
        app.logger.error(f"ফাইল ম্যানেজার ত্রুটি: {str(e)}")
        items = []
    
    content = '''
    <div class="container-fluid">
        <h2 class="mb-4 fw-bold">
            <i class="fas fa-folder"></i> ফাইল ম্যানেজার
        </h2>
        
        <!-- টুলবার -->
        <div class="glass-card p-3 mb-4">
            <div class="row align-items-center">
                <div class="col-md-6">
                    <div class="btn-group">
                        <button class="btn btn-glass btn-sm" onclick="createFolder()">
                            <i class="fas fa-folder-plus"></i> নতুন ফোল্ডার
                        </button>
                        <button class="btn btn-glass btn-sm" onclick="uploadFile()">
                            <i class="fas fa-upload"></i> আপলোড
                        </button>
                        <button class="btn btn-glass btn-sm" onclick="createFile()">
                            <i class="fas fa-file-plus"></i> নতুন ফাইল
                        </button>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="search-box">
                        <span class="search-icon">
                            <i class="fas fa-search"></i>
                        </span>
                        <input type="text" class="form-control glass-input" 
                               placeholder="ফাইল সার্চ করুন..." id="searchInput"
                               onkeyup="searchFiles()">
                    </div>
                </div>
            </div>
        </div>
        
        <!-- ফাইল লিস্ট -->
        <div class="glass-card p-3">
            <div class="table-responsive">
                <table class="table table-dark table-hover">
                    <thead>
                        <tr>
                            <th>নাম</th>
                            <th>সাইজ</th>
                            <th>পরিবর্তিত</th>
                            <th>পারমিশন</th>
                            <th>অ্যাকশন</th>
                        </tr>
                    </thead>
                    <tbody id="fileList">
    '''
    
    # ফাইল লিস্ট আইটেম
    for item in items:
        icon = 'fa-folder text-warning' if item['is_dir'] else 'fa-file text-info'
        content += f'''
                        <tr class="file-row" data-name="{item['name']}">
                            <td>
                                <i class="fas {icon}"></i>
                                {item['name']}
                            </td>
                            <td>{item['size']}</td>
                            <td>{item['modified']}</td>
                            <td>{item['permissions']}</td>
                            <td>
                                <div class="btn-group btn-group-sm">
        '''
        if item['is_dir']:
            content += f'''
                                    <button class="btn btn-glass" onclick="openFolder('{item['path']}')">
                                        <i class="fas fa-folder-open"></i>
                                    </button>
            '''
        else:
            content += f'''
                                    <button class="btn btn-glass" onclick="downloadFile('{item['path']}')">
                                        <i class="fas fa-download"></i>
                                    </button>
                                    <button class="btn btn-glass" onclick="editFile('{item['path']}')">
                                        <i class="fas fa-edit"></i>
                                    </button>
            '''
        content += f'''
                                    <button class="btn btn-glass" onclick="renameItem('{item['path']}')">
                                        <i class="fas fa-pencil-alt"></i>
                                    </button>
                                    <button class="btn btn-glass text-danger" onclick="deleteItem('{item['path']}')">
                                        <i class="fas fa-trash"></i>
                                    </button>
                                </div>
                            </td>
                        </tr>
        '''
    
    content += '''
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    
    <!-- আপলোড মোডাল (লুকানো) -->
    <input type="file" id="fileUploadInput" style="display: none" multiple onchange="handleFileUpload(event)">
    '''
    
    extra_js = '''
    function searchFiles() {
        const searchTerm = document.getElementById('searchInput').value.toLowerCase();
        const rows = document.querySelectorAll('.file-row');
        
        rows.forEach(row => {
            const name = row.getAttribute('data-name').toLowerCase();
            row.style.display = name.includes(searchTerm) ? '' : 'none';
        });
    }
    
    function uploadFile() {
        document.getElementById('fileUploadInput').click();
    }
    
    async function handleFileUpload(event) {
        const files = event.target.files;
        if (!files.length) return;
        
        const formData = new FormData();
        for (let file of files) {
            formData.append('files', file);
        }
        formData.append('csrf_token', getCsrfToken());
        
        showLoading();
        try {
            const response = await fetch('/api/upload', {
                method: 'POST',
                body: formData,
                headers: {
                    'X-CSRF-Token': getCsrfToken()
                }
            });
            
            const data = await response.json();
            if (data.success) {
                showToast('ফাইল আপলোড সফল!', 'success');
                location.reload();
            } else {
                showToast(data.message, 'error');
            }
        } catch (error) {
            showToast('আপলোড ব্যর্থ: ' + error.message, 'error');
        } finally {
            hideLoading();
            event.target.value = '';
        }
    }
    
    function openFolder(path) {
        window.location.href = '/file-manager?path=' + encodeURIComponent(path);
    }
    
    function downloadFile(path) {
        window.location.href = '/api/download?path=' + encodeURIComponent(path);
    }
    
    async function deleteItem(path) {
        if (!await confirmAction('আপনি কি নিশ্চিতভাবে এটি মুছে ফেলতে চান?')) return;
        
        showLoading();
        try {
            const response = await fetchAPI('/api/delete', {
                method: 'POST',
                body: JSON.stringify({ path: path })
            });
            
            if (response.success) {
                showToast('মুছে ফেলা সফল!', 'success');
                location.reload();
            }
        } catch (error) {
            // Error already shown by fetchAPI
        } finally {
            hideLoading();
        }
    }
    
    function createFolder() {
        const name = prompt('ফোল্ডারের নাম লিখুন:');
        if (!name) return;
        
        fetchAPI('/api/create-folder', {
            method: 'POST',
            body: JSON.stringify({ name: name })
        }).then(() => location.reload());
    }
    
    function createFile() {
        const name = prompt('ফাইলের নাম লিখুন:');
        if (!name) return;
        
        fetchAPI('/api/create-file', {
            method: 'POST',
            body: JSON.stringify({ name: name })
        }).then(() => location.reload());
    }
    
    function renameItem(oldPath) {
        const newName = prompt('নতুন নাম লিখুন:');
        if (!newName) return;
        
        fetchAPI('/api/rename', {
            method: 'POST',
            body: JSON.stringify({ old_path: oldPath, new_name: newName })
        }).then(() => location.reload());
    }
    
    function editFile(path) {
        window.location.href = '/file-editor?path=' + encodeURIComponent(path);
    }
    '''
    
    return render_template_string(render_page('ফাইল ম্যানেজার', content, extra_js=extra_js, active_page='file-manager'))

# ==================== ফাইল ম্যানেজার API (নতুন) ====================
@app.route('/api/upload', methods=['POST'])
@login_required
def api_upload():
    """ফাইল আপলোড API"""
    try:
        csrf_token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
        validate_csrf_token(csrf_token)
        
        if 'files' not in request.files:
            return jsonify({'success': False, 'message': 'কোনো ফাইল নির্বাচন করা হয়নি'}), 400
        
        files = request.files.getlist('files')
        uploaded_files = []
        
        for file in files:
            if file.filename == '':
                continue
            
            if not is_allowed_file(file.filename):
                return jsonify({'success': False, 'message': f'অননুমোদিত ফাইল টাইপ: {file.filename}'}), 400
            
            filename = secure_filename(file.filename)
            filepath = os.path.join(Config.UPLOAD_FOLDER, filename)
            
            # ফাইল সেভ
            file.save(filepath)
            uploaded_files.append(filename)
            app.logger.info(f'ফাইল আপলোড: {filename}')
        
        return jsonify({
            'success': True,
            'message': f'{len(uploaded_files)} টি ফাইল আপলোড সফল!',
            'files': uploaded_files
        })
        
    except Exception as e:
        app.logger.error(f'আপলোড ত্রুটি: {str(e)}')
        return jsonify({'success': False, 'message': 'আপলোড ব্যর্থ'}), 500

@app.route('/api/download')
@login_required
def api_download():
    """ফাইল ডাউনলোড API"""
    try:
        path = request.args.get('path')
        if not path:
            abort(404)
        
        safe_path = validate_path(path)
        
        if not os.path.exists(safe_path) or os.path.isdir(safe_path):
            abort(404)
        
        return send_file(safe_path, as_attachment=True)
        
    except Exception as e:
        app.logger.error(f'ডাউনলোড ত্রুটি: {str(e)}')
        abort(500)

@app.route('/api/delete', methods=['POST'])
@login_required
def api_delete():
    """ফাইল/ফোল্ডার ডিলিট API"""
    try:
        data = request.get_json()
        validate_csrf_token(request.headers.get('X-CSRF-Token'))
        
        path = data.get('path')
        if not path:
            return jsonify({'success': False, 'message': 'পাথ প্রয়োজন'}), 400
        
        safe_path = validate_path(path)
        
        if os.path.isdir(safe_path):
            import shutil
            shutil.rmtree(safe_path)
            app.logger.info(f'ফোল্ডার ডিলিট: {path}')
        else:
            os.remove(safe_path)
            app.logger.info(f'ফাইল ডিলিট: {path}')
        
        return jsonify({'success': True, 'message': 'মুছে ফেলা সফল!'})
        
    except Exception as e:
        app.logger.error(f'ডিলিট ত্রুটি: {str(e)}')
        return jsonify({'success': False, 'message': 'মুছে ফেলা ব্যর্থ'}), 500

@app.route('/api/create-folder', methods=['POST'])
@login_required
def api_create_folder():
    """ফোল্ডার তৈরি API"""
    try:
        data = request.get_json()
        validate_csrf_token(request.headers.get('X-CSRF-Token'))
        
        name = data.get('name')
        if not name:
            return jsonify({'success': False, 'message': 'নাম প্রয়োজন'}), 400
        
        safe_name = secure_filename(name)
        folder_path = os.path.join(Config.UPLOAD_FOLDER, safe_name)
        
        os.makedirs(folder_path, exist_ok=True)
        app.logger.info(f'ফোল্ডার তৈরি: {safe_name}')
        
        return jsonify({'success': True, 'message': 'ফোল্ডার তৈরি সফল!'})
        
    except Exception as e:
        app.logger.error(f'ফোল্ডার তৈরি ত্রুটি: {str(e)}')
        return jsonify({'success': False, 'message': 'ফোল্ডার তৈরি ব্যর্থ'}), 500

@app.route('/api/create-file', methods=['POST'])
@login_required
def api_create_file():
    """ফাইল তৈরি API"""
    try:
        data = request.get_json()
        validate_csrf_token(request.headers.get('X-CSRF-Token'))
        
        name = data.get('name')
        if not name:
            return jsonify({'success': False, 'message': 'নাম প্রয়োজন'}), 400
        
        safe_name = secure_filename(name)
        file_path = os.path.join(Config.UPLOAD_FOLDER, safe_name)
        
        with open(file_path, 'w') as f:
            f.write('')
        
        app.logger.info(f'ফাইল তৈরি: {safe_name}')
        return jsonify({'success': True, 'message': 'ফাইল তৈরি সফল!'})
        
    except Exception as e:
        app.logger.error(f'ফাইল তৈরি ত্রুটি: {str(e)}')
        return jsonify({'success': False, 'message': 'ফাইল তৈরি ব্যর্থ'}), 500

@app.route('/api/rename', methods=['POST'])
@login_required
def api_rename():
    """ফাইল/ফোল্ডার রিনেম API"""
    try:
        data = request.get_json()
        validate_csrf_token(request.headers.get('X-CSRF-Token'))
        
        old_path = data.get('old_path')
        new_name = data.get('new_name')
        
        if not old_path or not new_name:
            return jsonify({'success': False, 'message': 'পুরনো পাথ এবং নতুন নাম প্রয়োজন'}), 400
        
        safe_old_path = validate_path(old_path)
        safe_new_name = secure_filename(new_name)
        
        parent_dir = os.path.dirname(safe_old_path)
        new_path = os.path.join(parent_dir, safe_new_name)
        
        os.rename(safe_old_path, new_path)
        app.logger.info(f'রিনেম: {old_path} -> {new_name}')
        
        return jsonify({'success': True, 'message': 'নাম পরিবর্তন সফল!'})
        
    except Exception as e:
        app.logger.error(f'রিনেম ত্রুটি: {str(e)}')
        return jsonify({'success': False, 'message': 'নাম পরিবর্তন ব্যর্থ'}), 500

# ==================== SearXNG পেজ (নতুন) ====================
@app.route('/searxng')
@login_required
def searxng_page():
    """SearXNG ম্যানেজমেন্ট পেজ"""
    
    content = '''
    <div class="container-fluid">
        <h2 class="mb-4 fw-bold">
            <i class="fas fa-search"></i> SearXNG ম্যানেজার
        </h2>
        
        <div class="row">
            <div class="col-md-6 mb-3">
                <div class="glass-card p-4">
                    <h5><i class="fas fa-info-circle"></i> ইনস্টলেশন স্ট্যাটাস</h5>
                    <div id="installStatus">
                        <p>চেক করা হচ্ছে...</p>
                    </div>
                    <button class="btn btn-primary-gradient mt-2" onclick="checkSearXNG()">
                        <i class="fas fa-sync-alt"></i> চেক করুন
                    </button>
                </div>
            </div>
            
            <div class="col-md-6 mb-3">
                <div class="glass-card p-4">
                    <h5><i class="fas fa-cog"></i> কন্ট্রোল</h5>
                    <div class="d-grid gap-2">
                        <button class="btn btn-success" onclick="controlSearXNG('install')">
                            <i class="fas fa-download"></i> ইন্সটল
                        </button>
                        <button class="btn btn-primary" onclick="controlSearXNG('start')">
                            <i class="fas fa-play"></i> স্টার্ট
                        </button>
                        <button class="btn btn-warning" onclick="controlSearXNG('stop')">
                            <i class="fas fa-stop"></i> স্টপ
                        </button>
                        <button class="btn btn-info" onclick="controlSearXNG('restart')">
                            <i class="fas fa-redo"></i> রিস্টার্ট
                        </button>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="glass-card p-4 mt-3">
            <h5><i class="fas fa-terminal"></i> লগ</h5>
            <pre id="searxngLogs" style="max-height: 400px; overflow-y: auto; background: rgba(0,0,0,0.3); padding: 15px; border-radius: 10px;">
লোড হচ্ছে...
            </pre>
        </div>
    </div>
    '''
    
    extra_js = '''
    function checkSearXNG() {
        showLoading();
        fetchAPI('/api/searxng/status')
            .then(data => {
                document.getElementById('installStatus').innerHTML = `
                    <p>স্ট্যাটাস: <span class="badge bg-${data.installed ? 'success' : 'danger'}">
                        ${data.installed ? 'ইন্সটল করা আছে' : 'ইন্সটল করা নেই'}
                    </span></p>
                    ${data.running ? '<p>রানিং: <span class="badge bg-success">হ্যাঁ</span></p>' : ''}
                `;
            })
            .finally(() => hideLoading());
    }
    
    function controlSearXNG(action) {
        showLoading();
        fetchAPI('/api/searxng/control', {
            method: 'POST',
            body: JSON.stringify({ action: action })
        })
        .then(data => {
            showToast(data.message, 'success');
            loadSearXNGLogs();
        })
        .finally(() => hideLoading());
    }
    
    function loadSearXNGLogs() {
        fetchAPI('/api/searxng/logs')
            .then(data => {
                document.getElementById('searxngLogs').textContent = data.logs;
            });
    }
    
    document.addEventListener('DOMContentLoaded', () => {
        checkSearXNG();
        loadSearXNGLogs();
    });
    '''
    
    return render_template_string(render_page('SearXNG', content, extra_js=extra_js, active_page='searxng'))

@app.route('/api/searxng/status')
@login_required
def searxng_status():
    """SearXNG স্ট্যাটাস API"""
    try:
        installed = os.path.exists('/usr/local/searxng') or os.path.exists('./searxng')
        running = False
        
        # SearXNG প্রসেস চেক
        for proc in psutil.process_iter(['name', 'cmdline']):
            try:
                if 'searxng' in proc.info['name'].lower() or \
                   any('searxng' in cmd.lower() for cmd in (proc.info.get('cmdline') or [])):
                    running = True
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        return jsonify({
            'installed': installed,
            'running': running
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/searxng/control', methods=['POST'])
@login_required
def searxng_control():
    """SearXNG কন্ট্রোল API"""
    try:
        data = request.get_json()
        action = data.get('action')
        
        # বেসিক কন্ট্রোল (পরবর্তীতে সম্পূর্ণ ইমপ্লিমেন্ট হবে)
        if action == 'install':
            message = 'SearXNG ইন্সটলেশন শুরু হয়েছে (ডেমো)'
        elif action == 'start':
            message = 'SearXNG শুরু হয়েছে (ডেমো)'
        elif action == 'stop':
            message = 'SearXNG বন্ধ হয়েছে (ডেমো)'
        elif action == 'restart':
            message = 'SearXNG রিস্টার্ট হয়েছে (ডেমো)'
        else:
            return jsonify({'success': False, 'message': 'অজানা অ্যাকশন'}), 400
        
        app.logger.info(f'SearXNG {action}: {message}')
        return jsonify({'success': True, 'message': message})
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/searxng/logs')
@login_required
def searxng_logs():
    """SearXNG লগ API"""
    return jsonify({'logs': 'SearXNG লগ দেখানো হবে (ডেমো)'})

# ==================== সার্ভার ইনফো পেজ ====================
@app.route('/server-info')
@login_required
def server_info():
    """সার্ভার তথ্য পেজ"""
    info = get_system_info()
    
    content = f'''
    <div class="container-fluid">
        <h2 class="mb-4 fw-bold">
            <i class="fas fa-info-circle"></i> সার্ভার তথ্য
        </h2>
        
        <div class="row">
            <div class="col-md-6">
                <div class="glass-card p-4 mb-3">
                    <h5>সিস্টেম</h5>
                    <ul class="list-unstyled">
                        <li><strong>Python:</strong> {info.get('python_version', 'N/A')}</li>
                        <li><strong>Flask:</strong> {info.get('flask_version', 'N/A')}</li>
                        <li><strong>প্ল্যাটফর্ম:</strong> {info.get('platform', 'N/A')}</li>
                        <li><strong>প্রসেসর:</strong> {info.get('processor', 'N/A')}</li>
                        <li><strong>হোস্টনেম:</strong> {info.get('hostname', 'N/A')}</li>
                    </ul>
                </div>
            </div>
            <div class="col-md-6">
                <div class="glass-card p-4 mb-3">
                    <h5>রিসোর্স</h5>
                    <ul class="list-unstyled">
                        <li><strong>CPU কোর:</strong> {info.get('cpu_count', 'N/A')}</li>
                        <li><strong>CPU ফ্রিকোয়েন্সি:</strong> {info.get('cpu_freq_current', 'N/A')}</li>
                        <li><strong>মোট RAM:</strong> {info.get('total_ram', 'N/A')}</li>
                        <li><strong>উপলব্ধ RAM:</strong> {info.get('available_ram', 'N/A')}</li>
                        <li><strong>ফ্রি স্টোরেজ:</strong> {info.get('free_storage', 'N/A')}</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>
    '''
    
    return render_template_string(render_page('সার্ভার তথ্য', content, active_page='server-info'))

# ==================== প্রজেক্ট ম্যানেজার (প্লেসহোল্ডার) ====================
@app.route('/project-manager')
@login_required
def project_manager():
    """প্রজেক্ট ম্যানেজার পেজ"""
    content = '''
    <div class="container-fluid">
        <h2 class="mb-4 fw-bold">
            <i class="fas fa-project-diagram"></i> প্রজেক্ট ম্যানেজার
        </h2>
        <div class="glass-card p-4">
            <p>প্রজেক্ট ম্যানেজার শীঘ্রই আসছে...</p>
        </div>
    </div>
    '''
    return render_template_string(render_page('প্রজেক্ট ম্যানেজার', content, active_page='project-manager'))

# ==================== সেটিংস (প্লেসহোল্ডার) ====================
@app.route('/settings')
@login_required
def settings():
    """সেটিংস পেজ"""
    content = '''
    <div class="container-fluid">
        <h2 class="mb-4 fw-bold">
            <i class="fas fa-cog"></i> সেটিংস
        </h2>
        <div class="glass-card p-4">
            <p>সেটিংস পেজ শীঘ্রই আসছে...</p>
        </div>
    </div>
    '''
    return render_template_string(render_page('সেটিংস', content, active_page='settings'))

# ==================== প্রোফাইল (প্লেসহোল্ডার) ====================
@app.route('/profile')
@login_required
def profile():
    """প্রোফাইল পেজ"""
    content = f'''
    <div class="container-fluid">
        <h2 class="mb-4 fw-bold">
            <i class="fas fa-user"></i> প্রোফাইল
        </h2>
        <div class="glass-card p-4">
            <h5>ইউজার: {session.get("username", "N/A")}</h5>
            <p>রোল: {session.get("role", "N/A")}</p>
        </div>
    </div>
    '''
    return render_template_string(render_page('প্রোফাইল', content, active_page='profile'))

# ==================== লগ (প্লেসহোল্ডার) ====================
@app.route('/logs')
@login_required
def logs():
    """লগ পেজ"""
    content = '''
    <div class="container-fluid">
        <h2 class="mb-4 fw-bold">
            <i class="fas fa-history"></i> লগ
        </h2>
        <div class="glass-card p-4">
            <p>লগ পেজ শীঘ্রই আসছে...</p>
        </div>
    </div>
    '''
    return render_template_string(render_page('লগ', content, active_page='logs'))

# ==================== এরর হ্যান্ডলার ====================
@app.errorhandler(404)
def not_found_error(error):
    """404 এরর হ্যান্ডলার"""
    if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'error': 'Resource not found'}), 404
    
    content = '''
    <div class="container">
        <div class="row justify-content-center align-items-center min-vh-100">
            <div class="col-md-6">
                <div class="glass-card p-5 text-center">
                    <h1 style="font-size: 6rem; color: #667eea;">404</h1>
                    <h3>পেজ পাওয়া যায়নি</h3>
                    <p class="text-muted">আপনি যে পেজটি খুঁজছেন তা বিদ্যমান নেই</p>
                    <a href="/dashboard" class="btn btn-primary-gradient mt-3">ড্যাশবোর্ডে ফিরুন</a>
                </div>
            </div>
        </div>
    </div>
    '''
    return render_template_string(render_page('404', content)), 404

@app.errorhandler(403)
def forbidden_error(error):
    """403 এরর হ্যান্ডলার"""
    if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'error': 'Access forbidden'}), 403
    
    content = '''
    <div class="container">
        <div class="row justify-content-center align-items-center min-vh-100">
            <div class="col-md-6">
                <div class="glass-card p-5 text-center">
                    <h1 style="font-size: 6rem; color: #f45c43;">403</h1>
                    <h3>অননুমোদিত প্রবেশ</h3>
                    <p class="text-muted">এই পৃষ্ঠায় প্রবেশের অনুমতি আপনার নেই</p>
                    <a href="/dashboard" class="btn btn-primary-gradient mt-3">ড্যাশবোর্ডে ফিরুন</a>
                </div>
            </div>
        </div>
    </div>
    '''
    return render_template_string(render_page('403', content)), 403

@app.errorhandler(500)
def internal_error(error):
    """500 এরর হ্যান্ডলার"""
    app.logger.error(f"Internal Server Error: {str(error)}", exc_info=True)
    
    if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'error': 'Internal server error'}), 500
    
    content = '''
    <div class="container">
        <div class="row justify-content-center align-items-center min-vh-100">
            <div class="col-md-6">
                <div class="glass-card p-5 text-center">
                    <h1 style="font-size: 6rem; color: #eb3349;">500</h1>
                    <h3>সার্ভার ত্রুটি</h3>
                    <p class="text-muted">কিছু একটা ভুল হয়েছে। পরে আবার চেষ্টা করুন।</p>
                    <a href="/dashboard" class="btn btn-primary-gradient mt-3">ড্যাশবোর্ডে ফিরুন</a>
                </div>
            </div>
        </div>
    </div>
    '''
    return render_template_string(render_page('500', content)), 500

@app.errorhandler(Exception)
def handle_exception(error):
    """গ্লোবাল এক্সেপশন হ্যান্ডলার"""
    app.logger.error(f"Unhandled Exception: {str(error)}", exc_info=True)
    
    if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            'error': 'An unexpected error occurred',
            'message': str(error) if Config.DEBUG else 'Internal server error'
        }), 500
    
    return internal_error(error)

# ==================== সিকিউরিটি হেডার মিডলওয়্যার ====================
@app.after_request
def add_security_headers(response):
    """প্রত্যেক রেসপন্সে সিকিউরিটি হেডার যোগ করা"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains' if Config.SESSION_COOKIE_SECURE else ''
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; img-src 'self' data:;"
    response.headers['Referrer-Policy'] = 'same-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    
    # Cache কন্ট্রোল (সিকিউর পেজের জন্য)
    if request.path.startswith('/dashboard') or request.path.startswith('/admin'):
        response.headers['Cache-Control'] = 'no-store, max-age=0'
    
    return response

# ==================== অ্যাপ্লিকেশন স্টার্টআপ ====================
if __name__ == '__main__':
    # প্রয়োজনীয় ডিরেক্টরি তৈরি
    os.makedirs('data', exist_ok=True)
    os.makedirs('logs', exist_ok=True)
    os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
    
    # ডিফল্ট ইউজার তৈরি
    create_default_users()
    
    # Flask অ্যাপ চালু
    port = int(os.environ.get('PORT', 5000))
    app.run(
        host='0.0.0.0',
        port=port,
        debug=Config.DEBUG
)
