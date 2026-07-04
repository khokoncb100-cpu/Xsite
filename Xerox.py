#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
লাইভ হোস্টিং প্যানেল - একক ফাইল Flask অ্যাপ্লিকেশন
SearXNG মেটা সার্চ ইঞ্জিন • ফাইল ম্যানেজার • অটো জিপ এক্সট্রাক্ট
Production Quality • Secure • Professional
"""

# ==================== প্রয়োজনীয় লাইব্রেরি ইম্পোর্ট ====================
import os
import sys
import json
import time
import hashlib
import secrets
import subprocess
import psutil
import platform
import zipfile
import tarfile
import shutil
import requests
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
    make_response, flash, send_from_directory, Response
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
import uuid
import html

# ==================== অ্যাপ্লিকেশন কনফিগারেশন ====================
class Config:
    """অ্যাপ্লিকেশন কনফিগারেশন ক্লাস - প্রোডাকশন রেডি"""
    
    # সিকিউরিটি কী
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(64)
    
    # সেশন কনফিগারেশন
    SESSION_COOKIE_SECURE = bool(os.environ.get('RENDER'))
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_NAME = '__Host-session' if SESSION_COOKIE_SECURE else 'session'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    
    # ফাইল আপলোড
    MAX_CONTENT_LENGTH = 500 * 1024 * 1024  # 500MB
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'uploads')
    ALLOWED_EXTENSIONS = {
        'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'svg',
        'py', 'js', 'html', 'css', 'json', 'xml', 'md',
        'zip', 'tar', 'gz', 'rar', '7z', 'bz2', 'xz',
        'mp4', 'mp3', 'wav', 'webm',
        'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
        'csv', 'log', 'ini', 'cfg', 'conf'
    }
    
    # বেস ডিরেক্টরি
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    
    # SearXNG কনফিগ
    SEARXNG_PORT = int(os.environ.get('SEARXNG_PORT', 8888))
    SEARXNG_DIR = os.path.join(BASE_DIR, 'searxng')
    
    # প্রোডাকশন মোড
    @staticmethod
    def is_production():
        return bool(os.environ.get('RENDER') or os.environ.get('PRODUCTION'))
    
    DEBUG = not is_production.__func__()

# ==================== Flask অ্যাপ ইনিশিয়ালাইজেশন ====================
app = Flask(__name__)
app.config.from_object(Config)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# ==================== লগিং সেটআপ ====================
if not os.path.exists('logs'):
    os.makedirs('logs')

general_handler = RotatingFileHandler('logs/hosting_panel.log', maxBytes=10485760, backupCount=10)
general_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s'))
general_handler.setLevel(logging.INFO)

error_handler = RotatingFileHandler('logs/error.log', maxBytes=10485760, backupCount=10)
error_handler.setFormatter(logging.Formatter('%(asctime)s ERROR: %(message)s'))
error_handler.setLevel(logging.ERROR)

app.logger.addHandler(general_handler)
app.logger.addHandler(error_handler)
app.logger.setLevel(logging.INFO)

# ==================== ইউটিলিটি ফাংশন ====================
def sanitize_input(input_string):
    """ইনপুট স্যানিটাইজেশন"""
    if input_string is None:
        return None
    return html.escape(str(input_string).strip())

def validate_path(user_path, base_path=None):
    """পাথ ট্রাভার্সাল প্রতিরোধ"""
    if base_path is None:
        base_path = os.path.abspath(Config.UPLOAD_FOLDER)
    safe_path = os.path.abspath(os.path.join(base_path, user_path))
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
        abort(403)
    return True

def get_system_info():
    """সিস্টেম তথ্য সংগ্রহ"""
    try:
        cpu_percent = psutil.cpu_percent(interval=0.5)
        cpu_count = psutil.cpu_count()
        cpu_freq = psutil.cpu_freq()
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        disk = psutil.disk_usage('/')
        disk_io = psutil.disk_io_counters()
        net_io = psutil.net_io_counters()
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
            'uptime_formatted': format_uptime(uptime_seconds),
            'running_apps': get_running_applications()
        }
    except Exception as e:
        app.logger.error(f"সিস্টেম তথ্য সংগ্রহে ত্রুটি: {str(e)}")
        return {}

def format_uptime(seconds):
    """আপটাইম ফরম্যাটিং"""
    days, remainder = divmod(int(seconds), 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    parts = []
    if days > 0: parts.append(f"{days}দিন")
    if hours > 0: parts.append(f"{hours}ঘণ্টা")
    if minutes > 0: parts.append(f"{minutes}মিনিট")
    parts.append(f"{seconds}সেকেন্ড")
    return " ".join(parts[:3])

def get_running_applications():
    """চলমান অ্যাপ্লিকেশন তালিকা"""
    try:
        apps = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status', 'username']):
            try:
                pinfo = proc.info
                if pinfo['cpu_percent'] > 0 or pinfo['memory_percent'] > 0.5:
                    apps.append({
                        'pid': pinfo['pid'],
                        'name': pinfo['name'],
                        'cpu': f"{pinfo['cpu_percent']:.1f}%",
                        'memory': f"{pinfo['memory_percent']:.1f}%",
                        'status': pinfo['status'],
                        'username': pinfo.get('username', 'N/A')
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return sorted(apps, key=lambda x: float(x['cpu'].rstrip('%')), reverse=True)[:15]
    except Exception as e:
        app.logger.error(f"অ্যাপ্লিকেশন তালিকা সংগ্রহে ত্রুটি: {str(e)}")
        return []

def extract_archive(file_path, extract_to=None):
    """জিপ/টার ফাইল এক্সট্রাক্ট"""
    if extract_to is None:
        extract_to = os.path.dirname(file_path)
    
    try:
        if zipfile.is_zipfile(file_path):
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(extract_to)
            return True, "জিপ ফাইল সফলভাবে এক্সট্রাক্ট হয়েছে"
        
        elif tarfile.is_tarfile(file_path):
            with tarfile.open(file_path, 'r:*') as tar_ref:
                tar_ref.extractall(extract_to)
            return True, "টার ফাইল সফলভাবে এক্সট্রাক্ট হয়েছে"
        
        else:
            return False, "ফাইলটি আর্কাইভ নয়"
            
    except Exception as e:
        return False, f"এক্সট্রাক্ট করতে সমস্যা: {str(e)}"

# ==================== SearXNG ম্যানেজমেন্ট ====================
class SearXNGManager:
    """SearXNG মেটা সার্চ ইঞ্জিন ম্যানেজার"""
    
    @staticmethod
    def check_installation():
        """SearXNG ইন্সটলেশন চেক"""
        searxng_dir = Config.SEARXNG_DIR
        return os.path.exists(os.path.join(searxng_dir, 'searx')) or \
               os.path.exists(os.path.join(searxng_dir, 'searxng'))
    
    @staticmethod
    def check_running():
        """SearXNG চলছে কিনা চেক"""
        for proc in psutil.process_iter(['name', 'cmdline']):
            try:
                if 'searx' in proc.info['name'].lower() or \
                   any('searx' in cmd.lower() for cmd in (proc.info.get('cmdline') or [])):
                    return True, proc.info['pid']
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return False, None
    
    @staticmethod
    def install_searxng():
        """SearXNG ইন্সটল"""
        try:
            searxng_dir = Config.SEARXNG_DIR
            os.makedirs(searxng_dir, exist_ok=True)
            
            # পাইথন ভার্চুয়াল এনভায়রনমেন্ট তৈরি
            venv_dir = os.path.join(searxng_dir, 'venv')
            if not os.path.exists(venv_dir):
                subprocess.run([sys.executable, '-m', 'venv', venv_dir], check=True)
            
            # pip আপগ্রেড
            pip_path = os.path.join(venv_dir, 'bin', 'pip') if os.name != 'nt' else os.path.join(venv_dir, 'Scripts', 'pip.exe')
            subprocess.run([pip_path, 'install', '--upgrade', 'pip'], check=True)
            
            # SearXNG ইন্সটল
            subprocess.run([pip_path, 'install', 'searxng'], check=True)
            
            app.logger.info("SearXNG ইন্সটলেশন সফল")
            return True, "SearXNG সফলভাবে ইন্সটল হয়েছে"
            
        except subprocess.CalledProcessError as e:
            error_msg = f"SearXNG ইন্সটলেশন ব্যর্থ: {str(e)}"
            app.logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"SearXNG ইন্সটলেশন ত্রুটি: {str(e)}"
            app.logger.error(error_msg)
            return False, error_msg
    
    @staticmethod
    def start_searxng():
        """SearXNG শুরু"""
        try:
            running, pid = SearXNGManager.check_running()
            if running:
                return True, f"SearXNG ইতিমধ্যে চলছে (PID: {pid})"
            
            searxng_dir = Config.SEARXNG_DIR
            venv_python = os.path.join(searxng_dir, 'venv', 'bin', 'python3') if os.name != 'nt' else os.path.join(searxng_dir, 'venv', 'Scripts', 'python.exe')
            
            # কনফিগ ফাইল তৈরি
            config_dir = os.path.join(searxng_dir, 'config')
            os.makedirs(config_dir, exist_ok=True)
            
            settings_yml = os.path.join(config_dir, 'settings.yml')
            if not os.path.exists(settings_yml):
                with open(settings_yml, 'w') as f:
                    f.write(f"""# SearXNG Configuration
use_default_settings: true
server:
  secret_key: "{secrets.token_hex(32)}"
  bind_address: "0.0.0.0"
  port: {Config.SEARXNG_PORT}
  base_url: false
  image_proxy: true
  http_protocol_version: "1.1"
search:
  safe_search: 0
  autocomplete: ""
  default_lang: ""
  formats:
    - html
    - json
ui:
  static_use_hash: true
  default_theme: simple
  default_locale: en
""")
            
            # SearXNG রান
            log_file = os.path.join('logs', 'searxng.log')
            with open(log_file, 'w') as log:
                process = subprocess.Popen(
                    [venv_python, '-m', 'searxng', '--config', config_dir],
                    stdout=log,
                    stderr=log,
                    cwd=searxng_dir
                )
            
            time.sleep(3)  # স্টার্টআপের জন্য অপেক্ষা
            
            if SearXNGManager.check_running()[0]:
                app.logger.info(f"SearXNG শুরু হয়েছে PID: {process.pid}")
                return True, f"SearXNG শুরু হয়েছে (PID: {process.pid}, Port: {Config.SEARXNG_PORT})"
            else:
                return False, "SearXNG শুরু হতে ব্যর্থ হয়েছে"
                
        except Exception as e:
            error_msg = f"SearXNG শুরু করতে ত্রুটি: {str(e)}"
            app.logger.error(error_msg)
            return False, error_msg
    
    @staticmethod
    def stop_searxng():
        """SearXNG বন্ধ"""
        try:
            running, pid = SearXNGManager.check_running()
            if not running:
                return True, "SearXNG চলছে না"
            
            process = psutil.Process(pid)
            process.terminate()
            time.sleep(2)
            
            if process.is_running():
                process.kill()
            
            app.logger.info(f"SearXNG বন্ধ করা হয়েছে PID: {pid}")
            return True, "SearXNG বন্ধ করা হয়েছে"
            
        except Exception as e:
            error_msg = f"SearXNG বন্ধ করতে ত্রুটি: {str(e)}"
            app.logger.error(error_msg)
            return False, error_msg
    
    @staticmethod
    def restart_searxng():
        """SearXNG রিস্টার্ট"""
        SearXNGManager.stop_searxng()
        time.sleep(2)
        return SearXNGManager.start_searxng()
    
    @staticmethod
    def get_searxng_logs():
        """SearXNG লগ"""
        log_file = os.path.join('logs', 'searxng.log')
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                return f.read()[-5000:]  # শেষ 5000 ক্যারেক্টার
        return "কোনো লগ পাওয়া যায়নি"

# ==================== রেন্ডারিং হেল্পার ====================
def render_page(title, content, extra_css='', extra_js='', active_page=''):
    """সকল পেজ রেন্ডার করার ইউনিফাইড ফাংশন"""
    
    user_logged_in = 'user_id' in session
    csrf_token = generate_csrf_token() if user_logged_in else ''
    
    def is_active(page):
        return 'active' if page == active_page else ''
    
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
    
    full_html = f'''<!DOCTYPE html>
<html lang="bn" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>হোস্টিং প্যানেল - {title}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Hind+Siliguri:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --glass-bg: rgba(255, 255, 255, 0.05);
            --glass-border: rgba(255, 255, 255, 0.1);
            --glass-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.37);
            --primary-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --success-gradient: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
            --danger-gradient: linear-gradient(135deg, #eb3349 0%, #f45c43 100%);
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Hind Siliguri', sans-serif;
            background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
            min-height: 100vh; color: #fff; overflow-x: hidden;
        }}
        .glass-card {{
            background: var(--glass-bg); backdrop-filter: blur(10px);
            border: 1px solid var(--glass-border); border-radius: 20px;
            box-shadow: var(--glass-shadow); transition: all 0.3s ease;
        }}
        .glass-card:hover {{ transform: translateY(-5px); box-shadow: 0 12px 40px 0 rgba(31, 38, 135, 0.5); }}
        .glass-input {{
            background: rgba(255, 255, 255, 0.08); border: 1px solid rgba(255, 255, 255, 0.1);
            color: #fff; backdrop-filter: blur(5px);
        }}
        .glass-input:focus {{
            background: rgba(255, 255, 255, 0.12); border-color: rgba(255, 255, 255, 0.3);
            color: #fff; box-shadow: 0 0 0 0.25rem rgba(102, 126, 234, 0.25);
        }}
        .sidebar {{
            background: rgba(15, 12, 41, 0.8); backdrop-filter: blur(10px);
            border-right: 1px solid rgba(255, 255, 255, 0.1);
            min-height: 100vh; width: 280px; transition: all 0.3s;
        }}
        .nav-link {{
            color: rgba(255, 255, 255, 0.7); padding: 12px 20px; margin: 5px 15px;
            border-radius: 12px; transition: all 0.3s; text-decoration: none; display: block;
        }}
        .nav-link:hover, .nav-link.active {{
            background: var(--primary-gradient); color: #fff; transform: translateX(5px);
        }}
        .nav-link i {{ margin-right: 10px; width: 20px; }}
        .btn-glass {{
            background: var(--glass-bg); backdrop-filter: blur(5px);
            border: 1px solid var(--glass-border); color: #fff;
            padding: 10px 25px; border-radius: 12px; transition: all 0.3s;
        }}
        .btn-glass:hover {{ background: rgba(255, 255, 255, 0.15); transform: translateY(-2px); color: #fff; }}
        .btn-primary-gradient {{
            background: var(--primary-gradient); border: none; color: #fff;
            padding: 12px 30px; border-radius: 12px; font-weight: 600; transition: all 0.3s;
        }}
        .btn-primary-gradient:hover {{ transform: translateY(-2px); box-shadow: 0 10px 20px rgba(102, 126, 234, 0.4); }}
        .toast-container {{ position: fixed; top: 20px; right: 20px; z-index: 1060; }}
        .custom-toast {{
            background: var(--glass-bg); backdrop-filter: blur(20px);
            border: 1px solid var(--glass-border); color: #fff;
            border-radius: 15px; margin-bottom: 10px; animation: slideInRight 0.3s ease-out;
        }}
        @keyframes slideInRight {{
            from {{ transform: translateX(100%); opacity: 0; }}
            to {{ transform: translateX(0); opacity: 1; }}
        }}
        .loading-overlay {{
            display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0, 0, 0, 0.7); z-index: 9999;
            justify-content: center; align-items: center;
        }}
        .loading-spinner {{
            width: 60px; height: 60px; border: 4px solid rgba(255, 255, 255, 0.1);
            border-top: 4px solid #667eea; border-radius: 50%; animation: spin 1s linear infinite;
        }}
        @keyframes spin {{ 0% {{ transform: rotate(0deg); }} 100% {{ transform: rotate(360deg); }} }}
        @media (max-width: 768px) {{
            .sidebar {{ width: 100%; min-height: auto; position: relative; }}
            .glass-card {{ margin: 10px; }}
            .btn-primary-gradient {{ width: 100%; }}
        }}
        .search-box {{ position: relative; }}
        .search-box input {{ padding-left: 45px; }}
        .search-box .search-icon {{
            position: absolute; left: 15px; top: 50%;
            transform: translateY(-50%); color: rgba(255, 255, 255, 0.5);
        }}
        .status-indicator {{ width: 12px; height: 12px; border-radius: 50%; display: inline-block; animation: pulse 2s infinite; }}
        .status-active {{ background: #38ef7d; box-shadow: 0 0 10px #38ef7d; }}
        .status-inactive {{ background: #f45c43; box-shadow: 0 0 10px #f45c43; }}
        @keyframes pulse {{
            0% {{ transform: scale(1); }} 50% {{ transform: scale(1.1); }} 100% {{ transform: scale(1); }}
        }}
        .progress-glass {{ background: rgba(255, 255, 255, 0.1); border-radius: 20px; height: 12px; overflow: hidden; }}
        .progress-bar-glass {{
            background: var(--primary-gradient); border-radius: 20px; transition: width 0.3s ease;
        }}
        {extra_css}
    </style>
</head>
<body>
    <div class="loading-overlay" id="loadingOverlay">
        <div class="text-center">
            <div class="loading-spinner mb-3"></div>
            <p class="text-white">লোড হচ্ছে...</p>
        </div>
    </div>
    <div class="toast-container" id="toastContainer"></div>
    <div class="d-flex flex-wrap">
        {sidebar_html}
        <main class="flex-grow-1 p-4">{content}</main>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        const CSRF_TOKEN = '{csrf_token}';
        function getCsrfToken() {{ return CSRF_TOKEN || document.querySelector('[name="csrf_token"]')?.value || ''; }}
        function showToast(message, type = 'info') {{
            const toastContainer = document.getElementById('toastContainer');
            const toastId = 'toast-' + Date.now();
            const icons = {{
                success: '<i class="fas fa-check-circle text-success"></i>',
                error: '<i class="fas fa-times-circle text-danger"></i>',
                warning: '<i class="fas fa-exclamation-triangle text-warning"></i>',
                info: '<i class="fas fa-info-circle text-info"></i>'
            }};
            const toastHTML = `<div class="custom-toast p-3" id="${{toastId}}">
                <div class="d-flex justify-content-between align-items-center">
                    <div>${{icons[type] || icons.info}}<span class="ms-2">${{escapeHtml(message)}}</span></div>
                    <button class="btn-close btn-close-white" onclick="closeToast('${{toastId}}')"></button>
                </div></div>`;
            toastContainer.insertAdjacentHTML('beforeend', toastHTML);
            setTimeout(() => closeToast(toastId), 5000);
        }}
        function closeToast(toastId) {{
            const toast = document.getElementById(toastId);
            if (toast) {{ toast.style.animation = 'slideInRight 0.3s ease-out reverse'; setTimeout(() => toast.remove(), 300); }}
        }}
        function escapeHtml(text) {{
            const map = {{ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }};
            return String(text).replace(/[&<>"']/g, m => map[m]);
        }}
        let loadingTimeout;
        function showLoading() {{ clearTimeout(loadingTimeout); document.getElementById('loadingOverlay').style.display = 'flex'; }}
        function hideLoading() {{ loadingTimeout = setTimeout(() => document.getElementById('loadingOverlay').style.display = 'none', 500); }}
        async function fetchAPI(url, options = {{}}) {{
            try {{
                const headers = {{ 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest', 'X-CSRF-Token': getCsrfToken(), ...options.headers }};
                const response = await fetch(url, {{ ...options, headers }});
                if (response.status === 401) {{ window.location.href = '/login'; return; }}
                if (response.status === 403) {{ showToast('অনুমতি নেই', 'error'); return; }}
                const data = await response.json();
                if (!response.ok) throw new Error(data.message || data.error || 'অজানা ত্রুটি');
                return data;
            }} catch (error) {{ showToast(error.message, 'error'); throw error; }}
        }}
        async function confirmAction(message) {{ return confirm(message); }}
        function toggleDarkMode() {{
            const html = document.documentElement;
            const currentTheme = html.getAttribute('data-bs-theme');
            html.setAttribute('data-bs-theme', currentTheme === 'dark' ? 'light' : 'dark');
            localStorage.setItem('theme', currentTheme === 'dark' ? 'light' : 'dark');
        }}
        document.addEventListener('DOMContentLoaded', () => {{
            document.documentElement.setAttribute('data-bs-theme', localStorage.getItem('theme') || 'dark');
        }});
        {extra_js}
    </script>
</body>
</html>'''
    
    return full_html

# ==================== রাউটস ====================
@app.route('/')
def index():
    """হোম পেজ - সরাসরি ড্যাশবোর্ডে"""
    session['user_id'] = 'guest'
    session['username'] = 'User'
    session['role'] = 'admin'
    session['last_activity'] = datetime.now().isoformat()
    session.permanent = True
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    """ড্যাশবোর্ড পেজ"""
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    system_info = get_system_info()
    running_apps = system_info.get('running_apps', [])
    
    apps_rows = ''
    for app in running_apps:
        status_class = 'status-active' if app.get('status') == 'running' else 'status-inactive'
        apps_rows += f'''
        <tr>
            <td><span class="badge bg-secondary">{app.get('pid', 'N/A')}</span></td>
            <td>{app.get('name', 'N/A')}</td>
            <td><span class="badge bg-primary">{app.get('cpu', 'N/A')}</span></td>
            <td><span class="badge bg-success">{app.get('memory', 'N/A')}</span></td>
            <td><span class="status-indicator {status_class}"></span> {app.get('status', 'N/A')}</td>
            <td>{app.get('username', 'N/A')}</td>
            <td><button class="btn btn-sm btn-glass" onclick="manageApp('{app.get('pid', '')}')"><i class="fas fa-cog"></i></button></td>
        </tr>'''
    
    content = f'''<div class="container-fluid">
        <h2 class="mb-4 fw-bold"><i class="fas fa-tachometer-alt"></i> ড্যাশবোর্ড</h2>
        <div class="row mb-4">
            <div class="col-md-3 mb-3">
                <div class="glass-card p-4 text-center">
                    <i class="fas fa-microchip fa-2x mb-2" style="color: #667eea;"></i>
                    <h5>CPU ব্যবহার</h5>
                    <h3 class="fw-bold">{system_info.get('cpu_usage', 0)}%</h3>
                    <small>{system_info.get('cpu_count', 'N/A')} কোর | {system_info.get('cpu_freq_current', 'N/A')}</small>
                    <div class="progress-glass mt-2"><div class="progress-bar-glass" style="width: {system_info.get('cpu_usage', 0)}%"></div></div>
                </div>
            </div>
            <div class="col-md-3 mb-3">
                <div class="glass-card p-4 text-center">
                    <i class="fas fa-memory fa-2x mb-2" style="color: #11998e;"></i>
                    <h5>RAM ব্যবহার</h5>
                    <h3 class="fw-bold">{system_info.get('ram_percent', 0)}%</h3>
                    <small>{system_info.get('used_ram', 'N/A')} / {system_info.get('total_ram', 'N/A')}</small>
                    <div class="progress-glass mt-2"><div class="progress-bar-glass" style="width: {system_info.get('ram_percent', 0)}%"></div></div>
                </div>
            </div>
            <div class="col-md-3 mb-3">
                <div class="glass-card p-4 text-center">
                    <i class="fas fa-hdd fa-2x mb-2" style="color: #f45c43;"></i>
                    <h5>স্টোরেজ</h5>
                    <h3 class="fw-bold">{system_info.get('storage_percent', 0)}%</h3>
                    <small>{system_info.get('used_storage', 'N/A')} / {system_info.get('total_storage', 'N/A')}</small>
                    <div class="progress-glass mt-2"><div class="progress-bar-glass" style="width: {system_info.get('storage_percent', 0)}%"></div></div>
                </div>
            </div>
            <div class="col-md-3 mb-3">
                <div class="glass-card p-4 text-center">
                    <i class="fas fa-clock fa-2x mb-2" style="color: #764ba2;"></i>
                    <h5>সার্ভার আপটাইম</h5>
                    <h3 class="fw-bold">{system_info.get('uptime_formatted', 'N/A')}</h3>
                    <small>{system_info.get('hostname', 'N/A')}</small>
                </div>
            </div>
        </div>
        <div class="row mb-4">
            <div class="col-md-4 mb-3"><div class="glass-card p-4"><h6><i class="fas fa-network-wired"></i> নেটওয়ার্ক</h6><p class="mb-1">প্রেরিত: <strong>{system_info.get('network_sent', 'N/A')}</strong></p><p class="mb-0">গৃহীত: <strong>{system_info.get('network_recv', 'N/A')}</strong></p></div></div>
            <div class="col-md-4 mb-3"><div class="glass-card p-4"><h6><i class="fas fa-exchange-alt"></i> ডিস্ক I/O</h6><p class="mb-1">পড়া: <strong>{system_info.get('disk_read_bytes', 'N/A')}</strong></p><p class="mb-0">লেখা: <strong>{system_info.get('disk_write_bytes', 'N/A')}</strong></p></div></div>
            <div class="col-md-4 mb-3"><div class="glass-card p-4"><h6><i class="fas fa-memory"></i> সোয়াপ</h6><p class="mb-1">ব্যবহৃত: <strong>{system_info.get('swap_used', 'N/A')}</strong></p><p class="mb-0">মোট: <strong>{system_info.get('swap_total', 'N/A')}</strong></p></div></div>
        </div>
        <div class="glass-card p-4 mb-4">
            <div class="d-flex justify-content-between align-items-center mb-3">
                <h4><i class="fas fa-play-circle"></i> চলমান অ্যাপ্লিকেশন</h4>
                <button class="btn btn-glass btn-sm" onclick="refreshApps()"><i class="fas fa-sync-alt"></i> রিফ্রেশ</button>
            </div>
            <div class="table-responsive">
                <table class="table table-dark table-hover">
                    <thead><tr><th>PID</th><th>নাম</th><th>CPU</th><th>RAM</th><th>স্ট্যাটাস</th><th>ইউজার</th><th>অ্যাকশন</th></tr></thead>
                    <tbody>{apps_rows}</tbody>
                </table>
            </div>
        </div>
    </div>'''
    
    extra_js = '''function refreshApps() { showToast('রিফ্রেশ হচ্ছে...', 'info'); location.reload(); }
    function manageApp(pid) { showToast('PID ' + pid + ' ম্যানেজ করা হচ্ছে...', 'info'); }'''
    
    return render_template_string(render_page('ড্যাশবোর্ড', content, extra_js=extra_js, active_page='dashboard'))

@app.route('/logout')
def logout():
    """লগআউট"""
    session.clear()
    return redirect(url_for('index'))

# ==================== ফাইল ম্যানেজার ====================
@app.route('/file-manager')
def file_manager():
    """ফাইল ম্যানেজার পেজ"""
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    current_path = request.args.get('path', '')
    try:
        base_path = os.path.abspath(Config.UPLOAD_FOLDER)
        target_path = validate_path(current_path) if current_path else base_path
        os.makedirs(target_path, exist_ok=True)
        
        items = []
        for item in os.listdir(target_path):
            item_path = os.path.join(target_path, item)
            item_stat = os.stat(item_path)
            items.append({
                'name': item,
                'path': os.path.relpath(item_path, base_path),
                'is_dir': os.path.isdir(item_path),
                'size': item_stat.st_size,
                'modified': datetime.fromtimestamp(item_stat.st_mtime).strftime('%Y-%m-%d %H:%M'),
                'permissions': oct(item_stat.st_mode)[-3:]
            })
        
        items.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))
        
    except Exception as e:
        app.logger.error(f"ফাইল ম্যানেজার ত্রুটি: {str(e)}")
        items = []
    
    file_rows = ''
    for item in items:
        icon = 'fa-folder text-warning' if item['is_dir'] else 'fa-file text-info'
        file_rows += f'''<tr class="file-row" data-name="{item['name']}">
            <td><i class="fas {icon}"></i> {item['name']}</td>
            <td>{item['size']}</td>
            <td>{item['modified']}</td>
            <td>{item['permissions']}</td>
            <td><div class="btn-group btn-group-sm">'''
        
        if item['is_dir']:
            file_rows += f'''<button class="btn btn-glass" onclick="openFolder('{item['path']}')"><i class="fas fa-folder-open"></i></button>'''
        else:
            file_rows += f'''<button class="btn btn-glass" onclick="downloadFile('{item['path']}')"><i class="fas fa-download"></i></button>
            <button class="btn btn-glass" onclick="editFile('{item['path']}')"><i class="fas fa-edit"></i></button>'''
        
        file_rows += f'''<button class="btn btn-glass" onclick="renameItem('{item['path']}')"><i class="fas fa-pencil-alt"></i></button>
        <button class="btn btn-glass text-danger" onclick="deleteItem('{item['path']}')"><i class="fas fa-trash"></i></button></div></td></tr>'''
    
    content = f'''<div class="container-fluid">
        <h2 class="mb-4 fw-bold"><i class="fas fa-folder"></i> ফাইল ম্যানেজার</h2>
        <div class="glass-card p-3 mb-4">
            <div class="row align-items-center">
                <div class="col-md-6">
                    <div class="btn-group">
                        <button class="btn btn-glass btn-sm" onclick="createFolder()"><i class="fas fa-folder-plus"></i> নতুন ফোল্ডার</button>
                        <button class="btn btn-glass btn-sm" onclick="uploadFile()"><i class="fas fa-upload"></i> আপলোড</button>
                        <button class="btn btn-glass btn-sm" onclick="createFile()"><i class="fas fa-file-plus"></i> নতুন ফাইল</button>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="search-box">
                        <span class="search-icon"><i class="fas fa-search"></i></span>
                        <input type="text" class="form-control glass-input" placeholder="ফাইল সার্চ করুন..." id="searchInput" onkeyup="searchFiles()">
                    </div>
                </div>
            </div>
        </div>
        <div class="glass-card p-3">
            <div class="table-responsive">
                <table class="table table-dark table-hover">
                    <thead><tr><th>নাম</th><th>সাইজ</th><th>পরিবর্তিত</th><th>পারমিশন</th><th>অ্যাকশন</th></tr></thead>
                    <tbody id="fileList">{file_rows}</tbody>
                </table>
            </div>
        </div>
    </div>
    <input type="file" id="fileUploadInput" style="display: none" multiple onchange="handleFileUpload(event)">'''
    
    extra_js = '''
    function searchFiles() {
        const searchTerm = document.getElementById('searchInput').value.toLowerCase();
        document.querySelectorAll('.file-row').forEach(row => {
            row.style.display = row.getAttribute('data-name').toLowerCase().includes(searchTerm) ? '' : 'none';
        });
    }
    function uploadFile() { document.getElementById('fileUploadInput').click(); }
    async function handleFileUpload(event) {
        const files = event.target.files;
        if (!files.length) return;
        const formData = new FormData();
        for (let file of files) { formData.append('files', file); }
        formData.append('csrf_token', getCsrfToken());
        showLoading();
        try {
            const response = await fetch('/api/upload', { method: 'POST', body: formData, headers: { 'X-CSRF-Token': getCsrfToken() } });
            const data = await response.json();
            if (data.success) { showToast(data.message, 'success'); if (data.extracted) showToast(data.extract_message, 'info'); location.reload(); }
            else showToast(data.message, 'error');
        } catch (error) { showToast('আপলোড ব্যর্থ: ' + error.message, 'error'); }
        finally { hideLoading(); event.target.value = ''; }
    }
    function openFolder(path) { window.location.href = '/file-manager?path=' + encodeURIComponent(path); }
    function downloadFile(path) { window.location.href = '/api/download?path=' + encodeURIComponent(path); }
    async function deleteItem(path) {
        if (!await confirmAction('মুছে ফেলতে চান?')) return;
        showLoading();
        try { const r = await fetchAPI('/api/delete', { method: 'POST', body: JSON.stringify({ path }) }); if (r.success) { showToast('মুছে ফেলা সফল!', 'success'); location.reload(); } }
        finally { hideLoading(); }
    }
    function createFolder() { const n = prompt('ফোল্ডারের নাম:'); if (!n) return; fetchAPI('/api/create-folder', { method: 'POST', body: JSON.stringify({ name: n }) }).then(() => location.reload()); }
    function createFile() { const n = prompt('ফাইলের নাম:'); if (!n) return; fetchAPI('/api/create-file', { method: 'POST', body: JSON.stringify({ name: n }) }).then(() => location.reload()); }
    function renameItem(oldPath) { const n = prompt('নতুন নাম:'); if (!n) return; fetchAPI('/api/rename', { method: 'POST', body: JSON.stringify({ old_path: oldPath, new_name: n }) }).then(() => location.reload()); }
    function editFile(path) { window.location.href = '/file-editor?path=' + encodeURIComponent(path); }
    '''
    
    return render_template_string(render_page('ফাইল ম্যানেজার', content, extra_js=extra_js, active_page='file-manager'))

# ==================== ফাইল API ====================
@app.route('/api/upload', methods=['POST'])
def api_upload():
    """ফাইল আপলোড API (অটো জিপ এক্সট্রাক্ট সহ)"""
    try:
        csrf_token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
        validate_csrf_token(csrf_token)
        
        if 'files' not in request.files:
            return jsonify({'success': False, 'message': 'কোনো ফাইল নির্বাচন করা হয়নি'}), 400
        
        files = request.files.getlist('files')
        uploaded_files = []
        extracted = False
        extract_message = ''
        
        for file in files:
            if file.filename == '':
                continue
            
            if not is_allowed_file(file.filename):
                return jsonify({'success': False, 'message': f'অননুমোদিত ফাইল টাইপ: {file.filename}'}), 400
            
            filename = secure_filename(file.filename)
            filepath = os.path.join(Config.UPLOAD_FOLDER, filename)
            file.save(filepath)
            uploaded_files.append(filename)
            
            # অটো এক্সট্রাক্ট চেক
            ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
            archive_formats = ['zip', 'tar', 'gz', 'bz2', 'xz', '7z', 'rar']
            
            if ext in archive_formats:
                success, message = extract_archive(filepath)
                if success:
                    extracted = True
                    extract_message = message
                    # আর্কাইভ ফাইল ডিলিট (অপশনাল)
                    try:
                        os.remove(filepath)
                    except:
                        pass
        
        response_data = {
            'success': True,
            'message': f'{len(uploaded_files)} টি ফাইল আপলোড সফল!',
            'files': uploaded_files
        }
        
        if extracted:
            response_data['extracted'] = True
            response_data['extract_message'] = extract_message
        
        return jsonify(response_data)
        
    except Exception as e:
        app.logger.error(f'আপলোড ত্রুটি: {str(e)}')
        return jsonify({'success': False, 'message': 'আপলোড ব্যর্থ'}), 500

@app.route('/api/download')
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
            shutil.rmtree(safe_path)
        else:
            os.remove(safe_path)
        return jsonify({'success': True, 'message': 'মুছে ফেলা সফল!'})
    except Exception as e:
        return jsonify({'success': False, 'message': 'মুছে ফেলা ব্যর্থ'}), 500

@app.route('/api/create-folder', methods=['POST'])
def api_create_folder():
    """ফোল্ডার তৈরি API"""
    try:
        data = request.get_json()
        validate_csrf_token(request.headers.get('X-CSRF-Token'))
        name = data.get('name')
        if not name:
            return jsonify({'success': False, 'message': 'নাম প্রয়োজন'}), 400
        safe_name = secure_filename(name)
        os.makedirs(os.path.join(Config.UPLOAD_FOLDER, safe_name), exist_ok=True)
        return jsonify({'success': True, 'message': 'ফোল্ডার তৈরি সফল!'})
    except Exception as e:
        return jsonify({'success': False, 'message': 'ফোল্ডার তৈরি ব্যর্থ'}), 500

@app.route('/api/create-file', methods=['POST'])
def api_create_file():
    """ফাইল তৈরি API"""
    try:
        data = request.get_json()
        validate_csrf_token(request.headers.get('X-CSRF-Token'))
        name = data.get('name')
        if not name:
            return jsonify({'success': False, 'message': 'নাম প্রয়োজন'}), 400
        safe_name = secure_filename(name)
        open(os.path.join(Config.UPLOAD_FOLDER, safe_name), 'w').close()
        return jsonify({'success': True, 'message': 'ফাইল তৈরি সফল!'})
    except Exception as e:
        return jsonify({'success': False, 'message': 'ফাইল তৈরি ব্যর্থ'}), 500

@app.route('/api/rename', methods=['POST'])
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
        new_path = os.path.join(os.path.dirname(safe_old_path), safe_new_name)
        os.rename(safe_old_path, new_path)
        return jsonify({'success': True, 'message': 'নাম পরিবর্তন সফল!'})
    except Exception as e:
        return jsonify({'success': False, 'message': 'নাম পরিবর্তন ব্যর্থ'}), 500

# ==================== ফাইল এডিটর ====================
@app.route('/file-editor')
def file_editor():
    """ফাইল এডিটর পেজ"""
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    path = request.args.get('path', '')
    content = ''
    try:
        safe_path = validate_path(path)
        if os.path.exists(safe_path) and not os.path.isdir(safe_path):
            with open(safe_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
    except:
        content = ''
    
    page_content = f'''<div class="container-fluid">
        <h2 class="mb-4 fw-bold"><i class="fas fa-edit"></i> ফাইল এডিটর</h2>
        <div class="glass-card p-3 mb-3">
            <div class="d-flex justify-content-between align-items-center">
                <h5 id="filePath">{path}</h5>
                <div>
                    <button class="btn btn-primary-gradient btn-sm" onclick="saveFile()"><i class="fas fa-save"></i> সেভ</button>
                    <a href="/file-manager" class="btn btn-glass btn-sm"><i class="fas fa-arrow-left"></i> ফিরুন</a>
                </div>
            </div>
        </div>
        <div class="glass-card p-3">
            <textarea id="editor" class="form-control glass-input" style="min-height: 500px; font-family: monospace;">{html.escape(content)}</textarea>
        </div>
    </div>'''
    
    extra_js = f'''
    async function saveFile() {{
        const content = document.getElementById('editor').value;
        const path = document.getElementById('filePath').textContent;
        showLoading();
        try {{
            const r = await fetchAPI('/api/save-file', {{ method: 'POST', body: JSON.stringify({{ path, content }}) }});
            if (r.success) showToast('ফাইল সেভ হয়েছে!', 'success');
        }} finally {{ hideLoading(); }}
    }}
    document.addEventListener('keydown', (e) => {{ if (e.ctrlKey && e.key === 's') {{ e.preventDefault(); saveFile(); }} }});
    '''
    
    return render_template_string(render_page('ফাইল এডিটর', page_content, extra_js=extra_js, active_page='file-manager'))

@app.route('/api/save-file', methods=['POST'])
def api_save_file():
    """ফাইল সেভ API"""
    try:
        data = request.get_json()
        validate_csrf_token(request.headers.get('X-CSRF-Token'))
        path = data.get('path')
        content = data.get('content', '')
        if not path:
            return jsonify({'success': False, 'message': 'পাথ প্রয়োজন'}), 400
        safe_path = validate_path(path)
        with open(safe_path, 'w', encoding='utf-8') as f:
            f.write(content)
        return jsonify({'success': True, 'message': 'ফাইল সেভ সফল!'})
    except Exception as e:
        return jsonify({'success': False, 'message': 'সেভ ব্যর্থ'}), 500

# ==================== SearXNG পেজ ====================
@app.route('/searxng')
def searxng_page():
    """SearXNG ম্যানেজমেন্ট পেজ"""
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    installed = SearXNGManager.check_installation()
    running, pid = SearXNGManager.check_running()
    
    content = f'''<div class="container-fluid">
        <h2 class="mb-4 fw-bold"><i class="fas fa-search"></i> SearXNG ম্যানেজার</h2>
        <div class="row">
            <div class="col-md-6 mb-3">
                <div class="glass-card p-4">
                    <h5><i class="fas fa-info-circle"></i> স্ট্যাটাস</h5>
                    <p>ইন্সটলেশন: <span class="badge bg-{'success' if installed else 'danger'}">{'ইন্সটল করা আছে' if installed else 'ইন্সটল করা নেই'}</span></p>
                    <p>রানিং: <span class="badge bg-{'success' if running else 'warning'}">{'চলছে (PID: ' + str(pid) + ')' if running else 'বন্ধ আছে'}</span></p>
                    <button class="btn btn-primary-gradient mt-2" onclick="location.reload()"><i class="fas fa-sync-alt"></i> রিফ্রেশ</button>
                </div>
            </div>
            <div class="col-md-6 mb-3">
                <div class="glass-card p-4">
                    <h5><i class="fas fa-cog"></i> কন্ট্রোল</h5>
                    <div class="d-grid gap-2">
                        <button class="btn btn-success" onclick="controlSearXNG('install')"><i class="fas fa-download"></i> ইন্সটল/আপডেট</button>
                        <button class="btn btn-primary" onclick="controlSearXNG('start')"><i class="fas fa-play"></i> স্টার্ট</button>
                        <button class="btn btn-warning" onclick="controlSearXNG('stop')"><i class="fas fa-stop"></i> স্টপ</button>
                        <button class="btn btn-info" onclick="controlSearXNG('restart')"><i class="fas fa-redo"></i> রিস্টার্ট</button>
                    </div>
                    <div class="mt-3">
                        <label class="form-label">SearXNG লোকাল URL:</label>
                        <div class="input-group">
                            <input type="text" class="form-control glass-input" value="http://localhost:{Config.SEARXNG_PORT}" readonly id="searxngUrl">
                            <button class="btn btn-glass" onclick="copyUrl()"><i class="fas fa-copy"></i></button>
                            <a href="http://localhost:{Config.SEARXNG_PORT}" target="_blank" class="btn btn-glass"><i class="fas fa-external-link-alt"></i></a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <div class="glass-card p-4 mt-3">
            <div class="d-flex justify-content-between align-items-center mb-3">
                <h5><i class="fas fa-terminal"></i> লগ</h5>
                <button class="btn btn-glass btn-sm" onclick="loadLogs()"><i class="fas fa-sync-alt"></i> রিফ্রেশ</button>
            </div>
            <pre id="searxngLogs" style="max-height: 400px; overflow-y: auto; background: rgba(0,0,0,0.3); padding: 15px; border-radius: 10px;">লোড হচ্ছে...</pre>
        </div>
    </div>'''
    
    extra_js = '''
    function controlSearXNG(action) {
        if (!confirm('SearXNG ' + action + ' করতে চান?')) return;
        showLoading();
        fetchAPI('/api/searxng/control', { method: 'POST', body: JSON.stringify({ action }) })
            .then(data => { showToast(data.message, 'success'); setTimeout(() => location.reload(), 2000); })
            .finally(() => hideLoading());
    }
    function loadLogs() {
        fetchAPI('/api/searxng/logs').then(data => document.getElementById('searxngLogs').textContent = data.logs);
    }
    function copyUrl() {
        const url = document.getElementById('searxngUrl');
        url.select(); document.execCommand('copy');
        showToast('URL কপি করা হয়েছে!', 'success');
    }
    document.addEventListener('DOMContentLoaded', loadLogs);
    '''
    
    return render_template_string(render_page('SearXNG', content, extra_js=extra_js, active_page='searxng'))

@app.route('/api/searxng/status')
def searxng_status_api():
    """SearXNG স্ট্যাটাস API"""
    installed = SearXNGManager.check_installation()
    running, pid = SearXNGManager.check_running()
    return jsonify({'installed': installed, 'running': running, 'pid': pid})

@app.route('/api/searxng/control', methods=['POST'])
def searxng_control_api():
    """SearXNG কন্ট্রোল API"""
    try:
        data = request.get_json()
        action = data.get('action')
        
        if action == 'install':
            success, message = SearXNGManager.install_searxng()
        elif action == 'start':
            success, message = SearXNGManager.start_searxng()
        elif action == 'stop':
            success, message = SearXNGManager.stop_searxng()
        elif action == 'restart':
            success, message = SearXNGManager.restart_searxng()
        else:
            return jsonify({'success': False, 'message': 'অজানা অ্যাকশন'}), 400
        
        return jsonify({'success': success, 'message': message})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/searxng/logs')
def searxng_logs_api():
    """SearXNG লগ API"""
    return jsonify({'logs': SearXNGManager.get_searxng_logs()})

# ==================== অন্যান্য পেজ ====================
@app.route('/project-manager')
def project_manager():
    """প্রজেক্ট ম্যানেজার"""
    if 'user_id' not in session:
        return redirect(url_for('index'))
    content = '<div class="glass-card p-4"><h5>প্রজেক্ট ম্যানেজার</h5><p>শীঘ্রই আসছে...</p></div>'
    return render_template_string(render_page('প্রজেক্ট ম্যানেজার', content, active_page='project-manager'))

@app.route('/settings')
def settings():
    """সেটিংস"""
    if 'user_id' not in session:
        return redirect(url_for('index'))
    content = '<div class="glass-card p-4"><h5>সেটিংস</h5><p>শীঘ্রই আসছে...</p></div>'
    return render_template_string(render_page('সেটিংস', content, active_page='settings'))

@app.route('/profile')
def profile():
    """প্রোফাইল"""
    if 'user_id' not in session:
        return redirect(url_for('index'))
    content = f'<div class="glass-card p-4"><h5>ইউজার: {session.get("username", "N/A")}</h5><p>রোল: {session.get("role", "N/A")}</p></div>'
    return render_template_string(render_page('প্রোফাইল', content, active_page='profile'))

@app.route('/logs')
def logs_page():
    """লগ পেজ"""
    if 'user_id' not in session:
        return redirect(url_for('index'))
    log_content = 'কোনো লগ নেই'
    log_file = 'logs/hosting_panel.log'
    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            log_content = f.read()[-10000:]
    content = f'<div class="glass-card p-4"><h5><i class="fas fa-history"></i> সিস্টেম লগ</h5><pre style="max-height: 500px; overflow-y: auto; background: rgba(0,0,0,0.3); padding: 15px; border-radius: 10px;">{html.escape(log_content)}</pre></div>'
    return render_template_string(render_page('লগ', content, active_page='logs'))

@app.route('/server-info')
def server_info():
    """সার্ভার তথ্য"""
    if 'user_id' not in session:
        return redirect(url_for('index'))
    info = get_system_info()
    content = f'''<div class="row">
        <div class="col-md-6"><div class="glass-card p-4 mb-3"><h5>সিস্টেম</h5>
            <ul class="list-unstyled">
                <li><strong>Python:</strong> {info.get('python_version', 'N/A')}</li>
                <li><strong>Flask:</strong> {info.get('flask_version', 'N/A')}</li>
                <li><strong>প্ল্যাটফর্ম:</strong> {info.get('platform', 'N/A')}</li>
                <li><strong>প্রসেসর:</strong> {info.get('processor', 'N/A')}</li>
                <li><strong>হোস্টনেম:</strong> {info.get('hostname', 'N/A')}</li>
        </ul></div></div>
        <div class="col-md-6"><div class="glass-card p-4 mb-3"><h5>রিসোর্স</h5>
            <ul class="list-unstyled">
                <li><strong>CPU কোর:</strong> {info.get('cpu_count', 'N/A')}</li>
                <li><strong>CPU ফ্রিকোয়েন্সি:</strong> {info.get('cpu_freq_current', 'N/A')}</li>
                <li><strong>মোট RAM:</strong> {info.get('total_ram', 'N/A')}</li>
                <li><strong>উপলব্ধ RAM:</strong> {info.get('available_ram', 'N/A')}</li>
                <li><strong>ফ্রি স্টোরেজ:</strong> {info.get('free_storage', 'N/A')}</li>
        </ul></div></div></div>'''
    return render_template_string(render_page('সার্ভার তথ্য', content, active_page='server-info'))

# ==================== এরর হ্যান্ডলার ====================
@app.errorhandler(404)
def not_found_error(error):
    if request.is_json:
        return jsonify({'error': 'Not found'}), 404
    content = '<div class="glass-card p-5 text-center"><h1 style="font-size: 6rem; color: #667eea;">404</h1><h3>পেজ পাওয়া যায়নি</h3><a href="/dashboard" class="btn btn-primary-gradient mt-3">ড্যাশবোর্ডে ফিরুন</a></div>'
    return render_template_string(render_page('404', content)), 404

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f"Internal Server Error: {str(error)}")
    if request.is_json:
        return jsonify({'error': 'Internal server error'}), 500
    content = '<div class="glass-card p-5 text-center"><h1 style="font-size: 6rem; color: #eb3349;">500</h1><h3>সার্ভার ত্রুটি</h3><a href="/dashboard" class="btn btn-primary-gradient mt-3">ড্যাশবোর্ডে ফিরুন</a></div>'
    return render_template_string(render_page('500', content)), 500

# ==================== সিকিউরিটি হেডার ====================
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# ==================== অ্যাপ্লিকেশন স্টার্টআপ ====================
if __name__ == '__main__':
    os.makedirs('data', exist_ok=True)
    os.makedirs('logs', exist_ok=True)
    os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(Config.SEARXNG_DIR, exist_ok=True)
    
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=Config.DEBUG)
