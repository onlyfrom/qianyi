from flask import Flask, request, jsonify, send_from_directory, send_file, make_response
from flask_cors import CORS
import json
import jwt
from datetime import datetime, timedelta
from functools import wraps
import requests
from Crypto.Cipher import AES
import base64
from werkzeug.utils import secure_filename
import os
from werkzeug.wrappers import Response
from openpyxl import load_workbook
import pandas as pd
from io import BytesIO
import openpyxl
import traceback
import random
import string
import time
import uuid
from extensions import db
from models import User, Product, StockRecord, ColorStock, ProductView, PurchaseOrder, \
    PurchaseOrderItem, DeliveryOrder, DeliveryItem, PushOrder, PushOrderProduct, SystemSettings
from sqlalchemy import inspect, text, func, desc, distinct, case, Text

from flask_migrate import Migrate  # 添加到文件开头的导入部分

app = Flask(__name__)
CORS(app, resources={
    r"/*": {
        "origins": "*",
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

SECRET_KEY = 'onlyfrom'  # 用于签名 JWT 的密钥


# 修改文件上传配置
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'xlsx', 'xls', 'pdf'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB

# 确保上传目录存在
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config.update(
    UPLOAD_FOLDER=UPLOAD_FOLDER,
    MAX_CONTENT_LENGTH=MAX_CONTENT_LENGTH
)

# 数据库配置
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:beibei&395@sh-cynosdbmysql-grp-kbj3s1h8.sql.tencentcdb.com:25481/qyflask'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 10,
    'pool_recycle': 3600,
    'pool_pre_ping': True
}

db.init_app(app)
migrate = Migrate(app, db)  # 移动到这里，在 db.init_app(app) 之后

# 初始化数据库
def init_db():
    """初始化数据库"""
    try:
        print('开始初始化数据库...')
        db.create_all()
        
        # 检查是否需要创建管理员账号
        admin = User.query.filter_by(user_type=1).first()
        if not admin:
            print('创建默认管理员账号...')
            admin = User(
                username='admin',
                password='admin123',  # 实际应用中应该使用加密密码
                nickname='管理员',
                user_type=1,
                status=1,
                created_at=datetime.now()
            )
            db.session.add(admin)
            db.session.commit()
            print('管理员账号创建成功')
            
        print('数据库初始化完成')
        
    except Exception as e:
        print(f'数据库初始化失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        db.session.rollback()
        raise

# 生成 JWT
def generate_token(user_id):
    """生成JWT token"""
    try:
        payload = {
            'user_id': user_id,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(hours=1)
        }
        return jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    except Exception as e:
        print(f'生成token失败: {str(e)}')
        return None

# 验证 JWT
def verify_token(token):
    """验证JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        print('token已过期')
        return None
    except jwt.InvalidTokenError as e:
        print(f'无效的token: {str(e)}')
        return None
    except Exception as e:
        print(f'验证token时发生错误: {str(e)}')
        return None

# 延长 token 有效期
def extend_token_expiry(token):
    """延长token的有效期"""
    try:
        # 解码当前token（不验证过期时间）
        payload = jwt.decode(token, SECRET_KEY, options={"verify_exp": False}, algorithms=['HS256'])
        # 更新过期时间
        payload['iat'] = datetime.utcnow()
        payload['exp'] = datetime.utcnow() + timedelta(hours=1)
        # 重新编码
        return jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    except Exception as e:
        print(f'延长token有效期失败: {str(e)}')
        return None

# 修改登录验证装饰器
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            # 获取 token
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                return jsonify({'error': '未提供认证令牌'}), 401
                
            token = auth_header.split(' ')[1] if len(auth_header.split(' ')) > 1 else auth_header
            
            # 验证 token
            user_id = verify_token(token)
            if not user_id:
                return jsonify({'error': '无效或已过期的认证令牌'}), 401
                
            # 检查用户是否存在且状态正常
            user = User.query.get(user_id)
            if not user:
                    return jsonify({'error': '用户不存在'}), 401
                    
            if user.status == 0:
                return jsonify({'error': '账号已被禁用'}), 403
                
            # 延长 token 有效期
            new_token = extend_token_expiry(token)
            if new_token:
                response = make_response(f(*args, user_id=user_id, **kwargs))
                response.headers['New-Token'] = new_token
                return response
                
            return f(*args, user_id=user_id, **kwargs)
            
        except Exception as e:
            print(f'认证过程发生错误: {str(e)}')
            print(f'错误追踪:\n{traceback.format_exc()}')
            return jsonify({'error': '认证失败'}), 401
            
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            # 获取 token
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                return jsonify({'error': '未提供认证令牌'}), 401

            token = auth_header.split(' ')[1] if len(auth_header.split(' ')) > 1 else auth_header

            # 验证 token
            user_id = verify_token(token)
            if not user_id:
                return jsonify({'error': '无效或已过期的认证令牌'}), 401

            # 检查用户是否是管理员
            user = User.query.get(user_id)
            if not user or user.user_type != 1:
                return jsonify({'error': '需要管理员权限'}), 403

            if user.status == 0:
                return jsonify({'error': '账号已被禁用'}), 403

            # 延长 token 有效期
            new_token = extend_token_expiry(token)
            if new_token:
                response = make_response(f(*args, user_id=user_id, **kwargs))
                response.headers['New-Token'] = new_token
                return response

            return f(*args, user_id=user_id, **kwargs)

        except Exception as e:
            print(f'管理员认证过程发生错误: {str(e)}')
            print(f'错误追踪:\n{traceback.format_exc()}')
            return jsonify({'error': '认证失败'}), 401

    return decorated_function

# 微信小程序配置
WECHAT_APPID = 'wxa17a5479891750b3'  # 替换为您的小程序 APPID
WECHAT_SECRET = '33359853cfee1dc1e2b6e535249e351d'  # 替换为您的小程序密钥

# 添加解密方法
def decrypt_user_info(session_key, encrypted_data, iv):
    try:
        # 使用 base64 解码
        session_key = base64.b64decode(session_key)
        encrypted_data = base64.b64decode(encrypted_data)
        iv = base64.b64decode(iv)
        
        # 使用 AES-128-CBC 解密
        cipher = AES.new(session_key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted_data)
        
        # 去除补位符号
        pad = decrypted[-1]
        if isinstance(pad, int):
            pad_size = pad
        else:
            pad_size = ord(pad)
        decrypted = decrypted[:-pad_size]
        
        # 解析 JSON 数据
        decrypted_data = json.loads(decrypted)
        return decrypted_data
    except Exception as e:
        print('解密用户信息失败:', str(e))
        return None

# 添加生成随机字符串的辅助函数
def generate_random_string(length=8):
    """生成指定长度的随机字符串，包含字母和数字"""
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

# 添加头像上传接口
@app.route('/upload/avatar', methods=['POST'])
@login_required
def upload_avatar(user_id):
    try:
        print('='*50)
        print('开始处理头像上传请求')
        print('='*50)
        
        if 'file' not in request.files:
            print('错误: 未找到上传的文件')
            return jsonify({'error': '未找到上传的文件'}), 400
            
        file = request.files['file']
        if not file:
            print('错误: 文件为空')
            return jsonify({'error': '文件为空'}), 400
            
        print(f'上传的文件: {file.filename}')
        
        # 检查文件类型
        if not file.filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
            print(f'错误: 不支持的文件类型 - {file.filename}')
            return jsonify({'error': '不支持的文件类型'}), 400
            
        # 生成安全的文件名
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        new_filename = f'avatar_{user_id}_{timestamp}_{filename}'
        print(f'生成的文件名: {new_filename}')
        
        # 确保上传目录存在
        upload_dir = os.path.join(app.root_path, 'uploads', 'avatars')
        if not os.path.exists(upload_dir):
            print(f'创建上传目录: {upload_dir}')
            os.makedirs(upload_dir)
            
        # 保存文件
        file_path = os.path.join(upload_dir, new_filename)
        file.save(file_path)
        print(f'文件已保存到: {file_path}')
        
        # 更新用户头像
        user = User.query.get(user_id)
        if user:
            # 获取旧头像路径
            old_avatar = user.avatar
            
            print(f'当前用户ID: {user_id}')
            print(f'原头像路径: {old_avatar}')
            
            # 更新数据库中的头像路径
            avatar_url = f'/uploads/avatars/{new_filename}'
            user.avatar = avatar_url
            db.session.commit()
            print(f'新头像路径已更新: {avatar_url}')
            
            # 删除旧头像文件
            if old_avatar and old_avatar != '/static/default_avatar.png':
                try:
                    old_file_path = os.path.join(app.root_path, old_avatar.lstrip('/'))
                    if os.path.exists(old_file_path):
                        os.remove(old_file_path)
                        print(f'已删除旧头像文件: {old_file_path}')
                except Exception as e:
                    print(f'删除旧头像文件失败: {str(e)}')
                    pass  # 忽略删除旧文件时的错误
            
            return jsonify({
                'code': 200,
                'message': '头像上传成功',
                'data': {
                    'avatar': avatar_url
                }
            })
            
        return jsonify({'error': '用户不存在'}), 404
            
    except Exception as e:
        print('\n头像上传时发生错误:')
        print(f'- 错误类型: {type(e).__name__}')
        print(f'- 错误信息: {str(e)}')
        print(f'- 错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '头像上传失败'}), 500

# 添加文件类型检查函数
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# 微信openid登录接口
@app.route('/wx/openid/login', methods=['POST'])
def wechat_openid_login():
    try:
        print('='*50)
        print('开始处理微信openid登录请求')
        print('='*50)
        
        data = request.json
        print('收到的请求数据:', json.dumps(data, ensure_ascii=False, indent=2))
        
        openid = data.get('openid')
        
        if not openid:
            print('错误: 缺少openid参数')
            return jsonify({'error': '缺少openid参数'}), 400
        
        # 查询是否存在该openid的用户
        user = User.query.filter_by(openid=openid).first()
        
        if user:
            print(f'找到已存在的用户: {user.username}')
            # 生成token并返回用户信息
            token = generate_token(user.id)
            return jsonify({
                'code': 200,
                'data': {
                    'userInfo': {
                        'id': user.id,
                        'username': user.username,
                        'nickname': user.nickname,
                        'avatar': user.avatar,
                        'phone': user.phone,
                        'address': user.address,
                        'contact': user.contact,
                        'user_type': user.user_type
                    },
                    'token': token
                }
            })
        
        # 不存在则创建新用户
        print('未找到用户,开始创建新用户')
        random_username = f'wx_{generate_random_string(10)}'
        random_password = generate_random_string(16)
        
        new_user = User(
            username=random_username,
            password=random_password,
            openid=openid,
            nickname=random_username,
            avatar="",
            user_type=0,
            created_at=datetime.now(),
            status=1,
            login_attempts=0,
            last_login_attempt=None,
            last_login=None
        )
        db.session.add(new_user)
        db.session.commit()
        
        print(f'新用户创建成功: ID={new_user.id}')
        
        token = generate_token(new_user.id)
        
        return jsonify({
            'code': 200,
            'data': {
                'userInfo': {
                    'id': new_user.id,
                    'username': new_user.username,
                    'nickname': new_user.nickname,
                    'avatar': new_user.avatar,
                    'phone': new_user.phone,
                    'address': new_user.address,
                    'contact': new_user.contact,
                    'user_type': new_user.user_type
                },
                'token': token
            }
        })
        
    except Exception as e:
        print('\n处理微信openid登录请求时发生错误:')
        print(f'- 错误类型: {type(e).__name__}')
        print(f'- 错误信息: {str(e)}')
        print(f'- 错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '登录失败'}), 500


# 微信登录接口
@app.route('/wx/login', methods=['POST'])
def wechat_login():
    try:
        print('='*50)
        print('开始处理微信登录请求')
        print('='*50)
        
        data = request.json
        print('收到的请求数据:', json.dumps(data, ensure_ascii=False, indent=2))
        
        code = data.get('code')
        encrypted_data = data.get('encryptedData')
        iv = data.get('iv')
        bind_user = data.get('bind_user', False)
        openid = data.get('openid')

        # 检查参数完整性
        print('参数检查:')
        print(f'- code: {"存在" if code else "缺失"}')
        print(f'- encryptedData: {"存在" if encrypted_data else "缺失"}')
        print(f'- iv: {"存在" if iv else "缺失"}')
        print(f'- bind_user: {bind_user}')
        
        if not all([code, encrypted_data, iv]):
            print('错误: 缺少必要参数')
            return jsonify({'error': '缺少必要参数'}), 400

        # 获取微信用户信息
        wx_data = get_wx_user_info(code)
        if not wx_data:
            return jsonify({'error': '获取微信用户信息失败'}), 400

        openid = wx_data.get('openid')
        session_key = wx_data.get('session_key')
        
        # 解密用户信息
        try:
            user_info = decrypt_weixin_data(session_key, encrypted_data, iv)
        except Exception as e:
            print('解密失败:', str(e))
            return jsonify({'error': '解密用户信息失败'}), 400
        
        # 查找或创建用户
        user = User.query.filter_by(openid=openid).first()
        
        if user:
            if user.status == 0:
                return jsonify({'error': '账号已被禁用'}), 403
            else:
                if bind_user:
                    return jsonify({
                        'code': 200,
                        'data': {
                            'need_bind': True,
                            'openid': openid,
                            'userInfo': {
                                'nickName': user_info.get('nickName'),
                                'avatarUrl': user_info.get('avatarUrl')
                            }
                        }
                    })
        
        # 创建新用户
        username = f'wx_{generate_random_string(8)}'
        while User.query.filter_by(username=username).first():
            username = f'wx_{generate_random_string(8)}'
        
        user = User(
            username=username,
            password=generate_random_string(12),
            nickname=user_info.get('nickName', username),
            avatar=user_info.get('avatarUrl', ''),
            openid=openid,
            user_type=0,
            status=1,
            created_at=datetime.now()
        )
        db.session.add(user)
        db.session.commit()

        # 生成token
        token = generate_token(user.id)
        
        return jsonify({
            'code': 200,
            'data': {
                'need_bind': False,
                'userInfo': {
                    'id': user.id,
                    'username': user.username,
                    'nickname': user.nickname,
                    'avatar': user.avatar,
                    'phone': user.phone,
                    'address': user.address,
                    'contact': user.contact,
                    'user_type': user.user_type
                },
                'token': token
            }
        })
            
    except Exception as e:
        print('\n发生未预期的错误:')
        print(f'- 错误类型: {type(e).__name__}')
        print(f'- 错误信息: {str(e)}')
        print(f'- 错误追踪:\n{traceback.format_exc()}')
        db.session.rollback()
        return jsonify({'error': '登录失败'}), 500

# 微信登录绑定账号接口
@app.route('/wx/login/link', methods=['POST'])
def wx_login_link():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        openid = data.get('openid')
        
        if not all([username, password, openid]):
            return jsonify({'error': '缺少必要参数'}), 400
        
        # 验证用户名和密码
        user = User.query.filter_by(username=username).first()
        if not user or password != user.password:  # 直接比较密码，因为目前密码是明文存储的
            return jsonify({'error': '用户名或密码错误'}), 401
        
        # 检查openid是否已被其他账号绑定
        if User.query.filter_by(openid=openid).first():
            return jsonify({'error': '该微信已绑定其他账号'}), 400
        
        # 更新用户的微信绑定信息
        user.openid = openid
        db.session.commit()

        # 生成 token 并返回最新的用户信息
        token = generate_token(user.id)
        return jsonify({
            'code': 200,
            'data': {
                'userInfo': {
                    'id': user.id,
                    'username': user.username,
                    'nickname': user.nickname,
                    'avatar': user.avatar,
                    'phone': user.phone,
                    'address': user.address,
                    'contact': user.contact,
                    'user_type': user.user_type
                },
                'token': token
            }
        })
            
    except Exception as e:
        print(f'微信账号关联失败: {str(e)}')
        db.session.rollback()
        return jsonify({'error': '微信账号关联失败'}), 500

# 添加获取微信用户信息的辅助函数
def get_wx_user_info(code):
    """获取微信用户信息"""
    try:
        print('\n开始请求微信API:')
        wx_api_url = 'https://api.weixin.qq.com/sns/jscode2session'
        print(f'- 接口地址: {wx_api_url}')
        print(f'- 请求参数: appid={WECHAT_APPID}, code={code}')
        
        params = {
            'appid': WECHAT_APPID,
            'secret': WECHAT_SECRET,
            'js_code': code,
            'grant_type': 'authorization_code'
        }
        
        response = requests.get(wx_api_url, params=params)
        wx_data = response.json()
        print('\n微信API响应:')
        print(json.dumps(wx_data, ensure_ascii=False, indent=2))

        if 'errcode' in wx_data:
            print('错误: 微信API返回错误')
            print(f'错误码: {wx_data.get("errcode")}')
            print(f'错误信息: {wx_data.get("errmsg")}')
            return None

        return wx_data
        
    except Exception as e:
        print(f'获取微信用户信息失败: {str(e)}')
        return None

# 数据解密函数也添加详细日志
def decrypt_weixin_data(session_key, encrypted_data, iv):
    try:
        print('开始解密微信数据:')
        print(f'- session_key长度: {len(session_key)}')
        print(f'- encrypted_data长度: {len(encrypted_data)}')
        print(f'- iv长度: {len(iv)}')
        
        # Base64解码
        print('\n执行Base64解码...')
        session_key = base64.b64decode(session_key)
        encrypted_data = base64.b64decode(encrypted_data)
        iv = base64.b64decode(iv)
        
        print('解码后数据长度:')
        print(f'- session_key: {len(session_key)} 字节')
        print(f'- encrypted_data: {len(encrypted_data)} 字节')
        print(f'- iv: {len(iv)} 字节')
        
        # 创建解密器
        print('\n创建AES解密器...')
        cipher = AES.new(session_key, AES.MODE_CBC, iv)
        
        # 解密数据
        print('执行解密...')
        decrypted = cipher.decrypt(encrypted_data)
        
        # 处理填充
        print('处理PKCS7填充...')
        pad = decrypted[-1]
        if not isinstance(pad, int):
            pad = ord(pad)
        data = decrypted[:-pad]
        
        # 解析JSON
        print('解析JSON数据...')
        result = json.loads(data)
        print('解密成功')
        return result
        
    except Exception as e:
        print('\n解密过程出错:')
        print(f'- 错误类型: {type(e).__name__}')
        print(f'- 错误信息: {str(e)}')
        print(f'- 错误追踪:\n{traceback.format_exc()}')
        raise Exception('解密用户信息失败')

# 更新用户信息接口
@app.route('/user/update', methods=['POST'])
@login_required
def update_user_info(user_id):
    try:
        data = request.json
        
        user = User.query.get(user_id)
        if user:
            user.phone = data.get('phone')
            user.address = data.get('address')
            user.contact = data.get('contact')
            user.nickname = data.get('nickname')
            db.session.commit()
            
            return jsonify({
                'message': '用户信息更新成功',
                'user': {
                    'id': user.id,
                    'nickname': user.nickname,
                    'avatar': user.avatar,
                    'phone': user.phone,
                    'address': user.address,
                    'contact': user.contact
                }
            }), 200
        
        return jsonify({'error': '用户不存在'}), 404

    except Exception as e:
        print('更新用户信息错误:', str(e))
        return jsonify({'error': '服务器错误'}), 500


# 用户注册
@app.route('/register', methods=['POST'])
def register():
    try:
        print('='*50)
        print('开始处理用户注册请求')
        print('='*50)
        
        data = request.json
        print('收到的注册数据:', json.dumps(data, ensure_ascii=False, indent=2))
        
        # 验证必要字段
        required_fields = ['username', 'password', 'nickname']
        print('\n检查必要字段:')
        for field in required_fields:
            if not data.get(field):
                print(f'错误: 缺少必要字段 {field}')
                return jsonify({'error': f'缺少必要参数: {field}'}), 400
            print(f'- {field}: 已提供')
        
        # 检查用户名是否已存在
        print('\n检查用户名是否已存在')
        if User.query.filter_by(username=data['username']).first():
            print(f'错误: 用户名 {data["username"]} 已存在')
            return jsonify({'error': '用户名已存在'}), 400
        print('用户名可用')

        print('\n开始创建新用户...')
        # 创建新用户
        new_user = User(
            username=data['username'],
            password=data['password'],
            nickname=data['nickname'],
            avatar=data.get('avatar', ''),
            phone=data.get('phone', ''),
            address=data.get('address', ''),
            contact=data.get('contact', ''),
            user_type=0,  # 普通用户
            status=1,  # 启用状态
            created_at=datetime.now()
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        print(f'新用户创建成功: ID={new_user.id}')
        print('\n返回注册成功响应')
        
        return jsonify({
            'code': 200,
            'message': '注册成功',
            'data': {'id': new_user.id}
        })
            
    except Exception as e:
        print('\n注册过程中发生错误:')
        print(f'- 错误类型: {type(e).__name__}')
        print(f'- 错误信息: {str(e)}')
        print(f'- 错误追踪:\n{traceback.format_exc()}')
        db.session.rollback()
        return jsonify({'error': '注册失败'}), 500


# 普通账号密码登录接口
@app.route('/login', methods=['POST'])
def login():
    try:
        print('='*50)
        print('开始处理账号密码登录请求')
        print('='*50)
        
        data = request.json
        print('收到的请求数据:', json.dumps(data, ensure_ascii=False, indent=2))
        
        username = data.get('username')
        password = data.get('password')
        
        # 检查参数完整性
        print('参数检查:')
        print(f'- username: {"存在" if username else "缺失"}')
        print(f'- password: {"存在" if password else "缺失"}')
        
        if not username or not password:
            print('错误: 缺少必要参数')
            return jsonify({'error': '请输入用户名和密码'}), 400
            
        # 添加登录频率限制检查
        if is_login_attempts_exceeded(username):
            print(f'错误: 用户 {username} 登录尝试次数过多')
            return jsonify({'error': '登录尝试次数过多，请稍后再试'}), 429

        print('\n开始验证用户信息...')
        
        # 查询用户信息
        user = User.query.filter_by(username=username).first()
        
        if not user:
            print(f'错误: 用户名 {username} 不存在')
            return jsonify({'error': '用户名或密码错误'}), 401
        
        # 检查账号状态
        if user.status == 0:
            print(f'错误: 用户 {username} 已被禁用')
            return jsonify({'error': '账号已被禁用，请联系管理员'}), 403
        
        # 验证密码
        if password != user.password:  # 这里应该使用安全的密码验证方法
            print(f'错误: 用户 {username} 密码错误')
            # 记录登录失败
            user.login_attempts += 1
            user.last_login_attempt = datetime.now()
            db.session.commit()
            return jsonify({'error': '用户名或密码错误'}), 401
        
        # 登录成功，重置登录尝试次数
        user.login_attempts = 0
        user.last_login = datetime.now()
        db.session.commit()
        
        # 生成token
        token = generate_token(user.id)
        print(f'\n用户 {username} 登录成功')
        
        response_data = {
            'token': token,
            'user': {
                'id': user.id,
                'username': user.username,
                'nickname': user.nickname,
                'avatar': user.avatar,
                'phone': user.phone,
                'address': user.address,
                'contact': user.contact,
                'user_type': user.user_type
            }
        }
        
        print('\n返回给客户端的数据:')
        print(json.dumps(response_data, ensure_ascii=False, indent=2))
        
        return jsonify(response_data), 200
            
    except Exception as e:
        print('\n发生未预期的错误:')
        print(f'- 错误类型: {type(e).__name__}')
        print(f'- 错误信息: {str(e)}')
        print(f'- 错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '登录失败'}), 500

# 修改登录频率限制检查函数
def is_login_attempts_exceeded(username):
    try:
        user = User.query.filter_by(username=username).first()
        if not user:
                return False
            
            # 如果尝试次数超过5次且最后一次尝试在30分钟内
        if user.login_attempts >= 5 and user.last_login_attempt:
            if datetime.utcnow() - user.last_login_attempt < timedelta(minutes=30):
                    return True
                    
            return False
            
    except Exception as e:
        print(f'检查登录频率时出错: {str(e)}')
        return False
# 新增或更新商品（需要登录）
@app.route('/products', methods=['POST'])
@admin_required
def add_or_update_product(user_id):
    try:
        data = request.get_json()
        
        # 验证必需的字段
        required_fields = ['name', 'description', 'price', 'type']
        if not all(field in data for field in required_fields):
            return jsonify({'error': '缺少必需的字段'}), 400
        
        # 获取价格字段，如果未提供则使用price的值
        price = float(data['price'])
        price_b = float(data.get('price_b', price))
        price_c = float(data.get('price_c', price))
        price_d = float(data.get('price_d', price))
        cost_price = float(data.get('cost_price', price))
        
        # 获取状态字段，设置默认值
        status = data.get('status', 1)  # 默认上架
        is_public = data.get('is_public', 1)  # 默认公开
        
        # 检查是否提供了商品ID
        product_id = data.get('id')
        if product_id:
            # 更新现有商品
            product = Product.query.get(product_id)
            if not product:
                return jsonify({'error': '商品不存在'}), 404
                
            product.name = data['name']
            product.description = data['description']
            product.price = price
            product.price_b = price_b
            product.price_c = price_c
            product.price_d = price_d
            product.cost_price = cost_price
            product.type = data['type']
            product.specs_info = json.dumps(data.get('specs_info', {}))
            product.updated_at = datetime.now()
            product.specs = json.dumps(data.get('specs', {}))
            product.images = json.dumps(data.get('images', []))
            product.status = status
            product.is_public = is_public
        else:
            # 生成新的商品ID
            product_type = str(data['type']).zfill(2)  # 确保类型是两位数
            
            # 查找当前类型下最大的编号
            latest_product = Product.query.filter(
                Product.id.like(f'qy{product_type}%')
            ).order_by(Product.id.desc()).first()
            
            if latest_product:
                # 从最后一个商品ID中提取编号
                try:
                    last_number = int(latest_product.id[4:])  # 跳过 'qyXX' 前缀
                    new_number = str(last_number + 1).zfill(4)  # 确保是4位数
                except ValueError:
                    new_number = '0001'
            else:
                new_number = '0001'
            
            # 生成新的商品ID
            new_product_id = f'qy{product_type}{new_number}'
            
            # 创建新商品
            product = Product(
                id=new_product_id,
                name=data['name'],
                description=data['description'],
                price=price,
                price_b=price_b,
                price_c=price_c,
                price_d=price_d,
                cost_price=cost_price,
                type=data['type'],
                specs_info=json.dumps(data.get('specs_info', {})),
                specs=json.dumps(data.get('specs', {})),
                images=json.dumps(data.get('images', [])),
                status=status,
                is_public=is_public,
                created_at=datetime.now(),
                updated_at=datetime.now()
            )
            db.session.add(product)
            
        try:
            db.session.commit()
            return jsonify({
                'message': '商品保存成功',
                'product_id': product.id
            }), 200
        except Exception as e:
            db.session.rollback()
            print(f"保存商品失败: {str(e)}")
            return jsonify({'error': '保存商品失败'}), 500
        
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({'error': f'处理请求失败: {str(e)}'}), 500

# 删除商品
@app.route('/products/<product_id>', methods=['DELETE'])
@login_required
def delete_product(user_id, product_id):
    try:
        # 检查商品是否存在
        product = Product.query.get(product_id)
        if not product:
            return jsonify({'error': '商品不存在'}), 404

        # 开始事务
        try:
            # 1. 删除商品浏览记录
            ProductView.query.filter_by(product_id=product_id).delete()
            
            # 2. 删除商品库存记录
            ColorStock.query.filter_by(product_id=product_id).delete()
            
            # 3. 删除商品库存变更记录
            StockRecord.query.filter_by(product_id=product_id).delete()
            
            # 4. 删除商品相关的图片
            if product.images:
                images = json.loads(product.images)
                for image_url in images:
                    try:
                        filename = image_url.split('/')[-1]
                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        if os.path.exists(file_path):
                            os.remove(file_path)
                    except Exception as e:
                        print(f"删除图片失败: {str(e)}")
                        # 继续执行，不中断流程

            # 5. 最后删除商品
            db.session.delete(product)
            db.session.commit()
            
            return jsonify({'message': '商品删除成功'}), 200
            
        except Exception as e:
            db.session.rollback()
            print(f"删除商品失败: {str(e)}")
            return jsonify({'error': f'删除商品失败: {str(e)}'}), 500
            
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({'error': f'处理请求失败: {str(e)}'}), 500

# 获取商品详情
@app.route('/products/<product_id>', methods=['GET'])
def get_product_detail(product_id):
    try:
        product = Product.query.get(product_id)
        if not product:
            return jsonify({'error': '商品不存在'}), 404

        product_detail = {
            'id': product.id,
            'name': product.name,
            'description': product.description,
            'price': float(product.price),
            'specs': json.loads(product.specs) if product.specs else [],
            'images': json.loads(product.images) if product.images else [],
            'type': product.type,
            'created_at': product.created_at.isoformat() if product.created_at else None,
            'specs_info': json.loads(product.specs_info) if product.specs_info else {},
            'status': product.status if product.status is not None else 1,  # 默认上架
            'is_public': product.is_public if product.is_public is not None else 1  # 默认公开
        }
        return jsonify({'product': product_detail}), 200

    except Exception as e:
        print(f"获取商品详情失败: {str(e)}")
        return jsonify({'error': '获取商品详情失败'}), 500

# 获取最近添加的商品
@app.route('/products/recent', methods=['GET'])
def get_recent_products():
    try:
        page = int(request.args.get('page', 1))  # 默认第 1 页
        limit = int(request.args.get('limit', 10))  # 默认每页 10 条
        
        # 使用 SQLAlchemy 查询
        products_query = Product.query.order_by(Product.created_at.desc())
        
        # 获取分页数据
        paginated_products = products_query.paginate(
            page=page, 
            per_page=limit, 
            error_out=False
        )
        
        # 格式化数据
        products = []
        for product in paginated_products.items:
            products.append({
                'id': product.id,
                'name': product.name,
                'description': product.description,
                'price': float(product.price),
                'specs': json.loads(product.specs) if product.specs else [],
                'images': json.loads(product.images) if product.images else [],
                'type': product.type,
                'created_at': product.created_at.isoformat() if product.created_at else None,
                'specs_info': json.loads(product.specs_info) if product.specs_info else {}
            })
            
        return jsonify({
            'products': products,
            'total': paginated_products.total,
            'pages': paginated_products.pages,
            'current_page': page
        }), 200
        
    except Exception as e:
        print(f"获取最近商品列表失败: {str(e)}")
        return jsonify({'error': '获取商品列表失败'}), 500

# 确保文件扩展名合法
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# 上传图片接口
@app.route('/upload', methods=['POST'])
@admin_required
def upload_file_handler(user_id):
    try:
        if 'file' not in request.files:
            return jsonify({'error': '未找到上传文件'}), 400
            
        file = request.files['file']
        if not file or file.filename == '':
            return jsonify({'error': '未选择文件'}), 400
            
        if not allowed_file(file.filename):
            return jsonify({'error': '不支持的文件类型'}), 400
            
        # 获取文件类型并创建对应目录
        file_ext = file.filename.rsplit('.', 1)[1].lower()
        upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], file_ext)
        os.makedirs(upload_dir, exist_ok=True)
            
        # 生成安全的文件名
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        random_str = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        new_filename = f'{timestamp}_{random_str}_{filename}'
        
        # 保存文件
        file_path = os.path.join(upload_dir, new_filename)
        file.save(file_path)
        
        # 如果是图片，生成缩略图
        if file_ext in {'png', 'jpg', 'jpeg', 'gif'}:
            create_thumbnail(file_path)
            
        # 返回可访问的URL
        file_url = f'/uploads/{file_ext}/{new_filename}'
        
        print(f'文件已保存: {file_path}')
        print(f'访问URL: {file_url}')
        
        return jsonify({
            'url': file_url,
            'filename': new_filename
        }), 200
        
    except Exception as e:
        print(f'处理文件上传失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '文件上传失败'}), 500


# 删除文件接口 - 修改路由路径以避免冲突
@app.route('/upload/delete/<path:filename>', methods=['DELETE'])  # 修改这里
@login_required
def delete_upload_file(user_id, filename):  # 修改函数名
    try:
        # 从文件名中提取文件类型
        file_type = filename.rsplit('.', 1)[1].lower()
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_type, filename)
        
        # 如果文件存在则删除
        if os.path.exists(file_path):
            os.remove(file_path)
            return jsonify({
                'message': '文件删除成功',
                'filename': filename
            }), 200
        else:
            return jsonify({'error': '文件不存在'}), 404
            
    except Exception as e:
        print(f'删除文件失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '删除文件失败'}), 500

@app.route('/')
def index():
    return send_file('static/admin/index.html')

@app.route('/static/<path:path>')
def serve_static(path):
    return send_from_directory('static', path)

@app.route('/admin')
def admin():
    return send_file('static/admin/index.html')

@app.route('/admin/<path:filename>')
def serve_admin(filename):
    return send_from_directory('static/admin', filename)

@app.route('/admin/views/<path:filename>')
def serve_admin_views(filename):
    response = send_from_directory('static/admin/views', filename)
    # 设置正确的 MIME 类型
    if filename.endswith('.js'):
        response.mimetype = 'application/javascript'
    return response

@app.route('/admin/components/<path:filename>')
def serve_admin_components(filename):
    return send_from_directory('static/admin/components', filename)

@app.route('/admin/utils/<path:filename>')
def serve_admin_utils(filename):
    return send_from_directory('static/admin/utils', filename)

@app.route('/upload/<path:filename>', methods=['DELETE'])
@login_required
def delete_file(user_id, filename):
    try:
        print(f'开始删除文件: {filename}')
        # 构建完整的文件路径
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # 从文件名中提取商品ID（假设文件名格式为：product_id_number.ext）
        try:
            product_id = filename.split('_')[0]
        except:
            return jsonify({'error': '无效的文件名格式'}), 400
            
        # 如果文件存在则删除
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                print(f'物理文件已删除: {file_path}')
            except Exception as e:
                print(f"删除物理文件失败: {str(e)}")
        
        # 更新数据库中的图片列表
        product = Product.query.get(product_id)
        if product and product.images:
            try:
                current_images = json.loads(product.images)
                image_url = f"/uploads/{filename}"
                
                if image_url in current_images:
                    current_images.remove(image_url)
                    product.images = json.dumps(current_images)
                    db.session.commit()
                    print(f'已从数据库中移除图片URL: {image_url}')
            except Exception as e:
                db.session.rollback()
                print(f"更新数据库图片列表失败: {str(e)}")
                return jsonify({'error': '更新数据库失败'}), 500
        
        return jsonify({
            'message': '文件删除成功',
            'file_existed': os.path.exists(file_path),
            'filename': filename
        }), 200
        
    except Exception as e:
        print(f"删除文件失败: {str(e)}")
        return jsonify({'error': '删除文件失败'}), 500

# 获取库存变动记录
@app.route('/products/<product_id>/stock/records', methods=['GET'])
@login_required
def get_stock_records(user_id, product_id):
    try:
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 10))
        
        # 使用 SQLAlchemy 查询
        records_query = StockRecord.query.filter_by(product_id=product_id)\
            .order_by(StockRecord.created_at.desc())
        
        # 获取分页数据
        paginated_records = records_query.paginate(
            page=page,
            per_page=limit,
            error_out=False
        )
        
        records = [{
            'id': record.id,
            'product_id': record.product_id,
            'change_amount': record.change_amount,
            'type': record.type,
            'remark': record.remark,
            'operator': record.operator,
            'color': record.color,
            'created_at': record.created_at.isoformat() if record.created_at else None
        } for record in paginated_records.items]
        
        return jsonify({
            'records': records,
            'total': paginated_records.total,
            'pages': paginated_records.pages,
            'current_page': page
        }), 200
        
    except Exception as e:
        print('获取库存记录失败:', str(e))
        return jsonify({'error': '获取库存记录失败'}), 500
# 获取随机商品
@app.route('/products/random', methods=['GET'])
def get_random_products():
    try:
        # 获取请求参数 n，默认返回 4 个商品
        n = int(request.args.get('n', 4))
        
        # 使用 SQLAlchemy 的 func.random() 进行随机查询
        from sqlalchemy.sql.expression import func
        
        # 查询有图片的商品
        products = Product.query\
            .filter(Product.images.isnot(None))\
            .filter(Product.images != '[]')\
            .order_by(func.random())\
            .limit(n)\
            .all()
            
        # 格式化返回数据
        formatted_products = []
        for product in products:
            images = json.loads(product.images) if product.images else []
            # 只返回第一张图片
            formatted_products.append({
                'id': product.id,
                'name': product.name,
                'image': images[0] if images else None
            })
            
        return jsonify({
            'products': formatted_products,
            'count': len(formatted_products)
        }), 200
            
    except Exception as e:
        print('获取随机商品失败:', str(e))
        return jsonify({'error': '服务器错误'}), 500

# 添加商品库存管理相关接口
@app.route('/products/<product_id>/stock', methods=['POST'])
@login_required
def update_stock(user_id, product_id):
    try:
        data = request.json
        change_amount = data.get('amount', 0)  # 库存变动数量
        change_type = data.get('type', 'adjust')  # 变动类型
        remark = data.get('remark', '')  # 备注
        color = data.get('color', '')  # 颜色

        if not isinstance(change_amount, int):
            return jsonify({'error': '库存变动数量必须是整数'}), 400

        # 获取商品
        product = Product.query.get(product_id)
        if not product:
            return jsonify({'error': '商品不存在'}), 404

        # 如果指定了颜色，更新颜色库存
        if color:
            color_stock = ColorStock.query.filter_by(
                product_id=product_id,
                color=color
            ).first()

            if not color_stock:
                color_stock = ColorStock(
                    product_id=product_id,
                    color=color,
                    stock=0
                )
                db.session.add(color_stock)

            new_stock = color_stock.stock + change_amount
            if new_stock < 0:
                return jsonify({'error': '库存不足'}), 400
            color_stock.stock = new_stock

        # 记录库存变动
        stock_record = StockRecord(
            product_id=product_id,
            change_amount=change_amount,
            type=change_type,
            remark=remark,
            operator=f'user_{user_id}',
            color=color,
            created_at=datetime.now()
        )
        db.session.add(stock_record)

        try:
            db.session.commit()
            return jsonify({
                'message': '库存更新成功',
                'new_stock': new_stock if color else None,
                'change': change_amount
            }), 200
        except Exception as e:
            db.session.rollback()
            print(f'更新库存失败: {str(e)}')
            return jsonify({'error': '更新库存失败'}), 500

    except Exception as e:
        print(f'处理库存更新请求失败: {str(e)}')
        return jsonify({'error': '更新库存失败'}), 500

# 更新商品颜色库存
@app.route('/products/<product_id>/specs/stock', methods=['POST'])
@login_required
def update_color_stock(user_id, product_id):
    try:
        data = request.json
        color = data.get('color')
        change_amount = data.get('amount', 0)
        change_type = data.get('type', 'adjust')
        remark = data.get('remark', '')

        if not color:
            return jsonify({'error': '颜色不能为空'}), 400

        if not isinstance(change_amount, int):
            return jsonify({'error': '库存变动数量必须是整数'}), 400

        # 获取商品
        product = Product.query.get(product_id)
        if not product:
            return jsonify({'error': '商品不存在'}), 404
            
        # 获取或创建颜色库存记录
        color_stock = ColorStock.query.filter_by(
            product_id=product_id,
            color=color
        ).first()
        
        if not color_stock:
            color_stock = ColorStock(
                product_id=product_id,
                color=color,
                stock=0
            )
            db.session.add(color_stock)
            
        # 更新库存
        new_stock = color_stock.stock + change_amount
        if new_stock < 0:
            return jsonify({'error': '库存不足'}), 400
        color_stock.stock = new_stock
            
        # 记录库存变动
        stock_record = StockRecord(
            product_id=product_id,
            change_amount=change_amount,
            type=change_type,
            remark=remark,
            operator=f'user_{user_id}',
            color=color,
            created_at=datetime.now()
        )
        db.session.add(stock_record)

        try:
            db.session.commit()
            return jsonify({
                'message': '库存更新成功',
                'color': color,
                'new_stock': new_stock,
                'change': change_amount
            }), 200
        except Exception as e:
            db.session.rollback()
            print(f'更新颜色库存失败: {str(e)}')
            return jsonify({'error': '更新失败'}), 500
            
    except Exception as e:
        print('更新颜色库存失败:', str(e))
        return jsonify({'error': '更新失败'}), 500

# 获取商品所有颜色库存
@app.route('/products/<product_id>/specs/stock', methods=['GET'])
def get_color_stocks(product_id):
    try:
        # 获取商品的所有颜色库存
        color_stocks = ColorStock.query.filter_by(product_id=product_id).all()
        
        # 格式化返回数据
        stocks = [{
            'color': stock.color,
            'stock': stock.stock,
            'color_code': stock.color_code
        } for stock in color_stocks]
        
        return jsonify({'specs': stocks}), 200
            
    except Exception as e:
        print('获取颜色库存失败:', str(e))
        return jsonify({'error': '服务器错误'}), 500

@app.errorhandler(404)
def not_found_error(error):
    return jsonify({'error': '请求的资源不存在'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': '服务器内部错误'}), 500


def validate_product_data(data):
    required_fields = ['id', 'name', 'price']
    for field in required_fields:
        if field not in data:
            return False, f'缺少必要字段: {field}'
    return True, None

# 添加Excel导入接口
@app.route('/products/import', methods=['POST'])
@login_required
def import_products(user_id):
    try:
        print('开始处理Excel导入请求...')
        if 'file' not in request.files:
            print('错误：没有上传文件')
            return jsonify({'error': '没有上传文件'}), 400
            
        file = request.files['file']
        print(f'接收到文件: {file.filename}, 类型: {file.content_type}')
        
        if not file.filename.endswith(('.xlsx', '.xls')):
            print(f'错误：不支持的文件类型: {file.filename}')
            return jsonify({'error': '只支持Excel文件'}), 400

        # 读取Excel文件
        try:
            df = pd.read_excel(file)
            print(f'成功读取Excel文件，共 {len(df)} 行数据')
            print('Excel表头:', list(df.columns))
        except Exception as e:
            print(f'读取Excel文件失败: {str(e)}')
            return jsonify({'error': f'读取Excel文件失败: {str(e)}'}), 400
        
        imported_count = 0
        errors = []
            
        for index, row in df.iterrows():
            try:
                print(f'\n处理第 {index + 2} 行数据...')
                # 验证必要字段
                if pd.isna(row['款号']) or pd.isna(row['商品名称']):
                    error_msg = f'第 {index + 2} 行：款号或商品名称不能为空'
                    print(f'错误: {error_msg}')
                    errors.append(error_msg)
                    continue
                
                # 打印行数据用于调试    
                print(f'行数据: {dict(row)}')
                    
                try:
                    product_data = {
                        'id': str(row['款号']).strip(),
                        'name': str(row['商品名称']).strip(),
                        'price': float(row['价格']) if not pd.isna(row['价格']) else 0,
                        'description': str(row['描述']).strip() if not pd.isna(row['描述']) else '',
                        'type': int(float(row['款式'])) if not pd.isna(row['款式']) else 1
                    }
                except ValueError as e:
                    error_msg = f'第 {index + 2} 行：数据格式错误 - {str(e)}'
                    print(f'错误: {error_msg}')
                    errors.append(error_msg)
                    continue
                
                # 处理颜色和库存
                colors = str(row['颜色']).split(',') if not pd.isna(row['颜色']) else []
                stocks = str(row['库存']).split(',') if not pd.isna(row['库存']) else []
                print(f'解析的颜色: {colors}')
                print(f'解析的库存: {stocks}')
                
                # 确保颜色和库存数量匹配
                if len(colors) != len(stocks):
                    error_msg = f'第 {index + 2} 行：颜色和库存数量不匹配'
                    print(f'错误: {error_msg}')
                    errors.append(error_msg)
                    continue
                
                # 处理可能的空字符串
                colors = [c.strip() for c in colors if c.strip()]
                stocks = [s.strip() for s in stocks if s.strip()]
                
                specs = []
                for color, stock in zip(colors, stocks):
                    try:
                        stock_value = int(float(stock)) if stock.strip() else 0
                        if stock_value < 0:
                            print(f'警告: 第 {index + 2} 行，颜色 {color} 的库存为负数，已设为0')
                            stock_value = 0
                        specs.append({
                            'color': color.strip(),
                            'stock': stock_value
                        })
                    except ValueError:
                        print(f'警告: 第 {index + 2} 行，颜色 {color} 的库存 "{stock}" 无效，已设为0')
                        specs.append({
                            'color': color.strip(),
                            'stock': 0
                        })
                
                product_data['specs'] = json.dumps(specs)
                
                # 处理标签
                tags = [tag.strip() for tag in str(row['标签']).split(',')] if not pd.isna(row['标签']) else []
                product_data['tags'] = json.dumps(tags)
                print(f'解析的标签: {tags}')
                
                product_data['created_at'] = datetime.now().isoformat()
                
                # 检查商品是否已存在
                existing_product = Product.query.get(product_data['id'])
                if existing_product:
                    print('更新现有商品...')
                    existing_product.name = product_data['name']
                    existing_product.description = product_data['description']
                    existing_product.price = product_data['price']
                    existing_product.specs = product_data['specs']
                    existing_product.type = product_data['type']
                    existing_product.tags = product_data['tags']
                    db.session.commit()
                else:
                    print('插入新商品...')
                    new_product = Product(
                        id=product_data['id'],
                        name=product_data['name'],
                        description=product_data['description'],
                        price=product_data['price'],
                        specs=product_data['specs'],
                        type=product_data['type'],
                        tags=product_data['tags'],
                        created_at=product_data['created_at']
                    )
                    db.session.add(new_product)
                    db.session.commit()
                
                imported_count += 1
                print(f'成功处理第 {index + 2} 行数据')
                
            except Exception as e:
                error_msg = f'第 {index + 2} 行：{str(e)}'
                print(f'错误: {error_msg}')
                errors.append(error_msg)
                
        print(f'\n导入完成: 成功导入 {imported_count} 条数据，失败 {len(errors)} 条')
            
        return jsonify({
            'success': True,
            'imported': imported_count,
            'errors': errors if errors else None
        })
        
    except Exception as e:
        print(f'导入过程发生错误: {str(e)}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# 添加模板下载路由
@app.route('/static/templates/products_template.xlsx')
def download_template():
    try:
        return send_file(
            'static/templates/products_template.xlsx',
            as_attachment=True,
            download_name='商品导入模板.xlsx'
        )
    except Exception as e:
        return jsonify({'error': '模板文件不存在'}), 404

# 添加创建模板的函数
def create_template():
    import pandas as pd
    
    # 创建示例数据
    data = {
        '款号': ['A001', 'A002'],
        '商品名称': ['羊毛围巾-灰色', '羊毛围巾-黑色'],
        '价格': [299, 299],
        '描述': ['100%羊毛，柔软保暖', '100%羊毛，经典黑色'],
        '款式': [1, 1],  # 1代表围巾
        '颜色': ['灰色,黑色', '黑色,灰色'],  # 用逗号分隔多个颜色
        '库存': ['10,5', '8,3'],  # 对应颜色的库存数量
        '标签': ['羊毛,保暖,围巾', '羊毛,经典,围巾']  # 用逗号分隔多个标签
    }
    
    df = pd.DataFrame(data)
    
    # 确保目录存在
    os.makedirs('static/templates', exist_ok=True)
    
    # 保存为Excel文件
    template_path = 'static/templates/products_template.xlsx'
    writer = pd.ExcelWriter(template_path, engine='openpyxl')
    
    # 写入数据
    df.to_excel(writer, index=False, sheet_name='商品数据')
    
    # 获取工作表
    worksheet = writer.sheets['商品数据']
    
    # 添加说明
    notes = {
        'A1': '商品唯一标识，必填',
        'B1': '商品名称，必填',
        'C1': '商品价格，可选（默认0）',
        'D1': '商品描述，可选',
        'E1': '款式：1=围巾，2=帽子，3=手套（默认1）',
        'F1': '颜色：多个颜色用英文逗号分隔',
        'G1': '库存：与颜色一一对应，用英文逗号分隔',
        'H1': '标签：多个标签用英文逗号分隔'
    }
    
    # 设置列宽
    worksheet.column_dimensions['A'].width = 15
    worksheet.column_dimensions['B'].width = 20
    worksheet.column_dimensions['C'].width = 10
    worksheet.column_dimensions['D'].width = 30
    worksheet.column_dimensions['E'].width = 10
    worksheet.column_dimensions['F'].width = 20
    worksheet.column_dimensions['G'].width = 20
    worksheet.column_dimensions['H'].width = 30
    
    # 添加批注
    for cell, note in notes.items():
        worksheet[cell].comment = openpyxl.comments.Comment(note, 'System')
    
    writer.close()
    print(f'模板文件已创建: {template_path}')

# 数据统计接口
@app.route('/statistics', methods=['GET'])
@login_required
def get_statistics(user_id):
    try:
        # 获取时间范围参数
        time_range = request.args.get('range', 'all')  # all, today, week, month
        
        # 构建时间过滤条件
        if time_range == 'today':
            time_filter = func.date(PurchaseOrder.created_at) == func.current_date()
        elif time_range == 'week':
            time_filter = PurchaseOrder.created_at >= func.date_sub(func.current_date(), func.interval(7, 'DAY'))
        elif time_range == 'month':
            time_filter = PurchaseOrder.created_at >= func.date_sub(func.current_date(), func.interval(30, 'DAY'))
        else:
            time_filter = True

        # 获取总体统计数据
        summary = db.session.query(
            func.count(distinct(PurchaseOrder.id)).label('total_orders'),
            func.sum(PurchaseOrder.total_amount).label('total_amount'),
            func.sum(PurchaseOrderItem.quantity).label('total_quantity'),
            func.count(distinct(PurchaseOrderItem.product_id)).label('total_products'),
            func.count(distinct(ProductView.id)).label('total_views'),
            func.count(distinct(ProductView.product_id)).label('viewed_products')
        ).join(
            PurchaseOrderItem, PurchaseOrder.id == PurchaseOrderItem.order_id
        ).outerjoin(
            ProductView, PurchaseOrderItem.product_id == ProductView.product_id
        ).filter(
            time_filter,
            PurchaseOrder.status != 2
        ).first()
        
        # 获取商品浏览统计
        top_viewed = db.session.query(
            Product.id,
            Product.name,
            func.count(ProductView.id).label('view_count')
        ).outerjoin(
            ProductView, Product.id == ProductView.product_id
        ).filter(
            time_filter
        ).group_by(
            Product.id, Product.name
        ).order_by(
            func.count(ProductView.id).desc()
        ).limit(10).all()

        top_viewed_data = [{
            'id': row.id,
            'name': row.name,
            'view_count': row.view_count
        } for row in top_viewed]
        
        # 获取采购统计
        top_purchased = db.session.query(
            Product.id,
            Product.name,
            func.count(distinct(PurchaseOrder.id)).label('order_count'),
            func.sum(PurchaseOrderItem.quantity).label('total_quantity'),
            func.sum(PurchaseOrderItem.quantity * PurchaseOrderItem.price).label('total_amount'),
            PurchaseOrderItem.color,
            func.sum(case((PurchaseOrderItem.color != None, PurchaseOrderItem.quantity), else_=0)).label('color_quantity')
        ).join(
            PurchaseOrderItem, Product.id == PurchaseOrderItem.product_id
        ).join(
            PurchaseOrder, PurchaseOrderItem.order_id == PurchaseOrder.id
        ).filter(
            time_filter,
            PurchaseOrder.status != 2
        ).group_by(
            Product.id, Product.name, PurchaseOrderItem.color
        ).order_by(
            func.sum(PurchaseOrderItem.quantity).desc()
        ).limit(10).all()
        
        current_product = None
        top_purchased_data = []
        color_stats = {}
        
        for row in top_purchased:
            product_id = row.id
            
            if current_product != product_id:
                if current_product is not None:
                    product_data['color_stats'] = color_stats
                    top_purchased_data.append(product_data)
                
                current_product = product_id
                color_stats = {}
                product_data = {
                    'id': product_id,
                    'name': row.name,
                    'order_count': row.order_count or 0,
                    'total_quantity': row.total_quantity or 0,
                    'total_amount': float(row.total_amount or 0)
                }
            
            if row.color:
                color_stats[row.color] = row.color_quantity
        
        if current_product is not None:
            product_data['color_stats'] = color_stats
            top_purchased_data.append(product_data)
        
        return jsonify({
            'summary': {
                'total_orders': summary.total_orders or 0,
                'total_amount': summary.total_amount or 0,
                'total_quantity': summary.total_quantity or 0,
                'total_products': summary.total_products or 0,
                'total_views': summary.total_views or 0,
                'viewed_products': summary.viewed_products or 0
            },
            'top_viewed': top_viewed_data,
            'top_purchased': top_purchased_data,
            'time_range': time_range,
            'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }), 200
        
    except Exception as e:
        print(f'获取统计数据失败: {str(e)}')
        return jsonify({'error': '获取统计数据失败'}), 500

# 辅助函数：处理采购统计数据
def process_top_purchased(data):
    result = []
    current_product = None
    product_data = None
    color_stats = {}
    
    for row in data:
        product_id = row.id
        
        if current_product != product_id:
            if current_product is not None:
                product_data['color_stats'] = color_stats
                result.append(product_data)
                
            current_product = product_id
            color_stats = {}
            product_data = {
                'id': product_id,
                'name': row.name,
                'order_count': row.order_count or 0,
                'total_quantity': row.total_quantity or 0,
                'total_amount': float(row.total_amount or 0)
            }
        
        if row.color:
            color_stats[row.color] = row.color_quantity
    
    if current_product is not None:
        product_data['color_stats'] = color_stats
        result.append(product_data)
    
    return result

# 添加记录商品访问的接口
@app.route('/products/<product_id>/view', methods=['POST'])
def record_product_view(product_id):
    try:
        user_id = None
        token = request.headers.get('Authorization')
        if token:
            user_id = verify_token(token)
            
        new_view = ProductView(
            product_id=product_id,
            view_time=datetime.now(),
            ip_address=request.remote_addr,
            user_id=user_id
        )
        db.session.add(new_view)
        db.session.commit()
            
        return jsonify({'message': '访问记录已保存'}), 200
        
    except Exception as e:
        print(f'记录访问失败: {str(e)}')
        return jsonify({'error': '记录访问失败'}), 500

# 添加采购单接口
@app.route('/purchase_orders', methods=['POST'])
@login_required
def create_purchase_order(user_id):
    try:
        data = request.json
        if not data or 'items' not in data:
            return jsonify({'error': '无效的请求数据'}), 400
        
        # 生成订单号
        order_number = datetime.now().strftime('%Y%m%d%H%M%S') + str(random.randint(1000, 9999))
        
        # 计算总金额
        total_amount = sum(item.get('price', 0) * item.get('quantity', 0) for item in data['items'])
        
        # 创建采购单
        purchase_order = PurchaseOrder(
            order_number=order_number,
            user_id=user_id,
            total_amount=total_amount,
            status=0,  # 初始状态：待处理
            remark=data.get('remark', ''),
            created_at=datetime.now()
        )
        
        db.session.add(purchase_order)
        db.session.flush()  # 立即刷新会话，获取新创建的 ID
        
        # 添加采购明细
        for item in data['items']:
            order_item = PurchaseOrderItem(
                order_id=purchase_order.id,  # 现在可以安全地使用 ID
                product_id=item['product_id'],
                quantity=item['quantity'],
                price=item['price'],
                color=item.get('color', '')
            )
            db.session.add(order_item)

        # 提交事务
        db.session.commit()
        
        return jsonify({
            'message': '采购单创建成功',
            'order_id': purchase_order.id,
            'order_number': order_number
        }), 201
        
    except Exception as e:
        db.session.rollback()
        print(f'创建采购单失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '创建采购单失败'}), 500

# 获取采购单列表
@app.route('/purchase_orders', methods=['GET'])
@login_required
def get_purchase_orders(user_id):
    try:
        print(f"开始获取采购单列表 - 用户ID: {user_id}")
        
        # 获取分页参数
        page = int(request.args.get('page', 1))
        page_size = min(int(request.args.get('page_size', 10)), 50)
        status = request.args.get('status')
        date_range = request.args.get('date_range')
        
        # 获取当前用户信息
        current_user = User.query.get(user_id)
        
        # 构建查询，加入用户信息
        query = db.session.query(PurchaseOrder, User).join(
            User, PurchaseOrder.user_id == User.id
        )
        print(f"当前用户信息: {current_user.user_type}")
        # 如果不是管理员，限制只能查看自己的订单
        if current_user.user_type != 1:  # 假设 1 表示管理员
            query = query.filter(PurchaseOrder.user_id == user_id)
        
        print(f"基础查询构建完成: {str(query)}")

        # 添加筛选条件
        if status:
            query = query.filter(PurchaseOrder.status == status)
            
        if date_range:
            query = query.filter(PurchaseOrder.created_at.between(date_range[0], date_range[1]))

        # 按创建时间倒序排序
        query = query.order_by(PurchaseOrder.created_at.desc())
        
        # 执行分页
        pagination = query.paginate(page=page, per_page=page_size)
        
        # 构建返回数据
        orders = []
        print("开始处理订单数据...")
        
        for order, user in pagination.items:
            try:
                # 获取订单明细
                order_items = db.session.query(PurchaseOrderItem).filter(
                    PurchaseOrderItem.order_id == order.id
                ).all()
                print(f"获取到订单 {order.id} 的明细数量: {len(order_items)}")
                
                # 使用字典来临时存储合并的商品数据
                merged_products = {}
                
                for item in order_items:
                    try:
                        product = Product.query.get(item.product_id)
                        print(f"获取商品信息: product_id={item.product_id}, found={product is not None}")
                        
                        if not product:
                            continue
                            
                        # 使用商品ID作为键
                        if item.product_id not in merged_products:
                            merged_products[item.product_id] = {
                                'id': product.id,
                                'product_id': product.id,
                                'product_name': product.name,
                                'image': json.loads(product.images)[0] if product.images else None,
                                'total_quantity': 0,
                                'total_amount': 0,                                
                                'specs': []  # 用于存储不同颜色规格的信息
                            }
                        
                        # 添加当前规格信息
                        spec_info = {
                            'color': item.color,
                            'quantity': item.quantity,
                            'price': float(item.price),
                            'subtotal': item.quantity * float(item.price)
                        }
                        merged_products[item.product_id]['specs'].append(spec_info)
                        
                        # 更新总数量和总金额
                        merged_products[item.product_id]['total_quantity'] += item.quantity
                        merged_products[item.product_id]['total_amount'] += spec_info['subtotal']
                        
                    except Exception as e:
                        print(f"处理订单项时出错: {str(e)}")
                        continue
                
                # 将合并后的商品数据转换为列表
                items = list(merged_products.values())
                
                # 添加用户信息到订单数据
                order_data = {
                    'id': order.id,
                    'order_number': order.order_number,
                    'total_amount': float(order.total_amount),
                    'total_quantity': sum(item['total_quantity'] for item in merged_products.values()),
                    'status': order.status,
                    'remark': order.remark,
                    'created_at': order.created_at.isoformat() if order.created_at else None,
                    'items': items,
                    'user': {
                        'id': user.id,
                        'username': user.username,
                        'nickname': user.nickname,
                        'avatar': user.avatar,
                        'phone': user.phone
                    }
                }
                orders.append(order_data)
                print(f"订单 {order.id} 处理完成")
                
            except Exception as e:
                print(f"处理订单 {order.id} 时出错: {str(e)}")
                continue
            
            return jsonify({
                'orders': orders,
            'total': pagination.total,
            'pages': pagination.pages,
            'current_page': page
            }), 200
            
    except Exception as e:
        print(f'获取采购单列表失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '获取采购单列表失败'}), 500

# 更新采购单状态
@app.route('/purchase_orders/<int:order_id>', methods=['PUT'])
@login_required
def update_purchase_order(user_id, order_id):
    try:
        data = request.json
        new_status = data.get('status')
        
        if new_status is None:
            return jsonify({'error': '缺少状态参数'}), 400
            
        if new_status not in [0, 1, 2]:  # 0:待处理 1:已处理 2:已取消
            return jsonify({'error': '无效的状态值'}), 400
            
        # 获取采购单
        order = PurchaseOrder.query.get(order_id)
        if not order:
                return jsonify({'error': '采购单不存在'}), 404
                
            # 更新状态
        order.status = new_status
        
        try:
            db.session.commit()
            return jsonify({'message': '采购单状态更新成功'}), 200
        except Exception as e:
            db.session.rollback()
            print(f'更新采购单状态失败: {str(e)}')
            return jsonify({'error': '更新采购单状态失败'}), 500
            
    except Exception as e:
        print(f'处理采购单状态更新请求失败: {str(e)}')
        return jsonify({'error': '更新采购单状态失败'}), 500


# 添加用户管理相关接口
@app.route('/users', methods=['GET'])
@login_required
def get_users(user_id):
    try:
        # 检查权限
        current_user = User.query.get(user_id)
        if not current_user or current_user.user_type != 1:
            return jsonify({'error': '无权限访问'}), 403

        # 获取查询参数
        page = int(request.args.get('page', 1))
        page_size = min(int(request.args.get('page_size', 10)), 50)
        keyword = request.args.get('keyword', '').strip()
        status = request.args.get('status')
        
        # 构建基础查询
        query = User.query.filter(User.user_type == 0)
        
        # 添加筛选条件
        if keyword:
            search = f'%{keyword}%'
            query = query.filter(db.or_(
                User.username.like(search),
                User.nickname.like(search),
                User.phone.like(search)
            ))
            
        if status is not None:
            query = query.filter(User.status == int(status))
            
        # 获取分页数据
        paginated_users = query.order_by(User.created_at.desc())\
            .paginate(page=page, per_page=page_size, error_out=False)
            
        # 格式化返回数据
        users = [{
            'id': user.id,
            'username': user.username,
            'nickname': user.nickname,
            'phone': user.phone,
            'address': user.address,
            'contact': user.contact,
            'user_type': user.user_type,
            'status': user.status,
            'created_at': user.created_at.isoformat() if user.created_at else None,
            'avatar': user.avatar,
            'last_login': user.last_login.isoformat() if user.last_login else None
        } for user in paginated_users.items]

        return jsonify({
            'users': users,
            'total': paginated_users.total,
            'page': page,
            'page_size': page_size,
            'total_pages': paginated_users.pages
        }), 200

    except Exception as e:
        print(f'获取用户列表失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '获取用户列表失败'}), 500

# 更新用户状态
@app.route('/users/<int:target_user_id>/status', methods=['PUT'])
@login_required
def update_user_status(user_id, target_user_id):
    try:
        # 检查权限
        current_user = User.query.get(user_id)
        if not current_user or current_user.user_type != 1:
            return jsonify({'error': '无权限执行此操作'}), 403

            data = request.json
        new_status = data.get('status')
        
        if new_status not in [0, 1]:  # 0:禁用 1:启用
            return jsonify({'error': '无效的状态值'}), 400
            
        # 获取目标用户
        target_user = User.query.get(target_user_id)
        if not target_user:
            return jsonify({'error': '用户不存在'}), 404
            
        # 不能修改管理员状态
        if target_user.user_type == 1:
            return jsonify({'error': '不能修改管理员状态'}), 400
            
        # 更新状态
        target_user.status = new_status
        
        try:
            db.session.commit()
            return jsonify({'message': '用户状态更新成功'}), 200
        except Exception as e:
            db.session.rollback()
            print(f'更新用户状态失败: {str(e)}')
            return jsonify({'error': '更新用户状态失败'}), 500

    except Exception as e:
        print(f'处理用户状态更新请求失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '更新用户状态失败'}), 500

# 获取当前用户信息
@app.route('/user/profile', methods=['GET'])
@login_required
def get_user_profile(user_id):
    try:
        print(f'开始获取用户信息, user_id: {user_id}')
        
        user = User.query.get(user_id)
        if not user:
            print(f'用户不存在: {user_id}')
            return jsonify({'error': '用户不存在'}), 404
        
        user_info = {
            'id': user.id,
            'username': user.username,
            'nickname': user.nickname,
            'phone': user.phone,
            'address': user.address,
            'contact': user.contact,
            'avatar': user.avatar,
            'user_type': user.user_type
        }
        print(f'获取用户信息成功: {user_info}')
        return jsonify({'user': user_info}), 200
        
    except Exception as e:
        print(f'获取用户信息失败: {str(e)}')
        print(f'错误类型: {type(e).__name__}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '获取用户信息失败'}), 500

# 更新当前用户信息
@app.route('/user/profile', methods=['PUT'])
@login_required
def update_user_profile(user_id):
    try:
        print(f'开始更新用户信息, user_id: {user_id}')
        data = request.json
        print(f'接收到的更新数据: {data}')
        
        allowed_fields = ['nickname', 'phone', 'address', 'contact', 'avatar']
        update_data = {}

        for field in allowed_fields:
            if field in data:
                update_data[field] = data[field]
                print(f'更新字段 {field}: {data[field]}')

        if not update_data:
            print('没有要更新的字段')
            return jsonify({'error': '没有要更新的字段'}), 400

        # 使用SQLAlchemy进行更新
        user = User.query.get(user_id)
        if not user:
            print(f'用户不存在: {user_id}')
            return jsonify({'error': '用户不存在'}), 404

        for field, value in update_data.items():
            setattr(user, field, value)

        db.session.commit()

        # 获取更新后的用户信息
        updated_user = User.query.get(user_id)
        user_info = {
            'id': updated_user.id,
            'username': updated_user.username,
            'nickname': updated_user.nickname,
            'phone': updated_user.phone,
            'address': updated_user.address,
            'contact': updated_user.contact,
            'avatar': updated_user.avatar,
            'user_type': updated_user.user_type
        }
        print(f'更新后的用户信息: {user_info}')

        return jsonify({
            'message': '个人信息更新成功',
            'user': user_info
        }), 200

    except Exception as e:
        print(f'更新用户信息失败: {str(e)}')
        print(f'错误类型: {type(e).__name__}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '更新用户信息失败'}), 500



# 创建配送单
@app.route('/delivery_orders', methods=['POST'])
@login_required
def create_delivery_order(user_id):
    try:
        data = request.json
        if not data:
            return jsonify({'error': '无效的请求数据'}), 400
        
        # 验证必要字段
        required_fields = ['customer_name', 'customer_phone', 'delivery_address', 'items']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'缺少必要字段: {field}'}), 400
        
        # 生成订单号
        order_number = 'D' + datetime.now().strftime('%Y%m%d%H%M%S') + str(random.randint(1000, 9999))
        
        # 创建配送单
        delivery_order = DeliveryOrder(
            order_number=order_number,
            customer_name=data['customer_name'],
            customer_phone=data['customer_phone'],
            delivery_address=data['delivery_address'],
            delivery_date=data.get('delivery_date'),
            delivery_time_slot=data.get('delivery_time_slot'),
            status=0,  # 待配送
            remark=data.get('remark', ''),
            created_by=user_id,
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        
        db.session.add(delivery_order)
        
        # 添加配送商品
        for item in data['items']:
            delivery_item = DeliveryItem(
                delivery_id=delivery_order.id,
                product_id=item['product_id'],
                quantity=item['quantity'],
                color=item.get('color', '')
            )
            db.session.add(delivery_item)

        try:
            db.session.commit()
            return jsonify({
                'message': '配送单创建成功',
                'order_id': delivery_order.id,
                'order_number': order_number
            }), 201
        except Exception as e:
            db.session.rollback()
            print(f'保存配送单失败: {str(e)}')
            return jsonify({'error': '创建配送单失败'}), 500
            
    except Exception as e:
        print(f'创建配送单失败: {str(e)}')
        return jsonify({'error': '创建配送单失败'}), 500

# 获取配送单列表
@app.route('/delivery_orders', methods=['GET'])
@login_required
def get_delivery_orders(user_id):
    try:
        # 获取查询参数
        page = int(request.args.get('page', 1))
        page_size = min(int(request.args.get('page_size', 10)), 50)
        status = request.args.get('status')
        keyword = request.args.get('keyword', '').strip()
        date_range = request.args.get('date_range', '').split(',')
        
        # 检查用户类型
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': '用户不存在'}), 404
            
        # 构建基础查询
        query = DeliveryOrder.query\
            .outerjoin(User, DeliveryOrder.created_by == User.id)\
            .outerjoin(DeliveryItem)\
            .outerjoin(Product, DeliveryItem.product_id == Product.id)
            
        # 非管理员只能查看自己创建的订单
        if user.user_type != 1:
            query = query.filter(DeliveryOrder.created_by == user_id)
            
        # 状态筛选
        if status is not None and status.strip():
            query = query.filter(DeliveryOrder.status == int(status))
            
        # 关键字搜索
        if keyword:
            search = f'%{keyword}%'
            query = query.filter(db.or_(
                DeliveryOrder.order_number.like(search),
                DeliveryOrder.customer_name.like(search),
                DeliveryOrder.customer_phone.like(search),
                DeliveryOrder.delivery_address.like(search),
                Product.name.like(search)
            ))
            
        # 日期范围筛选
        if len(date_range) == 2 and date_range[0] and date_range[1]:
            query = query.filter(
                DeliveryOrder.created_at.between(date_range[0], date_range[1])
            )
            
        # 获取分页数据
        paginated_orders = query.order_by(DeliveryOrder.created_at.desc())\
            .paginate(page=page, per_page=page_size, error_out=False)
            
        orders = []
        for order in paginated_orders.items:
            # 获取订单明细
            items = []
            for item in order.items:
                product = Product.query.get(item.product_id)
                if product:
                    items.append({
                        'id': item.id,
                        'product_id': item.product_id,
                        'product_name': product.name,
                        'quantity': item.quantity,
                        'color': item.color,
                        'image': json.loads(product.images)[0] if product.images else None
                    })
                    
            orders.append({
                'id': order.id,
                'order_number': order.order_number,
                'customer_name': order.customer_name,
                'customer_phone': order.customer_phone,
                'delivery_address': order.delivery_address,
                'delivery_date': order.delivery_date,
                'delivery_time_slot': order.delivery_time_slot,
                'status': order.status,
                'remark': order.remark,
                'created_at': order.created_at.isoformat(),
                'updated_at': order.updated_at.isoformat(),
                'created_by': order.created_by,
                'delivery_by': order.delivery_by,
                'delivery_image': json.loads(order.delivery_image) if order.delivery_image else [],
                'items': items
            })
            
        return jsonify({
                'orders': orders,
            'total': paginated_orders.total,
                'page': page,
            'page_size': page_size,
            'total_pages': paginated_orders.pages
        }), 200
            
    except Exception as e:
        print(f'获取配送单列表失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '获取配送单列表失败'}), 500

# 获取配送单详情
@app.route('/delivery_orders/<int:order_id>', methods=['GET'])
@login_required
def get_delivery_order_detail(user_id, order_id):
    try:
        # 获取配送单及相关信息
        order = DeliveryOrder.query\
            .join(User, DeliveryOrder.created_by == User.id)\
            .filter(DeliveryOrder.id == order_id)\
            .first()
        
        if not order:
            return jsonify({'error': '配送单不存在'}), 404

        # 检查权限（非管理员只能查看自己创建的订单）
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': '用户不存在'}), 404

        if user.user_type != 1 and order.created_by != user_id:
            return jsonify({'error': '无权限查看此配送单'}), 403

        # 获取配送商品列表
        items = []
        for item in order.items:
            product = Product.query.get(item.product_id)
            if product:
                items.append({
                    'id': item.id,
                    'product_id': item.product_id,
                    'product_name': product.name,
                    'quantity': item.quantity,
                    'color': item.color,
                    'image': json.loads(product.images)[0] if product.images else None
                })

        # 获取创建者和配送员信息
        creator = User.query.get(order.created_by)
        delivery_user = User.query.get(order.delivery_by) if order.delivery_by else None

        # 格式化返回数据
        order_detail = {
            'id': order.id,
            'order_number': order.order_number,
            'customer_name': order.customer_name,
            'customer_phone': order.customer_phone,
            'delivery_address': order.delivery_address,
            'delivery_date': order.delivery_date,
            'delivery_time_slot': order.delivery_time_slot,
            'status': order.status,
            'remark': order.remark,
            'created_at': order.created_at.isoformat(),
            'updated_at': order.updated_at.isoformat(),
            'creator': {
                'id': creator.id,
                'username': creator.username,
                'nickname': creator.nickname
            } if creator else None,
            'delivery_user': {
                'id': delivery_user.id,
                'username': delivery_user.username,
                'nickname': delivery_user.nickname
            } if delivery_user else None,
            'delivery_image': json.loads(order.delivery_image) if order.delivery_image else [],
            'items': items
        }

        return jsonify({'order': order_detail}), 200

    except Exception as e:
        print(f'获取配送单详情失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '获取配送单详情失败'}), 500

# 更新配送单状态
@app.route('/delivery_orders/<int:order_id>/status', methods=['PUT'])
@login_required
def update_delivery_status(user_id, order_id):
    try:
        data = request.json
        new_status = data.get('status')
        
        if new_status not in [0, 1, 2, 3]:
            return jsonify({'error': '无效的状态值'}), 400
            
        # 使用SQLAlchemy进行数据库操作
        order = DeliveryOrder.query.get(order_id)
        if not order:
            return jsonify({'error': '配送单不存在'}), 404
        
        order.status = new_status
        order.updated_at = datetime.now()
        if new_status == 1:
            order.delivery_by = user_id
        
        db.session.commit()
        
        return jsonify({'message': '配送单状态更新成功'}), 200
            
    except Exception as e:
        db.session.rollback()
        print(f'更新配送单状态失败: {str(e)}')
        return jsonify({'error': '更新配送单状态失败'}), 500


# 获取配送单统计数据
@app.route('/delivery_orders/stats', methods=['GET'])
@login_required
def get_delivery_orders_stats(user_id):
    try:
        print('='*50)
        print('开始获取配送单统计数据')
        print('='*50)
        
        # 使用SQLAlchemy进行数据库操作
        total = db.session.query(func.count(DeliveryOrder.id)).scalar()
        pending = db.session.query(func.count(DeliveryOrder.id)).filter(DeliveryOrder.status == 0).scalar()
        delivering = db.session.query(func.count(DeliveryOrder.id)).filter(DeliveryOrder.status == 1).scalar()
        completed = db.session.query(func.count(DeliveryOrder.id)).filter(DeliveryOrder.status == 2).scalar()
        cancelled = db.session.query(func.count(DeliveryOrder.id)).filter(DeliveryOrder.status == 3).scalar()
        
        stats = {
            'total': total or 0,
            'pending': pending or 0,
            'delivering': delivering or 0,
            'completed': completed or 0,
            'cancelled': cancelled or 0
        }
        
        print('统计数据:', json.dumps(stats, indent=2))
        
        return jsonify({
            'data': stats,
            'code': 200,
            'msg': 'success'
        }), 200
            
    except Exception as e:
        print('\n获取统计数据失败:')
        print(f'错误类型: {type(e).__name__}')
        print(f'错误信息: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({
            'code': 500,
            'msg': '获取统计数据失败',
            'data': None
        }), 500


# 上传配送单底图
@app.route('/delivery_orders/<int:order_id>/image', methods=['POST'])
@login_required
def upload_delivery_image(user_id, order_id):
    try:
        print('='*50)
        print('开始上传配送单底图')
        print(f'订单ID: {order_id}')
        
        if 'file' not in request.files:
            return jsonify({'error': '没有文件'}), 400
            
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': '没有选择文件'}), 400
            
        if file and allowed_file(file.filename):
            try:
                # 生成文件名：delivery_订单ID_时间戳.扩展名
                filename = secure_filename(file.filename)
                file_ext = filename.rsplit('.', 1)[1].lower()
                unique_filename = f"delivery_{order_id}_{int(time.time())}.{file_ext}"
                
                # 确保上传目录存在
                if not os.path.exists(app.config['UPLOAD_FOLDER']):
                    os.makedirs(app.config['UPLOAD_FOLDER'])
                
                # 保存文件
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(file_path)
                
                # 生成访问URL
                file_url = f"/uploads/{unique_filename}"
                
                # 更新数据库
                delivery_order = DeliveryOrder.query.get(order_id)
                
                if delivery_order:
                    # 解析现有图片列表并添加新图片
                    current_images = json.loads(delivery_order.delivery_image or '[]')
                    current_images.append(file_url)
                    
                    # 更新数据库
                    delivery_order.delivery_image = json.dumps(current_images)
                    delivery_order.updated_at = datetime.now()
                    
                    db.session.commit()
                
                    return jsonify({
                        'message': '底图上传成功',
                        'url': file_url
                    }), 200
                else:
                    return jsonify({
                        'error': '配送单不存在',
                        'url': file_url
                    }), 201
                
            except Exception as e:
                db.session.rollback()
                print(f'保存文件失败: {str(e)}')
                return jsonify({'error': f'文件保存失败: {str(e)}'}), 500
                
        return jsonify({'error': '不允许的文件类型'}), 400
        
    except Exception as e:
        print(f'上传底图失败: {str(e)}')
        return jsonify({'error': '上传底图失败'}), 500

# 获取采购单统计数据
@app.route('/purchase_orders/stats', methods=['GET'])
@login_required
def get_purchase_orders_stats(user_id):
    try:
        # 检查用户类型
        user = User.query.get(user_id)
        user_type = user.user_type
        
        # 构建基础查询条件
        query = db.session.query(
            func.count(distinct(PurchaseOrder.id)).label('total_orders'),
            func.sum(PurchaseOrder.total_amount).label('total_amount'),
            func.sum(func.case([(PurchaseOrder.status == 0, 1)], else_=0)).label('pending_count'),
            func.sum(func.case([(PurchaseOrder.status == 1, 1)], else_=0)).label('processed_count'),
            func.sum(func.case([(PurchaseOrder.status == 2, 1)], else_=0)).label('cancelled_count'),
            func.sum(func.case([(PurchaseOrder.status == 0, PurchaseOrder.total_amount)], else_=0)).label('pending_amount'),
            func.sum(func.case([(PurchaseOrder.status == 1, PurchaseOrder.total_amount)], else_=0)).label('processed_amount'),
            func.sum(func.case([(PurchaseOrder.status == 2, PurchaseOrder.total_amount)], else_=0)).label('cancelled_amount'),
            func.sum(PurchaseOrderItem.quantity).label('total_quantity')
        ).join(
            PurchaseOrderItem, PurchaseOrder.id == PurchaseOrderItem.order_id
        )
        
        # 非管理员只能看到自己的数据
        if user_type != 1:
            query = query.filter(PurchaseOrder.user_id == user_id)
        
        basic_stats = query.one()
        
        # 获取最近30天的每日统计
        daily_stats = db.session.query(
            func.date(PurchaseOrder.created_at).label('date'),
            func.count(distinct(PurchaseOrder.id)).label('order_count'),
            func.sum(PurchaseOrder.total_amount).label('daily_amount'),
            func.sum(PurchaseOrderItem.quantity).label('daily_quantity')
        ).join(
            PurchaseOrderItem, PurchaseOrder.id == PurchaseOrderItem.order_id
        ).filter(
            PurchaseOrder.created_at >= func.date_sub(func.current_date(), func.interval(30, 'DAY'))
        ).group_by(
            func.date(PurchaseOrder.created_at)
        ).order_by(
            func.date(PurchaseOrder.created_at).desc()
        ).all()
        
        daily_stats_data = [{
            'date': stat.date,
            'order_count': stat.order_count or 0,
            'amount': stat.daily_amount or 0,
            'quantity': stat.daily_quantity or 0
        } for stat in daily_stats]
        
        # 获取商品采购排行
        top_purchased = db.session.query(
            Product.id,
            Product.name,
            func.count(distinct(PurchaseOrder.id)).label('order_count'),
            func.sum(PurchaseOrderItem.quantity).label('total_quantity'),
            func.sum(PurchaseOrderItem.quantity * PurchaseOrderItem.price).label('total_amount'),
            PurchaseOrderItem.color,
            func.sum(func.case([(PurchaseOrderItem.color != None, PurchaseOrderItem.quantity)], else_=0)).label('color_quantity')
        ).join(
            PurchaseOrderItem, Product.id == PurchaseOrderItem.product_id
        ).join(
            PurchaseOrder, PurchaseOrderItem.order_id == PurchaseOrder.id
        ).filter(
            PurchaseOrder.status != 2  # 排除已取消的订单
        ).group_by(
            Product.id, Product.name, PurchaseOrderItem.color
        ).order_by(
            func.sum(PurchaseOrderItem.quantity).desc()
        ).all()
        
        current_product = None
        top_purchased_data = []
        color_stats = {}
        
        for row in top_purchased:
            product_id = row.id
            
            if current_product != product_id:
                if current_product is not None:
                    product_data['color_stats'] = color_stats
                top_purchased_data.append(product_data)
                
                current_product = product_id
                color_stats = {}
                product_data = {
                    'id': product_id,
                    'name': row.name,
                    'order_count': row.order_count or 0,
                    'total_quantity': row.total_quantity or 0,
                    'total_amount': float(row.total_amount or 0)
                }
            
            if row.color:
                color_stats[row.color] = row.color_quantity
        
        if current_product is not None:
            product_data['color_stats'] = color_stats
        top_purchased_data.append(product_data)
        
        return jsonify({
            'basic': {
                'total_orders': basic_stats.total_orders or 0,
                'total_amount': basic_stats.total_amount or 0,
                'total_quantity': basic_stats.total_quantity or 0,
                'status_count': {
                    'pending': basic_stats.pending_count or 0,
                    'processed': basic_stats.processed_count or 0,
                    'cancelled': basic_stats.cancelled_count or 0
                },
                'status_amount': {
                    'pending': basic_stats.pending_amount or 0,
                    'processed': basic_stats.processed_amount or 0,
                    'cancelled': basic_stats.cancelled_amount or 0
                }
            },
            'daily': daily_stats_data,
            'products': top_purchased_data,
            'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }), 200
        
    except Exception as e:
        print(f'获取采购单统计数据失败: {str(e)}')
        return jsonify({'error': '获取统计数据失败'}), 500

# 修改商品销量统计查询
@app.route('/products/sales', methods=['GET'])
@login_required
def get_product_sales(user_id):
    try:
        # 使用 SQLAlchemy 查询
        results = db.session.query(
            Product.id,
            Product.name,
            func.count(distinct(PurchaseOrder.id)).label('order_count'),
            func.sum(PurchaseOrderItem.quantity).label('total_quantity'),
            func.sum(PurchaseOrderItem.quantity * PurchaseOrderItem.price).label('total_amount'),
            func.json_extract(Product.images, '$[0]').label('image')
        ).outerjoin(
            PurchaseOrderItem, Product.id == PurchaseOrderItem.product_id
        ).outerjoin(
            PurchaseOrder, PurchaseOrderItem.order_id == PurchaseOrder.id
        ).filter(
            PurchaseOrder.status == 1  # 只统计已处理的订单
        ).group_by(
            Product.id
        ).order_by(
            desc('total_quantity')
        ).all()
        
        # 构建返回数据
        sales_data = [{
            'id': result.id,
            'name': result.name,
            'order_count': result.order_count,
            'total_quantity': result.total_quantity,
            'total_amount': float(result.total_amount),
            'image': result.image
        } for result in results]
        
        return jsonify(sales_data), 200
            
    except Exception as e:
        print(f'获取商品销量统计失败: {str(e)}')
        return jsonify({'error': '获取统计数据失败'}), 500

# 接受采购单
@app.route('/purchase_orders/<int:order_id>/accept', methods=['PUT'])
@login_required
def accept_purchase_order(user_id, order_id):
    try:
        # 检查采购单是否存在
        order = PurchaseOrder.query.get(order_id)
        if not order:
            return jsonify({'error': '采购单不存在'}), 404

        if order.status != 0:  # 只有待处理的订单可以接受
            return jsonify({'error': '采购单状态不正确'}), 400

        # 更新采购单状态为已处理(1)
        order.status = 1
        db.session.commit()

        return jsonify({
            'message': '采购单已接受',
            'order_id': order_id
        }), 200

    except Exception as e:
        db.session.rollback()
        print(f'接受采购单失败: {str(e)}')
        return jsonify({'error': '接受采购单失败'}), 500

# 取消采购单
@app.route('/purchase_orders/<int:order_id>/cancel', methods=['PUT'])
@admin_required
def cancel_purchase_order(user_id, order_id):
    try:
        # 检查采购单是否存在和状态
        order = db.session.query(PurchaseOrder, User).join(
            User, PurchaseOrder.user_id == User.id
        ).filter(
            PurchaseOrder.id == order_id
        ).first()

        if not order:
            return jsonify({'error': '采购单不存在'}), 404

        purchase_order, user = order

        # 只有待处理的订单可以取消
        if purchase_order.status != 0:
            return jsonify({'error': '只能取消待处理的采购单'}), 400

        # 更新采购单状态为已取消(2)
        purchase_order.status = 2
        db.session.commit()

        return jsonify({
            'message': '采购单已取消',
            'order_id': order_id
        }), 200

    except Exception as e:
        db.session.rollback()
        print(f'取消采购单失败: {str(e)}')
        return jsonify({'error': '取消采购单失败'}), 500

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

@app.after_request
def add_header(response):
    if response.headers.get('Content-Type', '').startswith('text/plain'):
        if response.headers['Content-Type'] == 'text/plain; charset=utf-8':
            if response.response and response.response[0].decode('utf-8').startswith('export'):
                response.headers['Content-Type'] = 'application/javascript; charset=utf-8'
    return response

# 获取采购单详情
@app.route('/purchase_orders/<int:order_id>', methods=['GET'])
@login_required
def get_purchase_order(user_id, order_id):
    try:
        # 获取采购单及相关信息
        order = PurchaseOrder.query\
            .join(User)\
            .filter(PurchaseOrder.id == order_id)\
            .first()
        
        if not order:
            return jsonify({'error': '采购单不存在'}), 404
        
        # 检查权限（非管理员只能查看自己的订单）
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': '用户不存在'}), 404
        
        if user.user_type != 1 and order.user_id != user_id:
            return jsonify({'error': '无权限查看此采购单'}), 403
        
        # 获取订单明细
        items = []
        for item in order.items:
            product = Product.query.get(item.product_id)
            if product:
                items.append({
                    'id': item.id,
                    'product_id': item.product_id,
                    'product_name': product.name,
                    'quantity': item.quantity,
                    'price': float(item.price),
                    'color': item.color,
                    'image': json.loads(product.images)[0] if product.images else None,
                    'subtotal': item.quantity * float(item.price)
                })
        
        # 格式化返回数据
        order_detail = {
            'id': order.id,
            'order_number': order.order_number,
            'total_amount': float(order.total_amount),
            'status': order.status,
            'created_at': order.created_at.isoformat(),
            'remark': order.remark,
            'user': {
                'id': order.user.id,
                'username': order.user.username,
                'nickname': order.user.nickname,
                'phone': order.user.phone,
                'address': order.user.address,
                'contact': order.user.contact
            },
            'items': items
        }
        
        return jsonify({'order': order_detail}), 200
    
    except Exception as e:
        print(f'获取采购单详情失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '获取采购单详情失败'}), 500

# 开始配送
@app.route('/delivery_orders/<int:order_id>/start', methods=['PUT'])
@login_required
def start_delivery(user_id, order_id):
    try:
        print('='*50)
        print(f'开始配送订单 {order_id}')
        print('='*50)
        
        # 获取订单信息
        order = DeliveryOrder.query.get(order_id)
        if not order:
                print(f'订单不存在: {order_id}')
                return jsonify({'error': '订单不存在'}), 404
            
        print(f'当前订单状态: {order.status}')
        if order.status != 0:
                print('订单状态不正确，无法开始配送')
                return jsonify({'error': '订单状态不正确'}), 400
            
            # 更新状态
        order.status = 1  # 配送中
        order.delivery_by = user_id
        order.updated_at = datetime.now()
        
        try:
            db.session.commit()
            print('订单状态已更新为配送中')
            return jsonify({'message': '开始配送成功'}), 200
        except Exception as e:
            db.session.rollback()
            print(f'更新订单状态失败: {str(e)}')
            return jsonify({'error': '开始配送失败'}), 500
            
    except Exception as e:
        print('\n开始配送失败:')
        print(f'错误类型: {type(e).__name__}')
        print(f'错误信息: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '开始配送失败'}), 500

# 完成配送
@app.route('/delivery_orders/<int:order_id>/complete', methods=['PUT'])
@login_required
def complete_delivery(user_id, order_id):
    try:
        data = request.json
        delivery_image = data.get('delivery_image', [])
        
        # 获取订单信息
        order = DeliveryOrder.query.get(order_id)
        if not order:
                return jsonify({'error': '订单不存在'}), 404
            
        if order.status != 1:
                return jsonify({'error': '订单状态不正确'}), 400
            
        # 更新订单状态
        order.status = 2  # 已完成
        order.delivery_image = json.dumps(delivery_image)
        order.updated_at = datetime.now()
        
        try:
            db.session.commit()
            return jsonify({'message': '配送完成'}), 200
        except Exception as e:
            db.session.rollback()
            print(f'更新订单状态失败: {str(e)}')
            return jsonify({'error': '完成配送失败'}), 500
            
    except Exception as e:
        print(f'完成配送失败: {str(e)}')
        return jsonify({'error': '完成配送失败'}), 500

# 取消配送
@app.route('/delivery_orders/<int:order_id>/cancel', methods=['PUT'])
@login_required
def cancel_delivery(user_id, order_id):
    try:
        data = request.json
        cancel_reason = data.get('reason', '')
        
        # 获取订单信息
        order = DeliveryOrder.query.get(order_id)
        if not order:
            return jsonify({'error': '订单不存在'}), 404
            
        if order.status not in [0, 1]:  # 只有待配送和配送中的订单可以取消
            return jsonify({'error': '订单状态不正确'}), 400
            
        # 更新订单状态
        order.status = 3  # 已取消
        order.remark = cancel_reason
        order.updated_at = datetime.now()
        
        try:
            db.session.commit()
            return jsonify({'message': '配送已取消'}), 200
        except Exception as e:
            db.session.rollback()
            print(f'更新订单状态失败: {str(e)}')
            return jsonify({'error': '取消配送失败'}), 500
            
    except Exception as e:
        print(f'取消配送失败: {str(e)}')
        return jsonify({'error': '取消配送失败'}), 500

# 删除用户接口
@app.route('/users/delete', methods=['POST'])
@login_required
def delete_user(current_user_id):
    try:
        data = request.json
        target_user_id = data.get('user_id')
        
        if not target_user_id:
            return jsonify({'error': '缺少用户ID'}), 400
        
        # 检查当前用户是否是管理员
        current_user = User.query.get(current_user_id)
        if not current_user:
            return jsonify({'error': '当前用户不存在'}), 401
        
        if current_user.user_type != 1:
            return jsonify({'error': '没有权限执行此操作'}), 403

        # 检查要删除的用户是否存在
        target_user = User.query.get(target_user_id)
        if not target_user:
            return jsonify({'error': '用户不存在'}), 404

        # 不允许删除自己
        if int(target_user_id) == current_user_id:
            return jsonify({'error': '不能删除自己的账号'}), 400

        # 执行删除操作
        db.session.delete(target_user)
        
        try:
            db.session.commit()
            return jsonify({
                'code': 200,
                'message': '用户删除成功'
            })
        except Exception as e:
            db.session.rollback()
            print(f'删除用户失败: {str(e)}')
            return jsonify({'error': '删除用户失败'}), 500

    except Exception as e:
        print(f'删除用户失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '删除用户失败'}), 500

# 批量删除商品接口
@app.route('/products/batch/delete', methods=['POST'])
@login_required
def batch_delete_products(current_user_id):
    try:
        data = request.json
        product_ids = data.get('product_ids', [])
        
        if not product_ids:
            return jsonify({'error': '未选择要删除的商品'}), 400
            
            # 检查权限
        current_user = User.query.get(current_user_id)
        if not current_user or current_user.user_type != 1:
                return jsonify({'error': '没有权限执行此操作'}), 403
            
        # 获取要删除的商品
        products = Product.query.filter(Product.id.in_(product_ids)).all()
        
        # 删除相关的图片文件
        for product in products:
            if product.images:
                images = json.loads(product.images)
                for image_url in images:
                    try:
                        filename = image_url.split('/')[-1]
                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        if os.path.exists(file_path):
                            os.remove(file_path)
                    except Exception as e:
                        print(f"删除图片文件失败: {str(e)}")

            # 删除相关的库存记录
            StockRecord.query.filter_by(product_id=product.id).delete()
            
            # 删除相关的颜色库存记录
            ColorStock.query.filter_by(product_id=product.id).delete()
            
            # 删除商品
            db.session.delete(product)

        try:
            db.session.commit()
            return jsonify({
                'code': 200,
                'message': f'成功删除 {len(products)} 个商品'
            })
        except Exception as e:
            db.session.rollback()
            print(f'批量删除商品失败: {str(e)}')
            return jsonify({'error': '批量删除失败'}), 500
            
    except Exception as e:
        print(f'处理批量删除请求失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '批量删除失败'}), 500

@app.route('/delivery_orders/from_purchase/<int:purchase_id>', methods=['POST'])
@login_required
def create_delivery_from_purchase(current_user_id, purchase_id):
    try:
        # 获取采购单信息
        purchase_order = PurchaseOrder.query\
            .options(db.joinedload(PurchaseOrder.items))\
            .get(purchase_id)
            
        if not purchase_order:
            return jsonify({'error': '采购单不存在'}), 404

        # 检查权限
        current_user = User.query.get(current_user_id)
        if not current_user or current_user.user_type != 1:
            return jsonify({'error': '没有权限执行此操作'}), 403

        # 生成配送单号
        order_number = 'D' + datetime.now().strftime('%Y%m%d%H%M%S') + str(random.randint(1000, 9999))
        
        # 创建配送单
        delivery_order = DeliveryOrder(
            order_number=order_number,
            customer_name=purchase_order.user.nickname or '未知客户',
            customer_phone=purchase_order.user.phone or '',
            delivery_address=purchase_order.user.address or '',
            delivery_date=datetime.now().strftime('%Y-%m-%d'),
            delivery_time_slot='',
            status=0,  # 待配送
            remark=f'从采购单 {purchase_order.order_number} 生成',
            created_by=current_user_id,
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        
        db.session.add(delivery_order)
        
        # 添加配送商品
        for purchase_item in purchase_order.items:
            delivery_item = DeliveryItem(
                delivery_id=delivery_order.id,
                product_id=purchase_item.product_id,
                quantity=purchase_item.quantity,
                color=purchase_item.color
            )
            db.session.add(delivery_item)

        try:
            db.session.commit()
            
            # 更新采购单状态为已处理
            purchase_order.status = 1  # 已处理
            db.session.commit()
            
            return jsonify({
                'message': '配送单创建成功',
                'delivery_order': {
                    'id': delivery_order.id,
                    'order_number': order_number,
                    'status': delivery_order.status,
                    'customer_name': delivery_order.customer_name,
                    'customer_phone': delivery_order.customer_phone,
                    'delivery_address': delivery_order.delivery_address,
                    'delivery_date': delivery_order.delivery_date,
                    'items_count': len(purchase_order.items)
                }
            }), 201
            
        except Exception as e:
            db.session.rollback()
            print(f'保存配送单失败: {str(e)}')
            return jsonify({'error': '创建配送单失败'}), 500
            
    except Exception as e:
        print(f'从采购单创建配送单失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '创建配送单失败'}), 500

@app.route('/delivery_orders/<int:order_id>', methods=['DELETE'])
@login_required
def delete_delivery_order(current_user_id, order_id):
    try:
        # 检查权限
        current_user = User.query.get(current_user_id)
        if not current_user or current_user.user_type != 1:
            return jsonify({'error': '没有权限执行此操作'}), 403
        
        # 获取配送单
        order = DeliveryOrder.query.get(order_id)
        if not order:
            return jsonify({'error': '配送单不存在'}), 404
            
        if order.status not in [0, 3]:  # 只能删除待配送或已取消的订单
            return jsonify({'error': '当前状态不允许删除'}), 400
        
        # 删除配送单商品
        DeliveryItem.query.filter_by(delivery_id=order_id).delete()
        
        # 删除配送单
        db.session.delete(order)
        
        try:
            db.session.commit()
            return jsonify({
                'code': 200,
                'message': '配送单删除成功'
            })
        except Exception as e:
            db.session.rollback()
            print(f'删除配送单失败: {str(e)}')
            return jsonify({'error': '删除配送单失败'}), 500
            
    except Exception as e:
        print(f'处理删除配送单请求失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '删除配送单失败'}), 500

# 生成小程序码接口
@app.route('/qrcode', methods=['POST'])
def generate_qrcode_api():
    try:
        data = request.get_json()
        page = data.get('page')
        scene = data.get('scene')
        
        qrcode_path = generate_qrcode(page, scene)
        return jsonify({
            'code': 200,
            'message': 'QR code generated successfully',
            'qrcode': qrcode_path
        })
    except Exception as e:
        print(f"生成二维码出错: {str(e)}")
        return jsonify({
            'code': 500,
            'message': str(e)
        }), 500

def generate_qrcode(page, scene):
    try:
        # 确保存储目录存在
        qrcode_dir = os.path.join(app.static_folder, 'qrcodes')
        if not os.path.exists(qrcode_dir):
            os.makedirs(qrcode_dir)
            
        # 生成唯一的文件名
        filename = f"qr_{int(time.time())}_{uuid.uuid4().hex[:8]}.jpg"
        filepath = os.path.join(qrcode_dir, filename)
        
        # 调用微信接口生成小程序码
        access_token = get_access_token()
        url = f'https://api.weixin.qq.com/wxa/getwxacode?access_token={access_token}'
        
        params = {
            "path": f"{page}?{scene}",
            "width": 430,
            "auto_color": False,
            "line_color": {"r": 0, "g": 0, "b": 0},
            "is_hyaline": False
        }
        
        response = requests.post(url, json=params)
        
        if response.status_code == 200:
            # 保存文件
            with open(filepath, 'wb') as f:
                f.write(response.content)
            
            print(f"二维码已保存到: {filepath}")

            # 返回相对路径
            relative_path = f'/static/qrcodes/{filename}'
            return relative_path
        else:
            print(f"生成二维码失败: {response.text}")
            return None
            
    except Exception as e:
        print(f"生成二维码出错: {str(e)}")
        return None

def get_access_token():
    """获取小程序 access_token"""
    try:
        print('='*50)
        print('开始获取小程序access_token')
        print('='*50)
        
        print('\n配置信息:')
        print(f'- APPID: {WECHAT_APPID}')
        print(f'- SECRET: {"*" * len(WECHAT_SECRET)}')  # 不输出实际的SECRET
        
        url = f'https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid={WECHAT_APPID}&secret={WECHAT_SECRET}'
        print(f'\n请求URL: {url}')
        
        print('\n发送请求到微信服务器...')
        response = requests.get(url)
        print(f'接收到响应，状态码: {response.status_code}')
        
        if response.status_code == 200:
            data = response.json()
            print('\n接口响应数据:')
            # 处理响应数据时隐藏实际的access_token
            safe_data = data.copy()
            if 'access_token' in safe_data:
                safe_data['access_token'] = safe_data['access_token'][:10] + '...'
            print(json.dumps(safe_data, ensure_ascii=False, indent=2))
            
            if 'access_token' in data:
                print('\n成功获取access_token')
                return data['access_token']
                
        print('\n获取access_token失败')
        print('错误响应:')
        print(response.text)
        raise Exception('获取 access_token 失败')
        
    except Exception as e:
        print('\n获取access_token时发生错误:')
        print(f'- 错误类型: {type(e).__name__}')
        print(f'- 错误信息: {str(e)}')
        print(f'- 错误追踪:\n{traceback.format_exc()}')
        raise


@app.route('/push_orders', methods=['POST'])
@admin_required
def create_push_order(user_id):
    try:
        data = request.json
        target_name = data.get('target_name', '仟艺测试')
        target_user_id = data.get('target_user_id', None)

        if not data or 'products' not in data:
            return jsonify({'error': '无效的请求数据'}), 400

        # 生成推送单号
        order_number = f"PUSH{datetime.now().strftime('%Y%m%d%H%M%S')}{random.randint(100,999)}"

        # 生成分享码
        share_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        # 生成二维码
        qrcode_path = generate_qrcode('pages/pushShare/pushShare', f'code={share_code}')

        # 获取目标用户的openid
        target_openid = None
        if target_user_id:
            target_user = User.query.filter_by(id=target_user_id).first()
            if target_user:
                target_openid = target_user.openid

        # 创建推送单
        push_order = PushOrder(
            user_id=user_id,
            order_number=order_number,
            target_name=target_name,
            target_user_id=target_user_id,
            openid=target_openid,
            share_code=share_code,
            qrcode_path=qrcode_path,
            created_at=datetime.now()
        )

        db.session.add(push_order)
        db.session.flush()  # 获取 push_order.id

        # 添加推送商品
        products_data = []
        for product_info in data['products']:
            product = Product.query.filter_by(id=product_info['id']).first()
            if product:
                push_product = PushOrderProduct(
                    push_order_id=push_order.id,
                    product_id=product_info['id'],
                    price=product_info['price'],
                    specs=json.dumps(product_info.get('specs', [])),
                    specs_info=json.dumps(product_info.get('specs_info', {})),
                    created_at=datetime.now()
                )
                db.session.add(push_product)
                products_data.append({'name': product.name})

        try:
            db.session.commit()

            # 如果有openid，发送微信通知
            if target_openid:
                print(f'发送微信通知给用户: {target_openid}')
                send_push_notification(target_openid, order_number, products_data)

            return jsonify({
                'message': '推送单创建成功',
                'order_id': push_order.id,
                'order_number': order_number,
                'share_code': share_code,
                'qrcode_path': qrcode_path
            }), 201

        except Exception as e:
            db.session.rollback()
            print(f'保存推送单失败: {str(e)}')
            print(f'错误追踪:\n{traceback.format_exc()}')
            return jsonify({'error': '创建推送单失败'}), 500

    except Exception as e:
        print(f'创建推送单失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '创建推送单失败'}), 500



# 修改权限检查函数
def check_push_order_permission(cursor, user_id, order_id):
    """检查用户是否有权限操作该推送单"""
    # 获取用户信息
    cursor.execute('SELECT user_type, openid FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    if not user:
        return False
        
    user_type, user_openid = user
    
    # 管理员有所有权限
    if user_type == 1:
        return True
        
    # 获取推送单信息
    cursor.execute('SELECT user_id, openid FROM push_orders WHERE id = ?', (order_id,))
    order = cursor.fetchone()
    if not order:
        return False
        
    order_user_id, order_openid = order
    
    # 如果推送单没有设置 openid，所有人都可以访问
    if order_openid is None:
        return True
        
    # 检查是否是创建者或 openid 匹配
    return order_user_id == user_id or (order_openid and order_openid == user_openid)
# 查询推送单列表
@app.route('/push_orders', methods=['GET'])
@login_required
def get_push_orders(user_id):
    try:
        # 获取用户信息
        user = User.query.filter_by(id=user_id).first()
        if not user:
            return jsonify({'error': '用户不存在'}), 404
                
        user_type = user.user_type
        openid = user.openid

        print(f'用户类型: {user_type}, openid: {openid}, user_id: {user_id}')

        # 构建查询
        if user_type == 1:  # 管理员
            orders_query = db.session.query(
                PushOrder.id,
                PushOrder.order_number,
                PushOrder.target_name,
                PushOrder.target_user_id,
                PushOrder.share_code,
                PushOrder.status,
                PushOrder.created_at,
                func.count(PushOrderProduct.id).label('product_count'),
                PushOrder.openid,
                func.json_extract(PushOrderProduct.specs_info, '$').label('specs_info'),
                PushOrder.qrcode_path
            ).outerjoin(
                PushOrderProduct, PushOrder.id == PushOrderProduct.push_order_id
            ).group_by(
                PushOrder.id, PushOrder.order_number, PushOrder.target_name,
                PushOrder.target_user_id, PushOrder.share_code, PushOrder.status,
                PushOrder.created_at, PushOrder.openid, PushOrder.qrcode_path,
                PushOrderProduct.specs_info
            ).order_by(
                PushOrder.created_at.desc()
            )
        else:  # 普通用户
            orders_query = db.session.query(
                PushOrder.id,
                PushOrder.order_number,
                PushOrder.target_name,
                PushOrder.target_user_id,
                PushOrder.share_code,
                PushOrder.status,
                PushOrder.created_at,
                func.count(PushOrderProduct.id).label('product_count'),
                PushOrder.openid,
                func.json_extract(PushOrderProduct.specs_info, '$').label('specs_info'),
                PushOrder.qrcode_path
            ).outerjoin(
                PushOrderProduct, PushOrder.id == PushOrderProduct.push_order_id
            ).filter(
                (PushOrder.target_user_id == user_id) | 
                ((PushOrder.openid == openid) & (PushOrder.openid != None))
            ).group_by(
                PushOrder.id, PushOrder.order_number, PushOrder.target_name,
                PushOrder.target_user_id, PushOrder.share_code, PushOrder.status,
                PushOrder.created_at, PushOrder.openid, PushOrder.qrcode_path,
                PushOrderProduct.specs_info
            ).order_by(
                PushOrder.created_at.desc()
            )
            
        orders = []
        for row in orders_query.all():
            order = {
                'id': row.id,
                'order_number': row.order_number,
                'target_name': row.target_name,
                'target_user_id': row.target_user_id,
                'share_code': row.share_code,
                'status': row.status,
                'created_at': row.created_at,
                'product_count': row.product_count,
                'openid': row.openid,
                'specs_info': json.loads(row.specs_info) if row.specs_info else {},
                'qrcode_path': row.qrcode_path
            }
                
            # 获取订单商品详情
            products_query = db.session.query(
                PushOrderProduct.product_id,
                Product.name,
                PushOrderProduct.price,
                PushOrderProduct.specs,
                func.json_extract(Product.images, '$[0]').label('image'),
                PushOrderProduct.specs_info
            ).join(
                Product, PushOrderProduct.product_id == Product.id
            ).filter(
                PushOrderProduct.push_order_id == order['id']
            )
                
            order['products'] = [{
                'id': product.product_id,
                'name': product.name,
                'price': product.price,
                'specs': json.loads(product.specs) if product.specs else [],
                'image': json.loads(product.image) if product.image else None,
                'specs_info': json.loads(product.specs_info) if product.specs_info else {}
            } for product in products_query.all()]
                
            orders.append(order)
            
        return jsonify({'orders': orders})
            
    except Exception as e:
        print(f'获取推送单列表失败: {str(e)}')
        return jsonify({'error': '获取推送单列表失败'}), 500


# 在编辑和删除接口中使用权限检查
@app.route('/push_orders/<int:order_id>', methods=['PUT'])
@login_required
def update_push_order(user_id, order_id):
    try:
        # 检查权限
        if not check_push_order_permission(user_id, order_id):
            return jsonify({'error': '无权限操作此推送单'}), 403

        data = request.json
        if not data or 'products' not in data:
            return jsonify({'error': '无效的请求数据'}), 400

        # 删除原有商品
        db.session.query(PushOrderProduct).filter_by(push_order_id=order_id).delete()

        # 添加新的商品
        for product in data['products']:
            new_product = PushOrderProduct(
                push_order_id=order_id,
                product_id=product['id'],
                price=product['price'],
                specs=json.dumps(product.get('specs', [])),
                specs_info=json.dumps(product.get('specs_info', {}))
            )
            db.session.add(new_product)

        db.session.commit()

        return jsonify({
            'message': '推送单更新成功',
            'order_id': order_id
        })

    except Exception as e:
        db.session.rollback()
        print(f'更新推送单失败: {str(e)}')
        return jsonify({'error': '更新推送单失败'}), 500


@app.route('/push_orders/<int:order_id>', methods=['DELETE'])
@login_required
def delete_push_order(user_id, order_id):
    try:
        # 检查权限
        if not check_push_order_permission(user_id, order_id):
            return jsonify({'error': '无权限操作此推送单'}), 403

        # 删除推送单商品
        db.session.query(PushOrderProduct).filter_by(push_order_id=order_id).delete()

        # 删除推送单
        db.session.query(PushOrder).filter_by(id=order_id).delete()

        db.session.commit()

        return jsonify({
            'message': '推送单删除成功',
            'order_id': order_id
        })

    except Exception as e:
        db.session.rollback()
        print(f'删除推送单失败: {str(e)}')
        return jsonify({'error': '删除推送单失败'}), 500


# 获取推送单详情
@app.route('/push_orders/<int:order_id>', methods=['GET'])
@login_required
def get_push_order(user_id, order_id):
    try:
        # 获取推送单及相关信息
        order = PushOrder.query\
            .filter_by(id=order_id)\
            .first()
            
        if not order:
            return jsonify({'error': '推送单不存在'}), 404
                
        # 检查权限
        if order.user_id != user_id and order.target_user_id != user_id:
            return jsonify({'error': '无权访问此推送单'}), 403
            
        # 获取推送商品列表
        products = []
        for item in order.products:
            product = Product.query.filter_by(id=item.product_id).first()
            if product:
                print(f'images: {json.loads(product.images)}')
                products.append({
                    'id': item.id,
                    'product_id': item.product_id,
                    'product_name': product.name,
                    'price': float(item.price),
                    'specs': json.loads(item.specs) if item.specs else [],
                    'specs_info': json.loads(item.specs_info) if item.specs_info else {},
                    'image': json.loads(product.images)[0] if product.images else None,
                    'type': product.type
                })
                
        # 格式化返回数据
        order_data = {
            'id': order.id,
            'order_number': order.order_number,
            'target_name': order.target_name,
            'target_user_id': order.target_user_id,
            'status': order.status,
            'share_code': order.share_code,
            'qrcode_path': order.qrcode_path,
            'created_at': order.created_at.isoformat(),
            'user': {
                'id': order.user.id,
                'username': order.user.username,
                'nickname': order.user.nickname
            } if order.user else None,
            'products': products
        }
        
        return jsonify(order_data), 200
            
    except Exception as e:
        print(f'获取推送单详情失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '获取推送单详情失败'}), 500

# 获取系统设置
@app.route('/system/settings', methods=['GET'])
def get_system_settings():
    try:
        # 获取所有系统设置
        settings = SystemSettings.query.all()
        
        # 格式化返回数据
        result = {}
        for setting in settings:
            if setting.setting_type == 'json':
                try:
                    result[setting.setting_key] = json.loads(setting.setting_value)
                except json.JSONDecodeError:
                    result[setting.setting_key] = setting.setting_value
            else:
                result[setting.setting_key] = setting.setting_value
                    
        return jsonify(result), 200
        
    except Exception as e:
        print(f'获取系统设置失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '获取系统设置失败'}), 500

# 更新系统设置
@app.route('/system/settings', methods=['PUT'])
@admin_required
def update_system_settings():
    try:
        data = request.json
        if not data:
            return jsonify({'error': '无效的请求数据'}), 400
            
        # 遍历更新设置
        for key, value in data.items():
            # 获取或创建设置记录
            setting = SystemSettings.query.filter_by(setting_key=key).first()
            if not setting:
                setting = SystemSettings(setting_key=key)
                db.session.add(setting)
                
            # 根据值的类型设置类型字段
            if isinstance(value, (dict, list)):
                setting.setting_type = 'json'
                setting.setting_value = json.dumps(value)
            else:
                setting.setting_type = 'string'
                setting.setting_value = str(value)
                
        try:
            db.session.commit()
            return jsonify({'message': '系统设置更新成功'}), 200
        except Exception as e:
            db.session.rollback()
            print(f'保存系统设置失败: {str(e)}')
            return jsonify({'error': '更新系统设置失败'}), 500
            
    except Exception as e:
        print(f'更新系统设置失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '更新系统设置失败'}), 500

# 初始化系统设置
def init_system_settings():
    try:
        print('开始初始化系统设置...')
        
        # 检查商品类型设置是否存在
        product_types = SystemSettings.query.filter_by(setting_key='product_types').first()
        if not product_types:
            print('创建默认商品类型设置...')
            default_types = [
                {'id': 1, 'name': '披肩'},
                {'id': 2, 'name': '围巾'},
                {'id': 3, 'name': '帽子'},
                {'id': 4, 'name': '三角巾'},
                {'id': 5, 'name': '其他'}
            ]
            product_types = SystemSettings(
                setting_key='product_types',
                setting_value=json.dumps(default_types),
                setting_type='json'
            )
            db.session.add(product_types)
            
        # 检查其他默认设置...
        
        try:
            db.session.commit()
            print('系统设置初始化完成')
        except Exception as e:
            db.session.rollback()
            print(f'保存系统设置失败: {str(e)}')
            raise
            
    except Exception as e:
        print(f'初始化系统设置失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        raise

# 获取用户统计数据
@app.route('/user/statistics', methods=['GET'])
@login_required
def get_user_statistics(user_id):
    try:
        # 获取用户的推送单
        push_orders = PushOrder.query.filter_by(user_id=user_id).all()
        orders_data = []
        for order in push_orders:
            products = [
                {
                    'id': p.product_id,
                    'name': Product.query.filter_by(id=p.product_id).first().name,
                    'price': float(p.price)
                } for p in order.products.all()
            ]
            orders_data.append({
                'id': order.id,
                'order_number': order.order_number,
                'products': products,
                'created_at': order.created_at.isoformat()
            })
            
            return jsonify({
            'push_orders': orders_data
            }), 200
            
    except Exception as e:
        print(f'获取用户统计数据失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '获取统计数据失败'}), 500

# 获取用户推送商品列表
@app.route('/user/push_products', methods=['GET'])
@login_required
def get_user_push_products(user_id):
    try:
        # 获取分页参数
        page = int(request.args.get('page', 1))
        page_size = min(int(request.args.get('page_size', 10)), 50)

        # 获取筛选参数
        product_type = request.args.get('type')
        date_filter = request.args.get('date')
        keyword = request.args.get('keyword')

        from sqlalchemy import func, text

        # 先获取最新推送记录的子查询
        latest_push_dates = db.session.query(
            PushOrderProduct.product_id,
            func.max(PushOrder.created_at).label('max_push_time')
        ).join(
            PushOrder,
            PushOrder.id == PushOrderProduct.push_order_id
        ).filter(
            PushOrder.target_user_id == user_id
        ).group_by(
            PushOrderProduct.product_id
        ).subquery()

        # 主查询
        query = db.session.query(
            Product,
            PushOrderProduct.price.label('push_price'),
            PushOrderProduct.specs.label('specs'),
            PushOrderProduct.specs_info.label('specs_info'),
            PushOrder.created_at.label('push_time')
        ).join(
            latest_push_dates,
            Product.id == latest_push_dates.c.product_id
        ).join(
            PushOrderProduct,
            Product.id == PushOrderProduct.product_id
        ).join(
            PushOrder,
            db.and_(
                PushOrder.id == PushOrderProduct.push_order_id,
                PushOrder.created_at == latest_push_dates.c.max_push_time
            )
        )

        # 添加筛选条件
        if product_type and product_type != '0':
            query = query.filter(Product.type == product_type)

        if date_filter:
            query = query.filter(func.date(PushOrder.created_at) == date_filter)

        if keyword:
            search = f'%{keyword}%'
            query = query.filter(db.or_(
                Product.name.ilike(search),
                Product.description.ilike(search)
            ))

        # 按最新推送时间排序并分页
        query = query.order_by(PushOrder.created_at.desc())
        pagination = query.paginate(page=page, per_page=page_size, error_out=False)

        # 构建返回数据
        products = []
        for product, push_price, specs, specs_info, push_time in pagination.items:
            products.append({
                'id': product.id,
                'name': product.name,
                'description': product.description,
                'price': float(push_price) if push_price else 0,
                'images': json.loads(product.images) if product.images else [],
                'type': product.type,
                'specs': json.loads(specs) if specs else [],
                'specs_info': json.loads(specs_info) if specs_info else {},
                'push_time': push_time.isoformat() if push_time else None,
                'created_at': product.created_at.isoformat() if product.created_at else None
            })

        return jsonify({
            'products': products,
            'total': pagination.total,
            'page': page,
            'page_size': page_size,
            'total_pages': pagination.pages
        }), 200

    except Exception as e:
        print(f'获取用户推送商品列表失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '获取用户推送商品列表失败'}), 500

@app.route('/users/search', methods=['GET'])
@login_required
def search_users(user_id):
    try:
        # 获取搜索关键词
        keyword = request.args.get('keyword', '')
        if not keyword:
            return jsonify({'users': []}), 200
            
        # 构建模糊搜索查询
        search = f'%{keyword}%'
        users = User.query.filter(
            db.or_(
                User.username.like(search),
                User.nickname.like(search),
                User.phone.like(search)
            ),
            User.user_type == 0,  # 只搜索普通用户
            User.status == 1      # 只搜索启用状态的用户
        ).limit(10).all()
        
        # 格式化返回数据
        users_list = [{
            'id': user.id,
            'username': user.username,
            'nickname': user.nickname,
            'phone': user.phone,
            'avatar': user.avatar
        } for user in users]
        
        return jsonify({'users': users_list}), 200
            
    except Exception as e:
        print(f'搜索用户失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '搜索用户失败'}), 500

# 获取商品列表（需要管理员登录）
@app.route('/products', methods=['GET'])
@admin_required
def get_products(user_id):  # 添加 user_id 参数来接收装饰器传入的值
    try:
        # 获取查询参数
        page = request.args.get('page', 1, type=int)
        page_size = request.args.get('page_size', 10, type=int)
        keyword = request.args.get('keyword', '')
        product_type = request.args.get('type')
        
        # 构建基础查询
        query = Product.query
        
        # 添加搜索条件
        if keyword:
            search = f'%{keyword}%'
            query = query.filter(db.or_(
                Product.name.like(search),
                Product.description.like(search)
            ))
            
        # 添加类型筛选
        if product_type:
            query = query.filter(Product.type == product_type)
            
        # 获取分页数据
        paginated_products = query.order_by(Product.created_at.desc())\
            .paginate(page=page, per_page=page_size, error_out=False)
            
        # 格式化返回数据
        products = []
        for product in paginated_products.items:
            products.append({
                'id': product.id,
                'name': product.name,
                'description': product.description,
                'price': float(product.price) if product.price else 0,
                'price_b': float(product.price_b) if product.price_b else float(product.price),
                'price_c': float(product.price_c) if product.price_c else float(product.price),
                'price_d': float(product.price_d) if product.price_d else float(product.price),
                'cost_price': float(product.cost_price) if product.cost_price else float(product.price),
                'type': product.type,
                'created_at': product.created_at.isoformat() if product.created_at else None,
                'specs_info': json.loads(product.specs_info) if product.specs_info else {},
                'specs': json.loads(product.specs) if product.specs else [],
                'images': json.loads(product.images) if product.images else [],
                'status': product.status if product.status is not None else 1,  # 默认上架
                'is_public': product.is_public if product.is_public is not None else 1  # 默认公开
            })
            
        return jsonify({
            'products': products,
            'total': paginated_products.total,
            'page': page,
            'page_size': page_size,
            'total_pages': paginated_products.pages
        }), 200
        
    except Exception as e:
        print(f'获取商品列表失败: {str(e)}')
        return jsonify({'error': '获取商品列表失败'}), 500


def send_push_notification(openid, order_number, products):
    """发送微信推送消息"""
    try:
        access_token = get_access_token()
        if not access_token:
            return False

        url = f'https://api.weixin.qq.com/cgi-bin/message/subscribe/send?access_token={access_token}'
        
        # 处理订单编号，确保不超过20个字符
        if len(order_number) > 20:
            display_order_number = order_number[-20:]
        else:
            display_order_number = order_number
            
        # 构建商品信息文本，限制在20个字符内
        product_names = [p.get('name', '未知商品') for p in products]
        products_text = ''
        total_products = len(products)
        
        if total_products == 1:
            products_text = product_names[0][:20]
        elif total_products == 2:
            products_text = f"{product_names[0][:8]}、{product_names[1][:8]}"
        else:
            products_text = f"{product_names[0][:6]}等{total_products}件商品"
            
        # 获取当前时间
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M")
            
        data = {
            "touser": openid,
            "template_id": "DMHyXBE15LMRREDyij2FrlRiSKNOO6iLvmxITZSr480",
            "page": "pages/pushRecords/pushRecords",
            "data": {
                "thing1": {  # 订单编号
                    "value": display_order_number
                },
                "thing4": {  # 商品信息
                    "value": products_text
                },
                "time2": {  # 推送时间
                    "value": current_time
                }
            }
        }
        
        print("发送的订阅消息数据:", data)  # 添加日志
        
        response = requests.post(url, json=data)
        result = response.json()
        
        if result.get('errcode') == 0:
            print("订阅消息发送成功")
            return True
        else:
            print(f"订阅消息发送失败: {result}")
            return False
            
    except Exception as e:
        print(f"发送订阅消息异常: {str(e)}")
        return False

@app.route('/push_orders/share', methods=['POST'])
@login_required
def share_push_order(user_id):
    try:
        data = request.json
        order_id = data.get('orderId')
        target_user_id = data.get('targetUserId')

        if not order_id or not target_user_id:
            return jsonify({'error': '缺少必要参数'}), 400

        # 检查原始订单是否存在且当前用户有权限访问
        original_order = PushOrder.query\
            .join(User, PushOrder.target_user_id == User.id)\
            .filter(PushOrder.id == order_id, PushOrder.user_id == user_id)\
            .first()

        if not original_order:
            return jsonify({'error': '订单不存在或无权访问'}), 404

        # 检查目标用户是否存在
        target_user = User.query.get(target_user_id)
        if not target_user:
            return jsonify({'error': '目标用户不存在'}), 404

        # 生成新的订单号和随机字符串
        new_order_number = f"PO{int(time.time())}{random.randint(1000, 9999)}"

        # 创建新的推送订单
        new_order = PushOrder(
            user_id=user_id,
            target_user_id=target_user_id,
            order_number=new_order_number,
            status=0,  # 待推送
            created_at=datetime.now(),
            updated_at=datetime.now(),
            qrcode_path=None,
            openid=target_user.openid
        )
        db.session.add(new_order)

        try:
            db.session.flush()  # 获取新订单ID

            # 复制原订单的商品到新订单
            for original_product in original_order.products:
                new_product = PushOrderProduct(
                    push_order_id=new_order.id,
                    product_id=original_product.product_id,
                    name=original_product.name,
                    image=original_product.image,
                    price=original_product.price,
                    created_at=datetime.now(),
                    updated_at=datetime.now()
                )
                db.session.add(new_product)

            # 获取商品信息用于发送通知
            products = PushOrderProduct.query\
                .filter(PushOrderProduct.push_order_id == new_order.id)\
                .limit(3).all()
            product_names = [p.name for p in products]

            db.session.commit()

            # 发送微信通知
            if target_user.openid:
                try:
                    send_push_notification(
                        target_user.openid,
                        new_order_number,
                        product_names
                    )
                except Exception as e:
                    print(f"发送通知失败: {str(e)}")
                    # 通知失败不影响整体流程

            return jsonify({
                'message': '分享成功',
                'order_id': new_order.id,
                'order_number': new_order_number
            })

        except Exception as e:
            db.session.rollback()
            print(f"保存分享订单失败: {str(e)}")
            return jsonify({'error': '分享失败'}), 500

    except Exception as e:
        print(f"分享订单失败: {str(e)}")
        print(f"错误追踪:\n{traceback.format_exc()}")
        return jsonify({'error': '分享失败'}), 500

@app.route('/push_orders/bind/<share_code>', methods=['POST'])
@login_required
def bind_push_order(user_id, share_code):
    try:
        print(f"开始绑定推送单 - 分享码: {share_code}, 用户ID: {user_id}")
        
        # 获取当前用户信息
        current_user = User.query.get(user_id)
        if not current_user:
            print(f"绑定失败 - 用户不存在: {user_id}")
            return jsonify({'error': '用户不存在'}), 404
            
        # 查找对应的推送单
        order = PushOrder.query\
            .outerjoin(User, PushOrder.target_user_id == User.id)\
            .filter(PushOrder.share_code == share_code)\
            .first()
        
        if not order:
            print(f"绑定失败 - 分享码无效: {share_code}")
            return jsonify({'error': '无效的分享码'}), 400
            
        # 检查是否已被绑定
        if order.target_user_id is not None:
            # 如果是同一用户在绑定，返回不同的错误信息
            if order.target_user_id == user_id:
                print(f"绑定失败 - 用户重复绑定 - 用户ID: {user_id}")
                return jsonify({'error': '您已经绑定过这个推送单了'}), 400
                
            # 如果是其他用户已绑定，返回详细信息
            bound_user = User.query.get(order.target_user_id)
            user_info = f"用户ID: {bound_user.id}"
            if bound_user.nickname:
                user_info += f", 昵称: {bound_user.nickname}"
            if bound_user.username:
                user_info += f", 用户名: {bound_user.username}"
            if bound_user.phone:
                user_info += f", 手机号: {bound_user.phone}"
            print(f"绑定失败 - 推送单已被其他用户绑定 - {user_info}")
            return jsonify({'error': '该推送单已被其他用户绑定'}), 400
            
        print(f"找到推送单 - 订单ID: {order.id}, 订单号: {order.order_number}")
            
        # 更新推送单信息
        order.target_user_id = user_id
        order.target_name = current_user.nickname or current_user.username or '未知用户'
        order.openid = current_user.openid
        order.share_code = None
        
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"绑定失败 - 更新推送单失败: {str(e)}")
            return jsonify({'error': '绑定失败，请重试'}), 400
            
        print(f"已更新推送单 - 订单ID: {order.id} 绑定到用户: {user_id}")
            
        # 构建返回数据
        order_data = {
            'id': order.id,
            'order_number': order.order_number,
            'created_at': order.created_at.isoformat(),
            'target_name': order.target_name,
            'target_user_id': user_id,
            'openid': current_user.openid,
            'products': []
        }
        
        # 获取推送单商品信息
        product_count = 0
        for item in order.products:
            product = Product.query.get(item.product_id)
            if product:
                try:
                    product_data = {
                        'id': product.id,
                        'name': product.name,
                        'price': float(item.price) if item.price else 0,
                        'images': json.loads(product.images)[0] if product.images else '',
                        'specs_info': json.loads(item.specs_info) if item.specs_info else {},
                        'specs': json.loads(item.specs) if item.specs else []
                    }
                    order_data['products'].append(product_data)
                    product_count += 1
                except (ValueError, json.JSONDecodeError) as e:
                    print(f"处理商品数据出错 - 商品ID: {product.id}, 错误: {str(e)}")
                    continue
        
        print(f"推送单商品数据已处理 - 订单ID: {order.id}, 商品数量: {product_count}")
        
        # 发送微信通知
        if current_user.openid:
            try:
                print(f"准备发送微信通知 - 用户: {current_user.nickname or current_user.username}, openid: {current_user.openid}")
                send_push_notification(current_user.openid, order_data['order_number'], order_data['products'])
                print(f"微信通知发送成功 - 订单号: {order_data['order_number']}")
            except Exception as e:
                print(f"发送微信通知失败: {str(e)}")
                # 通知失败不影响主流程
                pass
            
        print(f"推送单绑定成功 - 订单ID: {order.id}, 订单号: {order_data['order_number']}")
        return jsonify({
            'message': '推送单绑定成功',
            'order': order_data
        }), 200
            
    except Exception as e:
        print(f"绑定推送单失败 - 分享码: {share_code}, 错误信息: {str(e)}")
        print(f"错误追踪:\n{traceback.format_exc()}")
        return jsonify({'error': '绑定失败'}), 500

#获取用户采购单的总数，商品总数，总金额
@app.route('/user/purchase_statistics', methods=['GET'])
@login_required
def get_user_purchase_statistics(user_id):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # 获取今日统计
            cursor.execute("""
                SELECT 
                    COUNT(DISTINCT id) as order_count,
                    COALESCE(SUM(total_quantity), 0) as total_quantity,
                    COALESCE(SUM(total_amount), 0) as total_amount
                FROM purchase_orders 
                WHERE user_id = %s 
                AND status != 3
                AND DATE(created_at) = CURDATE()
            """, (user_id,))
            daily_stats = cursor.fetchone()
            
            # 获取本周统计
            cursor.execute("""
                SELECT 
                    COUNT(DISTINCT id) as order_count,
                    COALESCE(SUM(total_quantity), 0) as total_quantity,
                    COALESCE(SUM(total_amount), 0) as total_amount
                FROM purchase_orders 
                WHERE user_id = %s 
                AND status != 3
                AND YEARWEEK(created_at) = YEARWEEK(NOW())
            """, (user_id,))
            weekly_stats = cursor.fetchone()
            
            # 获取近30天统计
            cursor.execute("""
                SELECT 
                    COUNT(DISTINCT id) as order_count,
                    COALESCE(SUM(total_quantity), 0) as total_quantity,
                    COALESCE(SUM(total_amount), 0) as total_amount
                FROM purchase_orders 
                WHERE user_id = %s 
                AND status != 3
                AND created_at >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
            """, (user_id,))
            monthly_stats = cursor.fetchone()
            
            # 其他查询保持不变...
            
            stats_data = {
                'daily_statistics': {
                    'order_count': daily_stats[0] if daily_stats else 0,
                    'total_quantity': float(daily_stats[1]) if daily_stats else 0,
                    'total_amount': float(daily_stats[2]) if daily_stats else 0
                },
                'weekly_statistics': {
                    'order_count': weekly_stats[0] if weekly_stats else 0,
                    'total_quantity': float(weekly_stats[1]) if weekly_stats else 0,
                    'total_amount': float(weekly_stats[2]) if weekly_stats else 0
                },
                'monthly_statistics': {
                    'order_count': monthly_stats[0] if monthly_stats else 0,
                    'total_quantity': float(monthly_stats[1]) if monthly_stats else 0,
                    'total_amount': float(monthly_stats[2]) if monthly_stats else 0
                }
            }
            
            return jsonify({
                'code': 0,
                'message': 'success',
                'data': stats_data
            })
            
    except Exception as e:
        print(f"Error getting purchase statistics: {str(e)}")
        return jsonify({
            'code': 1,
            'message': f"获取统计数据失败: {str(e)}"
        }), 500

# 添加商品推送记录接口
@app.route('/products/push', methods=['POST'])
@login_required
def push_products(user_id):
    try:
        data = request.json
        if not data or 'products' not in data or 'target_user_id' not in data:
            return jsonify({'error': '无效的请求数据'}), 400
            
        # 生成推送单号
        order_number = 'P' + datetime.now().strftime('%Y%m%d%H%M%S') + str(random.randint(1000, 9999))
        share_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        
        # 创建推送单
        push_order = PushOrder(
            order_number=order_number,
            user_id=user_id,
            target_user_id=data['target_user_id'],
            target_name=data.get('target_name', ''),
            status=0,  # 待推送
            share_code=share_code,
            created_at=datetime.now()
        )
        
        db.session.add(push_order)
        
        # 添加推送商品
        for product in data['products']:
            push_product = PushOrderProduct(
                push_order_id=push_order.id,
                product_id=product['id'],
                price=product.get('price', 0),
                specs=json.dumps(product.get('specs', [])),
                specs_info=json.dumps(product.get('specs_info', {})),
                created_at=datetime.now()
            )
            db.session.add(push_product)

        try:
            db.session.commit()
            return jsonify({
                'message': '商品推送成功',
                'order_id': push_order.id,
                'order_number': order_number,
                'share_code': share_code
            }), 201
        except Exception as e:
            db.session.rollback()
            print(f'保存推送记录失败: {str(e)}')
            return jsonify({'error': '商品推送失败'}), 500
            
    except Exception as e:
        print(f'推送商品失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '商品推送失败'}), 500

# 获取推送单详情
@app.route('/push_orders/<int:order_id>', methods=['GET'])
@login_required
def get_push_order_detail(user_id, order_id):
    try:
        # 获取推送单及相关信息
        order = PushOrder.query\
            .join(User, PushOrder.user_id == User.id)\
            .filter(PushOrder.id == order_id)\
            .first()
            
        if not order:
            return jsonify({'error': '推送单不存在'}), 404
            
        # 获取推送商品列表
        items = []
        for item in order.products:
            product = Product.query.get(item.product_id)
            if product:
                items.append({
                    'id': item.id,
                    'product_id': item.product_id,
                    'product_name': product.name,
                    'price': float(item.price),
                    'specs': json.loads(item.specs) if item.specs else [],
                    'specs_info': json.loads(item.specs_info) if item.specs_info else {},
                    'image': json.loads(product.images)[0] if product.images else None
                })
                
        # 格式化返回数据
        order_detail = {
            'id': order.id,
            'order_number': order.order_number,
            'target_name': order.target_name,
            'status': order.status,
            'share_code': order.share_code,
            'created_at': order.created_at.isoformat(),
            'user': {
                'id': order.user.id,
                'username': order.user.username,
                'nickname': order.user.nickname
            },
            'items': items
        }
        
        return jsonify({'order': order_detail}), 200
        
    except Exception as e:
        print(f'获取推送单详情失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '获取推送单详情失败'}), 500

# 更新推送单状态
@app.route('/push_orders/<int:order_id>/status', methods=['PUT'])
@login_required
def update_push_order_status(user_id, order_id):
    try:
        data = request.json
        new_status = data.get('status')
        
        if new_status not in [0, 1, 2]:  # 0:待推送 1:已推送 2:已取消
            return jsonify({'error': '无效的状态值'}), 400
            
        # 获取推送单
        order = PushOrder.query.get(order_id)
        if not order:
            return jsonify({'error': '推送单不存在'}), 404
            
        # 更新状态
        order.status = new_status
        
        try:
            db.session.commit()
            return jsonify({'message': '推送单状态更新成功'}), 200
        except Exception as e:
            db.session.rollback()
            print(f'更新推送单状态失败: {str(e)}')
            return jsonify({'error': '更新推送单状态失败'}), 500
            
    except Exception as e:
        print(f'处理推送单状态更新请求失败: {str(e)}')
        return jsonify({'error': '更新推送单状态失败'}), 500


# 辅助函数：生成缩略图
def create_thumbnail(image_path, max_size=(800, 800)):
    """生成图片缩略图"""
    try:
        from PIL import Image
        
        # 打开图片
        with Image.open(image_path) as img:
            # 保持宽高比缩放
            img.thumbnail(max_size)
            # 保存缩略图，使用优化和压缩
            img.save(image_path, quality=85, optimize=True)
            return True
    except Exception as e:
        print(f'生成缩略图失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return False

# 访问上传的图片
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    try:
        
        # 获取文件类型和文件名
        if '/' in filename:
            file_ext = filename.split('/')[0]  # 获取文件类型目录
            base_filename = os.path.basename(filename)  # 获取文件名
        else:
            file_ext = filename.rsplit('.', 1)[1].lower()
            base_filename = filename
        
        # 构建完整路径
        file_dir = os.path.join(app.config['UPLOAD_FOLDER'], file_ext)
        file_path = os.path.join(file_dir, base_filename)
        
        if not os.path.exists(file_path):
            print(f"错误: 文件不存在 - {file_path}")
            return jsonify({'error': '文件不存在'}), 404
        
        return send_from_directory(file_dir, base_filename)
        
    except Exception as e:

        return jsonify({'error': f'访问文件失败: {str(e)}'}), 500

@app.route('/home/statistics', methods=['GET'])
def get_home_statistics():
    try:
        # 今日统计
        daily_stats = db.session.query(
            func.count(distinct(PurchaseOrder.id)).label('order_count'),
            func.sum(PurchaseOrderItem.quantity).label('total_quantity'),
            func.sum(PurchaseOrder.total_amount).label('total_amount')
        ).outerjoin(
            PurchaseOrderItem, PurchaseOrder.id == PurchaseOrderItem.order_id
        ).filter(
            func.date(PurchaseOrder.created_at) == func.current_date()
        ).first()

        # 本周统计
        weekly_stats = db.session.query(
            func.count(distinct(PurchaseOrder.id)).label('order_count'),
            func.sum(PurchaseOrderItem.quantity).label('total_quantity'),
            func.sum(PurchaseOrder.total_amount).label('total_amount')
        ).outerjoin(
            PurchaseOrderItem, PurchaseOrder.id == PurchaseOrderItem.order_id
        ).filter(
            text('YEARWEEK(created_at) = YEARWEEK(CURRENT_DATE)')
        ).first()

        # 本月统计
        monthly_stats = db.session.query(
            func.count(distinct(PurchaseOrder.id)).label('order_count'),
            func.sum(PurchaseOrderItem.quantity).label('total_quantity'),
            func.sum(PurchaseOrder.total_amount).label('total_amount')
        ).outerjoin(
            PurchaseOrderItem, PurchaseOrder.id == PurchaseOrderItem.order_id
        ).filter(
            PurchaseOrder.created_at >= text('DATE_SUB(CURRENT_DATE, INTERVAL 30 DAY)')
        ).first()

        # 最多购买的商品
        most_purchased = db.session.query(
            Product.name,
            func.sum(PurchaseOrderItem.quantity).label('total_quantity'),
            func.sum(PurchaseOrderItem.quantity * PurchaseOrderItem.price).label('total_amount')
        ).join(
            PurchaseOrderItem, Product.id == PurchaseOrderItem.product_id
        ).join(
            PurchaseOrder, PurchaseOrder.id == PurchaseOrderItem.order_id
        ).group_by(
            Product.id, Product.name
        ).order_by(
            text('total_quantity DESC')
        ).limit(5).all()

        # 最近订单
        recent_orders = db.session.query(
            PurchaseOrder.order_number,
            PurchaseOrder.total_amount,
            PurchaseOrder.created_at,
            func.group_concat(
                func.json_object(
                    'product_name', Product.name,
                    'quantity', PurchaseOrderItem.quantity,
                    'price', PurchaseOrderItem.price,
                    'color', PurchaseOrderItem.color
                ).cast(Text)
            ).label('items')
        ).join(
            PurchaseOrderItem, PurchaseOrder.id == PurchaseOrderItem.order_id
        ).join(
            Product, PurchaseOrderItem.product_id == Product.id
        ).group_by(
            PurchaseOrder.id
        ).order_by(
            PurchaseOrder.created_at.desc()
        ).limit(5).all()

        return jsonify({
            'code': 200,
            'message': 'success',
            'data': {
                'daily': {
                    'order_count': daily_stats[0] or 0,
                    'total_quantity': daily_stats[1] or 0,
                    'total_amount': daily_stats[2] or 0
                },
                'weekly': {
                    'order_count': weekly_stats[0] or 0,
                    'total_quantity': weekly_stats[1] or 0,
                    'total_amount': weekly_stats[2] or 0
                },
                'monthly': {
                    'order_count': monthly_stats[0] or 0,
                    'total_quantity': monthly_stats[1] or 0,
                    'total_amount': monthly_stats[2] or 0
                },
                'most_purchased': [{
                    'name': item[0],
                    'total_quantity': item[1] or 0,
                    'total_amount': item[2] or 0
                } for item in most_purchased],
                'recent_orders': [{
                    'order_number': order[0],
                    'total_amount': order[1],
                    'created_at': order[2].strftime('%Y-%m-%d %H:%M:%S'),
                    'items': json.loads('[' + order[3] + ']') if order[3] else []
                } for order in recent_orders]
            }
        })
    except Exception as e:
        print(f"Error getting statistics: {str(e)}")
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({
            'code': 500,
            'message': f'Failed to get statistics: {str(e)}',
            'data': None
        })


if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(host='0.0.0.0', port=80)