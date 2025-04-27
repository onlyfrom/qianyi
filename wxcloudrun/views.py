from datetime import datetime, timedelta
from flask import render_template, request, jsonify, send_from_directory, abort, make_response, send_file, current_app, g
from run import app
from wxcloudrun.model import *
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import pandas as pd
import jwt
from functools import wraps
import os
import time
import config
import requests
import uuid
import json
from wxcloudrun import db
from wxcloudrun.token import generate_token, verify_token, extend_token_expiry
import traceback
from Crypto.Cipher import AES
import base64
from werkzeug.utils import secure_filename
import string
import random
from sqlalchemy import inspect, text, func, desc, distinct, case, Text
from sqlalchemy.sql import literal, literal_column
from wxcloudrun.response import *
from wxcloudrun.recommended import get_recommended_products, update_recommended_products
import re

WECHAT_APPID = "wxa17a5479891750b3"
WECHAT_SECRET = "33359853cfee1dc1e2b6e535249e351d"
WX_ENV = 'prod-9gd4jllic76d4842'
API_URL = os.environ.get("APIURL", "https://api.weixin.qq.com")

# 用户认证中间件
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

#管理员认证中间件
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            # 获取 token
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                print('未提供认证令牌')
                return jsonify({'error': '未提供认证令牌'}), 401

            token = auth_header.split(' ')[1] if len(auth_header.split(' ')) > 1 else auth_header

            # 验证 token
            user_id = verify_token(token)
            if not user_id:
                print('无效或已过期的认证令牌')
                return jsonify({'error': '无效或已过期的认证令牌'}), 401

            # 检查用户是否是管理员
            user = User.query.get(user_id)
            if not user:
                print('用户不存在')
                return jsonify({'error': '用户不存在'}), 404
                
            # 验证用户类型和角色
            if user.user_type != 1 or (user.role != 'admin' and user.role != 'ADMIN' and user.role != 'normal_admin'):
                print(f"当前用户信息: ID={user.id}, 用户名={user.username}, 角色={user.role}, 用户类型={user.user_type}")
                print('需要管理员权限')
                return jsonify({'error': '需要管理员权限'}), 403

            if user.status != 1:
                print('账号已被禁用')
                return jsonify({'error': '账号已被禁用'}), 403

            # 将管理员信息存储在请求上下文中
            setattr(g, 'admin_user', user)

            # 延长 token 有效期
            new_token = extend_token_expiry(token)
            if new_token:
                response = make_response(f(*args, user_id=user_id, **kwargs))
                response.headers['New-Token'] = new_token
                return response

            return f(*args, user_id=user_id, **kwargs)

        except Exception as e:
            print(f"管理员权限验证失败: {str(e)}")
            print(f"错误追踪:\n{traceback.format_exc()}")
            return jsonify({'error': '权限验证失败'}), 500

    return decorated_function

def staff_required(f):
    """员工权限验证装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            # 从请求头获取用户ID
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                return jsonify({'error': '未提供认证令牌'}), 401

            token = auth_header.split(' ')[1] if len(auth_header.split(' ')) > 1 else auth_header

            # 验证 token
            user_id = verify_token(token)
            if not user_id:
                return jsonify({
                    'code': 401,
                    'message': '未登录'
                }), 401

            # 查询用户信息
            user = User.query.get(user_id)
            if not user:
                return jsonify({
                    'code': 401,
                    'message': '用户不存在'
                }), 401

            # 验证用户类型和状态
            if user.user_type != 2 or user.role != 'STAFF':
                return jsonify({
                    'code': 403,
                    'message': '无员工权限'
                }), 403

            if user.status != 1:
                return jsonify({
                    'code': 403,
                    'message': '账号已禁用'
                }), 403

            # 将用户信息存储在g对象中，方便后续使用
            g.staff_user = user
            return f(*args, **kwargs)

        except Exception as e:
            print(f"员工权限验证失败: {str(e)}")
            print(f"错误追踪:\n{traceback.format_exc()}")
            return jsonify({
                'code': 500,
                'message': '权限验证失败'
            }), 500

    return decorated_function

def check_staff_permission(permission):
    """
    检查员工特定权限的装饰器
    :param permission: 权限标识符，例如：'product.view', 'order.edit' 等
    """
    def decorator(f):
        @wraps(f)
        @login_required  # 添加登录验证装饰器
        def decorated_function(*args, **kwargs):
            try:
                user_id = kwargs.get('user_id')
                user = User.query.get(user_id)
                
                print(f'当前用户信息: {user.user_type}, {user.role}')
                # 管理员拥有所有权限
                if user.user_type == 1 or user.role == 'admin' or user.role == 'normalAdmin':
                    # 将用户信息存储在请求上下文中
                    setattr(g, 'admin_user', user)
                    return f(*args, **kwargs)

                print(f'当前用户信息: {user.user_type}, {user.role}')
                # 验证员工权限
                if user.user_type != 5 or user.role != 'STAFF' :
                    return jsonify({
                        'code': 403,
                        'message': '无员工权限'
                    }), 403

                if user.status != 1:
                    return jsonify({
                        'code': 403,
                        'message': '账号已禁用'
                    }), 403

                # TODO: 这里可以添加更细粒度的权限检查
                # 例如：检查用户是否拥有特定的权限标识符
                # if not has_permission(user, permission):
                #     return jsonify({'code': 403, 'message': f'无{permission}权限'}), 403

                # 将员工信息存储在请求上下文中
                setattr(g, 'staff_user', user)
                return f(*args, **kwargs)

            except Exception as e:
                print(f"权限检查失败: {str(e)}")
                print(f"错误追踪:\n{traceback.format_exc()}")
                return jsonify({
                    'code': 500,
                    'message': '权限检查失败'
                }), 500

        return decorated_function
    return decorator

@app.route('/api/test/db', methods=['GET'])
def test_db():
    """
    测试数据库连接的接口
    """
    try:
        return jsonify({
            'code': 0,
            'data': {
                'database_name': config.database,
                'host': config.db_address,
                'connection_status': 'connected' if db.session.is_active else 'disconnected'
            },
            'message': '数据库连接测试'
        })
    except Exception as e:
        return jsonify({
            'code': -1,
            'message': f'数据库连接测试失败：{str(e)}'
        }), 500



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



# 微信openid登录接口
@app.route('/wx/openid/login', methods=['POST'])
def wechat_openid_login():
    try:
        print('='*50)
        print('开始处理微信openid登录请求')
        print('='*50)
        
        # 从header中获取openid
        openid = request.headers.get('x-wx-openid')
        nickname = request.get('x-wx-nickname')
        if not openid:
            print('错误: 未获取到openid')
            return jsonify({'error': '未获取到openid'}), 401
            
        print('从header获取到的openid:', openid)
        
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

@app.route('/wx/openid/logintype', methods=['POST'])
def wechat_openid_logintype():
    try:
        print('='*50)
        print('开始处理微信openid登录请求')
        print('='*50)
        
        # 从header中获取openid和请求数据
        data = request.get_json()
        openid = request.headers.get('x-wx-openid')
        nickname = data.get('nickname') if data else None
        
        if not openid:
            print('错误: 未获取到openid')
            return jsonify({'error': '未获取到openid'}), 401
            
        print('从header获取到的openid:', openid)
        print('获取到的nickname:', nickname)
        
        # 先通过openid查询用户
        user = User.query.filter_by(openid=openid).first()
        
        if not user and nickname:
            # 如果openid没找到用户，且提供了nickname，尝试通过nickname查找
            print(f'通过nickname查找用户: {nickname}')
            user = User.query.filter_by(nickname=nickname).first()
            
            if user and not user.openid:
                # 如果找到用户且该用户没有openid，则更新用户的openid
                print(f'找到现有用户(ID={user.id})，更新openid')
                user.openid = openid
                user.last_login = datetime.now()
                db.session.commit()
        
        if user:
            print(f'找到用户: ID={user.id}, nickname={user.nickname}')
            # 更新最后登录时间
            user.last_login = datetime.now()
            db.session.commit()
            
            # 生成token并返回用户信息
            token = generate_token(user.id)
            return jsonify({
                'code': 200,
                'data': {
                'is_registered': True,
                'token': token,
                'userInfo': {
                    'id': user.id,
                    'username': user.username,
                    'nickname': user.nickname,
                    'avatar': user.avatar,
                    'phone': user.phone,
                    'address': user.address,
                    'contact': user.contact,
                    'user_type': user.user_type,
                    'status': user.status,
                    'created_at': user.created_at,
                    'last_login': user.last_login,
                    'role': user.role,                    

                }
            }
            })
        
        # 如果没有找到用户，返回非邀请客户错误
        print('未找到用户，返回非邀请客户错误')
        return jsonify({
            'code': 403,
            'message': '非邀请客户'
        }), 403
        
    except Exception as e:
        print('\n处理微信openid登录请求时发生错误:')
        print(f'- 错误类型: {type(e).__name__}')
        print(f'- 错误信息: {str(e)}')
        print(f'- 错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '登录失败'}), 500

#微信注册
@app.route('/wx/register', methods=['POST'])
def wechat_register():
    try:
        print('='*50)
        print('开始处理微信登录请求')
        print('='*50)
        
        data = request.json
        print('收到的请求数据:', json.dumps(data, ensure_ascii=False, indent=2))
        
        code = data.get('code')
        encrypted_data = data.get('encryptedData')
        iv = data.get('iv')

        if not all([code, encrypted_data, iv]):
            print('错误: 缺少必要参数')
            return jsonify({'error': '缺少必要参数'}), 400

        # 获取微信用户信息
        wx_data = get_wx_user_info(code)
        if not wx_data:
            return jsonify({'error': '获取微信用户信息失败'}), 400

        openid = wx_data.get('openid')
        
        # 注册用户
        user = User.query.filter_by(openid=openid).first()
        if not user:
            user = User(
                openid=openid,
                nickname=wx_data.get('nickName'),
                avatar=wx_data.get('avatarUrl'),
                user_type=0,
                status=1,
                created_at=datetime.now()
            )
            db.session.add(user)
            db.session.commit()
            print(f'新用户创建成功: ID={user.id}')
        
        # 生成token
        token = generate_token(user.id)
        
        return jsonify({
            'code': 200,
            'data': {
                'token': token
            }
        })
        
    except Exception as e:
        print('\n处理微信注册请求时发生错误:')
        print(f'- 错误类型: {type(e).__name__}')
        print(f'- 错误信息: {str(e)}')
        print(f'- 错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '注册失败'}), 500  

        
@app.route('/wx/login', methods=['POST'])
def wechat_login():
    try:
        print('='*50)
        print('开始处理微信登录请求')
        print('='*50)
        
        # 从header中获取openid
        openid = request.headers.get('x-wx-openid')
        if not openid:
            print('错误: 未获取到openid')
            return jsonify({'error': '未获取到openid'}), 401
            
        print('从header获取到的openid:', openid)
            
        # 查找用户
        user = User.query.filter_by(openid=openid).first()
        
        # 用户不存在
        if not user:
            print('用户不存在,询问是否注册')
            return jsonify({
                'code': 200,
                'data': {
                    'is_registered': False
                }
            }),400
            
        # 用户被禁用
        if user.status == 0:
            print('用户已被禁用')
            return jsonify({'error': '账号已被禁用'}), 403
            
        # 生成token
        token = generate_token(user.id)
        if not token:
            print('生成token失败')
            return jsonify({'error': '登录失败'}), 500
            
        print('登录成功')
        return jsonify({
            'code': 200,
            'data': {
                'is_registered': True,
                'token': token,
                'userInfo': {
                    'id': user.id,
                    'username': user.username,
                    'nickname': user.nickname,
                    'avatar': user.avatar,
                    'phone': user.phone,
                    'address': user.address,
                    'contact': user.contact,
                    'user_type': user.user_type,
                    'status': user.status,
                    'created_at': user.created_at,
                    'last_login': user.last_login,
                    'role': user.role,                    

                }
            }
        })
            
    except Exception as e:
        print('微信登录失败:', str(e))
        print('错误追踪:\n', traceback.format_exc())
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
        user_type = data.get('user_type', 0)
        role = data.get('role', 'customer')
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
            user_type=user_type,  # 普通用户
            role=role,
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
                'user_type': user.user_type,
                'status': user.status,
                'role': user.role,

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


# 新增或更新商品（需要登录）
@app.route('/products', methods=['POST'])
@check_staff_permission('product.edit')
def add_or_update_product(user_id):
    try:
        data = request.get_json()
        
        # 验证必需的字段
        if not any(field in data for field in ['name', 'id']):
            print('缺少的字段: name或id')
            return jsonify({'error': '缺少必需的字段: name或id'}), 400
        
        # 检查是否提供了商品ID
        product_id = data.get('id')
        print(f'商品ID: {product_id}')
        if product_id:
            # 更新现有商品
            product = Product.query.get(product_id)
            if not product:
                return jsonify({'error': '商品不存在'}), 404                
            # 只更新传入的字段
            if 'name' in data:
                product.name = data['name'].strip()
            if 'description' in data:
                product.description = data['description'].strip()
            if 'price' in data:
                product.price = float(data['price'])
            if 'price_b' in data:
                product.price_b = float(data['price_b'])
            if 'price_c' in data:
                product.price_c = float(data['price_c'])
            if 'price_d' in data:
                product.price_d = float(data['price_d'])
            if 'cost_price' in data:
                product.cost_price = float(data['cost_price'])            
            if 'type' in data:
                product.type = data['type']
            if 'specs_info' in data:
                product.specs_info = json.dumps(data['specs_info'])
            if 'specs' in data:
                product.specs = json.dumps(data['specs'])
            if 'images' in data:
                product.images = json.dumps(data['images'])                
            if 'status' in data:
                product.status = data['status']
            if 'is_public' in data:
                product.is_public = data['is_public']
            if 'video_url' in data:
                product.video_url = data['video_url']
            if 'size' in data:
                product.size = data['size']
            if 'weight' in data:
                product.weight = data['weight']
            if 'yarn' in data:
                product.yarn = data['yarn']
            if 'composition' in data:
                product.composition = data['composition']
            product.updated_at = datetime.now()
        else:
            # 新增商品时的必需字段验证
            print(f'新增商品!  字段验证: {data}')
            required_fields = ['name']
            if not all(field in data for field in required_fields):
                missing_fields = [field for field in required_fields if field not in data]
                print(f'缺少的字段: {missing_fields}')
                return jsonify({'error': f'新增商品缺少必需的字段{missing_fields}'}), 400
                
            # 获取价格字段，如果未提供则使用price的值
            price = float(data.get('price', 0))
            price_b = float(data.get('price_b', 0))
            price_c = float(data.get('price_c', price_b +2))
            price_d = float(data.get('price_d', price_c +2))
            cost_price = float(data.get('cost_price', 0))
            
            # 获取状态字段，设置默认值
            status = data.get('status', 1)  # 默认上架
            is_public = data.get('is_public', 0)  # 默认私密
            
            # 生成新的商品ID
            product_type = str(data['type']).zfill(2)  # 确保类型是两位数
            
            # 生成新的商品ID，格式为 QY{number}
            # 查找当前最大的编号
            all_products = Product.query.filter(
                Product.id.like('QY%')
            ).all()
            
            max_number = 0
            for product in all_products:
                try:
                    num = int(product.id[2:])  # 跳过 'QY' 前缀
                    if num > max_number:
                        max_number = num
                except ValueError:
                    continue
            
            new_number = str(max_number + 1)
            new_product_id = f'QY{new_number}'
            print(f'新增商品ID: {new_product_id}')
            
            # 创建新商品
            product = Product(
                id=new_product_id,
                name=data['name'].strip(),
                description=data['description'].strip(),
                price=price,
                price_b=price_b,
                price_c=price_c,
                price_d=price_d,
                cost_price=cost_price,
                type=data.get('type', 1),
                specs=json.dumps(data.get('specs', {})),
                images=json.dumps(data.get('images', [])),
                status=status,
                is_public=is_public,
                created_at=datetime.now(),
                updated_at=datetime.now(),
                video_url=data.get('video_url', ''),
                size=data.get('size', '-'),
                weight=data.get('weight', '0'),
                yarn=data.get('yarn', '-'),
                composition=data.get('composition', '-')
            )
            db.session.add(product)
            
        try:
            db.session.commit()
            print(f'商品保存成功: {product.id}')
            return jsonify({
                'message': '商品保存成功',
                'product_id': product.id,
                'product_images': json.loads(product.images) if product.images else []
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
@login_required
def get_product_detail(user_id, product_id):
    try:
        product = Product.query.get(product_id)
        if not product:
            return jsonify({'error': '商品不存在'}), 404
            
        # 获取当前用户信息
        current_user = User.query.get(user_id)
        if not current_user:
            return jsonify({'error': '用户不存在'}), 404
        
        # 获取推送过该商品的用户
        pushed_users = db.session.query(User.id, User.nickname, User.avatar)\
            .join(PushOrder, PushOrder.target_user_id == User.id)\
            .join(PushOrderProduct, PushOrderProduct.push_order_id == PushOrder.id)\
            .filter(PushOrderProduct.product_id == product_id)\
            .distinct().all()
            
        # 获取所有用户
        all_users = db.session.query(User.id, User.nickname, User.avatar).all()
        
        # 获取未推送过的用户
        pushed_user_ids = {user.id for user in pushed_users}
        not_pushed_users = [user for user in all_users if user.id not in pushed_user_ids]
        
        # 格式化用户数据
        pushed_users_data = [{
            'id': user.id,
            'nickname': user.nickname,
            'avatar': user.avatar
        } for user in pushed_users]
        
        not_pushed_users_data = [{
            'id': user.id, 
            'nickname': user.nickname,
            'avatar': user.avatar
        } for user in not_pushed_users]

        # 获取基础价格
        base_price = float(product.price) if product.price is not None else 0
        
        # 初始化规格信息
        specs = json.loads(product.specs) if product.specs else []
        specs_info = json.loads(product.specs_info) if product.specs_info else {}
        
        # 如果是普通客户，检查推送单中的价格和规格
        if current_user.role == 'customer':
            # 查找该用户最新的有效推送单中的商品信息
            latest_push = db.session.query(PushOrderProduct)\
                .join(PushOrder, PushOrder.id == PushOrderProduct.push_order_id)\
                .filter(
                    PushOrderProduct.product_id == product_id,
                    PushOrder.target_user_id == user_id  
                )\
                .order_by(PushOrder.created_at.desc())\
                .first()
                
            if latest_push:
                # 如果在推送单中找到信息，使用推送单中的价格和规格
                display_price = float(latest_push.price)
                if latest_push.specs:
                    specs = json.loads(latest_push.specs)
            else:
                # 如果不在推送单中，检查是否是公开商品
                if product.is_public:
                    # 根据用户类型获取对应价格
                    if current_user.customer_type == 2:
                        display_price = float(product.price_b) if product.price_b is not None else base_price
                    elif current_user.customer_type == 3:
                        display_price = float(product.price_c) if product.price_c is not None else base_price
                    elif current_user.customer_type == 4:
                        display_price = float(product.price_d) if product.price_d is not None else base_price
                    else:
                        display_price = base_price
                else:
                    # 如果不是公开商品，返回错误
                    return jsonify({'error': '该商品未对您开放'}), 403
        else:
            # 如果不是普通客户，显示基础价格
            display_price = base_price

        product_detail = {
            'id': product.id,
            'name': product.name,
            'description': product.description,
            'price': display_price,  # 使用计算后的价格
            'price_b': float(product.price_b) if product.price_b is not None else base_price,
            'price_c': float(product.price_c) if product.price_c is not None else base_price,
            'price_d': float(product.price_d) if product.price_d is not None else base_price,
            'cost_price': float(product.cost_price) if product.cost_price is not None else base_price,
            'specs': specs,
            'images': json.loads(product.images) if product.images else [],
            'type': product.type,
            'created_at': product.created_at.isoformat() if product.created_at else None,
            'status': product.status if product.status is not None else 1,  # 默认上架
            'is_public': product.is_public if product.is_public is not None else 1,  # 默认公开
            'size': product.size if product.size is not None else '-',
            'weight': product.weight if product.weight is not None else '0',
            'yarn': product.yarn if product.yarn is not None else '-',
            'composition': product.composition if product.composition is not None else '-',
            'pushed_users': pushed_users_data,
            'not_pushed_users': not_pushed_users_data,
            'video_url': product.video_url if product.video_url is not None else ''
        }
        return jsonify({'product': product_detail}), 200

    except Exception as e:
        print(f"获取商品详情失败: {str(e)}")
        return jsonify({'error': '获取商品详情失败'}), 500

# 获取最近添加的商品
@app.route('/products/recent', methods=['GET'])
def get_recent_products():
    try:
        # 获取最近7天的商品
        one_week_ago = datetime.now() - timedelta(days=7)
        
        # 查询最近一周添加的商品
        recent_products = Product.query.filter(
            Product.created_at >= one_week_ago,
            Product.status == 1,  # 确保商品是上架状态
            Product.is_public == 1  # 确保商品是公开的
        ).order_by(Product.created_at.desc()).all()

        # 如果一周内没有新商品，则获取最近的10件商品
        if not recent_products:
            recent_products = Product.query.filter(
                Product.status == 1
            ).order_by(Product.created_at.desc()).limit(10).all()

        result = []
        for product in recent_products:
            # 获取规格信息
            specs = json.loads(product.specs) if product.specs else []
            all_colors_stock = []
            total_stock = 0
            
            # 计算总库存和各颜色库存
            for spec in specs:
                try:
                    stock = int(spec.get('stock', 0))
                    total_stock += stock
                    color_info = {
                        'color': spec.get('color', '未知颜色'),
                        'stock': stock
                    }
                    all_colors_stock.append(color_info)
                except (ValueError, TypeError):
                    continue

            base_price = float(product.price) if product.price is not None else 0
            product_data = {
                'id': product.id,
                'name': product.name,
                'description': product.description,
                'price': base_price,
                'images': json.loads(product.images) if product.images else [],
                'total_stock': total_stock,
                'all_colors_stock': all_colors_stock,
                'created_at': product.created_at.isoformat() if product.created_at else None,
                'days_since_created': (datetime.now() - product.created_at).days if product.created_at else None,
                'is_new': (datetime.now() - product.created_at).days <= 7 if product.created_at else False  # 标记是否是一周内的新品
            }
            result.append(product_data)

        return jsonify({
            'code': 0,
            'data': {
                'products': result,
                'total': len(result),
                'has_new': any(p['is_new'] for p in result)  # 是否包含新品
            },
            'message': 'success'
        })

    except Exception as e:
        print(f"获取近期上新商品失败: {str(e)}")
        return jsonify({
            'code': -1,
            'message': '获取近期上新商品失败'
        }), 500

# 确保文件扩展名合法
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in config.ALLOWED_EXTENSIONS


@app.route('/upload', methods=['POST'])
@admin_required
def upload_file_handler(user_id):
    try:
        # 检查是否是base64上传
        if request.is_json:
            data = request.get_json()
            if 'file' in data and isinstance(data['file'], str):
                # 处理base64上传
                try:
                    # 解码base64数据
                    base64_data = data['file']
                    if ',' in base64_data:
                        base64_data = base64_data.split(',')[1]
                    
                    file_data = base64.b64decode(base64_data)
                    
                    # 获取文件扩展名
                    file_ext = data.get('ext', 'jpg').lower()
                    if not allowed_file(f'temp.{file_ext}'):
                        return jsonify({'error': '不支持的文件类型'}), 400
                    
                    # 创建上传目录（使用绝对路径）
                    upload_dir = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], file_ext)
                    os.makedirs(upload_dir, exist_ok=True)
                    
                    # 生成安全的文件名
                    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
                    random_str = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
                    new_filename = f'{timestamp}_{random_str}.{file_ext}'
                    
                    # 保存文件
                    file_path = os.path.join(upload_dir, new_filename)
                    with open(file_path, 'wb') as f:
                        f.write(file_data)
                    
                    # 返回可访问的URL
                    file_url = f'/uploads/{file_ext}/{new_filename}'
                    
                    print(f'Base64文件已保存: {file_path}')
                    print(f'访问URL: {file_url}')
                    
                    return jsonify({
                        'url': file_url,
                        'filename': new_filename
                    }), 200
                    
                except Exception as e:
                    print(f'处理Base64文件上传失败: {str(e)}')
                    return jsonify({'error': 'Base64文件处理失败'}), 400
        
        # 处理普通文件上传
        if 'file' not in request.files:
            return jsonify({'error': '未找到上传文件'}), 400
            
        file = request.files['file']
        if not file or file.filename == '':
            return jsonify({'error': '未选择文件'}), 400
            
        if not allowed_file(file.filename):
            return jsonify({'error': '不支持的文件类型'}), 400
            
        # 获取文件类型并创建对应目录（使用绝对路径）
        file_ext = file.filename.rsplit('.', 1)[1].lower()
        upload_dir = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], file_ext)
        os.makedirs(upload_dir, exist_ok=True)
            
        # 生成安全的文件名
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        random_str = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        new_filename = f'{timestamp}_{random_str}_{filename}'
        
        # 保存文件
        file_path = os.path.join(upload_dir, new_filename)
        file.save(file_path)  
        
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


@app.errorhandler(404)
def not_found_error(error):
    return jsonify({'error': '请求的资源不存在'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': '服务器内部错误'}), 500
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
                
                # 验证商品名称（必填）
                if pd.isna(row['商品名称']):
                    error_msg = f'第 {index + 2} 行：商品名称不能为空'
                    print(f'错误: {error_msg}')
                    errors.append(error_msg)
                    continue   
                
                # 生成商品ID（使用时间戳+随机数）
                try:
                    product_id = "QY" + str(row['货号']).strip()
                except Exception as e:
                    error_msg = f'第 {index + 2} 行：货号格式错误 - {str(e)}'
                    print(f'错误: {error_msg}')
                    errors.append(error_msg)
                    continue
                
                # 打印行数据用于调试    
                print(f'行数据: {dict(row)}')
                    
                try:
                    # 初始化specs列表
                    specs = []
                    
                    # 处理颜色信息
                    if not pd.isna(row.get('颜色', '')):
                        colors = str(row['颜色']).strip()
                        # 分割颜色（支持多个分隔符）
                        color_list = [c.strip() for c in re.split('[，、,]', colors) if c.strip()]
                        if not color_list:
                            color_list = ['默认']
                            
                        # 为每个颜色创建规格
                        for color in color_list:
                            spec = {
                                'color': color,
                                'stock': 0,  # 默认库存为0
                                'price': float(row['A类售价']) if not pd.isna(row.get('A类售价', '')) else 0
                            }
                            specs.append(spec)
                    else:
                        # 如果没有颜色信息，添加默认规格
                        specs.append({
                            'color': '默认',
                            'stock': 0,
                            'price': float(row['A类售价']) if not pd.isna(row.get('A类售价', '')) else 0
                        })

                    # 构建商品数据，使用默认值处理空值
                    product_data = {
                        'id': product_id,
                        'name': str(row['商品名称']).strip(),
                        'yarn': str(row['材质']).strip() if not pd.isna(row.get('材质', '')) else '',  # 材质
                        'composition': str(row['成份']).strip() if not pd.isna(row.get('成份', '')) else '',  # 成份
                        'size': str(row['尺寸']).strip() if not pd.isna(row.get('尺寸', '')) else '',  # 尺寸
                        'weight': str(row['克重']).strip() if not pd.isna(row.get('克重', '')) else '',  # 克重
                        'price': float(row['A类售价']) if not pd.isna(row.get('A类售价', '')) else 0,  # A类售价
                        'description': str(row['备注']).strip() if not pd.isna(row.get('备注', '')) else '',  # 备注
                        'type': 1,  # 默认类型
                        'created_at': datetime.now().isoformat(),
                        'specs': json.dumps(specs)
                    }
                except ValueError as e:
                    error_msg = f'第 {index + 2} 行：数据格式错误 - {str(e)}'
                    print(f'错误: {error_msg}')
                    errors.append(error_msg)
                    continue
                
                product_data['description'] = ''
  
                # 设置默认规格并获取商品颜色
                specs = []
                # 获取商品颜色
                try:
                    color_field = str(row['颜色']).strip() if not pd.isna(row.get('颜色', '')) else ''
                    if color_field:
                        # 尝试多种分隔符分离颜色
                        if '，' in color_field:
                            product_colors = color_field.split('，')
                        elif '、' in color_field:
                            product_colors = color_field.split('、')
                        elif ',' in color_field:
                            product_colors = color_field.split(',')
                        else:
                            # 如果没有分隔符，将整个字符串作为一个颜色
                            product_colors = [color_field]
                        
                        # 清理颜色名称
                        product_colors = [color.strip() for color in product_colors if color.strip()]
                    else:
                        product_colors = ['默认']
                except Exception as e:
                    print(f"处理颜色字段失败: {str(e)}")
                    product_colors = ['默认']

                # 为每个颜色创建规格
                for color in product_colors:
                    color_spec = {
                        'color': color,
                        'image': '',
                        'stock': 999999
                    }
                    specs.append(color_spec)

                # 如果没有有效的颜色，添加默认规格
                if not specs:
                    specs = [{
                        'color': '默认',
                        'image': '',
                        'stock': 999999
                    }]

                product_data['specs'] = json.dumps(specs)
         
                # 从系统设置获取商品类型配置
                settings = SystemSettings.query.filter_by(setting_key='product_types').first()
                product_types = []
                if settings and settings.setting_value:
                    try:
                        product_types = json.loads(settings.setting_value)
                    except:
                        print('解析商品类型配置失败')

                # 设置默认类型
                product_data['type'] = 5  # 默认类型

                # 从Excel获取类型名称
                type_name = str(row.get('类型', '')).strip() if not pd.isna(row.get('类型', '')) else ''
                
                # 根据类型名称匹配类型ID
                if type_name:
                    for type_config in product_types:
                        if type_name == type_config['name']:
                            product_data['type'] = type_config['id']
                            break
                
                print('插入新商品...')
                new_product = Product(
                    id=product_data['id'],
                    name=product_data['name'],
                    description=product_data['description'],
                    price = '0',
                    price_b=product_data['price'],
                    price_c= float(product_data['price']) + 2,
                    price_d= float(product_data['price']) + 4,
                    specs=product_data['specs'],
                    type=product_data['type'],
                    created_at=product_data['created_at'],
                    size=product_data['size'],
                    weight=product_data['weight'],
                    yarn=product_data['yarn'],
                    composition=product_data['composition'],
                    is_public = 0 #默认不公开
                    
                )
                db.session.add(new_product)
                db.session.commit()
                
                imported_count += 1
                print(f'成功处理第 {index + 2} 行数据')
                
            except Exception as e:
                error_msg = f'第 {index + 2} 行：{str(e)}'
                print(f'错误: {error_msg}')
                errors.append(error_msg)
                db.session.rollback()
                
        print(f'\n导入完成: 成功导入 {imported_count} 条数据，失败 {len(errors)} 条')
            
        return jsonify({
            'code': 200,
            'message': '导入成功',
            'data': {
                'imported': imported_count,
                'errors': errors if errors else None
            }
        })
        
    except Exception as e:
        print(f'导入过程发生错误: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({
            'code': 500,
            'message': '导入失败',
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
        handler_id = data.get('handler_id')
        # 生成订单号
        order_number = datetime.now().strftime('%Y%m%d%H%M%S') + str(random.randint(1000, 9999))
        
        # 计算总金额
        total_amount = sum(float(item.get('price', 0)) * float(item.get('quantity', 0)) for item in data['items'])
        print(len(data['items']))
        if len(data['items']) == 0:
            return jsonify({'error': '请添加至少一个商品'}), 400
        # 创建采购单

        status = data.get('status', 1)
        purchase_order = PurchaseOrder(
            order_number=order_number,
            user_id=data.get('user_id', user_id),            
            total_amount=total_amount,
            status=status,  # 初始状态：待处理
            remark=data.get('remark', ''),
            created_at=datetime.now()
        )
        
        if handler_id :
            purchase_order.handler_id = handler_id
        
        db.session.add(purchase_order)
        db.session.flush()  # 立即刷新会话，获取新创建的 ID
        
        # 添加采购明细
        for item in data['items']:
            order_item = PurchaseOrderItem(
                order_id=purchase_order.id,  # 现在可以安全地使用 ID
                product_id=item['product_id'],
                quantity=item['quantity'],
                price=item['price'],
                color=item.get('color', ''),
                logo_price=item.get('logo_price', 0.0),  # 加标价格
                accessory_price=item.get('accessory_price', 0.0),  # 辅料价格
                packaging_price=item.get('packaging_price', 0.0)  # 包装价格
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
        keyword = request.args.get('keyword')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        # 获取当前用户信息
        current_user = User.query.get(user_id)
        if not current_user:
            return jsonify({'error': '用户不存在'}), 404
            
        # 构建查询，加入用户信息
        query = db.session.query(PurchaseOrder, User).join(
            User, PurchaseOrder.user_id == User.id
        )
        
        # 如果不是管理员，限制只能查看自己的订单
        if current_user.role != 'admin' and current_user.role != 'STAFF':  # 假设 1 表示管理员
            query = query.filter(PurchaseOrder.user_id == user_id)
        
        if keyword:
            query = query.filter(db.or_(
                PurchaseOrder.order_number.like(f'%{keyword}%'),
                User.username.like(f'%{keyword}%'),
                User.nickname.like(f'%{keyword}%'),
                User.phone.like(f'%{keyword}%')
            ))
        # 添加筛选条件
        if status:
            query = query.filter(PurchaseOrder.status == status)
            
        if date_range:
            query = query.filter(PurchaseOrder.created_at.between(date_range[0], date_range[1]))

        # 日期范围筛选
        if start_date and end_date:
            print('开始时间和结束时间', start_date, end_date)
            query = query.filter(
                db.and_(
                    func.date(PurchaseOrder.created_at) >= func.date(start_date),
                    func.date(PurchaseOrder.created_at) <= func.date(end_date)
                )
            )
        elif start_date:
            query = query.filter(func.date(PurchaseOrder.created_at) >= func.date(start_date))
        elif end_date:
            query = query.filter(func.date(PurchaseOrder.created_at) <= func.date(end_date))

        # 按创建时间倒序排序
        query = query.order_by(PurchaseOrder.created_at.desc())
        
        # 执行分页
        pagination = query.paginate(page=page, per_page=page_size)
        
        # 构建返回数据
        orders = []
        
        for order, user in pagination.items:
            try:
                # 获取订单明细
                order_items = db.session.query(PurchaseOrderItem).filter(
                    PurchaseOrderItem.order_id == order.id
                ).all()
                
                # 使用字典来临时存储合并的商品数据
                merged_products = {}
                
                for item in order_items:
                    try:
                        product = Product.query.get(item.product_id)
                        if not product:
                            continue
                            
                        # 使用商品ID作为键
                        if item.product_id not in merged_products:
                            merged_products[item.product_id] = {
                                'id': product.id,
                                'product_id': product.id,
                                'product_name': product.name,
                                'image': json.loads(product.images)[0] if product.images and len(json.loads(product.images)) > 0 else None,
                                'total_quantity': 0,
                                'total_amount': 0,
                                'total_amount_extra': 0,
                                'specs': []
                            }
                        
                        # 查询该商品规格的已发货数量
                        shipped_quantity = 0
                        if item.color:
                            # 查询相同商品ID和颜色的已发货数量
                            shipped_result = db.session.query(func.sum(DeliveryItem.quantity)).filter(
                                DeliveryItem.product_id == item.product_id,
                                DeliveryItem.color == item.color,
                                DeliveryItem.order_number == order.order_number
                            ).scalar()
                            shipped_quantity = int(shipped_result) if shipped_result is not None else 0
                        # 添加当前规格信息
                        spec_info = {
                            'color': item.color,
                            'quantity': item.quantity,
                            'price': float(item.price),
                            'logo_price': float(item.logo_price),  # 加标价格
                            'accessory_price': float(item.accessory_price),  # 辅料价格
                            'packaging_price': float(item.packaging_price),  # 包装价格
                            'total': item.quantity * float(item.price),
                            'extra': item.quantity * (float(item.logo_price) + float(item.accessory_price) + float(item.packaging_price)),
                            'shipped_quantity': shipped_quantity  # 添加已发货数量字段
                        }
                        merged_products[item.product_id]['specs'].append(spec_info)
                       
                        # 更新总数量和总金额
                        merged_products[item.product_id]['total_quantity'] += item.quantity
                        merged_products[item.product_id]['total_amount'] += spec_info['total']
                        merged_products[item.product_id]['total_amount_extra'] += spec_info['extra']
                    except Exception as e:
                        print(f"处理订单项时出错: {str(e)}")
                        continue
                
                # 将合并后的商品数据转换为列表
                items = list(merged_products.values())
                
                # 添加订单数据
                order_data = {
                    'id': order.id,
                    'order_number': order.order_number,
                    'total_amount': sum(item['total_amount'] for item in merged_products.values()),
                    'total_quantity': sum(item['total_quantity'] for item in merged_products.values()),
                    'total_amount_extra': sum(item['total_amount_extra'] for item in merged_products.values()),
                    'total_shipped_quantity': sum(sum(spec['shipped_quantity'] for spec in item['specs']) for item in merged_products.values()),
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
                
            except Exception as e:
                print(f"处理订单 {order.id} 时出错: {str(e)}")
                continue
        
        # 返回所有订单数据
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


# 编辑采购单商品信息
@app.route('/purchase_orders/<int:order_id>/items', methods=['PUT'])
@login_required
def update_purchase_order_items(user_id, order_id):
    try:
        # 检查权限
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': '用户不存在'}), 404
            
        # 获取采购单
        order = PurchaseOrder.query.get(order_id)
        if not order:
            return jsonify({'error': '采购单不存在'}), 404
            
        # 非管理员只能编辑自己的采购单
        if user.role != 'admin' and order.user_id != user_id and user.role != 'STAFF' and user.role != 'normalAdmin':
            return jsonify({'error': '无权限编辑此采购单'}), 403
            
            
        data = request.json
        items = data.get('items', [])
        
        if not items:
            return jsonify({'error': '缺少商品信息'}), 400
            
        # 清除原有商品信息
        PurchaseOrderItem.query.filter_by(order_id=order_id).delete()
        
        # 添加新的商品信息
        total_amount = 0
        for item_data in items:
            product_id = item_data.get('product_id')
            quantity = item_data.get('quantity', 0)
            price = item_data.get('price', 0)
            color = item_data.get('color', '')
            logo_price = item_data.get('logo_price', 0)
            accessory_price = item_data.get('accessory_price', 0)
            packaging_price = item_data.get('packaging_price', 0)
            
            if not product_id or quantity <= 0:
                continue
                
            # 检查产品是否存在
            product = Product.query.get(product_id)
            if not product:
                continue
                
            # 创建新的订单项
            item = PurchaseOrderItem(
                order_id=order_id,
                product_id=product_id,
                quantity=quantity,
                price=price,
                color=color,
                logo_price=logo_price,
                accessory_price=accessory_price,
                packaging_price=packaging_price
            )
            db.session.add(item)
            
            # 计算总金额
            item_total = quantity * float(price) + float(logo_price) + float(accessory_price) + float(packaging_price)
            total_amount += item_total
            
        # 更新采购单总金额
        order.total_amount = total_amount
        order.updated_at = datetime.now()
        
        try:
            db.session.commit()
            return jsonify({
                'message': '采购单商品信息更新成功',
                'total_amount': float(total_amount)
            }), 200
        except Exception as e:
            db.session.rollback()
            print(f'更新采购单商品信息失败: {str(e)}')
            print(f'错误追踪:\n{traceback.format_exc()}')
            return jsonify({'error': '更新采购单商品信息失败'}), 500
            
    except Exception as e:
        print(f'处理采购单商品信息更新请求失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '更新采购单商品信息失败'}), 500


# 添加用户管理相关接口
@app.route('/users', methods=['GET'])
@check_staff_permission('users.view')   
def get_users(user_id):
    try:       
        # 获取查询参数
        page = int(request.args.get('page', 1))
        page_size = min(int(request.args.get('page_size', 10)), 50)
        keyword = request.args.get('keyword', '').strip()
        status = request.args.get('status')
        user_type = request.args.get('user_type')  # 添加用户类型筛选
        
        # 构建基础查询
        query = User.query.filter(User.user_type != 1)  # 排除管理员
        
        # 添加筛选条件
        if keyword:
            search = f'%{keyword}%'
            query = query.filter(db.or_(
                User.username.like(search),
                User.nickname.like(search),
                User.phone.like(search)
            ))
            
        if status is not None:
            try:
                status = int(status)
                if status in [0, 1]:  # 验证状态值是否有效
                    query = query.filter(User.status == status)
            except ValueError:
                pass
                
        if user_type is not None:
            try:
                user_type = int(user_type)
                if user_type in [0, 2, 3, 4]:  # 验证用户类型是否有效 (0:零售 2:A类 3:B类 4:C类)
                    query = query.filter(User.user_type == user_type)
            except ValueError:
                pass
            
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
            'role': user.role,
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
            'user_type': user.user_type,
            'role': user.role
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

# 创建发货单
@app.route('/delivery_orders', methods=['POST'])
@login_required
def create_delivery_order(user_id):
    try:
        print('='*50)
        print('开始创建发货单')
        print('='*50)
        
        data = request.json
        if not data:
            print('无效的请求数据')
            return jsonify({'error': '无效的请求数据'}), 400
        
        print(f'请求数据: {data}')
        
        # 验证必要字段
        required_fields = ['customer_name', 'packages']
        for field in required_fields:
            if not data.get(field):
                print(f'缺少必要字段: {field}')
                return jsonify({'error': f'缺少必要字段: {field}'}), 400
        
        try:
            # 创建发货单
            delivery_order = DeliveryOrder(
                order_number=data['order_number'],
                customer_id=data['customer_id'],
                customer_name=data['customer_name'],
                customer_phone=data['customer_phone'],
                delivery_date=data.get('delivery_date'),
                delivery_time_slot=data.get('delivery_time_slot'),
                status=data.get('status', 1),  # 待配送
                remark=data.get('remark', ''),
                logistics_company=data.get('logistics_company'),  # 添加物流公司
                tracking_number=data.get('tracking_number'),  # 添加物流单号
                created_by=user_id,
                created_at=datetime.now(),
                updated_at=datetime.now()
            )
            
            print('添加发货单到会话')
            db.session.add(delivery_order)
            db.session.flush()
            print(f'发货单创建成功，ID: {delivery_order.id}')
            
            # 添加商品并更新库存
            print('开始处理商品')
            for items in data['packages']:
                for item in items:
                    print(f'处理商品: {item}')
                    # 查找商品
                    product = Product.query.get(item['product_id'])
                    if not product:
                        raise ValueError(f'商品不存在: {item["product_id"]}')
                    
                    # 查找并更新商品规格库存
                    specs = json.loads(product.specs) if isinstance(product.specs, str) else product.specs
                    spec_found = False
                    
                    for spec in specs:
                        if spec['color'] == item.get('color', ''):                            
                            # 更新库存
                            spec['stock'] -= item['quantity']
                            spec_found = True
                            break
                    
                    if not spec_found and item.get('color'):
                        raise ValueError(f'商品 {product.name} 不存在指定颜色: {item["color"]}')
                    
                    # 更新商品规格
                    product.specs = json.dumps(specs)
                    
                    # 更新商品总库存
                    product.stock = sum(spec['stock'] for spec in specs)
                    print(f"package_id: {item.get('package_id', 0)}")
                    # 创建发货单商品项
                    delivery_item = DeliveryItem(
                        delivery_id=delivery_order.id,
                        product_id=item['product_id'],
                        order_number=data['order_number'],
                        quantity=item['quantity'],
                        color=item.get('color', ''),
                        package_id=item.get('package_id', 0)
                    )
                    print('添加发货单商品项到会话')
                    db.session.add(delivery_item)
                    print(f'添加发货单商品项: {delivery_item.id}')
            
            # 提交事务
            print('提交事务')
            db.session.commit()
            print('事务提交成功')
            
            # 检查采购单是否所有商品都已发货完毕
            try:
                print('检查采购单发货状态')
                # 查找对应的采购单
                purchase_order = PurchaseOrder.query.filter_by(order_number=data['order_number']).first()
                if purchase_order:
                    # 获取采购单所有商品项
                    purchase_items = PurchaseOrderItem.query.filter_by(order_id=purchase_order.id).all()
                    
                    # 检查每个商品项是否都已发货完毕
                    all_shipped = True
                    for purchase_item in purchase_items:
                        # 查询该商品规格的已发货数量
                        shipped_result = db.session.query(func.sum(DeliveryItem.quantity)).filter(
                            DeliveryItem.product_id == purchase_item.product_id,
                            DeliveryItem.color == purchase_item.color,
                            DeliveryItem.order_number == purchase_order.order_number
                        ).scalar()
                        
                        shipped_quantity = int(shipped_result) if shipped_result is not None else 0
                        
                        # 如果已发货数量小于订单数量，则未全部发货
                        if shipped_quantity < purchase_item.quantity:
                            all_shipped = False
                            break
                    
                    # 如果所有商品都已发货完毕，将采购单状态更新为已完成
                    if all_shipped and purchase_order.status != 2:  # 状态2表示已完成
                        purchase_order.status = 2  # 更新为已完成
                        db.session.commit()
                        print(f"采购单 {purchase_order.order_number} 所有商品已发货完毕，状态已更新为已完成")
            except Exception as e:
                print(f"检查采购单发货状态时出错: {str(e)}")
                print(f"错误追踪:\n{traceback.format_exc()}")
                # 不影响发货单创建的结果
            
            print('发货单创建完成')
            return jsonify({
                'message': '配送单创建成功',
                'order_id': delivery_order.id,
                'order_number': delivery_order.order_number
            }), 201
            
        except ValueError as ve:
            db.session.rollback()
            print(f'验证错误: {str(ve)}')
            return jsonify({'error': str(ve)}), 400
        except Exception as e:
            db.session.rollback()
            print(f'保存配送单失败: {str(e)}')
            print(f'错误追踪:\n{traceback.format_exc()}')
            return jsonify({'error': '创建配送单失败'}), 500
            
    except Exception as e:
        print(f'创建配送单失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '创建配送单失败'}), 500

# 获取配送单列表
@app.route('/delivery_orders', methods=['GET'])
@login_required
def get_delivery_orders(user_id):
    try:
        # 获取查询参数
        page = int(request.args.get('page', 1))
        page_size = min(int(request.args.get('pageSize', 10)), 50)
        status = request.args.get('status') 
        searchKey = request.args.get('keyword', '')
        order_number = request.args.get('order_number')  # 添加采购单号参数
        start_date = request.args.get('start_date')  # 添加开始日期参数
        end_date = request.args.get('end_date')  # 添加结束日期参数

        print(f'获取配送单列表, status: {status}, searchKey: {searchKey}, order_number: {order_number}, start_date: {start_date}, end_date: {end_date}')
        
        # 检查用户类型
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': '用户不存在'}), 404
            
        # 构建基础查询
        query = DeliveryOrder.query
        
        # 如果有关键词搜索，需要JOIN相关表
        if searchKey:
            search = f'%{searchKey}%'
            query = query.join(DeliveryItem, DeliveryOrder.id == DeliveryItem.delivery_id, isouter=True)\
                        .join(Product, DeliveryItem.product_id == Product.id, isouter=True)\
                        .filter(db.or_(
                            DeliveryOrder.order_number.like(search),
                            DeliveryOrder.customer_name.like(search),
                            DeliveryOrder.customer_phone.like(search),
                            DeliveryOrder.delivery_address.like(search),
                            Product.name.like(search)
                        ))\
                        .distinct()  # 添加distinct去重
            
        # 非管理员只能查看自己创建的订单
        if user.role != 'admin' and user.role != 'STAFF' and user.role != 'normalAdmin':
            print(f'非管理员用户, user_id: {user_id}')
            query = query.filter(DeliveryOrder.created_by == user_id)
            
        # 状态筛选
        if status is not None and status.strip():
            query = query.filter(DeliveryOrder.status == int(status))
            
        # 采购单号筛选
        if order_number:
            query = query.filter(DeliveryOrder.order_number == order_number)
        
        # 日期范围筛选
        if start_date and end_date:
            print(f'start_date: {start_date}, end_date: {end_date}')
            query = query.filter(
                db.and_(
                    func.date(DeliveryOrder.created_at) >= func.date(start_date),
                    func.date(DeliveryOrder.created_at) <= func.date(end_date)
                )
            )
        elif start_date:
            start_date = datetime.fromisoformat(start_date.replace('T', '+08:00'))
            query = query.filter(func.date(DeliveryOrder.created_at) >= func.date(start_date))
        elif end_date:
            end_date = datetime.fromisoformat(end_date.replace('T', '+08:00'))
            query = query.filter(func.date(DeliveryOrder.created_at) <= func.date(end_date))
            
        # 获取分页数据
        paginated_orders = query.order_by(DeliveryOrder.created_at.desc())\
            .paginate(page=page, per_page=page_size, error_out=False)
            
        orders = []
        for order in paginated_orders.items:
            # 获取订单明细
            items = []
            for item in DeliveryItem.query.filter_by(delivery_id=order.id).all():
                product = Product.query.get(item.product_id)
                if product:
                    items.append({
                        'id': item.id,
                        'product_id': item.product_id,
                        'product_name': product.name,
                        'quantity': item.quantity,
                        'color': item.color,
                        'image': json.loads(product.images)[0] if product.images and len(json.loads(product.images)) > 0 else None
                    })
                    
            # 获取创建者信息
            creator = User.query.get(order.created_by)
                    
            # 状态文本映射
            status_text_map = {
                0: '已开单',
                1: '已发货',
                2: '已完成',
                3: '已取消',
                4: '异常'
            }
            print(f'order: {order}')        
            orders.append({
                'id': order.id,
                'orderNumber': order.order_number,
                'customerName': order.customer_name,
                'customerPhone': order.customer_phone,
                'deliveryAddress': order.delivery_address,
                'deliveryDate': order.delivery_date,
                'delivery_time_slot': order.delivery_time_slot,
                'status': order.status,
                'statusText': status_text_map.get(order.status, '未知状态'),
                'remark': order.remark,
                'createdAt': order.created_at.isoformat(),
                'updatedAt': order.updated_at.isoformat(),
                'creator': {
                    'id': creator.id,
                    'username': creator.username,
                    'nickname': creator.nickname
                } if creator else None,
                'delivery_by': order.delivery_by,
                'deliveryImage': json.loads(order.delivery_image) if order.delivery_image else [],
                'logistics_company': order.logistics_company,  # 添加物流公司
                'tracking_number': order.tracking_number,  # 添加物流单号
                'items': items,
                'total_quantity': sum(item['quantity'] for item in items),
                'total_items': len(items),
                'additional_fee': order.additional_fee if order.additional_fee else 0
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
        total_amount = 0
        for item in DeliveryItem.query.filter_by(delivery_id=order.id).all():
            product = Product.query.get(item.product_id)
            if product:
                # 获取采购单中的价格信息
                purchase_item = db.session.query(PurchaseOrderItem)\
                    .join(PurchaseOrder, PurchaseOrder.id == PurchaseOrderItem.order_id)\
                    .filter(
                        PurchaseOrder.order_number == item.order_number,
                        PurchaseOrderItem.product_id == item.product_id,
                        PurchaseOrderItem.color == item.color
                    ).first()

                product_image = json.loads(product.images)[0] if product.images and len(json.loads(product.images)) > 0 else None
                
                # 计算价格信息
                price = purchase_item.price if purchase_item else 0
                logo_price = purchase_item.logo_price if purchase_item else 0
                packaging_price = purchase_item.packaging_price if purchase_item else 0
                accessory_price = purchase_item.accessory_price if purchase_item else 0
                
                # 计算总价
                item_total = (price + logo_price + packaging_price + accessory_price) * item.quantity
                total_amount += item_total

                items.append({
                    'id': item.id,
                    'product_id': item.product_id,
                    'product_name': product.name,
                    'quantity': item.quantity,
                    'color': item.color,
                    'product_image': product_image,
                    'price': price,
                    'logo_price': logo_price,
                    'packaging_price': packaging_price,
                    'accessory_price': accessory_price,
                    'total': item_total,
                    'has_logo': logo_price > 0,
                    'has_packaging': packaging_price > 0,
                    'has_accessory': accessory_price > 0,
                    'package_id': item.package_id
                    
                })

        # 获取创建者和配送员信息
        creator = User.query.get(order.created_by)
        delivery_user = User.query.get(order.delivery_by) if order.delivery_by else None

        # 状态文本映射
        status_text_map = {
            0: '已开单',
            1: '已发货',
            2: '已完成',
            3: '已取消',
            4: '异常'
        }

        # 格式化返回数据
        order_detail = {
            'id': order.id,
            'orderNumber': order.order_number,
            'customerName': order.customer_name,
            'customerPhone': order.customer_phone,
            'deliveryAddress': order.delivery_address,
            'deliveryDate': order.delivery_date,
            'deliveryTimeSlot': order.delivery_time_slot,
            'logistics_company': order.logistics_company,
            'tracking_number': order.tracking_number,
            'additional_fee': order.additional_fee,
            'status': order.status,
            'statusText': status_text_map.get(order.status, '未知状态'),
            'remark': order.remark,
            'createdAt': order.created_at.isoformat(),
            'updatedAt': order.updated_at.isoformat(),
            'creator': {
                'id': creator.id,
                'username': creator.username,
                'nickname': creator.nickname
            } if creator else None,
            'deliveryUser': {
                'id': delivery_user.id,
                'username': delivery_user.username,
                'nickname': delivery_user.nickname
            } if delivery_user else None,
            'deliveryImage': json.loads(order.delivery_image) if order.delivery_image else [],
            'total_quantity': sum(item['quantity'] for item in items),
            'total_amount': total_amount + (order.additional_fee or 0)
        }

        return jsonify({
            'order': order_detail,
            'items': items
        }), 200

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
        
        # 检查用户类型
        user = User.query.get(user_id)
        user_type = user.user_type
        
        # 使用SQLAlchemy进行数据库操作
        # 构建基础查询
        query = db.session.query(DeliveryOrder.id)
        
        # 非管理员只能看到自己的数据
        if user_type != 1:
            query = query.filter(DeliveryOrder.customer_id == user_id)
            
        # 统计数据
        total = query.count()
        pending = query.filter(DeliveryOrder.status == 0).count()
        delivering = query.filter(DeliveryOrder.status == 1).count()
        completed = query.filter(DeliveryOrder.status == 2).count()
        cancelled = query.filter(DeliveryOrder.status == 3).count()
        
        stats = {
            'all': total or 0,  # 全部
            '0': pending or 0,  # 已开单
            '1': delivering or 0,  # 已发货
            '2': completed or 0,  # 已完成
            '3': cancelled or 0  # 已取消
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
@check_staff_permission('purchase_order.cancel')
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

        # 如果订单状态为2（已发货），需要恢复库存
        if purchase_order.status == 2:
            # 获取所有发货单商品
            delivery_items = DeliveryItem.query.filter_by(
                order_number=purchase_order.order_number
            ).all()

            # 恢复每个商品的库存
            for item in delivery_items:
                product = Product.query.get(item.product_id)
                if product:
                    specs = json.loads(product.specs) if isinstance(product.specs, str) else product.specs
                    spec_found = False
                    
                    for spec in specs:
                        if spec['color'] == item.color:
                            # 恢复库存
                            spec['stock'] += item.quantity
                            spec_found = True
                            break
                    
                    if not spec_found and item.color:
                        print(f'商品 {product.name} 不存在指定颜色: {item.color}')
                        continue
                    
                    # 更新商品规格
                    product.specs = json.dumps(specs)
                    
                    # 更新商品总库存
                    product.stock = sum(spec['stock'] for spec in specs)

        # 更新采购单状态为已取消(2)
        purchase_order.status = 3
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
        print(f'开始获取采购单详情: order_id={order_id}, user_id={user_id}')
        
        # 获取采购单
        order = PurchaseOrder.query.filter(
            db.or_(
                PurchaseOrder.id == order_id,
                PurchaseOrder.order_number == order_id
            )
        ).first()
# ... existing code ...
        
        if not order:
            print(f'采购单不存在: order_id={order_id}')
            return jsonify({'error': '采购单不存在'}), 404
        
        # 获取下单用户信息
        order_user = User.query.get(order.user_id)
        if not order_user:
            print(f'下单用户不存在: user_id={order.user_id}')
            return jsonify({'error': '下单用户不存在'}), 404
        
        # 检查权限（非管理员只能查看自己的订单）
        current_user = User.query.get(user_id)
        if not current_user:
            print(f'当前用户不存在: user_id={user_id}')
            return jsonify({'error': '用户不存在'}), 404
        
        if current_user.role != 'admin' and order.user_id != user_id and current_user.role != 'STAFF':
            print(f'无权限查看此采购单: user_id={user_id}, order_user_id={order.user_id}')
            return jsonify({'error': '无权限查看此采购单'}), 403
        
        # 获取订单明细
        order_items = db.session.query(PurchaseOrderItem).filter(
            PurchaseOrderItem.order_id == order.id
        ).all()
        
        # 使用字典来临时存储合并的商品数据
        merged_products = {}
        
        for item in order_items:
            try:
                product = Product.query.get(item.product_id)
                if not product:
                    continue
                    
                # 使用商品ID作为键
                if item.product_id not in merged_products:
                    merged_products[item.product_id] = {
                        'id': product.id,
                        'product_id': product.id,
                        'product_name': product.name,
                        'image': json.loads(product.images)[0] if product.images and len(json.loads(product.images)) > 0 else None,
                        'price': float(item.price),
                        'total_quantity': 0,
                        'total_amount': 0,
                        'total_amount_extra': 0,
                        'specs': []
                    }
                
                # 添加当前规格信息
                spec_info = {
                    'color': item.color,
                    'quantity': item.quantity,
                    'price': float(item.price),
                    'logo_price': float(item.logo_price),  # 加标价格
                    'accessory_price': float(item.accessory_price),  # 辅料价格
                    'packaging_price': float(item.packaging_price),  # 包装价格
                    'total': item.quantity * float(item.price),
                    'extra': item.quantity * (float(item.logo_price) + float(item.accessory_price) + float(item.packaging_price)),
                    'shipped_quantity': 0  # 添加已发货数量字段，默认为0
                }
                
                # 查询该商品规格的已发货数量
                if item.color:
                    # 查询相同商品ID和颜色的已发货数量
                    shipped_result = db.session.query(func.sum(DeliveryItem.quantity)).filter(
                        DeliveryItem.product_id == item.product_id,
                        DeliveryItem.color == item.color,
                        DeliveryItem.order_number == order.order_number
                    ).scalar()
                    spec_info['shipped_quantity'] = int(shipped_result) if shipped_result is not None else 0
                
                merged_products[item.product_id]['specs'].append(spec_info)
                
                # 更新总数量和总金额
                merged_products[item.product_id]['total_quantity'] += item.quantity
                merged_products[item.product_id]['total_amount'] += spec_info['total']
                merged_products[item.product_id]['total_amount_extra'] += spec_info['extra']
            except Exception as e:
                print(f"处理订单项时出错: {str(e)}")
                continue
        
        # 将合并后的商品数据转换为列表
        items = list(merged_products.values())
        
        # 格式化返回数据
        order_detail = {
            'id': order.id,
            'order_number': order.order_number,
            'total_amount': sum(item['total_amount'] for item in merged_products.values()),
            'total_quantity': sum(item['total_quantity'] for item in merged_products.values()),
            'total_amount_extra': sum(item['total_amount_extra'] for item in merged_products.values()),
            'total_shipped_quantity': sum(sum(spec['shipped_quantity'] for spec in item['specs']) for item in merged_products.values()),
            'status': order.status,
            'remark': order.remark,
            'created_at': order.created_at.isoformat() if order.created_at else None,
            'items': items,
            'user': {
                'id': order_user.id,
                'username': order_user.username,
                'nickname': order_user.nickname,
                'avatar': order_user.avatar,
                'phone': order_user.phone
            }
        }
        
        print(f'成功获取采购单详情: order_id={order_id}, 商品数量={len(items)}')
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
@admin_required
def delete_user(user_id):
    try:
        data = request.json
        target_user_id = data.get('user_id')
        
        if not target_user_id:
            return jsonify({'error': '缺少用户ID'}), 400

        # 检查要删除的用户是否存在
        target_user = User.query.get(target_user_id)
        if not target_user:
            return jsonify({'error': '用户不存在'}), 404

        try:
            # 将用户状态设置为已删除，并清空openid
            target_user.status = 0  # 0表示禁用/删除状态
            target_user.openid = None  # 清空openid
            target_user.updated_at = datetime.now()
            
            db.session.commit()
            return jsonify({
                'code': 200,
                'message': '用户已禁用并解除微信绑定'
            })
            
        except Exception as e:
            db.session.rollback()
            print(f'禁用用户失败: {str(e)}')
            return jsonify({'error': '禁用用户失败'}), 500

    except Exception as e:
        print(f'禁用用户失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '禁用用户失败'}), 500

# 批量删除商品接口
@app.route('/products/batch/delete', methods=['POST'])
@check_staff_permission('product.delete')
def batch_delete_products(user_id):
    try:
        data = request.json
        product_ids = data.get('product_ids', [])
        
        if not product_ids:
            return jsonify({'error': '未选择要删除的商品'}), 400
            
        # 获取要删除的商品
        products = Product.query.filter(Product.id.in_(product_ids)).all()
        
        # 收集所有需要删除的图片文件路径
        file_list = []
        for product in products:
            if product.images:
                images = json.loads(product.images)
                for image_url in images:
                    try:
                        file_list.append(image_url)
                    except Exception as e:
                        print(f"处理图片URL失败: {str(e)}")

        # 先删除数据库记录
        try:
            # 使用原生SQL删除相关记录
            for product_id in product_ids:
                # 删除商品浏览记录
                db.session.execute(text('DELETE FROM product_views WHERE product_id = :product_id'), {'product_id': product_id})
                
                # 删除购物车记录
                db.session.execute(text('DELETE FROM cart_items WHERE product_id = :product_id'), {'product_id': product_id})
                
                # 删除库存记录
                db.session.execute(text('DELETE FROM stock_records WHERE product_id = :product_id'), {'product_id': product_id})
                
                # 删除颜色库存记录
                db.session.execute(text('DELETE FROM color_stocks WHERE product_id = :product_id'), {'product_id': product_id})
                
                # 删除商品记录
                db.session.execute(text('DELETE FROM products WHERE id = :product_id'), {'product_id': product_id})
            
            # 提交事务
            db.session.commit()
            
            # 数据库删除成功后，再删除文件
            if file_list:
                try:
                    # 获取access_token
                    access_token = get_access_token()
                    if not access_token:
                        print("警告：获取access_token失败，文件未删除")
                    else:
                        # 调用批量删除文件API
                        url = f'{API_URL}/tcb/batchdeletefile?access_token={access_token}'
                        print(f'调用批量删除文件列表: {file_list}')
                        data = {
                            'env': WX_ENV,
                            'fileid_list': file_list
                        }
                        response = requests.post(url, json=data)
                        result = response.json()
                        
                        if result.get('errcode') != 0:
                            print(f"警告：删除图片文件失败: {result}")
                        else:
                            print("成功删除图片文件")

                except Exception as e:
                    print(f"警告：调用删除图片API失败: {str(e)}")
                    # 文件删除失败不影响整体操作
            
            return jsonify({
                'code': 200,
                'message': f'成功删除 {len(product_ids)} 个商品'
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
def create_delivery_from_purchase(user_id, purchase_id):
    try:
        # 获取采购单信息
        purchase_order = PurchaseOrder.query\
            .options(db.joinedload(PurchaseOrder.items))\
            .get(purchase_id)
            
        if not purchase_order:
            return jsonify({'error': '采购单不存在'}), 404

        # 检查权限
        current_user = User.query.get(user_id)
        if not current_user or current_user.role != 'admin' and current_user.role != 'STAFF' and current_user.role != 'normalAdmin':
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
            created_by=user_id,
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


# 生成小程序码接口
@app.route('/qrcode', methods=['POST'])
def generate_qrcode_api():
    try:
        data = request.get_json()
        page = data.get('page')
        target_name= data.get('target_name')
        
        # 生成唯一的分享码
        max_attempts = 10  # 最大尝试次数
        attempt = 0
        while attempt < max_attempts:
            share_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
            # 检查分享码是否已存在
            existing_order = PushOrder.query.filter_by(share_code=share_code).first()
            if not existing_order:
                break
            attempt += 1
        
        if attempt >= max_attempts:
            return jsonify({
                'code': 500,
                'message': '无法生成唯一的分享码'
            }), 500
        
        print(f'开始生成分享码')
        # 使用分享码生成二维码
        # 检查请求头中是否有openid
        openid = request.headers.get('X-WX-OPENID')

        # 构建scene参数
        scene = f'{share_code}&1'
        
        if openid:
            print('使用微信云托管方式生成二维码')
            qrcode_path = generate_qrcode_wx(page, scene)
        else:
            print('使用普通方式生成二维码') 
            qrcode_path = generate_qrcode(page, scene)

        if qrcode_path:
            return jsonify({
                'code': 200,
                'message': 'QR code generated successfully',
                'share_code': share_code,
                'qrcode': qrcode_path
            })
        else:
            return jsonify({
                'code': 401,
                'message': 'QR code generation failed'
            }), 401
    except Exception as e:
        print(f"生成二维码出错: {str(e)}")
        return jsonify({
            'code': 500,
            'message': str(e)
        }), 500


def generate_qrcode(page, scene):
    try:
        
        qrcode_dir = os.path.join(app.static_folder, 'qrcodes')
        if not os.path.exists(qrcode_dir):
            os.makedirs(qrcode_dir)
            
        filename = f"qr{scene}.jpg"
        filepath = os.path.join(qrcode_dir, filename)
        
        # 调用微信接口生成小程序码
        access_token = get_access_token()
        url = f'https://api.weixin.qq.com/wxa/getwxacodeunlimit?access_token={access_token}'
        
        params = {
            "scene": scene,
            "page": page,
            "env_version": "release",  #体验版
            "check_path": False
        }
        
        response = requests.post(url, json=params)
        print(f'生成二维码响应: {response.text,response.status_code}')
        if response.status_code == 200:
            # 保存文件
            with open(filepath, 'wb') as f:
                f.write(response.content)
            
            print(f"二维码已保存到: {filepath}")
            # 返回相对路径
            relative_path = f'/static/qrcodes/{filename}'
        else:
            print(f"生成二维码失败: {response.text}")
            return None       

        # 2. 获取到上传链接
        print('\n[步骤3] 获取云存储上传链接')
        try:
            upload_url = 'https://api.weixin.qq.com/tcb/uploadfile?access_token=' + access_token
            upload_params = {
                'env': WX_ENV,
                'path': f'qrcodes/{filename}'
            }
            print(f'请求参数: {upload_params}')
            
            # 使用带有Authorization header的请求
            upload_response = requests.post(
                upload_url, 
                json=upload_params
            )
            upload_data = upload_response.json()
            print(f'获取上传链接响应: {upload_data}')
            
            if upload_data.get('errcode', 0) != 0:
                print(f"[错误] 获取上传链接失败: {upload_data}")
                return jsonify({
                    'code': 500,
                    'message': '获取上传链接失败',
                    'data': upload_data,
                    'error_location': '获取云存储上传链接步骤'
                }), 500
            
        except Exception as e:
            print(f"[错误] 上传文件过程出错: {str(e)}")
            print(f"错误追踪:\n{traceback.format_exc()}")
            return jsonify({
                'code': 500,
                'message': '上传文件过程出错',
                'error': str(e),
                'error_location': '上传文件过程',
                'traceback': traceback.format_exc()
            }), 500
        
        # 3. 上传文件到云存储
        try:
            print('\n[步骤4] 上传文件到云存储')
            cos_url = upload_data['url']
            with open(filepath, 'rb') as f:
                files = {
                   'file': (filename, f, 'image/jpeg')
                }
                form_data = {
                    'key': f'qrcodes/{filename}',
                    'Signature': upload_data['authorization'],
                    'x-cos-security-token': upload_data['token'],
                    'x-cos-meta-fileid': upload_data['file_id']
                }
                print(f'上传参数: {form_data}')            
                # 上传到对象存储
                upload_result = requests.post(cos_url, data=form_data, files=files)
                print(f'上传响应状态码: {upload_result.status_code}')
            
            return upload_data['file_id']
              
        except Exception as e:
            print(f"[错误] 上传文件到云存储失败: {str(e)}")
            print(f"错误追踪:\n{traceback.format_exc()}")
            return jsonify({
                'code': 500,
                'message': '上传文件到云存储失败',
                'error': str(e)
            })
        
        
    except Exception as e:
        print(f"[错误] 生成二维码过程出错: {str(e)}")
        print(f"错误追踪:\n{traceback.format_exc()}")
        return jsonify({
            'code': 500,
            'message': '生成二维码过程出错',
            'error': {
                'type': type(e).__name__,
                'message': str(e),
                'traceback': traceback.format_exc(),
                'error_location': '整体流程'
            }
        }), 500
    
def generate_qrcode_wx(page, scene):
    try:
        
        qrcode_dir = os.path.join(app.static_folder, 'qrcodes')
        if not os.path.exists(qrcode_dir):
            os.makedirs(qrcode_dir)
            
        filename = f"qr{scene}.jpg"
        filepath = os.path.join(qrcode_dir, filename)
        
        url = f'http://api.weixin.qq.com/wxa/getwxacodeunlimit'
        
        params = {
            "scene": scene,
            "page": page,
            "env_version": "release",  #体验版  trial 正式 release 
            "check_path": False
        }
        
        response = requests.post(url, json=params)
        
        if response.status_code == 200:
            # 保存文件
            with open(filepath, 'wb') as f:
                f.write(response.content)
            
            print(f"二维码已保存到: {filepath}")
        else:
            print(f"生成二维码失败: {response.text}")
            return None       

        # 2. 获取到上传链接
        print('\n[步骤3] 获取云存储上传链接')
        try:
            upload_url = 'http://api.weixin.qq.com/tcb/uploadfile'
            upload_params = {
                'env': WX_ENV,
                'path': f'qrcodes/{filename}'
            }
            print(f'请求参数: {upload_params}')
            
            # 使用带有Authorization header的请求
            upload_response = requests.post(
                upload_url, 
                json=upload_params
            )
            upload_data = upload_response.json()
            print(f'获取上传链接响应: {upload_data}')
            
            if upload_data.get('errcode', 0) != 0:
                print(f"[错误] 获取上传链接失败: {upload_data}")
                return jsonify({
                    'code': 500,
                    'message': '获取上传链接失败',
                    'data': upload_data,
                    'error_location': '获取云存储上传链接步骤'
                }), 500
            
        except Exception as e:
            print(f"[错误] 上传文件过程出错: {str(e)}")
            print(f"错误追踪:\n{traceback.format_exc()}")
            return jsonify({
                'code': 500,
                'message': '上传文件过程出错',
                'error': str(e),
                'error_location': '上传文件过程',
                'traceback': traceback.format_exc()
            }), 500
        
        # 3. 上传文件到云存储
        try:
            print('\n[步骤4] 上传文件到云存储')
            cos_url = upload_data['url']
            with open(filepath, 'rb') as f:
                files = {
                   'file': (filename, f, 'image/jpeg')
                }
                form_data = {
                    'key': f'qrcodes/{filename}',
                    'Signature': upload_data['authorization'],
                    'x-cos-security-token': upload_data['token'],
                    'x-cos-meta-fileid': upload_data['file_id']
                }
                print(f'上传参数: {form_data}')            
                # 上传到对象存储
                upload_result = requests.post(cos_url, data=form_data, files=files)
                print(f'上传响应状态码: {upload_result.status_code}')
            
            return upload_data['file_id']
              
        except Exception as e:
            print(f"[错误] 上传文件到云存储失败: {str(e)}")
            print(f"错误追踪:\n{traceback.format_exc()}")
            return jsonify({
                'code': 500,
                'message': '上传文件到云存储失败',
                'error': str(e)
            })
        
        
    except Exception as e:
        print(f"[错误] 生成二维码过程出错: {str(e)}")
        print(f"错误追踪:\n{traceback.format_exc()}")
        return jsonify({
            'code': 500,
            'message': '生成二维码过程出错',
            'error': {
                'type': type(e).__name__,
                'message': str(e),
                'traceback': traceback.format_exc(),
                'error_location': '整体流程'
            }
        }), 500

@app.route('/get_access_token', methods=['GET'])
def get_access_token_api():
    """获取小程序 access_token"""
    try:        
        url = f'https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid={WECHAT_APPID}&secret={WECHAT_SECRET}'
        response = requests.get(url)    
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
                return jsonify({
                    'code': 200,
                    'message': '获取access_token成功',
                    'data': data['access_token']
                })
                
        print('\n获取access_token失败')
        print('错误响应:')
        print(response.text)
        return jsonify({
            'code': 500,
            'message': '获取access_token失败',
            'error': response.text
        })
        
    except Exception as e:
        print('\n获取access_token时发生错误:')
        print(f'- 错误类型: {type(e).__name__}')
        print(f'- 错误信息: {str(e)}')
        print(f'- 错误追踪:\n{traceback.format_exc()}')
        return jsonify({
            'code': 500,
            'message': '获取access_token失败',
            'error': str(e)
        })

@app.route('/get_uploadfileUrl', methods=['POST'])
def get_uploadfileUrl():
    try:
        data = request.json
        access_token = get_access_token()
        print(f'获取access_token: {access_token}')
        path = data.get('path')
        
        url = f'{API_URL}/tcb/uploadfile?access_token={access_token}'
        params = {
            'env': WX_ENV,
            'path': path
        }   
        response = requests.post(url, json=params)
        print(f'获取上传文件URL响应: {response.json()}')
        return response.json()
    except Exception as e:
        return jsonify({
            'code': 500,
            'message': '获取上传文件URL失败',
            'error': str(e)
        })

def get_access_token():
    """获取小程序 access_token"""
    try:        
        url = f'http://api.weixin.qq.com/cgi-bin/token'
        response = requests.get(url) 
        header = request.headers
        print(f'header: {header}')
        if response.status_code == 200:
            data = response.json()
            # 处理响应数据时隐藏实际的access_token
            if 'access_token' in data:
                print('\n云调用access_token获取成功')
                return data['access_token']
        raise Exception('获取 access_token 失败')  
        
    except Exception as e:
        print('\n获取access_token时发生错误:')     

    try:        
        url = f'{API_URL}/cgi-bin/token?grant_type=client_credential&appid={WECHAT_APPID}&secret={WECHAT_SECRET}'
        response = requests.get(url)    
        print(f'获取access_token响应: {response.json()}')
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
        return None
        
    except Exception as e:
        print('\n获取access_token时发生错误:')
        print(f'- 错误类型: {type(e).__name__}')
        print(f'- 错误信息: {str(e)}')
        print(f'- 错误追踪:\n{traceback.format_exc()}')
        return None

@app.route('/push_orders', methods=['POST'])
@admin_required
def create_push_order(user_id):
    try:
        data = request.json
        target_name = data.get('target_name', '仟艺测试')
        target_user_id = data.get('target_user_id', None)
        share_code = data.get('share_code')
        qrcode = data.get('qrcode')
        print(f'data: {data}')
        if not data or 'products' not in data:
            return jsonify({'error': '无效的请求数据'}), 400

        # 生成推送单号
        order_number = f"PUSH{datetime.now().strftime('%Y%m%d%H%M%S')}{random.randint(100,999)}"

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
            qrcode_path=qrcode,  # 使用前端传递的二维码
            created_at=datetime.now()
        )

        db.session.add(push_order)
        db.session.flush()  # 获取 push_order.id

        # 添加推送商品
        products_data = []
        for product_info in data['products']:
            product = Product.query.filter_by(id=product_info['id']).first()
            if product:
                # 创建或更新用户商品价格记录
                user_price = UserProductPrice.query.filter_by(
                    user_id=target_user_id,
                    product_id=product_info['id']
                ).first()

                if target_user_id != None:                
                    if user_price :
                        # 更新现有价格记录
                        user_price.custom_price = product_info['price']
                        print(f'更新用户商品价格: 用户ID={target_user_id}, 商品ID={product_info["id"]}, 价格={product_info["price"]}')
                    else:
                        # 创建新的价格记录
                        new_price = UserProductPrice(
                            user_id=target_user_id,
                            product_id=product_info['id'],
                            custom_price=product_info['price']
                        )
                        db.session.add(new_price)
                        print(f'创建用户商品价格: 用户ID={target_user_id}, 商品ID={product_info["id"]}, 价格={product_info["price"]}')

                # 创建推送商品记录
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
                'qrcode_path': qrcode
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
    """删除推送单"""
    try:
        # 检查权限
        if not check_push_order_permission(user_id, order_id):
            return jsonify({
                'code': 403,
                'message': '没有权限删除此推送单'
            }), 403
            
        # 获取推送单
        push_order = PushOrder.query.get(order_id)
        if not push_order:
            return jsonify({
                'code': 404,
                'message': '推送单不存在'
            }), 404
            
        # 删除推送单商品关联
        PushOrderProduct.query.filter_by(push_order_id=order_id).delete()   
             
        # 删除推送单
        db.session.delete(push_order)
        db.session.commit()
        
        return jsonify({
            'code': 200,
            'message': '推送单删除成功'
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"删除推送单失败: {str(e)}")
        print(f"错误追踪:\n{traceback.format_exc()}")
        return jsonify({
            'code': 500,
            'message': f'删除推送单失败：{str(e)}'
        }), 500


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
                    'image': json.loads(product.images)[0] if product.images and len(json.loads(product.images)) > 0 else None,
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
@check_staff_permission('system.settings')
def update_system_settings(user_id):
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



# 获取用户统计数据
@app.route('/user/statistics', methods=['GET'])
@login_required
def get_user_statistics(user_id):
    try:
        # 检查用户类型
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': '用户不存在'}), 404
            
        user_type = user.user_type
        
        # 构建基础查询条件
        purchase_query = PurchaseOrder.query
        delivery_query = DeliveryOrder.query
        
        # 非管理员只能看到自己的数据
        if user.role != 'admin' and user.role != 'STAFF' and user.role != 'normalAdmin':
            purchase_query = purchase_query.filter_by(user_id=user_id)
            delivery_query = delivery_query.filter_by(user_id=user_id)
    
        # 获取今日待办事项数量（未完成的采购单）
        today_tasks = purchase_query.filter(
            PurchaseOrder.status == 0,
            func.date(PurchaseOrder.created_at) == func.curdate()
        ).count()
        
        # 获取未确认采购单数量（所有未确认的采购单）
        unconfirmed_orders = purchase_query.filter(
            PurchaseOrder.status == 0
        ).count()
        
        # 获取今日总采购单数量
        today_orders = purchase_query.filter(
            func.date(PurchaseOrder.created_at) == func.curdate()
        ).count()
        
        # 获取今日下单的客户数（去重）及其信息
        today_customers = db.session.query(
            PurchaseOrder.user_id,
            User.nickname,
            User.phone
        ).join(User, User.id == PurchaseOrder.user_id).filter(
            func.date(PurchaseOrder.created_at) == func.curdate()
        ).distinct().all()
        
        # 获取所有待发货商品数（所有已确认但未发货的采购单中的商品总数量）
        today_to_deliver_items = db.session.query(
            PurchaseOrderItem.product_id,
            Product.name.label('product_name'),
            PurchaseOrderItem.color,
            func.sum(PurchaseOrderItem.quantity)
        ).join(
            PurchaseOrder,
            PurchaseOrder.id == PurchaseOrderItem.order_id
        ).join(
            Product,
            Product.id == PurchaseOrderItem.product_id
        ).filter(
            PurchaseOrder.status == 1  # 状态为已确认
        ).group_by(PurchaseOrderItem.product_id, PurchaseOrderItem.color).all()
        
        today_to_deliver = sum(item[3] for item in today_to_deliver_items)  # 计算总数量
        
        # 获取今日实发货商品数（今日创建的发货单中的商品总数量）
        today_delivered_items = db.session.query(
            DeliveryItem.product_id,
            Product.name.label('product_name'),  # 从 Product 模型中获取名称
            DeliveryItem.color,
            func.sum(DeliveryItem.quantity)
        ).join(
            DeliveryOrder,
            DeliveryOrder.id == DeliveryItem.delivery_id
        ).join(
            Product,
            Product.id == DeliveryItem.product_id  # 连接 Product 模型
        ).filter(
            func.date(DeliveryOrder.created_at) == func.curdate()
        ).group_by(DeliveryItem.product_id, DeliveryItem.color).all()
        
        today_delivered = sum(item[3] for item in today_delivered_items)  # 计算总数量
        
        # 获取累计发货商品总数（所有发货单中商品的总数量）
       # 获取累计发货商品总数和金额
        total_query = db.session.query(
            func.sum(DeliveryItem.quantity).label('total_count'),
            func.sum(
                db.case(
                    (DeliveryOrder.status.in_([1, 2]), PurchaseOrderItem.price * DeliveryItem.quantity),
                    else_=0
                )
            ).label('total_amount'),
            func.sum(
                db.case(
                    (DeliveryOrder.status.in_([1, 2]), DeliveryOrder.additional_fee),
                    else_=0
                )
            ).label('total_additional_fee')
        ).join(
            DeliveryOrder, 
            DeliveryItem.delivery_id == DeliveryOrder.id
        ).join(
            PurchaseOrder, 
            DeliveryItem.order_number == PurchaseOrder.order_number
        ).join(
            PurchaseOrderItem,
            db.and_(
                PurchaseOrder.id == PurchaseOrderItem.order_id,
                PurchaseOrderItem.product_id == DeliveryItem.product_id,
                PurchaseOrderItem.color == DeliveryItem.color
            )
        )

        # 非管理员只能看到自己的数据
        if user.role != 'admin' and user.role != 'STAFF' and user.role != 'normalAdmin':
            total_query = total_query.filter(DeliveryOrder.customer_id == user_id)

        # 执行查询
        result = total_query.first()

        # 计算总金额（商品金额 + 附加费用）
        total_delivered_quantity = int(result.total_count or 0)
        total_amount = float(result.total_amount or 0)
        total_additional_fee = float(result.total_additional_fee or 0)
        total_delivered_amount = total_amount + total_additional_fee
        
        return jsonify({
            'today_tasks': today_tasks,
            'unconfirmed_orders': unconfirmed_orders,
            'today_orders': today_orders,
            'today_customers': [{'user_id': customer.user_id, 'nickname': customer.nickname, 'phone': customer.phone} for customer in today_customers],
            'today_to_deliver': [{'product_id': item.product_id, 'product_name': item.product_name, 'color': item.color, 'quantity': item[3]} for item in today_to_deliver_items],
            'today_delivered': [{'product_id': item.product_id, 'product_name': item.product_name, 'color': item.color, 'quantity': item[3]} for item in today_delivered_items],
            'today_to_deliver_count': today_to_deliver,  # 今日应发货商品总数
            'today_delivered_count': today_delivered,      # 今日实发货商品总数
            'total_delivered_quantity': int(total_delivered_quantity),
            'total_delivered_amount': float(total_delivered_amount),
            'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }), 200
            
    except Exception as e:
        print(f'获取用户统计数据失败: {str(e)}')
        print(f'错误类型: {type(e).__name__}')
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
            User.role == 'customer',  # 只搜索客户角色
            User.status == 1      # 只搜索启用状态的用户
        ).limit(20).all()
        
        # 格式化返回数据
        users_list = [{
            'id': user.id,
            'username': user.username,
            'nickname': user.nickname,
            'phone': user.phone,
            'avatar': user.avatar,
            'user_type': user.user_type
        } for user in users]
        
        return jsonify({'users': users_list}), 200
            
    except Exception as e:
        print(f'搜索用户失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '搜索用户失败'}), 500


@app.route('/products/batch-update', methods=['POST'])
@check_staff_permission('product.update')
def batch_update_product_type_api(user_id):
    """
    批量更新商品类型
    """
    try:
        # 获取请求数据
        data = request.get_json()
        if not data or 'ids' not in data or 'type' not in data:
            return jsonify({'code': -1, 'message': '缺少必要参数'}), 400

        product_ids = data['ids']
        new_type = data['type']

        # 验证参数
        if not isinstance(product_ids, list) or not product_ids:
            return jsonify({'code': -1, 'message': '商品ID列表不能为空'}), 400
        
        if not isinstance(new_type, int):
            return jsonify({'code': -1, 'message': '商品类型必须是整数'}), 400

        updated_count = 0
        for product_id in product_ids:
            product = Product.query.get(product_id)
            if product:
                product.type = new_type
                db.session.commit()
                updated_count += 1
        print(f'成功更新{updated_count}个商品的类型')
        
        if updated_count > 0:
            return jsonify({
                'code': 0,
                'message': f'成功更新{updated_count}个商品的类型',
                'data': {
                    'updated_count': updated_count
                }
            })
        else:
            return jsonify({'code': -1, 'message': '更新失败或没有符合条件的商品'}), 400

    except Exception as e:
        print(f'批量更新商品类型失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'code': -1, 'message': str(e)}), 500



# 获取商品列表（需要管理员登录）
@app.route('/products', methods=['GET'])
@check_staff_permission('product.view')
def get_products(user_id):
    try:
        # 获取查询参数
        page = request.args.get('page', 1, type=int)
        page_size = request.args.get('page_size', 10, type=int)
        keyword = request.args.get('keyword', '')
        product_type = request.args.get('type')
        status = request.args.get('status')
        is_public = request.args.get('is_public')
        sort_field = request.args.get('sort_field', 'created_at')  # 添加排序字段参数
        sort_order = request.args.get('sort_order', 'desc')  # 添加排序顺序参数
        
        # 获取规格筛选参数
        size = request.args.get('size')
        weight = request.args.get('weight')
        yarn = request.args.get('yarn')
        composition = request.args.get('composition')
        
        print(f'获取商品列表参数: page={page}, page_size={page_size}, keyword={keyword}, product_type={product_type}, size={size}, weight={weight}, yarn={yarn}, composition={composition}')
        
        # 构建基础查询
        query = Product.query
        
        # 添加搜索条件
        if keyword:
            search = f'%{keyword}%'
            query = query.filter(db.or_(
                Product.id.like(search),
                Product.name.like(search),
                Product.description.like(search)
            ))
        
        # 添加类型筛选
        if product_type:
            if product_type == '-':
                query = query.filter(db.or_(Product.type == None, Product.type == ''))
            else:
                query = query.filter(Product.type == product_type)
        
        # 添加状态筛选
        if status is not None:
            query = query.filter(Product.status == int(status))
            
        # 添加是否公开筛选
        if is_public is not None:
            query = query.filter(Product.is_public == int(is_public))
        
        if size:
            if size == '-':
                query = query.filter(db.or_(Product.size == None, Product.size == ''))
            else:
                query = query.filter(Product.size == size)
            
        if weight:
            if weight == '-':
                query = query.filter(db.or_(Product.weight == None, Product.weight == ''))
            else:
                query = query.filter(Product.weight == weight)
            
        if yarn:
            if yarn == '-':
                query = query.filter(db.or_(Product.yarn == None, Product.yarn == ''))
            else:
                query = query.filter(Product.yarn == yarn)
        
        if composition:
            if composition == '-':
                query = query.filter(db.or_(Product.composition == None, Product.composition == ''))
            else:
                query = query.filter(Product.composition == composition)
        
        # 获取分页数据
        # 根据排序字段和顺序构建排序
        if sort_field == 'name':
            order_column = Product.name
        elif sort_field == 'id':  # 添加对货号的排序支持
            order_column = Product.id
        else:
            order_column = Product.created_at
            
        if sort_order == 'asc':
            query = query.order_by(order_column.asc())
        else:
            query = query.order_by(order_column.desc())
            
        paginated_products = query.paginate(page=page, per_page=page_size, error_out=False)
            
        # 格式化返回数据
        products = []
        for product in paginated_products.items:            
            # 安全地获取基础价格
            base_price = float(product.price) if product.price is not None else 0
            product_dict = product.__dict__.copy()
            
            # 删除不需要的属性
            product_dict.pop('_sa_instance_state', None)
            # 获取推送过该商品的用户
           
            
            # 处理特殊字段
            product_dict['price'] = base_price
            product_dict['price_b'] = float(product.price_b) if product.price_b is not None else 0
            product_dict['price_c'] = float(product.price_c) if product.price_c is not None else 0
            product_dict['price_d'] = float(product.price_d) if product.price_d is not None else 0
            product_dict['cost_price'] = float(product.cost_price) if product.cost_price is not None else 0
            product_dict['created_at'] = product.created_at.isoformat() if product.created_at else None
            product_dict['specs'] = json.loads(product.specs) if product.specs else []
            product_dict['images'] = json.loads(product.images) if product.images else []
            product_dict['status'] = product.status if product.status is not None else 1
            product_dict['is_public'] = product.is_public if product.is_public is not None else 1
            product_dict['video_url'] = product.video_url if product.video_url is not None else ''
            product_dict['size'] = product.size if product.size is not None else ''
            product_dict['weight'] = product.weight if product.weight is not None else ''
            product_dict['yarn'] = product.yarn if product.yarn is not None else ''
            product_dict['composition'] = product.composition if product.composition is not None else ''
            product_dict['video_url'] = product.video_url if product.video_url is not None else ''
            
            products.append(product_dict)




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
                        'images': json.loads(product.images)[0] if product.images and len(json.loads(product.images)) > 0 else None,
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
                    'image': json.loads(product.images)[0] if product.images and len(json.loads(product.images)) > 0 else None
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



# 访问上传的图片
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    try:
        print(f'尝试访问文件: {filename}')
        # 从完整路径中提取文件类型目录和文件名
        if '/' in filename:
            file_type, base_filename = filename.split('/', 1)
        else:
            file_type = filename.rsplit('.', 1)[1].lower()
            base_filename = filename
            
        # 使用绝对路径
        upload_dir = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], file_type)
        print(f'文件目录: {upload_dir}')
        print(f'文件名: {base_filename}')
        
        if not os.path.exists(upload_dir):
            print(f'目录不存在: {upload_dir}')
            return jsonify({'error': '文件目录不存在'}), 404
            
        if not os.path.exists(os.path.join(upload_dir, base_filename)):
            print(f'文件不存在: {os.path.join(upload_dir, base_filename)}')
            return jsonify({'error': '文件不存在'}), 404
            
        return send_from_directory(upload_dir, base_filename)
    except Exception as e:
        print(f'访问上传文件失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '文件访问失败'}), 404

@app.route('/home/statistics', methods=['GET'])
@login_required
def get_home_statistics(user_id):
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

# 获取商品列表（包含公开商品和推送单商品）
@app.route('/products/combined', methods=['GET'])
@login_required
def get_combined_products(user_id):
    try:
        print('开始获取组合商品列表')
        
        # 获取当前用户信息
        current_user = User.query.get(user_id)
        if not current_user:
            return jsonify({'error': '用户不存在'}), 404
            
        # 获取分页参数
        page = int(request.args.get('page', 1))
        page_size = min(int(request.args.get('page_size', 10)), 50)
        
        # 根据用户类型获取对应价格
        def get_price_by_user_type(product):
            if current_user.user_type == 0:  # 零售客户
                return product.price
            elif current_user.user_type == 1:  # 管理员
                return product.cost_price
            elif current_user.user_type == 2:  # A类客户
                return product.price_b
            elif current_user.user_type == 3:  # B类客户
                return product.price_c
            elif current_user.user_type == 4:  # C类客户
                return product.price_d
            return product.retail_price  # 默认返回零售价
        
        # 获取所有公开的商品
        public_products = Product.query.filter_by(status=1).all()
        
        # 获取用户关联的所有推送单商品
        push_products = db.session.query(
            Product,
            PushOrder.created_at,
            PushOrderProduct.price
        ).join(
            PushOrderProduct, Product.id == PushOrderProduct.product_id
        ).join(
            PushOrder, PushOrderProduct.push_order_id == PushOrder.id
        ).filter(
            PushOrder.target_user_id == user_id,
            PushOrder.status != 2  # 排除已取消的推送单
        ).order_by(
            PushOrder.created_at.desc()
        ).all()
        
        # 创建一个字典来存储最新的商品信息
        products_dict = {}
        
        # 处理公开商品
        for product in public_products:
            try:
                price = get_price_by_user_type(product)
                products_dict[product.id] = {
                    'id': product.id,
                    'name': product.name,
                    'description': product.description,
                    'images': json.loads(product.images) if product.images else [],
                    'price': float(price) if price else 0,
                    'original_price': float(price) if price else 0,
                    'specs_info': json.loads(product.specs_info) if product.specs_info else {},
                    'specs': json.loads(product.specs) if product.specs else [],
                    'type': product.type,
                    'status': product.status,
                    'source': 'public',
                    'updated_at': product.updated_at.isoformat() if product.updated_at else None
                }
            except Exception as e:
                print(f'处理公开商品出错: {str(e)}')
                continue
        
        # 处理推送单商品
        for product, created_at, push_price in push_products:
            try:
                if product.id not in products_dict or created_at > datetime.fromisoformat(products_dict[product.id]['updated_at']):
                    original_price = get_price_by_user_type(product)
                    products_dict[product.id] = {
                        'id': product.id,
                        'name': product.name,
                        'description': product.description,
                        'images': json.loads(product.images) if product.images else [],
                        'price': float(push_price) if push_price else 0,
                        'original_price': float(original_price) if original_price else 0,
                        'stock': product.stock,
                        'specs': json.loads(product.specs) if product.specs else [],
                        'type': product.type,
                        'status': product.status,
                        'source': 'push',
                        'updated_at': created_at.isoformat() if created_at else None
                    }
            except Exception as e:
                print(f'处理推送商品出错: {str(e)}')
                continue
        
        # 将字典转换为列表并排序
        products_list = list(products_dict.values())
        products_list.sort(key=lambda x: x['updated_at'] or '', reverse=True)
        
        # 计算分页
        total = len(products_list)
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        paginated_products = products_list[start_idx:end_idx]
        
        return jsonify({
            'products': paginated_products,
            'total': total,
            'pages': (total + page_size - 1) // page_size,
            'current_page': page
        }), 200
            
    except Exception as e:
        print(f'获取组合商品列表失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '获取商品列表失败'}), 500

# 编辑用户信息
@app.route('/users/<int:target_user_id>', methods=['PUT'])
@admin_required
def edit_user(user_id, target_user_id):
    try:
        print(f'开始编辑用户信息 - 目标用户ID: {target_user_id}')
        
        # 获取请求数据
        data = request.json
        print('请求数据:', json.dumps(data, ensure_ascii=False))
        
        # 获取目标用户
        target_user = User.query.get(target_user_id)
        if not target_user:
            return jsonify({'error': '用户不存在'}), 404
            
        # 可编辑字段列表
        editable_fields = {
            'username': str,
            'nickname': str,
            'phone': str,
            'address': str,
            'contact': str,
            'user_type': int,
            'status': int,
            'password': str,
            'avatar': str,
            'role': str
        }
        
        # 验证用户类型
        if 'user_type' in data:
            if data['user_type'] not in [0, 1, 2, 3, 4, 5, 6]:  # 0:零售 1:管理员 2:A类 3:B类 4:C类 5:STAFF 6:普通管理员
                return jsonify({'error': '无效的用户类型'}), 400
                
        # 验证状态
        if 'status' in data:
            if data['status'] not in [0, 1]:  # 0:禁用 1:启用
                return jsonify({'error': '无效的状态值'}), 400
        
        # 更新用户信息
        changes_made = False
        for field, field_type in editable_fields.items():
            if field in data:
                try:
                    # 特殊处理密码字段
                    if field == 'password' and data[field]:
                        setattr(target_user, field, data[field])
                        changes_made = True
                        continue
                        
                    # 处理其他字段
                    value = data[field]
                    if value is not None:  # 只更新非空值
                        if isinstance(value, field_type):
                            setattr(target_user, field, value)
                            changes_made = True
                        else:
                            try:
                                # 尝试类型转换
                                setattr(target_user, field, field_type(value))
                                changes_made = True
                            except (ValueError, TypeError):
                                print(f'字段 {field} 的值 {value} 类型转换失败')
                                return jsonify({'error': f'字段 {field} 的值类型错误'}), 400
                except Exception as e:
                    print(f'更新字段 {field} 时出错: {str(e)}')
                    return jsonify({'error': f'更新字段 {field} 失败'}), 400
        
        if not changes_made:
            return jsonify({'message': '没有需要更新的信息'}), 200
            
        # 更新时间戳
        target_user.updated_at = datetime.now()
        
        try:
            db.session.commit()
            print(f'用户 {target_user_id} 信息更新成功')
            
            # 返回更新后的用户信息
            return jsonify({
                'message': '用户信息更新成功',
                'user': {
                    'id': target_user.id,
                    'username': target_user.username,
                    'nickname': target_user.nickname,
                    'phone': target_user.phone,
                    'address': target_user.address,
                    'contact': target_user.contact,
                    'user_type': target_user.user_type,
                    'role': target_user.role,
                    'status': target_user.status,
                    'avatar': target_user.avatar,
                    'created_at': target_user.created_at.isoformat() if target_user.created_at else None,
                    'updated_at': target_user.updated_at.isoformat() if target_user.updated_at else None
                }
            }), 200
            
        except Exception as e:
            db.session.rollback()
            print(f'保存用户信息时出错: {str(e)}')
            return jsonify({'error': '保存用户信息失败'}), 500
            
    except Exception as e:
        print(f'编辑用户信息失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '编辑用户信息失败'}), 500

# 重置数据库接口
@app.route('/system/reset', methods=['POST'])
def reset_database():
    try:
        print('开始重置数据库...')
        
        # 获取请求数据
        data = request.json
        if not data or 'admin_username' not in data or 'admin_password' not in data:
            return jsonify({'error': '缺少管理员账号或密码'}), 400
            
        admin_username = data['admin_username']
        admin_password = data['admin_password']
        
        # 验证用户名和密码格式
        if len(admin_username) < 4 or len(admin_password) < 6:
            return jsonify({'error': '用户名长度至少4位，密码长度至少6位'}), 400
            
        # 删除所有表的数据
        try:
            # 先删除关联表数据
            db.session.query(user_permissions).delete()
            db.session.query(Permission).delete()
            
            # 删除其他表数据
            db.session.query(PushOrderProduct).delete()
            db.session.query(PushOrder).delete()
            db.session.query(DeliveryOrder).delete()
            db.session.query(DeliveryItem).delete()
            db.session.query(PurchaseOrderItem).delete()
            db.session.query(PurchaseOrder).delete()
            db.session.query(ProductView).delete()
            db.session.query(Product).delete()
            db.session.query(User).delete()
            db.session.query(ColorStock).delete()
            db.session.query(StockRecord).delete()
            db.session.query(SystemSettings).delete()
            db.session.commit()
            print('所有表数据已清空')
            
        except Exception as e:
            db.session.rollback()
            print(f'清空数据失败: {str(e)}')
            return jsonify({'error': '清空数据失败'}), 500
            
        try:
            # 创建默认权限
            permissions = [
                Permission(name='admin', description='管理员权限'),
                Permission(name='user', description='普通用户权限'),
                Permission(name='customer', description='客户权限')
            ]
            db.session.add_all(permissions)
            db.session.flush()  # 刷新session获取权限ID
            
            # 创建新的管理员用户
            admin_user = User(
                username=admin_username,
                password=admin_password,
                role='admin',           # 新增：角色为admin
                customer_type='normal', # 新增：默认客户类型
                status=1,              # 启用状态
                created_at=datetime.now(),
                updated_at=datetime.now()
            )
            db.session.add(admin_user)
            db.session.flush()  # 刷新session获取用户ID
            
            # 为管理员分配所有权限
            admin_permission = next(p for p in permissions if p.name == 'admin')
            admin_user.permissions.append(admin_permission)
            
            # 创建默认系统设置
            default_settings = SystemSettings(
                min_delivery_amount=0,
                created_at=datetime.now(),
                updated_at=datetime.now()
            )
            db.session.add(default_settings)
            db.session.commit()
            print('创建默认系统设置和权限成功')
            
            return jsonify({
                'message': '数据库重置成功',
                'admin': {
                    'id': admin_user.id,
                    'username': admin_user.username,
                    'role': admin_user.role,
                    'customer_type': admin_user.customer_type,
                    'created_at': admin_user.created_at.isoformat()
                }
            }), 200
            
        except Exception as e:
            db.session.rollback()
            print(f'创建管理员用户和权限失败: {str(e)}')
            return jsonify({'error': '创建管理员用户和权限失败'}), 500
            
    except Exception as e:
        print(f'重置数据库失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '重置数据库失败'}), 500

# 获取公开商品列表
@app.route('/products/public', methods=['GET'])
@login_required
def get_public_products(user_id):
    try:
        print('开始获取公开商品列表')
        
        # 获取当前用户信息
        current_user = User.query.get(user_id)
        if not current_user:
            return jsonify({'error': '用户不存在'}), 404
        
        # 获取分页参数
        page = int(request.args.get('page', 1))
        page_size = min(int(request.args.get('page_size', 10)), 50)
        
        # 获取筛选参数
        product_type = request.args.get('type')
        keyword = request.args.get('keyword', '').strip()
        sort_by = request.args.get('sort_by', 'created_at')  # 默认按创建时间排序
        sort_order = request.args.get('sort_order', 'desc')  # 默认降序
        
        # 构建基础查询
        query = Product.query.filter(
            db.and_(
                Product.status == 1,      # 商品状态为上架
                Product.is_public == 1    # 商品为公开
            )
        )
        
        # 添加筛选条件
        if product_type:
            query = query.filter(Product.type == product_type)
            
        if keyword:
            search = f'%{keyword}%'
            query = query.filter(db.or_(
                Product.name.like(search),
                Product.description.like(search)
            ))
            
        # 添加排序
        if sort_by == 'price':
            order_column = Product.price
        elif sort_by == 'stock':
            order_column = Product.stock
        else:  # 默认按创建时间
            order_column = Product.created_at
            
        if sort_order == 'asc':
            query = query.order_by(order_column.asc())
        else:
            query = query.order_by(order_column.desc())
            
        # 获取分页数据
        pagination = query.paginate(page=page, per_page=page_size, error_out=False)
        
        # 根据用户类型获取价格
        def get_price_by_user_type(product):
            if current_user.user_type == 0:  # 零售客户
                return float(product.price) if product.price else 0
            elif current_user.user_type == 1:  # 管理员
                return float(product.cost_price) if product.cost_price else 0
            elif current_user.user_type == 2:  # A类客户
                return float(product.price_b) if product.price_b else 0
            elif current_user.user_type == 3:  # B类客户
                return float(product.price_c) if product.price_c else 0
            elif current_user.user_type == 4:  # C类客户
                return float(product.price_d) if product.price_d else 0
            return float(product.price) if product.price else 0
        
        # 格式化商品数据
        products = []
        for product in pagination.items:
            try:
                price = get_price_by_user_type(product)
                product_data = {
                    'id': product.id,
                    'name': product.name,
                    'description': product.description,
                    'price': price,
                    'retail_price': float(product.price) if product.price else 0,
                    'images': json.loads(product.images) if product.images else [],
                    'type': product.type,
                    'specs_info': product.specs_info,
                    'specs': json.loads(product.specs) if product.specs else [],
                    'created_at': product.created_at.isoformat() if product.created_at else None,
                    'updated_at': product.updated_at.isoformat() if product.updated_at else None
                }
                products.append(product_data)
            except Exception as e:
                print(f'处理商品数据出错 - 商品ID: {product.id}, 错误: {str(e)}')
                continue
                
        return jsonify({
            'products': products,
            'total': pagination.total,
            'page': page,
            'page_size': page_size,
            'total_pages': pagination.pages,
            'user_type': current_user.user_type
        }), 200
        
    except Exception as e:
        print(f'获取公开商品列表失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '获取商品列表失败'}), 500

# 获取用户推送单商品列表（只保留最新的）
@app.route('/products/push/latest', methods=['GET'])
@login_required
def get_latest_push_products(user_id):
    try:
        print('开始获取用户最新推送商品列表')
        
        # 获取当前用户信息
        current_user = User.query.get(user_id)
        if not current_user:
            return jsonify({'error': '用户不存在'}), 404
            
        # 获取分页参数
        page = int(request.args.get('page', 1))
        page_size = min(int(request.args.get('page_size', 10)), 50)
        
        # 获取筛选参数
        product_type = request.args.get('type')
        keyword = request.args.get('keyword', '').strip()
        sort_by = request.args.get('sort_by', 'push_time')  # 默认按推送时间排序
        sort_order = request.args.get('sort_order', 'desc')  # 默认降序
        
        # 构建子查询获取最新推送时间
        latest_push_subquery = db.session.query(
            PushOrderProduct.product_id,
            func.max(PushOrder.created_at).label('latest_push_time')
        ).join(
            PushOrder, PushOrder.id == PushOrderProduct.push_order_id
        ).filter(
            PushOrder.target_user_id == user_id,
            PushOrder.status != 2  # 排除已取消的推送单
        ).group_by(
            PushOrderProduct.product_id
        ).subquery()
        
        # 构建主查询
        query = db.session.query(
            Product,
            PushOrderProduct.price.label('push_price'),
            PushOrder.created_at.label('push_time')
        ).join(
            latest_push_subquery,
            Product.id == latest_push_subquery.c.product_id
        ).join(
            PushOrderProduct,
            Product.id == PushOrderProduct.product_id
        ).join(
            PushOrder,
            db.and_(
                PushOrder.id == PushOrderProduct.push_order_id,
                PushOrder.created_at == latest_push_subquery.c.latest_push_time
            )
        ).filter(
            Product.status == 1  # 只查询上架商品
        )
        
        # 添加筛选条件
        if product_type:
            query = query.filter(Product.type == product_type)
            
        if keyword:
            search = f'%{keyword}%'
            query = query.filter(db.or_(
                Product.name.like(search),
                Product.description.like(search)
            ))
            
        # 添加排序
        if sort_by == 'price':
            order_column = PushOrderProduct.price
        elif sort_by == 'push_time':
            order_column = PushOrder.created_at
        else:  # 默认按推送时间
            order_column = PushOrder.created_at
            
        if sort_order == 'asc':
            query = query.order_by(order_column.asc())
        else:
            query = query.order_by(order_column.desc())
            
        # 获取分页数据
        pagination = query.paginate(page=page, per_page=page_size, error_out=False)
        
        # 根据用户类型获取原始价格
        def get_price_by_user_type(product):
            if current_user.user_type == 0:  # 零售客户
                return float(product.retail_price) if product.retail_price else 0
            elif current_user.user_type == 1:  # 管理员
                return float(product.cost_price) if product.cost_price else 0
            elif current_user.user_type == 2:  # A类客户
                return float(product.price_b) if product.price_b else 0
            elif current_user.user_type == 3:  # B类客户
                return float(product.price_c) if product.price_c else 0
            elif current_user.user_type == 4:  # C类客户
                return float(product.price_d) if product.price_d else 0
            return float(product.retail_price) if product.retail_price else 0
        
        # 格式化商品数据
        products = []
        for product, push_price, push_time in pagination.items:
            try:
                original_price = get_price_by_user_type(product)
                product_data = {
                    'id': product.id,
                    'name': product.name,
                    'description': product.description,
                    'price': float(push_price) if push_price else original_price,  # 优先使用推送价格
                    'original_price': original_price,  # 原始价格（根据用户类型）
                    'retail_price': float(product.retail_price) if product.retail_price else 0,
                    'images': json.loads(product.images) if product.images else [],
                    'type': product.type,
                    'stock': product.stock,
                    'specs': json.loads(product.specs) if product.specs else [],
                    'push_time': push_time.isoformat() if push_time else None,
                    'created_at': product.created_at.isoformat() if product.created_at else None,
                    'updated_at': product.updated_at.isoformat() if product.updated_at else None
                }
                products.append(product_data)
            except Exception as e:
                print(f'处理商品数据出错 - 商品ID: {product.id}, 错误: {str(e)}')
                continue
                
                
        return jsonify({
            'products': products,
            'total': pagination.total,
            'page': page,
            'page_size': page_size,
            'total_pages': pagination.pages,
            'user_type': current_user.user_type
        }), 200
        
    except Exception as e:
        print(f'获取用户推送商品列表失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '获取商品列表失败'}), 500

# 获取合并商品列表（推送商品优先）
@app.route('/products/merged', methods=['GET'])
@login_required
def get_merged_products(user_id):
    try:
        print('开始获取合并商品列表')
        
        # 获取当前用户信息
        current_user = User.query.get(user_id)
        if not current_user:
            return jsonify({'error': '用户不存在'}), 404
            
        # 获取分页参数
        page = int(request.args.get('page', 1))
        page_size = min(int(request.args.get('page_size', 10)), 50)
        
        # 获取筛选参数
        product_type = request.args.get('type')
        keyword = request.args.get('keyword', '').strip()
        sort_by = request.args.get('sort_by', 'updated_time')  # 默认按更新时间排序
        sort_order = request.args.get('sort_order', 'desc')  # 默认降序
        
        # 构建推送商品子查询
        latest_push_subquery = db.session.query(
            PushOrderProduct.product_id,
            func.max(PushOrder.created_at).label('latest_push_time')
        ).join(
            PushOrder, PushOrder.id == PushOrderProduct.push_order_id
        ).filter(
            PushOrder.target_user_id == user_id,
            PushOrder.status != 2  # 排除已取消的推送单
        ).group_by(
            PushOrderProduct.product_id
        ).subquery()
        
        # 构建推送商品查询
        push_products_query = db.session.query(
            Product,
            PushOrderProduct.price.label('push_price'),
            PushOrder.created_at.label('push_time'),
            literal_column("'push'").label('source')  # 修改这里
        ).join(
            latest_push_subquery,
            Product.id == latest_push_subquery.c.product_id
        ).join(
            PushOrderProduct,
            Product.id == PushOrderProduct.product_id
        ).join(
            PushOrder,
            db.and_(
                PushOrder.id == PushOrderProduct.push_order_id,
                PushOrder.created_at == latest_push_subquery.c.latest_push_time
            )
        ).filter(
            Product.status == 1  # 只查询上架商品
        )
        
        # 获取已推送商品的ID列表
        pushed_product_ids = [row[0].id for row in push_products_query.all()]
        
        # 构建公开商品查询（排除已推送的商品）
        public_products_query = db.session.query(
            Product,
            literal(None).label('push_price'),
            literal(None).label('push_time'),
            literal_column("'public'").label('source')  # 修改这里
        ).filter(
            db.and_(
                Product.status == 1,      # 商品状态为上架
                Product.is_public == 1,   # 商品为公开
                ~Product.id.in_(pushed_product_ids) if pushed_product_ids else True  # 排除已推送商品
            )
        )
        
        # 合并两个查询
        query = push_products_query.union(public_products_query)
        
        # 添加筛选条件
        if product_type:
            query = query.filter(Product.type == product_type)
            
        if keyword:
            search = f'%{keyword}%'
            query = query.filter(db.or_(
                Product.name.like(search),
                Product.description.like(search)
            ))
            
        # 添加排序
        if sort_by == 'price':
            # 对于推送商品使用push_price，对于公开商品使用原价
            query = query.order_by(
                case(
                    (PushOrderProduct.price != None, PushOrderProduct.price),
                    else_=Product.price
                ).desc() if sort_order == 'desc' else case(
                    (PushOrderProduct.price != None, PushOrderProduct.price),
                    else_=Product.price
                ).asc()
            )
        elif sort_by == 'push_time':
            query = query.order_by(
                PushOrder.created_at.desc() if sort_order == 'desc' else PushOrder.created_at.asc()
            )
        else:  # 默认按更新时间
            query = query.order_by(
                Product.updated_at.desc() if sort_order == 'desc' else Product.updated_at.asc()
            )
            
        # 获取分页数据
        pagination = query.paginate(page=page, per_page=page_size, error_out=False)
        
        # 根据用户类型获取原始价格
        def get_price_by_user_type(product):
            if current_user.user_type == 0:  # 零售客户
                return float(product.price) if product.price else 0
            elif current_user.user_type == 1:  # 管理员
                return float(product.cost_price) if product.cost_price else 0
            elif current_user.user_type == 2:  # A类客户
                return float(product.price_b) if product.price_b else 0
            elif current_user.user_type == 3:  # B类客户
                return float(product.price_c) if product.price_c else 0
            elif current_user.user_type == 4:  # C类客户
                return float(product.price_d) if product.price_d else 0
            return float(product.price) if product.price else 0
        
        # 格式化商品数据
        products = []
        for product, push_price, push_time, source in pagination.items:
            try:
                original_price = get_price_by_user_type(product)
                product_data = {
                    'id': product.id,
                    'name': product.name,
                    'description': product.description,
                    'price': float(push_price) if push_price else original_price,  # 优先使用推送价格
                    'original_price': original_price,  # 原始价格（根据用户类型）
                    'retail_price': float(product.price) if product.price else 0,
                    'images': json.loads(product.images) if product.images else [],
                    'type': product.type,
                    'specs': json.loads(product.specs) if product.specs else [],
                    'size': product.size,
                    'weight': product.weight,
                    'yarn': product.yarn,
                    'composition': product.composition,
                    'source': source,  # 添加来源标记
                    'push_time': push_time.isoformat() if push_time else None,
                    'created_at': product.created_at.isoformat() if product.created_at else None,
                    'updated_at': product.updated_at.isoformat() if product.updated_at else None
                }
                products.append(product_data)
            except Exception as e:
                print(f'处理商品数据出错 - 商品ID: {product.id}, 错误: {str(e)}')
                continue
                
        return jsonify({
            'products': products,
            'total': pagination.total,
            'page': page,
            'page_size': page_size,
            'total_pages': pagination.pages,
            'user_type': current_user.user_type
        }), 200
        
    except Exception as e:
        print(f'获取合并商品列表失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '获取商品列表失败'}), 500

@app.route('/upload/cloud', methods=['POST'])
@admin_required
def handle_cloud_file(user_id):
    """
    处理从小程序云存储上传的文件
    """
    try:
        data = request.get_json()
        if not data or 'fileID' not in data:
            return jsonify({'error': '缺少fileID参数'}), 400

        fileID = data.get('fileID')
        product_id = data.get('product_id', '')

        # 获取云环境ID
        env = config.CLOUD_ENV_ID
        if not env:
            return jsonify({'error': '未配置云环境ID'}), 500

        # 获取小程序配置
        appid = config.WECHAT_APPID
        secret = config.WECHAT_SECRET
        if not appid or not secret:
            return jsonify({'error': '未配置小程序信息'}), 500

        # 获取access_token
        token_url = f"http://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid={appid}&secret={secret}"
        token_response = requests.get(token_url)
        if token_response.status_code != 200:
            return jsonify({'error': '获取access_token失败'}), 500

        token_data = token_response.json()
        if 'access_token' not in token_data:
            return jsonify({'error': f"获取access_token失败: {token_data.get('errmsg')}"}), 500

        access_token = token_data['access_token']
        
        # 构建下载URL
        download_url = f"http://api.weixin.qq.com/tcb/batchdownloadfile?access_token={access_token}"
        
        # 请求下载文件
        response = requests.post(download_url, json={
            "env": env,
            "file_list": [{
                "fileid": fileID,
                "max_age": 7200
            }]
        })

        if response.status_code != 200:
            return jsonify({'error': '下载文件失败'}), 500

        result = response.json()
        if result.get('errcode') != 0:
            return jsonify({'error': f"下载文件失败: {result.get('errmsg')}"}), 500

        file_list = result.get('file_list', [])
        if not file_list:
            return jsonify({'error': '文件列表为空'}), 500

        download_url = file_list[0].get('download_url')
        if not download_url:
            return jsonify({'error': '获取下载链接失败'}), 500

        # 下载文件
        file_response = requests.get(download_url)
        if file_response.status_code != 200:
            return jsonify({'error': '下载文件内容失败'}), 500

        # 生成唯一文件名
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        random_str = str(uuid.uuid4()).split('-')[0]
        filename = f"{timestamp}_{random_str}.jpg"

        # 确保上传目录存在
        upload_folder = os.path.join(current_app.root_path, 'uploads')
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)

        # 保存文件
        file_path = os.path.join(upload_folder, filename)
        with open(file_path, 'wb') as f:
            f.write(file_response.content)

        # 返回文件URL
        return jsonify({
            'url': f'/uploads/{filename}',
            'message': '文件上传成功'
        })

    except Exception as e:
        print(f"处理云存储文件失败: {str(e)}")
        return jsonify({'error': f'处理文件失败: {str(e)}'}), 500

@app.route('/test/headers', methods=['GET'])
def test_headers():
    try:
        # 获取所有请求头
        wx_headers =   dict(request.headers)

        url = 'https://api.weixin.qq.com/cgi-bin/token'
        params = {
            'grant_type': 'client_credential',
            'appid': "wxa17a5479891750b3",
            'secret': "33359853cfee1dc1e2b6e535249e351d"
        }
     
        response = requests.get(url,params)
        print(response.json())

        return jsonify({
            'code': 200,
            'message': '获取请求头信息成功',
            'data': {
                'all_headers': wx_headers,
                'token': response.json()
            }
        })
            
    except Exception as e:
        return jsonify({
            'code': 500,
            'message': '获取请求头信息失败',
            'error': {
                'type': type(e).__name__,
                'message': str(e),
                'traceback': traceback.format_exc()
            }
        }), 500


@app.route('/api/users', methods=['GET'])
@admin_required
def list_users(user_id):
    """获取用户列表"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        role = request.args.get('role')
        
        query = User.query
        
        # 按角色筛选
        if role:
            query = query.filter(User.role == role)
            
        # 分页
        pagination = query.paginate(page=page, per_page=per_page)
        
        return jsonify({
            'code': 200,
            'message': '获取用户列表成功',
            'data': {
                'items': [user.to_dict() for user in pagination.items],
                'total': pagination.total,
                'pages': pagination.pages,
                'current_page': page
            }
        })
        
    except Exception as e:
        return jsonify({
            'code': 500,
            'message': f'获取用户列表失败：{str(e)}'
        }), 500

def check_push_order_permission(user_id, order_id):
    """检查用户是否有权限操作推送单"""
    try:
        # 获取用户和推送单
        user = User.query.get(user_id)
        push_order = PushOrder.query.get(order_id)
        
        if not user or not push_order:
            return False
            
        # 管理员拥有所有权限
        if user.role == UserRole.ADMIN:
            return True
            
        # 员工需要检查具体权限
        if user.role == UserRole.STAFF:
            # 检查是否有推送单管理权限
            if not user.has_permission(PermissionEnum.PUSH_ORDER):
                return False
            # 只能操作自己创建的推送单
            return push_order.user_id == user_id
            
        # 客户只能查看自己的推送单
        if user.role == UserRole.CUSTOMER:
            return push_order.user_id == user_id or push_order.target_user_id == user_id
            
        return False
        
    except Exception as e:
        print(f"检查推送单权限失败: {str(e)}")
        return False

import base64
import urllib.parse

def encode_chinese_name(name):
    """将中文名称编码为URL安全的字符串"""
    try:
        # 限制中文字符数量为6个
        if len(name) > 6:
            name = name[:6]
            
        # 将中文转换为UTF-8字节
        name_bytes = name.encode('utf-8')
        # 使用Base64编码
        base64_str = base64.b64encode(name_bytes).decode('utf-8')
        # 替换Base64中的特殊字符为URL安全字符
        safe_str = base64_str.replace('+', '-').replace('/', '_').replace('=', '')
        
        # 验证编码后的长度是否超过32个字符
        if len(safe_str) > 32:
            print(f"警告：编码后的名称超过32个字符: {safe_str}")
            # 如果超过32个字符，截断到32个字符
            safe_str = safe_str[:32]
            
        return safe_str
    except Exception as e:
        print(f"编码中文名称失败: {str(e)}")
        return name

def decode_chinese_name(encoded_name):
    """将编码后的名称解码为中文"""
    try:
        # 还原Base64特殊字符
        base64_str = encoded_name.replace('-', '+').replace('_', '/')
        # 补充Base64填充
        padding = 4 - (len(base64_str) % 4)
        if padding != 4:
            base64_str += '=' * padding
        # Base64解码
        name_bytes = base64.b64decode(base64_str)
        return name_bytes.decode('utf-8')
    except Exception as e:
        print(f"解码名称失败: {str(e)}")
        return encoded_name

@app.route('/push_orders/bind/guest', methods=['POST'])
def bind_push_order_guest():
    """无需登录的推送单绑定接口"""
    try:
        data = request.get_json()
        if not data or 'share_code' not in data or 'name' not in data :
            return jsonify({
                'code': 400,
                'error': '缺少必要参数'
            }), 400
            
        share_code = data['share_code']
        name = data['name']
        openid = request.headers.get('X-WX-OPENID')
        if not openid:
            openid = data['openid']
        
        print(f"开始绑定推送单 - 分享码: {share_code}, 姓名: {name}, openid: {openid}")
        
        # 查找对应的推送单
        order = PushOrder.query.filter_by(share_code=share_code, target_name=name).first()
        
        if not order:
            print(f"绑定失败 - 分享码无效: {share_code}")
            return jsonify({
                'code': 401,
                'message': '无效的分享码,或姓名不正确'
            }), 400
            
        # 检查是否已被绑定
        if order.target_user_id is not None:
            print(f"绑定失败 - 推送单已被绑定 - 订单号: {order.order_number}")
            return jsonify({
                'code': 402,
                'message': '该推送单已被绑定'
            }), 400
            
        print(f"找到推送单 - 订单ID: {order.id}, 订单号: {order.order_number}")
        
        # 查找或创建用户
        user = User.query.filter_by(openid=openid).first()
        if not user:
            # 生成随机用户名和密码
            random_username = f"qyfs_{int(time.time())}"
            random_password = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=12))
            
            # 创建新用户
            user = User(
                username=random_username,
                password=generate_password_hash(random_password),
                nickname=name,
                openid=openid,
                role='customer',
                status=1,
                user_type=0
            )
            
            try:
                db.session.add(user)
                db.session.commit()
                print(f"创建新用户成功 - 用户ID: {user.id}, 昵称: {name}")
            except Exception as e:
                db.session.rollback()
                print(f"创建用户失败: {str(e)}")
                return jsonify({
                    'code': 403,
                    'message': '创建用户失败'
                }), 403
        else:
            print(f"找到已存在用户 - 用户ID: {user.id}, 昵称: {user.nickname}")
            
        # 更新推送单信息
        order.target_user_id = user.id
        order.target_name = name
        order.openid = openid
        order.share_code = None
        
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"绑定失败 - 更新推送单失败: {str(e)}")
            return jsonify({
                'code': 404,
                'message': '绑定失败，请重试'
            }), 404
            
        print(f"已更新推送单 - 订单ID: {order.id} 绑定到用户: {name}")
            
        # 构建返回数据
        order_data = {
            'id': order.id,
            'order_number': order.order_number,
            'created_at': order.created_at.isoformat(),
            'target_name': name,
            'target_user_id': user.id,
            'openid': openid,
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
                        'images': json.loads(product.images)[0] if product.images and len(json.loads(product.images)) > 0 else None,
                        'specs_info': json.loads(item.specs_info) if item.specs_info else {},
                        'specs': json.loads(item.specs) if item.specs else []
                    }
                    order_data['products'].append(product_data)
                    product_count += 1
                except (ValueError, json.JSONDecodeError) as e:
                    print(f"处理商品数据出错 - 商品ID: {product.id}, 错误: {str(e)}")
                    continue
        
        print(f"推送单绑定成功 - 订单ID: {order.id}, 订单号: {order_data['order_number']}")
        return jsonify({
            'code': 200,
            'message': '推送单绑定成功',
            'data': order_data
        }), 200
            
    except Exception as e:
        print(f"绑定推送单失败 - 分享码: {share_code}, 错误信息: {str(e)}")
        print(f"错误追踪:\n{traceback.format_exc()}")
        return jsonify({
            'code': 500,
            'message': '绑定失败'
        }), 500

# 添加商品到购物车
@app.route('/cart/add', methods=['POST'])
@login_required
def add_to_cart(user_id):
    try:
        data = request.get_json()
        if not data or 'product_id' not in data:
            return jsonify({
                'code': 400,
                'message': '缺少必要参数'
            }), 400
            
        product_id = data['product_id']
        quantity = data.get('quantity', 1)
        specs_info = data.get('specs_info', {})
        price = data.get('price', 0)
        
        # 检查商品是否存在
        product = Product.query.get(product_id)
        if not product:
            return jsonify({
                'code': 404,
                'message': '商品不存在'
            }), 404
            
        # 检查是否已在购物车中
        cart_item = CartItem.query.filter_by(
            user_id=user_id,
            product_id=product_id,
            price=price,
            specs_info=json.dumps(specs_info) if specs_info else None
        ).first()
        
        if cart_item:
            # 更新数量
            cart_item.quantity += quantity
            cart_item.updated_at = datetime.now()
        else:
            # 创建新的购物车项
            cart_item = CartItem(
                user_id=user_id,
                product_id=product_id,
                quantity=quantity,
                price=price,
                specs_info=json.dumps(specs_info) if specs_info else None
            )
            db.session.add(cart_item)
            
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"保存购物车失败: {str(e)}")
            return jsonify({
                'code': 500,
                'message': '添加到购物车失败'
            }), 500
            
        return jsonify({
            'code': 200,
            'message': '添加成功',
            'data': cart_item.to_dict()
        })
        
    except Exception as e:
        print(f"添加购物车失败: {str(e)}")
        print(f"错误追踪:\n{traceback.format_exc()}")
        return jsonify({
            'code': 500,
            'message': '系统错误'
        }), 500

# 获取购物车列表
@app.route('/cart', methods=['GET'])
@login_required
def get_cart_items(user_id):
    try:
        cart_items = CartItem.query.filter_by(user_id=user_id).all()
        return jsonify({
            'code': 200,
            'message': '获取成功',
            'data': [item.to_dict() for item in cart_items]
        })
        
    except Exception as e:
        print(f"获取购物车失败: {str(e)}")
        print(f"错误追踪:\n{traceback.format_exc()}")
        return jsonify({
            'code': 500,
            'message': '系统错误'
        }), 500

# 更新购物车商品数量
@app.route('/cart/<int:item_id>', methods=['PUT'])
@login_required
def update_cart_item(user_id, item_id):
    try:
        data = request.get_json()
        if not data or 'quantity' not in data:
            return jsonify({
                'code': 400,
                'message': '缺少必要参数'
            }), 400
            
        quantity = data['quantity']
        selected = data.get('selected', None)
        
        # 检查购物车项是否存在
        cart_item = CartItem.query.filter_by(id=item_id, user_id=user_id).first()
        if not cart_item:
            return jsonify({
                'code': 404,
                'message': '购物车项不存在'
            }), 404
            
        # 更新数量
        cart_item.quantity = quantity
        if selected is not None:
            cart_item.selected = selected
            
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"更新购物车失败: {str(e)}")
            return jsonify({
                'code': 500,
                'message': '更新失败'
            }), 500
            
        return jsonify({
            'code': 200,
            'message': '更新成功',
            'data': cart_item.to_dict()
        })
        
    except Exception as e:
        print(f"更新购物车失败: {str(e)}")
        print(f"错误追踪:\n{traceback.format_exc()}")
        return jsonify({
            'code': 500,
            'message': '系统错误'
        }), 500

# 删除购物车商品
@app.route('/cart/<int:item_id>', methods=['DELETE'])
@login_required
def delete_cart_item(user_id, item_id):
    try:
        # 检查购物车项是否存在
        cart_item = CartItem.query.filter_by(id=item_id, user_id=user_id).first()
        if not cart_item:
            return jsonify({
                'code': 404,
                'message': '购物车项不存在'
            }), 404
            
        try:
            db.session.delete(cart_item)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"删除购物车项失败: {str(e)}")
            return jsonify({
                'code': 500,
                'message': '删除失败'
            }), 500
            
        return jsonify({
            'code': 200,
            'message': '删除成功'
        })
        
    except Exception as e:
        print(f"删除购物车项失败: {str(e)}")
        print(f"错误追踪:\n{traceback.format_exc()}")
        return jsonify({
            'code': 500,
            'message': '系统错误'
        }), 500

# 清空购物车
@app.route('/cart/clear', methods=['POST'])
@login_required
def clear_cart(user_id):
    try:
        try:
            CartItem.query.filter_by(user_id=user_id).delete()
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"清空购物车失败: {str(e)}")
            return jsonify({
                'code': 500,
                'message': '清空失败'
            }), 500
            
        return jsonify({
            'code': 200,
            'message': '清空成功'
        })
        
    except Exception as e:
        print(f"清空购物车失败: {str(e)}")
        print(f"错误追踪:\n{traceback.format_exc()}")
        return jsonify({
            'code': 500,
            'message': '系统错误'
        }), 500

# 选择/取消选择购物车商品
@app.route('/cart/select', methods=['POST'])
@login_required
def select_cart_items(user_id):
    try:
        data = request.get_json()
        if not data or 'item_ids' not in data or 'selected' not in data:
            return jsonify({
                'code': 400,
                'message': '缺少必要参数'
            }), 400
            
        item_ids = data['item_ids']
        selected = data['selected']
        
        try:
            CartItem.query.filter(
                CartItem.user_id == user_id,
                CartItem.id.in_(item_ids)
            ).update({
                CartItem.selected: selected
            }, synchronize_session=False)
            
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"更新购物车选择状态失败: {str(e)}")
            return jsonify({
                'code': 500,
                'message': '更新失败'
            }), 500
            
        return jsonify({
            'code': 200,
            'message': '更新成功'
        })
        
    except Exception as e:
        print(f"更新购物车选择状态失败: {str(e)}")
        print(f"错误追踪:\n{traceback.format_exc()}")
        return jsonify({
            'code': 500,
            'message': '系统错误'
        }), 500

@app.route('/', methods=['GET', 'POST'])
def upload_handler():
    # 添加CORS头
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Headers'] = 'Origin, X-Requested-With, Content-Type, Accept'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        return response

    # 获取上传路径
    path = request.args.get('path', 'web/test')
    
    try:
        # 获取access token
        access_token = get_access_token()
        
        # 获取上传链接
        upload_url = f"https://api.weixin.qq.com/tcb/uploadfile?access_token={access_token}"
        data = {
            "env": "prod-9ed41111c76d4842",
            "path": path
        }
        response = requests.post(upload_url, json=data)
        result = response.json()
        
        if result.get('errcode') != 0:
            return jsonify({"error": "获取上传链接失败"}), 500
            
        # 添加CORS头
        response = jsonify(result)
        response.headers['Access-Control-Allow-Origin'] = '*'
        return response
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/products/filter-options', methods=['GET'])
@check_staff_permission('product.view')
def get_product_filter_options(user_id):
    try:
        # 查询所有商品
        products = Product.query.all()
        
        # 初始化筛选选项集合
        sizes = set()
        weights = set()
        yarns = set()
        compositions = set()
        types = set()
        
        
        for product in products:
            size = product.size if product.size else '-'
            weight = product.weight if product.weight else '-'
            yarn = product.yarn if product.yarn else '-'
            composition = product.composition if product.composition else '-'
            type = product.type if product.type else '-'
            sizes.add(size)
            weights.add(weight)
            yarns.add(yarn)
            compositions.add(composition)
            types.add(type)
        
        # 将集合转换为Element Plus过滤器格式
        return jsonify({
            'code': 0,
            'message': 'success',
            'data': {
                'sizes': [{'text': size, 'value': size} for size in sorted(sizes)],
                'weights': [{'text': f'{weight}', 'value': weight} for weight in sorted(weights)],
                'yarns': [{'text': yarn, 'value': yarn} for yarn in sorted(yarns)],
                'compositions': [{'text': composition, 'value': composition} for composition in sorted(compositions)],
                'types': [{'text': type, 'value': type} for type in sorted(types)]
                }
            })
        
    except Exception as e:
        print(f'获取筛选选项失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({
            'code': 500,
            'message': '获取筛选选项失败',
            'error': str(e)
        }), 500

@app.route('/recommended/products', methods=['GET'])
def recommended_products():
    return get_recommended_products()

@app.route('/recommended/products', methods=['POST'])
def set_recommended_products():
    return update_recommended_products()

@app.route('/products/batch/status', methods=['POST'])
@check_staff_permission('product.update')
def batch_update_status(user_id):
    """
    批量更新商品状态
    """
    try:
        # 获取请求数据
        data = request.get_json()
        if not data or 'product_ids' not in data or 'status' not in data:
            return jsonify({'code': -1, 'message': '缺少必要参数'}), 400

        product_ids = data['product_ids']
        new_status = data['status']

        # 验证参数
        if not isinstance(product_ids, list) or not product_ids:
            return jsonify({'code': -1, 'message': '商品ID列表不能为空'}), 400
        
        if new_status not in [0, 1]:
            return jsonify({'code': -1, 'message': '状态值必须是0或1'}), 400

        updated_count = 0
        for product_id in product_ids:
            product = Product.query.get(product_id)
            if product:
                product.status = new_status
                product.updated_at = datetime.now()
                updated_count += 1
        
        db.session.commit()
        print(f'成功更新{updated_count}个商品的状态')
        
        if updated_count > 0:
            return jsonify({
                'code': 200,
                'message': f'成功更新{updated_count}个商品的状态',
                'data': {
                    'updated_count': updated_count
                }
            })
        else:
            return jsonify({'code': -1, 'message': '更新失败或没有符合条件的商品'}), 400

    except Exception as e:
        db.session.rollback()
        print(f'批量更新商品状态失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'code': -1, 'message': str(e)}), 500

@app.route('/products/batch/public', methods=['POST'])
@check_staff_permission('product.update')
def batch_update_public(user_id):
    """
    批量更新商品公开状态
    """
    try:
        # 获取请求数据
        data = request.get_json()
        if not data or 'product_ids' not in data or 'is_public' not in data:
            return jsonify({'code': -1, 'message': '缺少必要参数'}), 400

        product_ids = data['product_ids']
        new_public_status = data['is_public']

        # 验证参数
        if not isinstance(product_ids, list) or not product_ids:
            return jsonify({'code': -1, 'message': '商品ID列表不能为空'}), 400
        
        if new_public_status not in [0, 1]:
            return jsonify({'code': -1, 'message': '公开状态值必须是0或1'}), 400

        updated_count = 0
        for product_id in product_ids:
            product = Product.query.get(product_id)
            if product:
                product.is_public = new_public_status
                product.updated_at = datetime.now()
                updated_count += 1
        
        db.session.commit()
        print(f'成功更新{updated_count}个商品的公开状态')
        
        if updated_count > 0:
            return jsonify({
                'code': 200,
                'message': f'成功更新{updated_count}个商品的公开状态',
                'data': {
                    'updated_count': updated_count
                }
            })
        else:
            return jsonify({'code': -1, 'message': '更新失败或没有符合条件的商品'}), 400

    except Exception as e:
        db.session.rollback()
        print(f'批量更新商品公开状态失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'code': -1, 'message': str(e)}), 500

@app.route('/products/low-stock', methods=['GET'])
@check_staff_permission('product.view')
def get_low_stock_products(user_id):
    try:
        # 设置库存预警阈值
        threshold = 100
        
        # 查询所有商品
        products = Product.query.all()

        # 过滤和处理结果
        result = []
        for product in products:
            # 获取规格信息
            specs = json.loads(product.specs) if product.specs else []
            low_stock_colors = []
            all_colors_stock = []
            total_stock = 0
            
            # 检查每个颜色的库存
            for spec in specs:
                try:
                    stock = int(spec.get('stock', 0))
                    total_stock += stock
                    color_info = {
                        'color': spec.get('color', '未知颜色'),
                        'stock': stock
                    }
                    all_colors_stock.append(color_info)
                    if stock < threshold:
                        low_stock_colors.append(color_info)
                except (ValueError, TypeError):
                    continue

            # 如果有任何颜色的库存低于阈值，添加到结果中
            if low_stock_colors:
                product_data = {
                    'id': product.id,
                    'name': product.name,
                    'images': json.loads(product.images) if product.images else [],
                    'total_stock': total_stock,  # 添加总库存
                    'all_colors_stock': all_colors_stock,  # 所有颜色的库存
                    'low_stock_colors': low_stock_colors,  # 低库存的颜色
                    'threshold': threshold
                }
                result.append(product_data)

        return jsonify({
            'code': 0,
            'data': result,
            'message': 'success'
        })

    except Exception as e:
        print(f"获取库存预警商品失败: {str(e)}")
        return jsonify({
            'code': -1,
            'message': '获取库存预警商品失败'
        }), 500

# 获取暗推产品列表
@app.route('/api/hidden_products', methods=['GET'])
def get_hidden_products_route():
    """
    获取暗推产品列表的路由
    """
    from .recommended import get_hidden_products
    return get_hidden_products()

# 更新暗推产品列表
@app.route('/api/hidden_products', methods=['POST'])
@admin_required
def update_hidden_products_route(user_id):
    """
    更新暗推产品列表的路由
    """
    from .recommended import update_hidden_products
    return update_hidden_products()

# 获取商品已发货数量
@app.route('/shipped_quantities', methods=['GET'])
@login_required
def get_shipped_quantities(user_id):
    try:
        # 获取请求参数
        product_id = request.args.get('product_id')
        color = request.args.get('color', '')
        order_number = request.args.get('order_number', '')
        status = request.args.getlist('status')  # 使用getlist获取多个相同名称的参数
        
        print(f'获取到请求参数: {product_id}, {color}, {order_number}, 状态: {status}')
        
        if not product_id:
            return jsonify({'error': '缺少商品ID参数'}), 400
            
        # 计算已发货数量
        query = db.session.query(func.sum(DeliveryItem.quantity).label('total_shipped'))\
            .filter(DeliveryItem.product_id == product_id)
        
        if order_number:
            query = query.filter(DeliveryItem.order_number == order_number)

        # 如果有颜色参数，添加颜色过滤条件
        if color:
            query = query.filter(DeliveryItem.color == color)
            
        # 只统计指定状态的订单
        query = query.join(DeliveryOrder, DeliveryItem.delivery_id == DeliveryOrder.id)

            
        result = query.scalar()
        shipped_quantity = int(result) if result is not None else 0
        
        # 返回结果
        return jsonify({
            'product_id': product_id,
            'color': color,
            'shipped_quantity': shipped_quantity
        }), 200
        
    except Exception as e:
        print(f'获取已发货数量失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '获取已发货数量失败'}), 500
    
@app.route('/users/list', methods=['GET'])
@login_required
def get_users_list(user_id):
    """获取用户列表 - 简化版"""
    try:
        # 获取查询参数
        page = int(request.args.get('page', 1))
        page_size = min(int(request.args.get('page_size', 20)), 100)
        keyword = request.args.get('keyword', '').strip()
        role = request.args.get('role')  # 按角色筛选
        customer_type = request.args.get('customer_type')  # 按客户类型筛选
        
        # 构建基础查询
        query = User.query
        
        # 添加筛选条件
        if keyword:
            search = f'%{keyword}%'
            query = query.filter(db.or_(
                User.username.like(search),
                User.nickname.like(search),
                User.phone.like(search)
            ))
            
        if role:
            query = query.filter(User.role == role)
            
        if customer_type:
            query = query.filter(User.customer_type == customer_type)
            
        # 获取分页数据
        paginated_users = query.order_by(User.created_at.desc())\
            .paginate(page=page, per_page=page_size, error_out=False)
            
        # 格式化返回数据 - 简化版
        users = [{
            'id': user.id,
            'username': user.username,
            'nickname': user.nickname,
            'phone': user.phone,
            'role': user.role,
            'customer_type': user.customer_type,
            'status': user.status,
            'created_at': user.created_at.isoformat() if user.created_at else None
        } for user in paginated_users.items]

        return jsonify({
            'code': 0,
            'data': {
                'users': users,
                'total': paginated_users.total,
                'page': page,
                'page_size': page_size,
                'total_pages': paginated_users.pages
            }
        }), 200

    except Exception as e:
        print(f'获取用户列表失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({
            'code': -1,
            'message': f'获取用户列表失败: {str(e)}'
        }), 500