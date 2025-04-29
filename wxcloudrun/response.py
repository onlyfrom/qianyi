import json
import base64
import string
import random
from Crypto.Cipher import AES
from datetime import datetime, timedelta
from flask import Response, request, jsonify
import jwt
from wxcloudrun import db
from wxcloudrun.model import *
import config
import requests
import traceback
import os
import pandas as pd
import openpyxl
import base64


def make_succ_empty_response():
    data = json.dumps({'code': 0, 'data': {}})
    return Response(data, mimetype='application/json')


def make_succ_response(data):
    data = json.dumps({'code': 0, 'data': data})
    return Response(data, mimetype='application/json')


def make_err_response(err_msg):
    data = json.dumps({'code': -1, 'errorMsg': err_msg})
    return Response(data, mimetype='application/json')

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

# 添加文件类型检查函数
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in config.ALLOWED_EXTENSIONS

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




def validate_product_data(data):
    required_fields = ['id', 'name', 'price']
    for field in required_fields:
        if field not in data:
            return False, f'缺少必要字段: {field}'
    return True, None

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
    
# 添加获取微信用户信息的辅助函数
def get_wx_user_info(code):
    """获取微信用户信息"""
    try:
        # 在云托管环境下，可以直接从header获取
        openid = request.headers.get('x-wx-openid')
        if openid:
            return {
                'openid': openid,
                'session_key': None  # 云托管环境下不需要session_key
            }
            
        # 如果不是云托管环境，使用传统方式获取
        print('\n开始请求微信API:')
        wx_api_url = 'https://api.weixin.qq.com/sns/jscode2session'
        params = {
            'appid': "wxa17a5479891750b3",
            'secret': "33359853cfee1dc1e2b6e535249e351d",
            'js_code': code,
            'grant_type': 'authorization_code'
        }
        
        response = requests.get(wx_api_url, params=params)
        wx_data = response.json()
        
        if 'errcode' in wx_data:
            print('错误: 微信API返回错误')
            print(f'错误码: {wx_data.get("errcode")}')
            print(f'错误信息: {wx_data.get("errmsg")}')
            return None

        return wx_data
        
    except Exception as e:
        print(f'获取微信用户信息失败: {str(e)}')
        return None

# 添加文件类型检查函数
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in config.ALLOWED_EXTENSIONS

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

def get_access_token():
    """获取小程序 access_token"""  
    try:        
        # 先尝试 HTTP
        url = f'http://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=wxa17a5479891750b3&secret=33359853cfee1dc1e2b6e535249e351d'
        print('\n尝试 HTTP 请求:')
        print(f'请求URL: {url}')
        print('请求头:', requests.get(url).request.headers)
        
        response = requests.get(url)    
        print(f'响应状态码: {response.status_code}')
        print(f'响应头: {dict(response.headers)}')
        print(f'响应内容: {response.text}')
        
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
            elif 'errcode' in data:
                print(f'\n获取access_token失败，错误码: {data.get("errcode")}')
                print(f'错误信息: {data.get("errmsg")}')
                if data.get('errcode') == 400:
                    print('可能的原因：')
                    print('1. appid 或 secret 不正确')
                    print('2. 请求参数格式错误')
                    print('3. 超出调用频率限制')
        
        # 如果 HTTP 失败，尝试 HTTPS
        print('\nHTTP 请求失败，尝试 HTTPS...')
        url = f'https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=wxa17a5479891750b3&secret=33359853cfee1dc1e2b6e535249e351d'
        print(f'请求URL: {url}')
        print('请求头:', requests.get(url).request.headers)
        
        response = requests.get(url)    
        print(f'响应状态码: {response.status_code}')
        print(f'响应头: {dict(response.headers)}')
        print(f'响应内容: {response.text}')
        
        if response.status_code == 200:
            data = response.json()
            print('\n接口响应数据:')
            safe_data = data.copy()
            if 'access_token' in safe_data:
                safe_data['access_token'] = safe_data['access_token'][:10] + '...'
            print(json.dumps(safe_data, ensure_ascii=False, indent=2))
            
            if 'access_token' in data:
                print('\n成功获取access_token')
                return data['access_token']
            elif 'errcode' in data:
                print(f'\n获取access_token失败，错误码: {data.get("errcode")}')
                print(f'错误信息: {data.get("errmsg")}')
                if data.get('errcode') == 400:
                    print('可能的原因：')
                    print('1. appid 或 secret 不正确')
                    print('2. 请求参数格式错误')
                    print('3. 超出调用频率限制')
                
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

def generate_invite_code_api(user_id):
    """生成邀请码"""
    try:
        print('='*50)
        print('开始处理生成邀请码请求')
        print('='*50)
        
        # 获取当前用户
        user = User.query.get(user_id)
        if not user:
            print(f'错误: 用户不存在 - ID: {user_id}')
            return jsonify({
                'code': 404,
                'message': '用户不存在'
            }), 404
            
        # 检查用户是否已经有邀请码
        if user.invite_code:
            print(f'用户已有邀请码: {user.invite_code}')
            return jsonify({
                'code': 200,
                'data': {
                    'invite_code': user.invite_code,
                    'user_id': user.id,
                    'nickname': user.nickname
                }
            })
            
        # 生成唯一的邀请码
        max_attempts = 10  # 最大尝试次数
        attempt = 0
        while attempt < max_attempts:
            invite_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
            # 检查邀请码是否已存在
            existing_user = User.query.filter_by(invite_code=invite_code).first()
            if not existing_user:
                break
            attempt += 1
            
        if attempt >= max_attempts:
            print('错误: 无法生成唯一的邀请码')
            return jsonify({
                'code': 500,
                'message': '无法生成邀请码，请稍后重试'
            }), 500
            
        # 更新用户的邀请码
        user.invite_code = invite_code
        db.session.commit()
        
        print(f'邀请码生成成功: {invite_code}')
        
        # 返回邀请码和用户信息
        return jsonify({
            'code': 200,
            'data': {
                'invite_code': invite_code,
                'user_id': user.id,
                'nickname': user.nickname
            }
        })
        
    except Exception as e:
        print('\n处理生成邀请码请求时发生错误:')
        print(f'- 错误类型: {type(e).__name__}')
        print(f'- 错误信息: {str(e)}')
        print(f'- 错误追踪:\n{traceback.format_exc()}')
        return jsonify({
            'code': 500,
            'message': '生成邀请码失败'
        }), 500

def register_subaccount_api(data):
    """通过邀请码注册子账号（绑定到父账号）"""
    try:
        print('='*50)
        print('开始处理微信附属账号绑定请求')
        print('='*50)
        
        print('收到的请求数据:', json.dumps(data, ensure_ascii=False, indent=2))
        
        # 验证必要参数
        required_fields = ['openid', 'invite_code', 'nickname']
        for field in required_fields:
            if not data.get(field):
                print(f'错误: 缺少必要参数 {field}')
                return jsonify({'error': f'缺少必要参数: {field}'}), 400
                
        openid = data['openid']
        invite_code = data['invite_code']
        nickname = data['nickname']
        
        # 通过nickname查找父账号
        parent_user = User.query.filter_by(nickname=nickname).first()
        if not parent_user:
            print(f'错误: 未找到用户 - nickname: {nickname}')
            return jsonify({'error': '未找到用户'}), 404
            
        # 验证邀请码是否有效
        if parent_user.invite_code != invite_code:
            print(f'错误: 邀请码无效 - 提供的邀请码: {invite_code}')
            return jsonify({'error': '邀请码无效'}), 400
            
        # 检查openid是否已被绑定
        existing_binding = UserWechatBinding.query.filter_by(openid=openid).first()
        if existing_binding:
            print(f'错误: 该微信账号已被绑定 - 用户ID: {existing_binding.user_id}')
            return jsonify({'error': '该微信账号已被绑定'}), 400
            
        # 创建微信绑定关系
        binding = UserWechatBinding(
            user_id=parent_user.id,
            openid=openid,
            contact_name=parent_user.nickname + '附属',
            created_at=datetime.now(),
            last_login=datetime.now()
        )
        
        # 清除邀请码
        parent_user.invite_code = None
        
        db.session.add(binding)
        db.session.commit()
        
        print(f'微信附属账号绑定成功: 父账号ID={parent_user.id}')
        
        # 生成token
        token = jwt.encode(
            {
                'user_id': parent_user.id,
                'exp': datetime.utcnow() + timedelta(days=30)
            },
            config.SECRET_KEY,
            algorithm='HS256'
        )
        
        # 获取所有绑定的微信账号信息
        bindings_info = [{
            'openid': b.openid,
            'contact_name': b.contact_name,
            'last_login': b.last_login.strftime('%Y-%m-%d %H:%M:%S') if b.last_login else None
        } for b in parent_user.wechat_bindings]
        
        return jsonify({
            'code': 200,
            'message': '微信附属账号绑定成功',
            'data': {
                'userInfo': {
                    'id': parent_user.id,
                    'username': parent_user.username,
                    'nickname': parent_user.nickname,
                    'avatar': parent_user.avatar,
                    'user_type': parent_user.user_type,
                    'role': parent_user.role,
                    'wechat_bindings': bindings_info
                },
                'token': token
            }
        })
        
    except Exception as e:
        print('\n处理微信附属账号绑定请求时发生错误:')
        print(f'- 错误类型: {type(e).__name__}')
        print(f'- 错误信息: {str(e)}')
        print(f'- 错误追踪:\n{traceback.format_exc()}')
        db.session.rollback()
        return jsonify({'error': '绑定失败'}), 500

