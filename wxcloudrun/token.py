import jwt
from datetime import datetime, timedelta
from wxcloudrun import config

# 生成 JWT
def generate_token(user_id):
    """生成JWT token"""
    try:
        payload = {
            'user_id': user_id,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(hours=1)
        }
        print(f'生成的payload: {payload}')
        return jwt.encode(payload, config.JWT_SECRET_KEY, algorithm='HS256')
    except Exception as e:
        print(f'生成token失败: {str(e)}')
        return None

# 验证 JWT
def verify_token(token):
    """验证JWT token"""
    try:
        payload = jwt.decode(token, config.JWT_SECRET_KEY, algorithms=['HS256'])
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
        payload = jwt.decode(token, config.JWT_SECRET_KEY, options={"verify_exp": False}, algorithms=['HS256'])
        # 更新过期时间
        payload['iat'] = datetime.utcnow()
        payload['exp'] = datetime.utcnow() + timedelta(hours=1)
        # 重新编码
        return jwt.encode(payload, config.JWT_SECRET_KEY, algorithm='HS256')
    except Exception as e:
        print(f'延长token有效期失败: {str(e)}')
        return None