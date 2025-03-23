from functools import wraps
from flask import request, jsonify, g
from wxcloudrun.model import User
import traceback

def staff_required(f):
    """员工权限验证装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            # 从请求头获取用户ID
            user_id = kwargs.get('user_id')
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
        def decorated_function(*args, **kwargs):
            try:
                user_id = verify_token(token)
                if not user_id:
                    return jsonify({
                        'code': 401,
                        'message': '未登录'
                    }), 401

                user = User.query.get(user_id)
                if not user:
                    return jsonify({
                        'code': 401,
                        'message': '用户不存在'
                    }), 401

                # 管理员拥有所有权限
                if user.user_type == 1:
                    return f(*args, **kwargs)

                # 验证员工权限
                if user.user_type != 5 or user.role != 'STAFF':
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

                g.staff_user = user
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