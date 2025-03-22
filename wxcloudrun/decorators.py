from functools import wraps
from flask import jsonify
from .models import UserRole, Permission

def permission_required(permission):
    """权限验证装饰器"""
    def decorator(f):
        @wraps(f)
        def decorated_function(user_id, *args, **kwargs):
            from .models import User
            user = User.query.get(user_id)
            
            if not user:
                return jsonify({
                    'code': 401,
                    'message': '用户不存在'
                }), 401
                
            if not user.has_permission(permission):
                return jsonify({
                    'code': 403,
                    'message': '没有权限执行此操作'
                }), 403
                
            return f(user_id, *args, **kwargs)
        return decorated_function
    return decorator

def admin_required(f):
    """管理员权限验证装饰器"""
    @wraps(f)
    def decorated_function(user_id, *args, **kwargs):
        from .models import User
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({
                'code': 401,
                'message': '用户不存在'
            }), 401
            
        if user.role != UserRole.ADMIN:
            return jsonify({
                'code': 403,
                'message': '需要管理员权限'
            }), 403
            
        return f(user_id, *args, **kwargs)
    return decorated_function

def staff_required(f):
    """员工权限验证装饰器"""
    @wraps(f)
    def decorated_function(user_id, *args, **kwargs):
        from .models import User
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({
                'code': 401,
                'message': '用户不存在'
            }), 401
            
        if user.role not in [UserRole.ADMIN, UserRole.STAFF]:
            return jsonify({
                'code': 403,
                'message': '需要员工权限'
            }), 403
            
        return f(user_id, *args, **kwargs)
    return decorated_function 