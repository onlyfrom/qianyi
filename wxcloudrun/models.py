from datetime import datetime
from wxcloudrun import db

# 用户角色枚举
class UserRole:
    ADMIN = 'admin'  # 管理员
    STAFF = 'staff'  # 员工
    CUSTOMER = 'customer'  # 客户

# 客户类型枚举
class CustomerType:
    TYPE_A = 'A'  # A类客户
    TYPE_B = 'B'  # B类客户
    TYPE_C = 'C'  # C类客户

# 权限枚举
class Permission:
    PUSH_ORDER = 'push_order'  # 发送推送单
    DELIVERY_ORDER = 'delivery_order'  # 发送发货单
    PRODUCT_MANAGE = 'product_manage'  # 商品管理
    ALL = 'all'  # 所有权限

# 用户权限关联表
user_permissions = db.Table('user_permissions',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('permission', db.String(50), primary_key=True)
)

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False, default=UserRole.CUSTOMER)  # 用户角色
    customer_type = db.Column(db.String(1), nullable=True)  # 客户类型（仅对客户角色有效）
    permissions = db.relationship('Permission', secondary=user_permissions, lazy='dynamic')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def has_permission(self, permission):
        """检查用户是否拥有指定权限"""
        if self.role == UserRole.ADMIN:
            return True
        return permission in self.permissions

    def get_price_rate(self):
        """获取用户对应的价格系数"""
        if self.role != UserRole.CUSTOMER:
            return 1.0
            
        price_rates = {
            CustomerType.TYPE_A: 0.8,  # A类客户享受8折
            CustomerType.TYPE_B: 0.9,  # B类客户享受9折
            CustomerType.TYPE_C: 0.95  # C类客户享受95折
        }
        return price_rates.get(self.customer_type, 1.0)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'role': self.role,
            'customer_type': self.customer_type,
            'permissions': [p.name for p in self.permissions],
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'updated_at': self.updated_at.strftime('%Y-%m-%d %H:%M:%S')
        } 