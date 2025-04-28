from datetime import datetime
import json

from wxcloudrun import db

# 从models.py导入的枚举类
class UserRole:
    ADMIN = 'admin'  # 管理员
    STAFF = 'staff'  # 员工
    CUSTOMER = 'customer'  # 客户
    STAFF_PRODUCT_EDIT = 'staff_product_edit'  # 员工产品编辑

class CustomerType:
    TYPE_A = 'A'  # A类客户
    TYPE_B = 'B'  # B类客户
    TYPE_C = 'C'  # C类客户

# 用户权限关联表
user_permissions = db.Table('user_permissions',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('permission_id', db.Integer, db.ForeignKey('permissions.id'), primary_key=True)
)

# 权限模型
class Permission(db.Model):
    __tablename__ = 'permissions'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.now)
    
    def __init__(self, name, description=None):
        self.name = name
        self.description = description

# 权限常量
class PermissionEnum:
    PUSH_ORDER = 'push_order'  # 发送推送单
    DELIVERY_ORDER = 'delivery_order'  # 发送发货单
    PRODUCT_MANAGE = 'product_manage'  # 商品管理
    ALL = 'all'  # 所有权限

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    avatar = db.Column(db.String(255))
    nickname = db.Column(db.String(80))
    phone = db.Column(db.String(20))
    address = db.Column(db.String(255))
    contact = db.Column(db.String(80))
    user_type = db.Column(db.Integer, default=0)  # 0:普通用户 1:管理员
    openid = db.Column(db.String(80))  # 微信openid
    status = db.Column(db.Integer, default=1)  # 0:禁用 1:启用
    created_at = db.Column(db.DateTime, default=datetime.now)
    login_attempts = db.Column(db.Integer, default=0)
    last_login_attempt = db.Column(db.DateTime)
    last_login = db.Column(db.DateTime)
    
    # 新增字段
    role = db.Column(db.String(20), nullable=False, default=UserRole.CUSTOMER)  # 用户角色
    customer_type = db.Column(db.String(1))  # 客户类型（仅对客户角色有效）
    
    # 修改权限关系定义
    permissions = db.relationship('Permission', 
                                secondary=user_permissions,
                                backref=db.backref('users', lazy='dynamic'),
                                lazy='dynamic')
    
    # 新增方法
    def has_permission(self, permission_name):
        """检查用户是否拥有指定权限"""
        if self.role == UserRole.ADMIN:
            return True
        return self.permissions.filter(
            Permission.name == permission_name
        ).first() is not None

    def add_permission(self, permission_name):
        """添加权限"""
        permission = Permission.query.filter_by(name=permission_name).first()
        if permission and permission not in self.permissions:
            self.permissions.append(permission)

    def remove_permission(self, permission_name):
        """移除权限"""
        permission = Permission.query.filter_by(name=permission_name).first()
        if permission and permission in self.permissions:
            self.permissions.remove(permission)

    def get_price_rate(self):
        """获取用户对应的价格系数"""
        if self.role != UserRole.CUSTOMER:
            return 1.0
            
        # 根据商品的不同价格字段返回对应价格
        price_rates = {
            CustomerType.TYPE_A: lambda p: p.price_b/p.price if p.price_b else 0,  # A类客户使用price_b,若无则8折
            CustomerType.TYPE_B: lambda p: p.price_c/p.price if p.price_c else 0,  # B类客户使用price_c,若无则9折 
            CustomerType.TYPE_C: lambda p: p.price_d/p.price if p.price_d else 0  # C类客户使用price_d,若无则95折
        }
        return price_rates.get(self.customer_type, 1.0)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'role': self.role,
            'customer_type': self.customer_type,
            'permissions': [p.name for p in self.permissions],
            'avatar': self.avatar,
            'nickname': self.nickname,
            'phone': self.phone,
            'address': self.address,
            'contact': self.contact,
            'status': self.status,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }
    

# 商品模型
class Product(db.Model):
    __tablename__ = 'products'
    
    id = db.Column(db.String(80), primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float)
    price_b = db.Column(db.Float)
    price_c = db.Column(db.Float)
    price_d = db.Column(db.Float)
    cost_price = db.Column(db.Float)
    specs = db.Column(db.Text)  # JSON字符串
    images = db.Column(db.Text)  # JSON字符串
    type = db.Column(db.Integer)
    specs_info = db.Column(db.Text)  # JSON字符串    
    is_public = db.Column(db.Integer, default=0)  # 0:私密 1:公开
    status = db.Column(db.Integer, default=1)  # 0:下架 1:上架
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    video_url = db.Column(db.Text)
    size = db.Column(db.Text)
    weight = db.Column(db.Text)
    yarn = db.Column(db.Text)
    composition = db.Column(db.Text)

# 库存记录模型
class StockRecord(db.Model):
    __tablename__ = 'stock_records'
    
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.String(80), db.ForeignKey('products.id'), nullable=False)
    change_amount = db.Column(db.Integer, nullable=False)
    type = db.Column(db.String(20), nullable=False)  # in:入库, out:出库, adjust:调整
    remark = db.Column(db.Text)
    operator = db.Column(db.String(80))
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now)
    color = db.Column(db.String(50))

# 颜色库存模型
class ColorStock(db.Model):
    __tablename__ = 'color_stocks'
    
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.String(80), db.ForeignKey('products.id'), nullable=False)
    color = db.Column(db.String(50), nullable=False)
    color_code = db.Column(db.String(20))
    stock = db.Column(db.Integer, default=0)
    __table_args__ = (db.UniqueConstraint('product_id', 'color'),)

# 商品浏览记录模型
class ProductView(db.Model):
    __tablename__ = 'product_views'
    
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.String(80), db.ForeignKey('products.id'), nullable=False)
    view_time = db.Column(db.DateTime, nullable=False, default=datetime.now)
    ip_address = db.Column(db.String(50))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

# 采购订单模型
class PurchaseOrder(db.Model):
    __tablename__ = 'purchase_orders'
    
    id = db.Column(db.Integer, primary_key=True)
    order_number = db.Column(db.String(50), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False) # 下单人
    total_amount = db.Column(db.Float, default=0)
    paid_amount = db.Column(db.Float, default=0)  # 已付货款（已结清金额）
    status = db.Column(db.Integer, default=0)  # 0:待处理 1:已接受
    remark = db.Column(db.Text)
    handler_id = db.Column(db.Integer, db.ForeignKey('users.id')) # 处理人
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now)
    
    # 添加与 PurchaseOrderItem 的关系
    items = db.relationship('PurchaseOrderItem', backref='purchase_order', lazy='dynamic')

# 采购订单商品模型
class PurchaseOrderItem(db.Model):
    __tablename__ = 'purchase_order_items'
    
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('purchase_orders.id'), nullable=False)
    product_id = db.Column(db.String(80), db.ForeignKey('products.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    logo_price = db.Column(db.Float, default=0.0)  # 加标价格
    accessory_price = db.Column(db.Float, default=0.0)  # 辅料价格
    packaging_price = db.Column(db.Float, default=0.0)  # 包装价格
    color = db.Column(db.String(50))
    
    # 添加与 Product 模型的关联关系
    product = db.relationship('Product', backref=db.backref('purchase_order_items', lazy=True))
    
    def to_dict(self):
        return {
            'id': self.id,
            'order_id': self.order_id,
            'product_id': self.product_id,
            'product_name': self.product.name if self.product else '未知商品',
            'quantity': self.quantity,
            'price': float(self.price),
            'logo_price': float(self.logo_price),
            'accessory_price': float(self.accessory_price),
            'packaging_price': float(self.packaging_price),
            'color': self.color,
            'total': float(self.price * self.quantity)
        }

# 发货订单模型
class DeliveryOrder(db.Model):
    __tablename__ = 'delivery_orders'
    
    id = db.Column(db.Integer, primary_key=True)  # 主键 发货订单ID
    order_number = db.Column(db.String(50), nullable=False)  # 关联采购单号
    customer_id = db.Column(db.Integer, nullable=False)  # 关联客户ID
    customer_name = db.Column(db.String(80), nullable=False)  # 客户姓名
    customer_phone = db.Column(db.String(20))  # 客户电话
    delivery_address = db.Column(db.String(255))  # 配送地址
    delivery_date = db.Column(db.String(20))  # 发货日期
    delivery_time_slot = db.Column(db.String(50))  # 配送时间段
    status = db.Column(db.Integer, default=0)  # 0:已开单，1:已发货，2:已完成，3:已取消，4:异常
    remark = db.Column(db.Text)  # 备注
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now)  # 创建时间
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.now, onupdate=datetime.now)  # 更新时间
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))  # 创建者
    delivery_by = db.Column(db.Integer, db.ForeignKey('users.id'))  # 发货人
    delivery_image = db.Column(db.Text)  # 打包图
    logistics_company = db.Column(db.String(50))  # 物流公司
    tracking_number = db.Column(db.String(50))  # 物流单号
    additional_fee = db.Column(db.Float, default=0.0)  # 附加费用

# 发货订单商品模型
class DeliveryItem(db.Model):
    __tablename__ = 'delivery_items'
    
    id = db.Column(db.Integer, primary_key=True)  # 主键 发货订单商品ID
    delivery_id = db.Column(db.Integer, db.ForeignKey('delivery_orders.id'), nullable=False)  # 关联发货订单ID
    order_number = db.Column(db.String(50), nullable=False)  # 关联采购单号
    product_id = db.Column(db.String(80), db.ForeignKey('products.id'), nullable=False)  # 关联商品ID
    quantity = db.Column(db.Integer, nullable=False)  # 数量
    color = db.Column(db.String(50))  # 颜色
    package_id = db.Column(db.String(10))  # 包装ID

# 推送订单模型
class PushOrder(db.Model):
    __tablename__ = 'push_orders'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    order_number = db.Column(db.String(50), nullable=False)
    target_name = db.Column(db.String(80), default='仟艺测试')
    target_user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    qrcode_path = db.Column(db.String(255))
    status = db.Column(db.Integer, default=0)  # 0:待推送 1:已推送
    created_at = db.Column(db.DateTime, default=datetime.now)
    openid = db.Column(db.String(80))
    share_code = db.Column(db.String(20), unique=True)
    
    # 添加关系
    products = db.relationship('PushOrderProduct', backref='push_order', lazy='dynamic')
    user = db.relationship('User', foreign_keys=[user_id], backref='push_orders')
    target_user = db.relationship('User', foreign_keys=[target_user_id], backref='received_push_orders')

# 推送订单商品模型
class PushOrderProduct(db.Model):
    __tablename__ = 'push_order_products'
    
    id = db.Column(db.Integer, primary_key=True)
    push_order_id = db.Column(db.Integer, db.ForeignKey('push_orders.id'), nullable=False)
    product_id = db.Column(db.String(80), db.ForeignKey('products.id'), nullable=False)
    price = db.Column(db.Float, nullable=False)
    specs = db.Column(db.Text)  # JSON字符串
    specs_info = db.Column(db.Text, default='{}')  # JSON字符串
    created_at = db.Column(db.DateTime, default=datetime.now)

# 系统设置模型
class SystemSettings(db.Model):
    __tablename__ = 'system_settings'
    
    id = db.Column(db.Integer, primary_key=True)
    setting_key = db.Column(db.String(50), unique=True, nullable=False)
    setting_value = db.Column(db.Text, nullable=False)
    setting_type = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

# 购物车项目模型    
class CartItem(db.Model):
    """购物车项目"""
    __tablename__ = 'cart_items'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    product_id = db.Column(db.String(100), db.ForeignKey('products.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1)  # 数量
    price = db.Column(db.Float, nullable=False)  # 价格
    selected = db.Column(db.Boolean, default=True)  # 是否选中
    specs_info = db.Column(db.Text)  # 规格信息，JSON格式
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    
    # 关联关系
    user = db.relationship('User', backref=db.backref('cart_items', lazy=True))
    product = db.relationship('Product', backref=db.backref('cart_items', lazy=True))
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'product_id': self.product_id,
            'quantity': self.quantity,
            'selected': self.selected,
            'price': self.price,
            'specs_info': json.loads(self.specs_info) if self.specs_info else {},
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'updated_at': self.updated_at.strftime('%Y-%m-%d %H:%M:%S'),
            'product_name': self.product.name if self.product else "未知商品",
            'product': {
                'id': self.product.id,
                'name': self.product.name,
                'price': self.product.price,
                'images': json.loads(self.product.images) if self.product and self.product.images else []
            } if self.product else None
        } 

class Payment(db.Model):
    """收款记录表"""
    __tablename__ = 'payments'
    
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    customer_name = db.Column(db.String(80))
    amount = db.Column(db.Numeric(10, 2), nullable=False)
    payment_date = db.Column(db.DateTime, nullable=False)
    remark = db.Column(db.Text)
    delivery_orders = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    
    # 关联字段
    customer = db.relationship('User', foreign_keys=[customer_id], backref='payments_received')
    
    def to_dict(self):
        return {
            'id': self.id,
            'customer_id': self.customer_id,
            'customer_name': self.customer_name,
            'amount': float(self.amount),
            'payment_date': self.payment_date.strftime('%Y-%m-%d %H:%M:%S'),
            'remark': self.remark,
            'delivery_orders': self.delivery_orders,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'updated_at': self.updated_at.strftime('%Y-%m-%d %H:%M:%S'),
            'customer': self.customer.to_dict() if self.customer else None
        } 

class UserProductPrice(db.Model):
    """用户商品价格表"""
    __tablename__ = 'user_product_prices'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    product_id = db.Column(db.String(80), db.ForeignKey('products.id'), nullable=False)
    custom_price = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    
    # 添加唯一约束，确保每个用户对同一商品只能有一个价格
    __table_args__ = (db.UniqueConstraint('user_id', 'product_id'),)
    
    # 关联关系
    user = db.relationship('User', backref=db.backref('product_prices', lazy=True))
    product = db.relationship('Product', backref=db.backref('user_prices', lazy=True))
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'product_id': self.product_id,
            'custom_price': float(self.custom_price),
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'updated_at': self.updated_at.strftime('%Y-%m-%d %H:%M:%S')
        }

class IgnoredStockWarning(db.Model):
    """忽略库存预警记录表"""
    __tablename__ = 'ignored_stock_warnings'
    
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.String(80), db.ForeignKey('products.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    
    # 关联关系
    user = db.relationship('User', backref=db.backref('ignored_warnings', lazy=True))
    product = db.relationship('Product', backref=db.backref('ignored_warnings', lazy=True))
    
    def to_dict(self):
        return {
            'id': self.id,
            'product_id': self.product_id,
            'user_id': self.user_id,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        } 
    
class UserWechatBinding(db.Model):
    __tablename__ = 'user_wechat_bindings'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    openid = db.Column(db.String(100), unique=True, nullable=False)
    contact_name = db.Column(db.String(100))  # 该微信绑定的联系人名称
    created_at = db.Column(db.DateTime, default=datetime.now)
    last_login = db.Column(db.DateTime)
    
    # 建立与User模型的关系
    user = db.relationship('User', backref=db.backref('wechat_bindings', lazy=True)) 