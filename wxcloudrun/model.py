from datetime import datetime

from wxcloudrun import db


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

class Product(db.Model):
    __tablename__ = 'products'
    
    id = db.Column(db.String(80), primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float, nullable=False)
    price_b = db.Column(db.Float)
    price_c = db.Column(db.Float)
    price_d = db.Column(db.Float)
    cost_price = db.Column(db.Float)
    specs = db.Column(db.Text)  # JSON字符串
    images = db.Column(db.Text)  # JSON字符串
    type = db.Column(db.Integer)
    specs_info = db.Column(db.Text)  # JSON字符串    
    is_public = db.Column(db.Integer, default=1)  # 0:私密 1:公开
    status = db.Column(db.Integer, default=1)  # 0:下架 1:上架
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

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

class ColorStock(db.Model):
    __tablename__ = 'color_stocks'
    
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.String(80), db.ForeignKey('products.id'), nullable=False)
    color = db.Column(db.String(50), nullable=False)
    color_code = db.Column(db.String(20))
    stock = db.Column(db.Integer, default=0)
    __table_args__ = (db.UniqueConstraint('product_id', 'color'),)

class ProductView(db.Model):
    __tablename__ = 'product_views'
    
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.String(80), db.ForeignKey('products.id'), nullable=False)
    view_time = db.Column(db.DateTime, nullable=False, default=datetime.now)
    ip_address = db.Column(db.String(50))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

class PurchaseOrder(db.Model):
    __tablename__ = 'purchase_orders'
    
    id = db.Column(db.Integer, primary_key=True)
    order_number = db.Column(db.String(50), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    total_amount = db.Column(db.Float, default=0)
    status = db.Column(db.Integer, default=0)  # 0:待处理 1:已处理 2:已取消
    remark = db.Column(db.Text)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now)

class PurchaseOrderItem(db.Model):
    __tablename__ = 'purchase_order_items'
    
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('purchase_orders.id'), nullable=False)
    product_id = db.Column(db.String(80), db.ForeignKey('products.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    color = db.Column(db.String(50))

class DeliveryOrder(db.Model):
    __tablename__ = 'delivery_orders'
    
    id = db.Column(db.Integer, primary_key=True)
    order_number = db.Column(db.String(50), unique=True, nullable=False)
    customer_name = db.Column(db.String(80), nullable=False)
    customer_phone = db.Column(db.String(20))
    delivery_address = db.Column(db.String(255), nullable=False)
    delivery_date = db.Column(db.String(20))
    delivery_time_slot = db.Column(db.String(50))
    status = db.Column(db.Integer, default=0)  # 0:待配送 1:配送中 2:已完成 3:已取消
    remark = db.Column(db.Text)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.now, onupdate=datetime.now)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    delivery_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    delivery_image = db.Column(db.Text)  # JSON字符串

class DeliveryItem(db.Model):
    __tablename__ = 'delivery_items'
    
    id = db.Column(db.Integer, primary_key=True)
    delivery_id = db.Column(db.Integer, db.ForeignKey('delivery_orders.id'), nullable=False)
    product_id = db.Column(db.String(80), db.ForeignKey('products.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    color = db.Column(db.String(50))

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

class PushOrderProduct(db.Model):
    __tablename__ = 'push_order_products'
    
    id = db.Column(db.Integer, primary_key=True)
    push_order_id = db.Column(db.Integer, db.ForeignKey('push_orders.id'), nullable=False)
    product_id = db.Column(db.String(80), db.ForeignKey('products.id'), nullable=False)
    price = db.Column(db.Float, nullable=False)
    specs = db.Column(db.Text)  # JSON字符串
    specs_info = db.Column(db.Text, default='{}')  # JSON字符串
    created_at = db.Column(db.DateTime, default=datetime.now)

class SystemSettings(db.Model):
    __tablename__ = 'system_settings'
    
    id = db.Column(db.Integer, primary_key=True)
    setting_key = db.Column(db.String(50), unique=True, nullable=False)
    setting_value = db.Column(db.Text, nullable=False)
    setting_type = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now) 