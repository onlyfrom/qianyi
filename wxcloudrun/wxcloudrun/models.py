class Product(db.Model):
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    price = db.Column(db.DECIMAL(10, 2), nullable=False)
    price_b = db.Column(db.DECIMAL(10, 2), nullable=True)
    price_c = db.Column(db.DECIMAL(10, 2), nullable=True)
    price_d = db.Column(db.DECIMAL(10, 2), nullable=True)
    cost_price = db.Column(db.DECIMAL(10, 2), nullable=True)
    type = db.Column(db.Integer, nullable=True)
    stock = db.Column(db.Integer, nullable=False, default=0)
    stock_warning = db.Column(db.Integer, nullable=False, default=10)
    images = db.Column(db.Text, nullable=True)
    specs = db.Column(db.Text, nullable=True)
    specs_info = db.Column(db.Text, nullable=True)
    video_url = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.now, onupdate=datetime.now)
    status = db.Column(db.Integer, nullable=False, default=1)  # 1: 已上架, 0: 已下架
    is_public = db.Column(db.Integer, nullable=False, default=1)  # 1: 公开, 0: 私有
    
    # 新增独立的规格字段
    size = db.Column(db.String(50), nullable=True)
    weight = db.Column(db.DECIMAL(10, 2), nullable=True)
    yarn = db.Column(db.String(50), nullable=True)
    composition = db.Column(db.String(100), nullable=True) 