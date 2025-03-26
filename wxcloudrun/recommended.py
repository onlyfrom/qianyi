from flask import jsonify, request
from wxcloudrun import db
from wxcloudrun.model import SystemSettings, Product
from datetime import datetime

def init_recommended_setting():
    """
    初始化推荐商品设置
    """
    setting = SystemSettings.query.filter_by(key='recommended_products').first()
    if not setting:
        setting = SystemSettings(
            key='recommended_products',
            value='[]',  # 空列表的JSON字符串
            created_time=datetime.now(),
            updated_time=datetime.now()
        )
        db.session.add(setting)
        db.session.commit()
    return setting

def get_recommended_products():
    """
    获取推荐商品列表
    """
    try:
        setting = init_recommended_setting()
        import json
        product_ids = json.loads(setting.value)
        
        # 获取商品详情
        products = Product.query.filter(Product.id.in_(product_ids)).all()
        
        # 按照推荐列表的顺序排序
        sorted_products = sorted(products, key=lambda x: product_ids.index(x.id))
        
        return jsonify({
            'code': 0,
            'message': 'success',
            'data': [product.to_dict() for product in sorted_products]
        })
    except Exception as e:
        return jsonify({
            'code': 500,
            'message': str(e)
        }), 500

def update_recommended_products():
    """
    更新推荐商品列表
    """
    try:
        data = request.get_json()
        product_ids = data.get('product_ids', [])
        
        # 验证商品是否存在
        products = Product.query.filter(Product.id.in_(product_ids)).all()
        if len(products) != len(product_ids):
            return jsonify({
                'code': 400,
                'message': '部分商品不存在'
            }), 400
        
        # 更新设置
        setting = init_recommended_setting()
        import json
        setting.value = json.dumps(product_ids)
        setting.updated_time = datetime.now()
        
        db.session.commit()
        
        return jsonify({
            'code': 0,
            'message': 'success',
            'data': {
                'product_ids': product_ids
            }
        })
    except Exception as e:
        return jsonify({
            'code': 500,
            'message': str(e)
        }), 500 