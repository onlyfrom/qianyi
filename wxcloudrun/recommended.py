from flask import jsonify, request
from wxcloudrun import db
from wxcloudrun.model import SystemSettings, Product
from datetime import datetime
import json

def init_recommended_setting():
    """
    初始化推荐商品设置
    """
    setting = SystemSettings.query.filter_by(setting_key='recommended_products').first()
    if not setting:
        setting = SystemSettings(
            setting_key='recommended_products',
            setting_value='[]',  # 空列表的JSON字符串
            setting_type='json',
            created_at=datetime.now(),
            updated_at=datetime.now()
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
        
        product_ids = json.loads(setting.setting_value)
        
        # 获取商品详情
        products = Product.query.filter(Product.id.in_(product_ids)).all()
        
        # 按照推荐列表的顺序排序
        sorted_products = sorted(products, key=lambda x: product_ids.index(x.id))
        
        # 序列化商品数据
        products_data = []
        for product in sorted_products:
            # 检查是否存在to_dict方法，若不存在则手动构建字典
            if hasattr(product, 'to_dict') and callable(getattr(product, 'to_dict')):
                products_data.append(product.to_dict())
            else:
                # 手动构建产品字典
                product_dict = {
                    'id': product.id,
                    'name': product.name,
                    'type': product.type,
                    'price': product.price if hasattr(product, 'price') else None,
                    'images': product.images if hasattr(product, 'images') else [],
                    'created_at': product.created_at.strftime('%Y-%m-%d %H:%M:%S') if hasattr(product, 'created_at') else None
                }
                products_data.append(product_dict)
        
        return jsonify({
            'code': 0,
            'message': 'success',
            'data': products_data
        })
    except Exception as e:
        import traceback
        print(f'获取推荐商品列表失败: {str(e)}')
        print(f'错误详情: {traceback.format_exc()}')
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
        setting  = init_recommended_setting()
        setting.setting_value = json.dumps(product_ids)
        setting.updated_at = datetime.now()
        
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