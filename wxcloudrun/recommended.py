from flask import jsonify, request
from wxcloudrun import db
from wxcloudrun.model import SystemSettings, Product, User, PushOrder, PushOrderProduct
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
        # 获取当前用户ID
        user_id = request.args.get('user_id')
        if user_id:
        # 获取当前用户信息
            current_user = User.query.get(user_id)
            if not current_user:
                return jsonify({
                    'code': 404,
                    'message': '用户不存在'
                }), 404

        setting = init_recommended_setting()
        product_ids = json.loads(setting.setting_value)
        
        # 获取商品详情
        products = Product.query.filter(Product.id.in_(product_ids)).all()
        
        # 过滤出用户有权限查看的商品
        filtered_products = []
        for product in products:
            # 检查商品是否公开
            if product.is_public == 1:
                filtered_products.append(product)
                continue
                
            # 检查商品是否在用户的推送单中
            has_push_permission = db.session.query(PushOrderProduct).join(
                PushOrder, PushOrder.id == PushOrderProduct.push_order_id
            ).filter(
                PushOrderProduct.product_id == product.id,
                PushOrder.target_user_id == user_id,
            ).first() is not None
            
            if has_push_permission:
                filtered_products.append(product)
        
        # 按照推荐列表的顺序排序
        sorted_products = sorted(filtered_products, key=lambda x: product_ids.index(x.id))
        
        # 序列化商品数据
        products_data = []
        for product in sorted_products:
            # 检查是否存在to_dict方法，若不存在则手动构建字典
            if hasattr(product, 'to_dict') and callable(getattr(product, 'to_dict')):
                products_data.append(product.to_dict())
            else:
                # 返回商品的所有属性构建产品字典
                product_dict = {
                    'id': product.id,
                    'name': product.name,
                    'type': product.type,
                    'price': product.price if hasattr(product, 'price') else None,
                    'images': json.loads(product.images) if hasattr(product, 'images') and product.images else [],
                    'created_at': product.created_at.strftime('%Y-%m-%d %H:%M:%S') if hasattr(product, 'created_at') else None,
                    'specs':  json.loads(product.specs) if hasattr(product, 'specs') and product.specs else None,
                    'size':product.size if hasattr(product, 'size') and product.size else None,
                    'weight':product.weight if hasattr(product, 'weight') and product.weight else None,
                    'yarn':product.yarn if hasattr(product, 'yarn') and product.yarn else None,
                    'composition':product.composition if hasattr(product, 'composition') and product.composition else None,
                    'style':product.style if hasattr(product, 'style') and product.style else None,
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

def init_hidden_products_setting():
    """
    初始化暗推产品设置
    """
    setting = SystemSettings.query.filter_by(setting_key='hidden_products').first()
    if not setting:
        setting = SystemSettings(
            setting_key='hidden_products',
            setting_value='[]',  # 空列表的JSON字符串
            setting_type='json',
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        db.session.add(setting)
        db.session.commit()
    return setting

def get_hidden_products():
    """
    获取暗推产品列表
    """
    try:
        # 获取当前用户ID
        user_id = request.args.get('user_id')
        if user_id:
        # 获取当前用户信息
            current_user = User.query.get(user_id)
            if not current_user:
                return jsonify({
                    'code': 404,
                    'message': '用户不存在'
                }), 404

        setting = init_hidden_products_setting()
        product_ids = json.loads(setting.setting_value)
        
        # 获取商品详情
        products = Product.query.filter(Product.id.in_(product_ids)).all()
        
        # 过滤出用户有权限查看的商品
        filtered_products = []
        for product in products:
            # 检查商品是否在用户的推送单中
            has_push_permission = db.session.query(PushOrderProduct).join(
                PushOrder, PushOrder.id == PushOrderProduct.push_order_id
            ).filter(
                PushOrderProduct.product_id == product.id,
                PushOrder.target_user_id == user_id,
                PushOrder.status != 2  # 排除已取消的推送单
            ).first() is not None
            
            if has_push_permission:
                filtered_products.append(product)
        
        # 按照暗推列表的顺序排序
        sorted_products = sorted(filtered_products, key=lambda x: product_ids.index(x.id))
        
        # 序列化商品数据
        products_data = []
        for product in sorted_products:
            # 检查是否存在to_dict方法，若不存在则手动构建字典
            if hasattr(product, 'to_dict') and callable(getattr(product, 'to_dict')):
                products_data.append(product.to_dict())
            else:
                # 返回商品的所有属性构建产品字典
                product_dict = {
                    'id': product.id,
                    'name': product.name,
                    'type': product.type,
                    'price': product.price if hasattr(product, 'price') else None,
                    'images': json.loads(product.images) if hasattr(product, 'images') and product.images else [],
                    'created_at': product.created_at.strftime('%Y-%m-%d %H:%M:%S') if hasattr(product, 'created_at') else None,
                    'specs':  json.loads(product.specs) if hasattr(product, 'specs') and product.specs else None,
                    'size':product.size if hasattr(product, 'size') and product.size else None,
                    'weight':product.weight if hasattr(product, 'weight') and product.weight else None,
                    'yarn':product.yarn if hasattr(product, 'yarn') and product.yarn else None,
                    'composition':product.composition if hasattr(product, 'composition') and product.composition else None,
                    'style':product.style if hasattr(product, 'style') and product.style else None,
                }
                products_data.append(product_dict)
        
        return jsonify({
            'code': 0,
            'message': 'success',
            'data': products_data
        })
    except Exception as e:
        import traceback
        print(f'获取暗推产品列表失败: {str(e)}')
        print(f'错误详情: {traceback.format_exc()}')
        return jsonify({
            'code': 500,
            'message': str(e)
        }), 500

def update_hidden_products():
    """
    更新暗推产品列表
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
        setting = init_hidden_products_setting()
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