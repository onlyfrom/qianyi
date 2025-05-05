from flask import Blueprint, request, jsonify
from wxcloudrun import db
from wxcloudrun.model import Product, ColorStock
from sqlalchemy import or_

manufacture_bp = Blueprint('manufacture', __name__)

@manufacture_bp.route('/api/manufacture/products', methods=['GET'])
def search_products():
    """搜索商品接口"""
    keyword = request.args.get('keyword', '')
    page = int(request.args.get('page', 1))
    page_size = int(request.args.get('page_size', 10))
    
    # 构建查询条件
    query = Product.query.filter(
        or_(
            Product.name.like(f'%{keyword}%'),
            Product.id.like(f'%{keyword}%')
        )
    )
    
    # 分页查询
    pagination = query.paginate(page=page, per_page=page_size)
    products = pagination.items
    
    # 获取每个商品的库存信息
    result = []
    for product in products:
        # 获取颜色库存
        color_stocks = ColorStock.query.filter_by(product_id=product.id).all()
        stock_info = [{
            'color': stock.color,
            'stock': stock.stock
        } for stock in color_stocks]
        
        result.append({
            'id': product.id,
            'name': product.name,
            'code': product.id,  # 使用商品ID作为货号
            'stock_info': stock_info
        })
    print(result)
    return jsonify({
        'code': 0,
        'data': {
            'items': result,
            'total': pagination.total,
            'page': page,
            'page_size': page_size
        }
    })

@manufacture_bp.route('/api/manufacture/plan', methods=['POST'])
def create_manufacture_plan():
    """创建制造计划"""
    data = request.get_json()
    if not data or 'items' not in data:
        return jsonify({'code': 1, 'message': '参数错误'})
    
    # TODO: 这里需要添加制造计划相关的数据库模型和逻辑
    # 目前先返回成功
    return jsonify({
        'code': 0,
        'message': '创建成功'
    })

@manufacture_bp.route('/api/manufacture/plans', methods=['GET'])
def get_manufacture_plans():
    """获取制造计划列表"""
    page = int(request.args.get('page', 1))
    page_size = int(request.args.get('page_size', 10))
    
    # TODO: 这里需要添加制造计划相关的数据库模型和逻辑
    # 目前返回空列表
    return jsonify({
        'code': 0,
        'data': {
            'items': [],
            'total': 0,
            'page': page,
            'page_size': page_size
        }
    }) 