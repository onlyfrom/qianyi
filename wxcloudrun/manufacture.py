from flask import Blueprint, request, jsonify
from wxcloudrun import db
from wxcloudrun.model import Product, ColorStock, ManufacturePlan, ManufactureStatusHistory
from sqlalchemy import or_, func
from datetime import datetime, timedelta

manufacture_bp = Blueprint('manufacture', __name__)

@manufacture_bp.route('/api/manufacture/products', methods=['GET'])
def search_products():
    """搜索商品接口"""
    print("请求参数:", request.args)
    print("请求URL:", request.url)
    keyword = request.args.get('keyword', '')
    print("获取到的keyword:", keyword)
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
    
    try:
        for item in data['items']:
            # 验证必要字段
            if not all(k in item for k in ['product_id', 'quantity', 'color']):
                return jsonify({'code': 1, 'message': '缺少必要参数'})
            
            # 创建制造计划
            plan = ManufacturePlan(
                product_id=item['product_id'],
                quantity=item['quantity'],
                color=item['color'],
                status1=0,
                status2=0,
                status3=0,
                status4=0
            )
            db.session.add(plan)
        
        db.session.commit()
        return jsonify({
            'code': 0,
            'message': '创建成功'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'code': 1,
            'message': f'创建失败: {str(e)}'
        })

@manufacture_bp.route('/api/manufacture/plans', methods=['GET'])
def get_manufacture_plans():
    """获取制造计划列表"""
    page = int(request.args.get('page', 1))
    page_size = int(request.args.get('page_size', 10))
    
    # 构建查询
    query = ManufacturePlan.query
    
    # 分页查询
    pagination = query.paginate(page=page, per_page=page_size)
    plans = pagination.items
    
    # 构建返回数据
    result = []
    for plan in plans:
        product = Product.query.get(plan.product_id)
        result.append({
            'id': plan.id,
            'product_id': plan.product_id,
            'product_name': product.name if product else '未知商品',
            'quantity': plan.quantity,
            'color': plan.color,
            'status1': plan.status1,
            'status2': plan.status2,
            'status3': plan.status3,
            'status4': plan.status4,
            'status5': plan.status5,
            'status6': plan.status6,
            'created_at': plan.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'updated_at': plan.updated_at.strftime('%Y-%m-%d %H:%M:%S')
        })
    
    return jsonify({
        'code': 0,
        'data': {
            'items': result,
            'total': pagination.total,
            'page': page,
            'page_size': page_size
        }
    })

@manufacture_bp.route('/api/manufacture/plan/<int:plan_id>/status', methods=['PUT'])
def update_plan_status(plan_id):
    """更新制造计划状态"""
    data = request.get_json()
    
    if not data or 'status_type' not in data or 'value' not in data or 'operator' not in data:
        return jsonify({'code': 1, 'message': '参数错误'})
    
    try:
        plan = ManufacturePlan.query.get(plan_id)
        if not plan:
            return jsonify({'code': 1, 'message': '制造计划不存在'})
        
        # 更新对应状态
        status_type = data['status_type']
        change_value = int(data['value'])  # 变更数量，可以为正数或负数
        operator = data['operator']
        
        # 获取当前状态值
        current_value = getattr(plan, status_type, 0) or 0
        # 计算新的状态值
        new_value = current_value + change_value
        
        # 验证新的状态值不能为负数
        if new_value < 0:
            return jsonify({'code': 1, 'message': '变更后数量不能为负数'})
        
        # 验证新的状态值不能超过计划总数
        if new_value > plan.quantity:
            return jsonify({'code': 1, 'message': '变更后数量不能超过计划总数'})
        
        # 更新状态数量
        if status_type in ['status1', 'status2', 'status3', 'status4', 'status5', 'status6']:
            setattr(plan, status_type, new_value)
        else:
            return jsonify({'code': 1, 'message': '无效的状态类型'})
        
        # 记录状态修改历史
        history = ManufactureStatusHistory(
            plan_id=plan_id,
            status=status_type,
            value=new_value,  # 记录变更后的最终数量
            created_by=operator
        )
        db.session.add(history)
        
        db.session.commit()
        return jsonify({
            'code': 0,
            'message': '更新成功',
            'data': {
                'current_value': new_value
            }
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'code': 1,
            'message': f'更新失败: {str(e)}'
        })

@manufacture_bp.route('/api/manufacture/plans/search', methods=['GET'])
def search_manufacture_plans():
    """搜索制造计划"""
    keyword = request.args.get('keyword', '')
    status = request.args.get('status', None)
    page = int(request.args.get('page', 1))
    page_size = int(request.args.get('page_size', 10))
    start_time = request.args.get('start_time')
    end_time = request.args.get('end_time')

    query = ManufacturePlan.query.join(Product)

    if keyword:
        query = query.filter(
            or_(
                Product.name.like(f'%{keyword}%'),
                Product.id.like(f'%{keyword}%'),
                ManufacturePlan.color.like(f'%{keyword}%')
            )
        )

    if status:
        # 将状态字符串转换为列表
        status_list = status.split(',')
        # 构建状态筛选条件
        status_conditions = []
        for status_type in status_list:
            if status_type in ['status1', 'status2', 'status3', 'status4', 'status5', 'status6']:
                status_conditions.append(getattr(ManufacturePlan, status_type) > 0)
        
        if status_conditions:
            query = query.filter(or_(*status_conditions))

    # 新增时间区间筛选
    if start_time:
        try:
            start_dt = datetime.strptime(start_time, '%Y-%m-%d')
            query = query.filter(ManufacturePlan.created_at >= start_dt)
        except Exception:
            pass
    if end_time:
        try:
            end_dt = datetime.strptime(end_time, '%Y-%m-%d')
            query = query.filter(ManufacturePlan.created_at <= end_dt)
        except Exception:
            pass

    pagination = query.paginate(page=page, per_page=page_size)
    plans = pagination.items

    result = []
    for plan in plans:
        product = plan.product
        result.append({
            'id': plan.id,
            'product_id': plan.product_id,
            'product_name': product.name if product else '未知商品',
            'quantity': plan.quantity,
            'color': plan.color,
            'status1': plan.status1,
            'status2': plan.status2,
            'status3': plan.status3,
            'status4': plan.status4,
            'status5': plan.status5,
            'status6': plan.status6,
            'created_at': plan.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'updated_at': plan.updated_at.strftime('%Y-%m-%d %H:%M:%S')
        })

    return jsonify({
        'code': 0,
        'data': {
            'items': result,
            'total': pagination.total,
            'page': page,
            'page_size': page_size
        }
    })

@manufacture_bp.route('/api/manufacture/plans/batch-status', methods=['PUT'])
def batch_update_plan_status():
    """批量更新制造计划状态"""
    data = request.get_json()
    if not data or 'plan_ids' not in data or 'status_type' not in data or 'status' not in data:
        return jsonify({'code': 1, 'message': '参数错误'})
    
    try:
        plan_ids = data['plan_ids']
        status_type = data['status_type']
        status_value = data['status']
        
        # 验证状态类型
        if status_type not in ['status1', 'status2', 'status3', 'status4']:
            return jsonify({'code': 1, 'message': '无效的状态类型'})
        
        # 批量更新
        plans = ManufacturePlan.query.filter(ManufacturePlan.id.in_(plan_ids)).all()
        for plan in plans:
            setattr(plan, status_type, status_value)
        
        db.session.commit()
        return jsonify({
            'code': 0,
            'message': '批量更新成功'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'code': 1,
            'message': f'批量更新失败: {str(e)}'
        })

@manufacture_bp.route('/api/manufacture/plans/statistics', methods=['GET'])
def get_manufacture_statistics():
    """获取制造计划统计信息"""
    try:
        # 获取各状态的数量统计
        status_stats = {
            'status1': {
                'total': ManufacturePlan.query.filter_by(status1=0).count(),
                'completed': ManufacturePlan.query.filter_by(status1=1).count()
            },
            'status2': {
                'total': ManufacturePlan.query.filter_by(status2=0).count(),
                'completed': ManufacturePlan.query.filter_by(status2=1).count()
            },
            'status3': {
                'total': ManufacturePlan.query.filter_by(status3=0).count(),
                'completed': ManufacturePlan.query.filter_by(status3=1).count()
            },
            'status4': {
                'total': ManufacturePlan.query.filter_by(status4=0).count(),
                'completed': ManufacturePlan.query.filter_by(status4=1).count()
            },
            'status5': {    
                'total': ManufacturePlan.query.filter_by(status5=0).count(),
                'completed': ManufacturePlan.query.filter_by(status5=1).count()
            },
            'status6': {
                'total': ManufacturePlan.query.filter_by(status6=0).count(),
                'completed': ManufacturePlan.query.filter_by(status6=1).count()
            }
        }
        # 获取最近7天的制造计划数量
        last_7_days = []
        for i in range(7):
            date = datetime.now() - timedelta(days=i)
            count = ManufacturePlan.query.filter(
                func.date(ManufacturePlan.created_at) == date.date()
            ).count()
            last_7_days.append({
                'date': date.strftime('%Y-%m-%d'),
                'count': count
            })
        
        return jsonify({
            'code': 0,
            'data': {
                'status_statistics': status_stats,
                'last_7_days': last_7_days
            }
        })
    except Exception as e:
        return jsonify({
            'code': 1,
            'message': f'获取统计信息失败: {str(e)}'
        })

@manufacture_bp.route('/api/manufacture/plans/export', methods=['GET'])
def export_manufacture_plans():
    """导出制造计划"""
    try:
        # 获取所有制造计划
        plans = ManufacturePlan.query.all()
        
        # 构建导出数据
        export_data = []
        for plan in plans:
            product = plan.product
            export_data.append({
                '计划ID': plan.id,
                '商品ID': plan.product_id,
                '商品名称': product.name if product else '未知商品',
                '数量': plan.quantity,
                '颜色': plan.color,
                '状态1': '已完成' if plan.status1 == 1 else '未完成',
                '状态2': '已完成' if plan.status2 == 1 else '未完成',
                '状态3': '已完成' if plan.status3 == 1 else '未完成',
                '状态4': '已完成' if plan.status4 == 1 else '未完成',
                '状态5': '已完成' if plan.status5 == 1 else '未完成',
                '状态6': '已完成' if plan.status6 == 1 else '未完成',
                '创建时间': plan.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                '更新时间': plan.updated_at.strftime('%Y-%m-%d %H:%M:%S')
            })
        
        return jsonify({
            'code': 0,
            'data': export_data
        })
    except Exception as e:
        return jsonify({
            'code': 1,
            'message': f'导出失败: {str(e)}'
        })

@manufacture_bp.route('/api/manufacture/plan/<int:plan_id>/status/history', methods=['GET'])
def get_plan_status_history():
    """获取制造计划状态修改历史"""
    plan_id = request.view_args.get('plan_id')
    page = int(request.args.get('page', 1))
    page_size = int(request.args.get('page_size', 10))
    
    try:
        # 构建查询
        query = ManufactureStatusHistory.query.filter_by(plan_id=plan_id)
        
        # 分页查询
        pagination = query.paginate(page=page, per_page=page_size)
        history_items = pagination.items
        
        # 构建返回数据
        result = []
        for item in history_items:
            result.append({
                'id': item.id,
                'plan_id': item.plan_id,
                'status': item.status,
                'value': item.value,
                'created_at': item.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'created_by': item.created_by
            })
        
        return jsonify({
            'code': 0,
            'data': {
                'items': result,
                'total': pagination.total,
                'page': page,
                'page_size': page_size
            }
        })
    except Exception as e:
        return jsonify({
            'code': 1,
            'message': f'获取历史记录失败: {str(e)}'
        }) 