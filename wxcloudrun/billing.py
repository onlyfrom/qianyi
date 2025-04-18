from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, send_file
from decimal import Decimal
from .model import PurchaseOrder, PurchaseOrderItem, User, db, DeliveryOrder, DeliveryItem
from .views import login_required, app
import pandas as pd
from io import BytesIO

# 恢复使用蓝图，确保登录状态正确继承
billing_bp = Blueprint('billing', __name__)

@billing_bp.route('/billing', methods=['GET'])
@login_required
def get_billing_list(user_id):
    """获取账单列表 - 按客户汇总"""
    try:
        # 从URL参数获取数据
        page = int(request.args.get('page', 1))
        page_size = int(request.args.get('page_size', 20))
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        customer_id = request.args.get('customer_id')
        sort_by = request.args.get('sort_by', 'total_amount')  # 默认按货款总额排序
        sort_order = request.args.get('sort_order', 'desc')    # 默认降序

        print(f"[DEBUG] 获取账单列表: 页码={page}, 每页数量={page_size}, 开始日期={start_date}, 结束日期={end_date}, 客户ID={customer_id}, 排序字段={sort_by}, 排序方式={sort_order}")

        # 构建基础查询 - 按客户分组汇总
        base_query = db.session.query(
            User.id.label('customer_id'),
            User.nickname.label('customer_name'),
            db.func.sum(PurchaseOrderItem.quantity).label('total_quantity'),
            db.func.sum(PurchaseOrderItem.price * PurchaseOrderItem.quantity).label('total_amount'),
            db.func.sum(PurchaseOrder.paid_amount).label('paid_amount')
        ).join(
            PurchaseOrder, User.id == PurchaseOrder.user_id
        ).join(
            PurchaseOrderItem, PurchaseOrder.id == PurchaseOrderItem.order_id
        ).group_by(
            User.id, User.nickname
        )

        # 应用筛选条件
        if start_date:
            try:
                start_datetime = datetime.strptime(start_date, '%Y-%m-%d')
                base_query = base_query.filter(PurchaseOrder.created_at >= start_datetime)
                print(f"[DEBUG] 应用开始日期筛选: {start_datetime}")
            except ValueError as e:
                print(f"[ERROR] 开始日期格式错误: {start_date}, 错误: {str(e)}")
                return jsonify({'error': '开始日期格式错误，请使用YYYY-MM-DD格式'}), 400
                
        if end_date:
            try:
                end_datetime = datetime.strptime(end_date, '%Y-%m-%d')
                end_datetime = end_datetime + timedelta(days=1) - timedelta(seconds=1)
                base_query = base_query.filter(PurchaseOrder.created_at <= end_datetime)
                print(f"[DEBUG] 应用结束日期筛选: {end_datetime}")
            except ValueError as e:
                print(f"[ERROR] 结束日期格式错误: {end_date}, 错误: {str(e)}")
                return jsonify({'error': '结束日期格式错误，请使用YYYY-MM-DD格式'}), 400
                
        if customer_id:
            base_query = base_query.filter(User.id == customer_id)

        # 获取总数
        total = base_query.count()
        
        # 排序
        sort_column = None
        if sort_by == 'customer_name':
            sort_column = User.nickname
        elif sort_by == 'total_quantity':
            sort_column = db.func.sum(PurchaseOrderItem.quantity)
        elif sort_by == 'total_amount':
            sort_column = db.func.sum(PurchaseOrderItem.price * PurchaseOrderItem.quantity)
        elif sort_by == 'paid_amount':
            sort_column = db.func.sum(PurchaseOrder.paid_amount)
        elif sort_by == 'unpaid_amount':
            sort_column = db.func.sum(PurchaseOrderItem.price * PurchaseOrderItem.quantity) - db.func.sum(PurchaseOrder.paid_amount)
        
        # 应用排序
        if sort_column is not None:
            if sort_order == 'desc':
                base_query = base_query.order_by(db.desc(sort_column))
            else:
                base_query = base_query.order_by(sort_column)
        else:
            # 默认排序
            base_query = base_query.order_by(db.desc(db.func.sum(PurchaseOrderItem.price * PurchaseOrderItem.quantity)))
        
        # 分页
        base_query = base_query.offset((page - 1) * page_size).limit(page_size)

        # 执行查询
        results = base_query.all()

        # 构建返回数据
        items = []
        for result in results:
            customer_id, customer_name, total_quantity, total_amount, paid_amount = result
            items.append({
                'id': customer_id,  # 使用客户ID作为标识
                'customer_name': customer_name,
                'total_quantity': total_quantity or 0,
                'total_amount': float(total_amount or 0),
                'paid_amount': float(paid_amount or 0),
                'unpaid_amount': float((total_amount or 0) - (paid_amount or 0))
            })

        print(f"[DEBUG] 成功获取账单列表: 总数={total}, 当前页数量={len(items)}")
        return jsonify({
            'items': items,
            'total': total
        })
    except Exception as e:
        print(f"[ERROR] 获取账单列表失败: {str(e)}")
        return jsonify({'error': '获取账单列表失败'}), 500

@billing_bp.route('/billing/statistics', methods=['GET'])
@login_required
def get_billing_statistics(user_id):
    """获取账单统计数据"""
    try:
        # 获取查询参数
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        # 构建基础查询
        base_query = db.session.query(
            db.func.sum(PurchaseOrderItem.quantity).label('total_count'),
            db.func.sum(PurchaseOrderItem.price * PurchaseOrderItem.quantity).label('total_amount'),
            db.func.sum(PurchaseOrder.paid_amount).label('paid_amount')
        ).join(
            PurchaseOrder, PurchaseOrderItem.order_id == PurchaseOrder.id
        )
        
        # 应用日期筛选
        if start_date:
            try:
                start_datetime = datetime.strptime(start_date, '%Y-%m-%d')
                base_query = base_query.filter(PurchaseOrder.created_at >= start_datetime)
            except ValueError:
                return jsonify({'error': '开始日期格式错误，请使用YYYY-MM-DD格式'}), 400
                
        if end_date:
            try:
                end_datetime = datetime.strptime(end_date, '%Y-%m-%d')
                end_datetime = end_datetime + timedelta(days=1) - timedelta(seconds=1)
                base_query = base_query.filter(PurchaseOrder.created_at <= end_datetime)
            except ValueError:
                return jsonify({'error': '结束日期格式错误，请使用YYYY-MM-DD格式'}), 400
        
        # 执行查询
        result = base_query.first()
        
        # 计算统计数据
        total_amount = float(result.total_amount or 0)
        paid_amount = float(result.paid_amount or 0)
        unpaid_amount = total_amount - paid_amount
        
        return jsonify({
            'totalAmount': total_amount,
            'paidAmount': paid_amount,
            'unpaidAmount': unpaid_amount,
            'totalCount': result.total_count or 0
        })
    except Exception as e:
        print(f"[ERROR] 获取账单统计数据失败: {str(e)}")
        return jsonify({'error': '获取账单统计数据失败'}), 500

@billing_bp.route('/billing/<int:customer_id>/orders', methods=['GET'])
@login_required
def get_customer_orders(user_id, customer_id):
    """获取客户的发货单列表"""
    try:
        print(f"[DEBUG] 获取客户发货单列表: 客户ID={customer_id}")
        
        # 获取查询参数
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        # 构建基础查询
        query = db.session.query(
            DeliveryOrder,
            db.func.sum(DeliveryItem.quantity).label('total_quantity'),
            db.func.sum(PurchaseOrderItem.price * DeliveryItem.quantity).label('total_amount')
        ).join(
            DeliveryItem, DeliveryOrder.id == DeliveryItem.delivery_id
        ).join(
            PurchaseOrder, DeliveryItem.order_number == PurchaseOrder.order_number
        ).join(
            PurchaseOrderItem, 
            db.and_(
                PurchaseOrder.id == PurchaseOrderItem.order_id,
                PurchaseOrderItem.product_id == DeliveryItem.product_id,
                PurchaseOrderItem.color == DeliveryItem.color
            )
        ).filter(
            DeliveryOrder.customer_id == customer_id
        )
        
        # 添加日期过滤
        if start_date:
            query = query.filter(db.func.date(DeliveryOrder.created_at) >= start_date)
        if end_date:
            query = query.filter(db.func.date(DeliveryOrder.created_at) <= end_date)
            
        # 分组并执行查询
        orders = query.group_by(DeliveryOrder.id).all()
        
        # 构建返回数据
        result = []
        for order, total_quantity, total_amount in orders:
            # 获取创建者信息
            creator = User.query.get(order.created_by)
            
            # 状态文本映射
            status_text_map = {
                0: '已开单',
                1: '已发货',
                2: '已完成',
                3: '已取消',
                4: '异常'
            }
            
            result.append({
                'id': order.id,
                'order_number': order.order_number,
                'created_at': order.created_at.strftime('%Y-%m-%d'),
                'total_quantity': total_quantity or 0,
                'total_amount': float(total_amount or 0),
                'status': order.status,
                'status_text': status_text_map.get(order.status, '未知状态'),
                'remark': order.remark,
                'creator': {
                    'id': creator.id if creator else None,
                    'username': creator.username if creator else None,
                    'nickname': creator.nickname if creator else None
                } if creator else None
            })
            
        return jsonify({
            'code': 0,
            'data': result
        })
        
    except Exception as e:
        print(f"[ERROR] 获取客户发货单列表失败: 客户ID={customer_id}, 错误={str(e)}")
        return jsonify({
            'code': -1,
            'message': f'获取客户发货单列表失败: {str(e)}'
        })

@billing_bp.route('/billing/<int:order_id>/payment', methods=['POST'])
@login_required
def confirm_payment(user_id, order_id):
    """确认收款"""
    try:
        print(f"[DEBUG] 确认收款: 订单ID={order_id}")
        data = request.get_json()
        amount = float(data.get('amount', 0))
        remark = data.get('remark', '')

        if amount <= 0:
            return jsonify({'error': '收款金额必须大于0'}), 400

        order = PurchaseOrder.query.get_or_404(order_id)
        
        # 计算订单总金额
        total_amount = db.session.query(
            db.func.sum(PurchaseOrderItem.price * PurchaseOrderItem.quantity)
        ).filter_by(order_id=order_id).scalar() or 0

        # 检查收款金额是否超过未付金额
        unpaid_amount = total_amount - (order.paid_amount or 0)
        if amount > unpaid_amount:
            return jsonify({'error': '收款金额不能超过未付金额'}), 400

        # 更新已付金额
        order.paid_amount = (order.paid_amount or 0) + amount
        if remark:
            order.remark = remark

        # 更新订单状态
        if order.paid_amount >= total_amount:
            order.status = 2  # 设置为已结清
        elif order.paid_amount > 0:
            order.status = 1  # 设置为部分付款
        else:
            order.status = 0  # 设置为未付款

        db.session.commit()
        
        print(f"[DEBUG] 成功确认收款: 订单ID={order_id}, 收款金额={amount}")
        return jsonify({'message': '收款确认成功'})
    except Exception as e:
        print(f"[ERROR] 确认收款失败: 订单ID={order_id}, 错误={str(e)}")
        db.session.rollback()
        return jsonify({'error': '确认收款失败'}), 500

@billing_bp.route('/billing/export', methods=['GET'])
@login_required
def export_billing(user_id):
    """导出账单数据"""
    try:
        print("[DEBUG] 开始导出账单数据")
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        customer_id = request.args.get('customer_id')

        # 构建查询条件 - 按客户分组汇总
        base_query = db.session.query(
            User.id.label('customer_id'),
            User.nickname.label('customer_name'),
            db.func.sum(PurchaseOrderItem.quantity).label('total_quantity'),
            db.func.sum(PurchaseOrderItem.price * PurchaseOrderItem.quantity).label('total_amount'),
            db.func.sum(PurchaseOrder.paid_amount).label('paid_amount')
        ).join(
            PurchaseOrder, User.id == PurchaseOrder.user_id
        ).join(
            PurchaseOrderItem, PurchaseOrder.id == PurchaseOrderItem.order_id
        ).group_by(
            User.id, User.nickname
        )

        # 添加日期过滤
        if start_date:
            try:
                start_datetime = datetime.strptime(start_date, '%Y-%m-%d')
                base_query = base_query.filter(PurchaseOrder.created_at >= start_datetime)
            except ValueError:
                return jsonify({'error': '开始日期格式错误，请使用YYYY-MM-DD格式'}), 400
                
        if end_date:
            try:
                end_datetime = datetime.strptime(end_date, '%Y-%m-%d')
                end_datetime = end_datetime + timedelta(days=1) - timedelta(seconds=1)
                base_query = base_query.filter(PurchaseOrder.created_at <= end_datetime)
            except ValueError:
                return jsonify({'error': '结束日期格式错误，请使用YYYY-MM-DD格式'}), 400

        # 添加客户过滤
        if customer_id:
            base_query = base_query.filter(User.id == customer_id)

        # 执行查询
        results = base_query.all()

        # 构建Excel数据
        data = []
        for result in results:
            customer_id, customer_name, total_quantity, total_amount, paid_amount = result
            data.append({
                '客户ID': customer_id,
                '客户名称': customer_name,
                '商品总数': total_quantity or 0,
                '货款总额': float(total_amount or 0),
                '已付金额': float(paid_amount or 0),
                '未付金额': float((total_amount or 0) - (paid_amount or 0))
            })

        df = pd.DataFrame(data)
        output = BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='账单数据')

        output.seek(0)
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=f'账单数据_{datetime.now().strftime("%Y%m%d")}.xlsx'
        )
    except Exception as e:
        print(f"[ERROR] 导出账单数据失败: {str(e)}")
        return jsonify({'error': '导出账单数据失败'}), 500

@billing_bp.route('/billing/<int:customer_id>/delivery_orders', methods=['GET'])
@login_required
def get_customer_delivery_orders(user_id, customer_id):
    """获取客户的发货单列表"""
    try:
        # 获取查询参数
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        # 构建基础查询
        base_query = db.session.query(
            DeliveryOrder.id,
            DeliveryOrder.order_number,
            DeliveryOrder.created_at,
            DeliveryOrder.status,
            DeliveryOrder.remark,
            db.func.sum(DeliveryItem.quantity).label('total_quantity')
        ).join(
            DeliveryItem, DeliveryOrder.id == DeliveryItem.delivery_id
        ).filter(
            DeliveryOrder.customer_id == customer_id
        ).group_by(
            DeliveryOrder.id,
            DeliveryOrder.order_number,
            DeliveryOrder.created_at,
            DeliveryOrder.status,
            DeliveryOrder.remark
        )
        
        # 应用日期筛选
        if start_date:
            try:
                start_datetime = datetime.strptime(start_date, '%Y-%m-%d')
                base_query = base_query.filter(DeliveryOrder.created_at >= start_datetime)
            except ValueError:
                return jsonify({'error': '开始日期格式错误，请使用YYYY-MM-DD格式'}), 400
                
        if end_date:
            try:
                end_datetime = datetime.strptime(end_date, '%Y-%m-%d')
                end_datetime = end_datetime + timedelta(days=1) - timedelta(seconds=1)
                base_query = base_query.filter(DeliveryOrder.created_at <= end_datetime)
            except ValueError:
                return jsonify({'error': '结束日期格式错误，请使用YYYY-MM-DD格式'}), 400
        
        # 执行查询
        results = base_query.all()
        
        # 构建返回数据
        delivery_orders = []
        for result in results:
            order_id, order_number, created_at, status, remark, total_quantity = result
            
            # 获取创建者信息
            creator = User.query.get(DeliveryOrder.query.get(order_id).created_by)
            
            # 状态文本映射
            status_text_map = {
                0: '已开单',
                1: '已发货',
                2: '已完成',
                3: '已取消',
                4: '异常'
            }
            
            delivery_orders.append({
                'id': order_id,
                'order_number': order_number,
                'created_at': created_at.isoformat(),
                'status': status,
                'status_text': status_text_map.get(status, '未知状态'),
                'remark': remark,
                'total_quantity': total_quantity or 0,
                'creator': {
                    'id': creator.id,
                    'username': creator.username,
                    'nickname': creator.nickname
                } if creator else None
            })
        
        return jsonify({
            'code': 0,
            'data': delivery_orders
        })
        
    except Exception as e:
        print(f"[ERROR] 获取客户发货单列表失败: {str(e)}")
        return jsonify({'error': '获取客户发货单列表失败'}), 500 