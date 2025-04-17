from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify
from decimal import Decimal
from .model import PurchaseOrder, PurchaseOrderItem, User, db
from .views import login_required, app

# 恢复使用蓝图，确保登录状态正确继承
billing_bp = Blueprint('billing', __name__)

@billing_bp.route('/billing', methods=['GET'])
@login_required
def get_billing_list(user_id):
    """获取账单列表"""
    try:
        # 从URL参数获取数据，而不是从JSON
        page = int(request.args.get('page', 1))
        page_size = int(request.args.get('page_size', 20))
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        customer_id = request.args.get('customer_id')

        print(f"[DEBUG] 获取账单列表: 页码={page}, 每页数量={page_size}, 开始日期={start_date}, 结束日期={end_date}, 客户ID={customer_id}")

        query = PurchaseOrder.query

        # 应用筛选条件
        if start_date:
            try:
                # 将字符串转换为日期对象，设置时间为当天的开始 (00:00:00)
                start_datetime = datetime.strptime(start_date, '%Y-%m-%d')
                query = query.filter(PurchaseOrder.created_at >= start_datetime)
                print(f"[DEBUG] 应用开始日期筛选: {start_datetime}")
            except ValueError as e:
                print(f"[ERROR] 开始日期格式错误: {start_date}, 错误: {str(e)}")
                return jsonify({'error': '开始日期格式错误，请使用YYYY-MM-DD格式'}), 400
                
        if end_date:
            try:
                # 将字符串转换为日期对象，设置时间为当天的结束 (23:59:59)
                end_datetime = datetime.strptime(end_date, '%Y-%m-%d')
                # 添加一天并减去1秒，确保包含当天的所有数据
                end_datetime = end_datetime + timedelta(days=1) - timedelta(seconds=1)
                query = query.filter(PurchaseOrder.created_at <= end_datetime)
                print(f"[DEBUG] 应用结束日期筛选: {end_datetime}")
            except ValueError as e:
                print(f"[ERROR] 结束日期格式错误: {end_date}, 错误: {str(e)}")
                return jsonify({'error': '结束日期格式错误，请使用YYYY-MM-DD格式'}), 400
                
        if customer_id:
            query = query.filter(PurchaseOrder.user_id == customer_id)

        # 获取总数
        total = query.count()
        
        # 分页
        orders = query.order_by(PurchaseOrder.created_at.desc()).paginate(
            page=page, per_page=page_size, error_out=False
        )

        items = []
        for order in orders.items:
            customer = User.query.get(order.user_id)
            items.append({
                'id': order.id,
                'order_number': order.order_number,
                'created_at': order.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'type': 'purchase',  # 采购订单类型
                'customer_name': customer.nickname or customer.username if customer else '未知',
                'amount': float(order.total_amount),
                'status': 'completed' if order.status == 2 else 'pending' if order.status == 1 else 'cancelled',
                'remark': order.remark
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
        print("[DEBUG] 开始获取账单统计数据")
        now = datetime.now()
        first_day = datetime(now.year, now.month, 1)
        last_month_first = first_day - timedelta(days=first_day.day)
        
        # 本月数据
        current_month = db.session.query(
            db.func.sum(PurchaseOrder.total_amount).label('income'),
            db.func.count(PurchaseOrder.id).label('count')
        ).filter(
            PurchaseOrder.created_at >= first_day,
            PurchaseOrder.status == 2  # 已完成的订单
        ).first()

        # 上月数据
        last_month = db.session.query(
            db.func.sum(PurchaseOrder.total_amount).label('income'),
            db.func.count(PurchaseOrder.id).label('count')
        ).filter(
            PurchaseOrder.created_at >= last_month_first,
            PurchaseOrder.created_at < first_day,
            PurchaseOrder.status == 2  # 已完成的订单
        ).first()

        # 计算环比
        monthly_income = float(current_month.income or 0)
        last_monthly_income = float(last_month.income or 0)
        monthly_orders = current_month.count or 0
        last_monthly_orders = last_month.count or 0

        income_trend = ((monthly_income - last_monthly_income) / last_monthly_income * 100) if last_monthly_income else 0
        orders_trend = ((monthly_orders - last_monthly_orders) / last_monthly_orders * 100) if last_monthly_orders else 0
        
        # 计算平均客单价
        avg_order_value = monthly_income / monthly_orders if monthly_orders > 0 else 0
        last_avg_order_value = last_monthly_income / last_monthly_orders if last_monthly_orders > 0 else 0
        avg_order_trend = ((avg_order_value - last_avg_order_value) / last_avg_order_value * 100) if last_avg_order_value else 0

        print(f"[DEBUG] 账单统计数据: 本月收入={monthly_income}, 本月订单数={monthly_orders}, 平均客单价={avg_order_value}")
        
        return jsonify({
            'monthlyIncome': monthly_income,
            'monthlyOrders': monthly_orders,
            'averageOrderValue': avg_order_value,
            'monthlyTrend': income_trend,
            'ordersTrend': orders_trend,
            'avgOrderTrend': avg_order_trend
        })
    except Exception as e:
        print(f"[ERROR] 获取账单统计数据失败: {str(e)}")
        return jsonify({'error': '获取账单统计数据失败'}), 500

@billing_bp.route('/billing/<int:order_id>', methods=['GET'])
@login_required
def get_billing_detail(user_id, order_id):
    """获取账单详情"""
    try:
        print(f"[DEBUG] 获取账单详情: 订单ID={order_id}")
        order = PurchaseOrder.query.get_or_404(order_id)
        customer = User.query.get(order.user_id)
        
        # 获取订单项
        order_items = PurchaseOrderItem.query.filter_by(order_id=order_id).all()
        items = [item.to_dict() for item in order_items]

        print(f"[DEBUG] 成功获取账单详情: 订单ID={order_id}, 订单项数量={len(items)}")
        return jsonify({
            'id': order.id,
            'order_number': order.order_number,
            'created_at': order.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'type': 'purchase',
            'customer_name': customer.nickname or customer.username if customer else '未知',
            'amount': float(order.total_amount),
            'status': 'completed' if order.status == 2 else 'pending' if order.status == 1 else 'cancelled',
            'remark': order.remark,
            'items': items
        })
    except Exception as e:
        print(f"[ERROR] 获取账单详情失败: 订单ID={order_id}, 错误={str(e)}")
        return jsonify({'error': '获取账单详情失败'}), 500

@billing_bp.route('/billing/<int:order_id>/confirm', methods=['PUT'])
@login_required
def confirm_billing(user_id, order_id):
    """确认账单"""
    try:
        print(f"[DEBUG] 确认账单: 订单ID={order_id}")
        order = PurchaseOrder.query.get_or_404(order_id)
        
        if order.status != 0:
            print(f"[WARNING] 确认账单失败: 订单ID={order_id}, 状态={order.status}, 只能确认待处理的订单")
            return jsonify({'error': '只能确认待处理的订单'}), 400
        
        order.status = 1  # 设置为已完成
        db.session.commit()
        
        print(f"[DEBUG] 成功确认账单: 订单ID={order_id}")
        return jsonify({'message': '订单确认成功'})
    except Exception as e:
        print(f"[ERROR] 确认账单失败: 订单ID={order_id}, 错误={str(e)}")
        db.session.rollback()
        return jsonify({'error': '确认账单失败'}), 500

@billing_bp.route('/billing/export', methods=['GET'])
@login_required
def export_billing(user_id):
    """导出账单数据"""
    try:
        print("[DEBUG] 开始导出账单数据")
        # TODO: 实现导出Excel功能
        print("[WARNING] 导出账单数据功能尚未实现")
        return jsonify({'error': '功能开发中'}), 501
    except Exception as e:
        print(f"[ERROR] 导出账单数据失败: {str(e)}")
        return jsonify({'error': '导出账单数据失败'}), 500 