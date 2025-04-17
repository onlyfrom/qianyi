from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, send_file
from decimal import Decimal
from .model import PurchaseOrder, PurchaseOrderItem, User, db
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

        print(f"[DEBUG] 获取账单列表: 页码={page}, 每页数量={page_size}, 开始日期={start_date}, 结束日期={end_date}, 客户ID={customer_id}")

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
        
        # 分页
        base_query = base_query.order_by(User.nickname)
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
        print("[DEBUG] 开始获取账单统计数据")
        now = datetime.now()
        first_day = datetime(now.year, now.month, 1)
        last_month_first = first_day - timedelta(days=first_day.day)
        
        # 本月数据
        current_month = db.session.query(
            db.func.sum(PurchaseOrderItem.price * PurchaseOrderItem.quantity).label('income'),
            db.func.count(PurchaseOrder.id.distinct()).label('count')
        ).join(
            PurchaseOrderItem, PurchaseOrder.id == PurchaseOrderItem.order_id
        ).filter(
            PurchaseOrder.created_at >= first_day
        ).first()

        # 上月数据
        last_month = db.session.query(
            db.func.sum(PurchaseOrderItem.price * PurchaseOrderItem.quantity).label('income'),
            db.func.count(PurchaseOrder.id.distinct()).label('count')
        ).join(
            PurchaseOrderItem, PurchaseOrder.id == PurchaseOrderItem.order_id
        ).filter(
            PurchaseOrder.created_at >= last_month_first,
            PurchaseOrder.created_at < first_day
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

@billing_bp.route('/billing/<int:customer_id>/orders', methods=['GET'])
@login_required
def get_customer_orders(user_id, customer_id):
    """获取客户的订单列表"""
    try:
        print(f"[DEBUG] 获取客户订单列表: 客户ID={customer_id}")
        
        # 获取查询参数
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        # 获取客户信息
        customer = User.query.get_or_404(customer_id)
        
        # 构建查询
        query = db.session.query(
            PurchaseOrder,
            db.func.sum(PurchaseOrderItem.quantity).label('total_quantity'),
            db.func.sum(PurchaseOrderItem.price * PurchaseOrderItem.quantity).label('total_amount')
        ).join(
            PurchaseOrderItem,
            PurchaseOrder.id == PurchaseOrderItem.order_id
        ).filter(
            PurchaseOrder.user_id == customer_id
        )
        
        # 添加日期过滤
        if start_date:
            query = query.filter(db.func.date(PurchaseOrder.created_at) >= start_date)
        if end_date:
            query = query.filter(db.func.date(PurchaseOrder.created_at) <= end_date)
            
        # 分组并执行查询
        orders = query.group_by(PurchaseOrder.id).all()
        
        # 构建返回数据
        result = []
        for order, total_quantity, total_amount in orders:
            # 计算订单状态
            status = 0  # 默认未付款
            if order.paid_amount >= total_amount:
                status = 2  # 已结清
            elif order.paid_amount > 0:
                status = 1  # 部分付款
                
            result.append({
                'id': order.id,
                'order_number': order.order_number,
                'created_at': order.created_at.strftime('%Y-%m-%d'),
                'total_quantity': total_quantity,
                'total_amount': float(total_amount),
                'paid_amount': order.paid_amount,
                'unpaid_amount': float(total_amount) - order.paid_amount,
                'status': status,  # 使用计算的状态
                'remark': order.remark
            })
            
        return jsonify({
            'code': 0,
            'data': result
        })
        
    except Exception as e:
        print(f"[ERROR] 获取客户订单列表失败: 客户ID={customer_id}, 错误={str(e)}")
        return jsonify({
            'code': -1,
            'message': f'获取客户订单列表失败: {str(e)}'
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