from flask import Blueprint, jsonify, request
from wxcloudrun.model import db, PurchaseOrder, PurchaseOrderItem, DeliveryOrder, DeliveryItem, User
from wxcloudrun.views import login_required
import traceback

order_bp = Blueprint('order', __name__)

@order_bp.route('/purchase_orders/<int:order_id>', methods=['DELETE'])
@login_required
def delete_purchase_order(user_id, order_id):
    """
    删除采购单及其关联的发货单
    参数:
        order_id: 采购单ID
    返回:
        成功: {"code": 200, "message": "删除成功"}
        失败: {"error": "错误信息"}
    """
    try:
        # 检查权限
        current_user = User.query.get(user_id)
        if not current_user or current_user.user_type != 1:
            return jsonify({'error': '没有权限执行此操作'}), 403
        
        # 获取采购单
        purchase_order = PurchaseOrder.query.get(order_id)
        if not purchase_order:
            return jsonify({'error': '采购单不存在'}), 404
            
        if purchase_order.status not in [0, 3]:  # 只能删除待确认或已取消的订单
            return jsonify({'error': '当前状态不允许删除'}), 400
        
        # 开始事务
        db.session.begin_nested()
        
        try:
            # 1. 删除关联的发货单明细
            delivery_orders = DeliveryOrder.query.filter_by(order_number=purchase_order.order_number).all()
            for delivery_order in delivery_orders:
                DeliveryItem.query.filter_by(delivery_id=delivery_order.id).delete()
            
            # 2. 删除关联的发货单
            for delivery_order in delivery_orders:
                db.session.delete(delivery_order)
            
            # 3. 删除采购单明细
            PurchaseOrderItem.query.filter_by(order_id=order_id).delete()
            
            # 4. 删除采购单
            db.session.delete(purchase_order)
            
            # 提交事务
            db.session.commit()
            
            return jsonify({
                'code': 200,
                'message': '采购单及相关发货单删除成功'
            })
            
        except Exception as e:
            db.session.rollback()
            print(f'删除采购单失败: {str(e)}')
            return jsonify({'error': '删除采购单失败'}), 500
            
    except Exception as e:
        print(f'处理删除采购单请求失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '删除采购单失败'}), 500

@order_bp.route('/delivery_orders/<int:order_id>', methods=['DELETE'])
@login_required
def delete_delivery_order(user_id, order_id):
    """
    删除发货单
    参数:
        order_id: 发货单ID
    返回:
        成功: {"code": 200, "message": "删除成功"}
        失败: {"error": "错误信息"}
    """
    try:
        # 检查权限
        current_user = User.query.get(user_id)
        if not current_user or current_user.role != 'admin' and current_user.role != 'STAFF':
            return jsonify({'error': '没有权限执行此操作'}), 403
        
        # 获取发货单
        delivery_order = DeliveryOrder.query.get(order_id)
        if not delivery_order:
            return jsonify({'error': '发货单不存在'}), 404
            
        
        # 开始事务
        db.session.begin_nested()
        
        try:
            # 1. 删除发货单明细
            DeliveryItem.query.filter_by(delivery_id=order_id).delete()
            
            # 2. 删除发货单
            db.session.delete(delivery_order)
            
            # 3. 恢复采购单状态为已处理（status=1）
            purchase_order = PurchaseOrder.query.filter_by(order_number=delivery_order.order_number).first()
            if purchase_order:
                purchase_order.status = 1  # 更新为已处理状态
            
            # 提交事务
            db.session.commit()
            
            return jsonify({
                'code': 200,
                'message': '发货单删除成功，采购单状态已恢复'
            })
            
        except Exception as e:
            db.session.rollback()
            print(f'删除发货单失败: {str(e)}')
            return jsonify({'error': '删除发货单失败'}), 500
            
    except Exception as e:
        print(f'处理删除发货单请求失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '删除发货单失败'}), 500 
    


@order_bp.route('/delivery_orders_old/<int:order_id>', methods=['DELETE'])
@login_required
def delete_delivery_order_old(current_user_id, order_id):
    try:
        # 检查权限
        current_user = User.query.get(current_user_id)
        if not current_user or current_user.user_type != 1:
            return jsonify({'error': '没有权限执行此操作'}), 403
        
        # 获取配送单
        order = DeliveryOrder.query.get(order_id)
        if not order:
            return jsonify({'error': '配送单不存在'}), 404
            
        if order.status not in [0, 3]:  # 只能删除待配送或已取消的订单
            return jsonify({'error': '当前状态不允许删除'}), 400
        
        # 删除配送单商品
        DeliveryItem.query.filter_by(delivery_id=order_id).delete()
        
        # 删除配送单
        db.session.delete(order)
        
        try:
            db.session.commit()
            return jsonify({
                'code': 200,
                'message': '配送单删除成功'
            })
        except Exception as e:
            db.session.rollback()
            print(f'删除配送单失败: {str(e)}')
            return jsonify({'error': '删除配送单失败'}), 500
            
    except Exception as e:
        print(f'处理删除配送单请求失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({'error': '删除配送单失败'}), 500