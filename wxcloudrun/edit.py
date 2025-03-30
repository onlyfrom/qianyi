# 获取商品详情
@app.route('/products/<product_id>', methods=['GET'])
@login_required
def get_product_detail(user_id, product_id):
    try:
        product = Product.query.get(product_id)
        if not product:
            return jsonify({'error': '商品不存在'}), 404
            
        # 获取当前用户信息
        current_user = User.query.get(user_id)
        if not current_user:
            return jsonify({'error': '用户不存在'}), 404
        
        # 获取推送过该商品的用户
        pushed_users = db.session.query(User.id, User.nickname, User.avatar)\
            .join(PushOrder, PushOrder.target_user_id == User.id)\
            .join(PushOrderProduct, PushOrderProduct.push_order_id == PushOrder.id)\
            .filter(PushOrderProduct.product_id == product_id)\
            .distinct().all()
            
        # 获取所有用户
        all_users = db.session.query(User.id, User.nickname, User.avatar).all()
        
        # 获取未推送过的用户
        pushed_user_ids = {user.id for user in pushed_users}
        not_pushed_users = [user for user in all_users if user.id not in pushed_user_ids]
        
        # 格式化用户数据
        pushed_users_data = [{
            'id': user.id,
            'nickname': user.nickname,
            'avatar': user.avatar
        } for user in pushed_users]
        
        not_pushed_users_data = [{
            'id': user.id, 
            'nickname': user.nickname,
            'avatar': user.avatar
        } for user in not_pushed_users]

        # 获取基础价格
        base_price = float(product.price) if product.price is not None else 0
        
        # 初始化规格信息
        specs = json.loads(product.specs) if product.specs else []
        specs_info = json.loads(product.specs_info) if product.specs_info else {}
        
        # 如果是普通客户，检查推送单中的价格和规格
        if current_user.role == UserRole.CUSTOMER:
            # 查找该用户最新的有效推送单中的商品信息
            latest_push = db.session.query(PushOrderProduct)\
                .join(PushOrder, PushOrder.id == PushOrderProduct.push_order_id)\
                .filter(
                    PushOrderProduct.product_id == product_id,
                    PushOrder.target_user_id == user_id,
                    PushOrder.status.in_(['pending', 'accepted'])  # 只考虑待处理和已接受的推送单
                )\
                .order_by(PushOrder.created_at.desc())\
                .first()
                
            if latest_push:
                # 如果在推送单中找到信息，使用推送单中的价格和规格
                display_price = float(latest_push.price)
                if latest_push.specs:
                    specs = json.loads(latest_push.specs)
                if latest_push.specs_info:
                    specs_info = json.loads(latest_push.specs_info)
            else:
                # 如果不在推送单中，检查是否是公开商品
                if product.is_public:
                    # 根据用户类型获取对应价格
                    if current_user.customer_type == CustomerType.TYPE_B:
                        display_price = float(product.price_b) if product.price_b is not None else base_price
                    elif current_user.customer_type == CustomerType.TYPE_C:
                        display_price = float(product.price_c) if product.price_c is not None else base_price
                    elif current_user.customer_type == CustomerType.TYPE_D:
                        display_price = float(product.price_d) if product.price_d is not None else base_price
                    else:
                        display_price = base_price
                else:
                    # 如果不是公开商品，返回错误
                    return jsonify({'error': '该商品未对您开放'}), 403
        else:
            # 如果不是普通客户，显示基础价格
            display_price = base_price

        product_detail = {
            'id': product.id,
            'name': product.name,
            'description': product.description,
            'price': display_price,  # 使用计算后的价格
            'price_b': float(product.price_b) if product.price_b is not None else base_price,
            'price_c': float(product.price_c) if product.price_c is not None else base_price,
            'price_d': float(product.price_d) if product.price_d is not None else base_price,
            'cost_price': float(product.cost_price) if product.cost_price is not None else base_price,
            'specs': specs,  # 使用推送单中的规格或默认规格
            'specs_info': specs_info,  # 使用推送单中的规格信息或默认规格信息
            'images': json.loads(product.images) if product.images else [],
            'type': product.type,
            'created_at': product.created_at.isoformat() if product.created_at else None,
            'status': product.status if product.status is not None else 1,  # 默认上架
            'is_public': product.is_public if product.is_public is not None else 1,  # 默认公开
            'size': product.size if product.size is not None else '-',
            'weight': product.weight if product.weight is not None else '0',
            'yarn': product.yarn if product.yarn is not None else '-',
            'composition': product.composition if product.composition is not None else '-',
            'pushed_users': pushed_users_data,
            'not_pushed_users': not_pushed_users_data,
            'video_url': product.video_url if product.video_url is not None else ''
        }
        return jsonify({'product': product_detail}), 200

    except Exception as e:
        print(f"获取商品详情失败: {str(e)}")
        return jsonify({'error': '获取商品详情失败'}), 500