import pandas as pd
import json
import traceback
import random
import string
from datetime import datetime
from flask import jsonify, request
from wxcloudrun.views import login_required, db, app
from wxcloudrun.model import Product, StockRecord, User, PushOrder, PushOrderProduct, UserRole, DeliveryOrder, DeliveryItem, PurchaseOrder, PurchaseOrderItem, Payment
from sqlalchemy import func

@app.route('/products/import-stock', methods=['POST'])
@login_required
def import_stock_only(user_id):
    """
    导入库存数据，如果商品不存在则创建新商品
    Excel格式要求：
    - 必须包含"商品名称"和"数量"列
    - 可选包含"颜色"列，如果没有则默认为"默认"
    """
    try:
        print('开始处理库存导入请求...')
        if 'file' not in request.files:
            print('错误：没有上传文件')
            return jsonify({'error': '没有上传文件'}), 400
            
        file = request.files['file']
        print(f'接收到文件: {file.filename}, 类型: {file.content_type}')
        
        if not file.filename.endswith(('.xlsx', '.xls')):
            print(f'错误：不支持的文件类型: {file.filename}')
            return jsonify({'error': '只支持Excel文件'}), 400

        # 读取Excel文件
        try:
            df = pd.read_excel(file)
            print(f'成功读取Excel文件，共 {len(df)} 行数据')
            print('Excel表头:', list(df.columns))
            
            # 过滤掉数量为0的行
            df = df[df['数量'] > 0]
            print(f'过滤后剩余 {len(df)} 行有效数据')
            
        except Exception as e:
            print(f'读取Excel文件失败: {str(e)}')
            return jsonify({'error': f'读取Excel文件失败: {str(e)}'}), 400
        
        # 验证必要的列是否存在
        required_columns = ['商品名称', '数量']
        for col in required_columns:
            if col not in df.columns:
                return jsonify({'error': f'Excel文件缺少必要的列: {col}'}), 400
        
        # 合并相同商品名称和颜色的数量
        if '颜色' in df.columns:
            # 按商品名称和颜色分组，合并数量
            df_grouped = df.groupby(['商品名称', '颜色'])['数量'].sum().reset_index()
        else:
            # 如果没有颜色列，只按商品名称分组
            df_grouped = df.groupby('商品名称')['数量'].sum().reset_index()
            df_grouped['颜色'] = '默认'  # 添加默认颜色列
        
        updated_count = 0
        created_count = 0
        errors = []
        
        for index, row in df_grouped.iterrows():
            try:
                product_name = str(row['商品名称']).strip()
                color = str(row['颜色']).strip() if not pd.isna(row.get('颜色', '')) else '默认'
                quantity = int(row['数量']) if not pd.isna(row['数量']) else 0
                
                print(f'处理商品: {product_name}, 颜色: {color}, 数量: {quantity}')
                
                # 查找商品
                product = Product.query.filter_by(name=product_name).first()
                
                if product:
                    # 商品存在，更新specs中的库存
                    try:
                        # 解析现有的specs
                        specs = json.loads(product.specs) if product.specs else []
                        
                        # 查找颜色是否存在
                        color_found = False
                        for spec in specs:
                            if spec.get('color') == color:
                                # 更新现有颜色的库存
                                spec['stock'] = quantity
                                color_found = True
                                break
                        
                        # 如果颜色不存在，添加新的颜色规格
                        if not color_found:
                            specs.append({
                                'color': color,
                                'image': '',
                                'stock': quantity
                            })
                        
                        # 更新商品的specs
                        product.specs = json.dumps(specs)
                        updated_count += 1
                        print(f'更新商品 {product_name} 的 {color} 颜色库存为 {quantity}')
                        
                        # 记录库存变动
                        stock_record = StockRecord(
                            product_id=product.id,
                            change_amount=quantity,
                            type='adjust',
                            remark=f'通过Excel导入设置库存',
                            operator=f'user_{user_id}',
                            color=color,
                            created_at=datetime.now()
                        )
                        db.session.add(stock_record)
                    except Exception as e:
                        error_msg = f'更新商品 {product_name} 的 {color} 颜色库存失败: {str(e)}'
                        print(f'错误: {error_msg}')
                        errors.append(error_msg)
                        db.session.rollback()
                        continue
                else:
                    # 商品不存在，创建新商品
                    try:
                        # 生成新的商品ID
                        all_products = Product.query.filter(
                            Product.id.like('QY%')
                        ).all()
                        
                        max_number = 0
                        for p in all_products:
                            try:
                                num = int(p.id[2:])  # 跳过 'QY' 前缀
                                if num > max_number:
                                    max_number = num
                            except ValueError:
                                continue
                        
                        new_number = str(max_number + 1)
                        new_product_id = f'QY{new_number}'
                        print(f'创建新商品ID: {new_product_id}')
                        
                        # 创建默认规格
                        specs = [{
                            'color': color,
                            'image': '',
                            'stock': quantity
                        }]
                        
                        # 创建新商品
                        new_product = Product(
                            id=new_product_id,
                            name=product_name,
                            description='',
                            price='0',
                            price_b=0,
                            price_c=0,
                            price_d=0,
                            specs=json.dumps(specs),
                            type=5,  # 默认类型
                            created_at=datetime.now().isoformat(),
                            is_public=0,  # 默认不公开
                            status=1,  # 默认上架
                            size='-',
                            weight='0',
                            yarn='-',
                            composition='-'
                        )
                        db.session.add(new_product)
                        
                        # 记录库存变动
                        stock_record = StockRecord(
                            product_id=new_product_id,
                            change_amount=quantity,
                            type='in',
                            remark=f'通过Excel导入创建商品并设置库存',
                            operator=f'user_{user_id}',
                            color=color,
                            created_at=datetime.now()
                        )
                        db.session.add(stock_record)
                        
                        # 立即提交事务，确保商品创建成功
                        try:
                            db.session.commit()
                            created_count += 1
                            print(f'创建新商品 {product_name} 并设置 {color} 颜色库存 {quantity}')
                        except Exception as e:
                            db.session.rollback()
                            error_msg = f'创建商品 {product_name} 失败: {str(e)}'
                            print(f'错误: {error_msg}')
                            errors.append(error_msg)
                            continue
                    except Exception as e:
                        error_msg = f'创建商品 {product_name} 失败: {str(e)}'
                        print(f'错误: {error_msg}')
                        errors.append(error_msg)
                        db.session.rollback()
                        continue
                
                # 每处理10条记录提交一次事务（只针对更新现有商品的情况）
                if product and (index + 1) % 10 == 0:
                    db.session.commit()
                    print(f'已提交 {index + 1} 条记录')
                
            except Exception as e:
                error_msg = f'处理商品 {product_name} 时出错: {str(e)}'
                print(f'错误: {error_msg}')
                errors.append(error_msg)
                db.session.rollback()
        
        # 提交剩余的事务
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            errors.append(f'提交事务时出错: {str(e)}')
        
        print(f'\n导入完成: 更新 {updated_count} 个商品库存，创建 {created_count} 个新商品，失败 {len(errors)} 条')
            
        return jsonify({
            'code': 200,
            'message': '库存导入成功',
            'data': {
                'updated': updated_count,
                'created': created_count,
                'errors': errors if errors else None
            }
        })
        
    except Exception as e:
        print(f'导入过程发生错误: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({
            'code': 500,
            'message': '导入失败',
            'error': str(e)
        }), 500

@app.route('/users/import-and-push', methods=['POST'])
@login_required
def import_users_and_push(user_id):
    """
    导入用户数据并创建推送单
    Excel格式要求：
    - 必须包含"客户名称"列
    - 必须包含"商品"列
    - 必须包含"单价"列
    """
    try:
        print('开始处理用户导入和推送单创建请求...')
        if 'file' not in request.files:
            print('错误：没有上传文件')
            return jsonify({'error': '没有上传文件'}), 400
            
        file = request.files['file']
        print(f'接收到文件: {file.filename}, 类型: {file.content_type}')
        
        if not file.filename.endswith(('.xlsx', '.xls')):
            print(f'错误：不支持的文件类型: {file.filename}')
            return jsonify({'error': '只支持Excel文件'}), 400

        # 读取Excel文件
        try:
            df = pd.read_excel(file)
            print(f'成功读取Excel文件，共 {len(df)} 行数据')
            print('Excel表头:', list(df.columns))
            
        except Exception as e:
            print(f'读取Excel文件失败: {str(e)}')
            return jsonify({'error': f'读取Excel文件失败: {str(e)}'}), 400
        
        # 验证必要的列是否存在
        required_columns = ['客户名称', '商品', '单价']
        for col in required_columns:
            if col not in df.columns:
                return jsonify({'error': f'Excel文件缺少必要的列: {col}'}), 400
        
        created_users = 0
        created_push_orders = 0
        errors = []
        
        # 按客户名称分组处理数据
        for customer_name, group in df.groupby('客户名称'):
            try:
                customer_name = str(customer_name).strip()
                print(f'处理客户: {customer_name}')
                
                # 查找用户是否已存在
                user = User.query.filter_by(nickname=customer_name).first()
                
                if not user:
                    # 用户不存在，创建新用户
                    try:
                        # 生成随机用户名和密码
                        username = f"user_{random.randint(10000, 99999)}"
                        password = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
                        
                        # 创建新用户
                        new_user = User(
                            username=username,
                            password=password,  # 注意：实际应用中应该对密码进行加密
                            nickname=customer_name,
                            role=UserRole.CUSTOMER,
                            status=1,  # 默认启用
                            created_at=datetime.now()
                        )
                        db.session.add(new_user)
                        db.session.flush()  # 获取新用户的ID
                        user = new_user
                        created_users += 1
                        print(f'创建新用户: {customer_name}, 用户名: {username}, 密码: {password}')
                    except Exception as e:
                        error_msg = f'创建用户 {customer_name} 失败: {str(e)}'
                        print(f'错误: {error_msg}')
                        errors.append(error_msg)
                        db.session.rollback()
                        continue
                
                # 创建推送单
                try:
                    # 生成推送单号
                    order_number = f"PO{datetime.now().strftime('%Y%m%d%H%M%S')}{random.randint(100, 999)}"
                    
                    # 创建推送单
                    push_order = PushOrder(
                        user_id=user_id,  # 当前登录用户
                        order_number=order_number,
                        target_name=customer_name,
                        target_user_id=user.id,
                        status=1,  # 已推送
                        created_at=datetime.now()
                    )
                    db.session.add(push_order)
                    db.session.flush()  # 获取推送单ID
                    
                    # 处理该客户的所有商品
                    for _, row in group.iterrows():
                        product_name = str(row['商品']).strip()
                        price = float(row['单价']) if not pd.isna(row['单价']) else 0
                        
                        # 提取商品名称（只取-前面的部分）
                        product_name = product_name.split('-')[0].strip()
                        
                        # 查找商品
                        product = Product.query.filter_by(name=product_name).first()
                        
                        if product:
                            # 获取商品的所有颜色规格
                            specs = json.loads(product.specs) if product.specs else []
                            
                            # 创建推送单商品，使用所有颜色规格
                            push_order_product = PushOrderProduct(
                                push_order_id=push_order.id,
                                product_id=product.id,
                                price=price,
                                specs=json.dumps(specs),  # 包含所有颜色规格
                                created_at=datetime.now()
                            )
                            db.session.add(push_order_product)
                            
                            created_push_orders += 1
                            print(f'为商品 {product_name} 创建推送单商品，价格: {price}')
                        else:
                            # 商品不存在，创建新商品
                            try:
                                # 生成新的商品ID，格式为 Tp{number}
                                all_products = Product.query.filter(
                                    Product.id.like('Tp%')
                                ).all()
                                
                                max_number = 0
                                for p in all_products:
                                    try:
                                        num = int(p.id[2:])  # 跳过 'Tp' 前缀
                                        if num > max_number:
                                            max_number = num
                                    except ValueError:
                                        continue
                                
                                new_number = str(max_number + 1)
                                new_product_id = f'Tp{new_number}'
                                print(f'创建新商品ID: {new_product_id}')
                                
                                # 创建默认规格
                                specs = [{
                                    'color': '默认',
                                    'image': '',
                                    'stock': 0
                                }]
                                
                                # 创建新商品
                                new_product = Product(
                                    id=new_product_id,
                                    name=product_name,
                                    description='',
                                    price=price,
                                    price_b=price,
                                    price_c=price,
                                    price_d=price,
                                    specs=json.dumps(specs),
                                    type=5,  # 默认类型
                                    created_at=datetime.now(),
                                    is_public=0,  # 默认不公开
                                    status=0,  # 默认下架
                                    size='-',
                                    weight='0',
                                    yarn='-',
                                    composition='-'
                                )
                                db.session.add(new_product)
                                db.session.flush()  # 获取新商品的ID
                                
                                # 创建推送单商品
                                push_order_product = PushOrderProduct(
                                    push_order_id=push_order.id,
                                    product_id=new_product.id,
                                    price=price,
                                    specs=json.dumps(specs),
                                    created_at=datetime.now()
                                )
                                db.session.add(push_order_product)
                                
                                created_push_orders += 1
                                print(f'创建新商品 {product_name} 并创建推送单商品，价格: {price}')
                            except Exception as e:
                                error_msg = f'创建商品 {product_name} 失败: {str(e)}'
                                print(f'错误: {error_msg}')
                                errors.append(error_msg)
                                db.session.rollback()
                                continue
                    
                    # 提交当前客户的事务
                    db.session.commit()
                    print(f'成功为客户 {customer_name} 创建推送单')
                    
                except Exception as e:
                    error_msg = f'为客户 {customer_name} 创建推送单失败: {str(e)}'
                    print(f'错误: {error_msg}')
                    errors.append(error_msg)
                    db.session.rollback()
                    continue
                
            except Exception as e:
                error_msg = f'处理客户 {customer_name} 时出错: {str(e)}'
                print(f'错误: {error_msg}')
                errors.append(error_msg)
                db.session.rollback()
        
        print(f'\n导入完成: 创建 {created_users} 个用户，创建 {created_push_orders} 个推送单，失败 {len(errors)} 条')
            
        return jsonify({
            'code': 200,
            'message': '用户导入和推送单创建成功',
            'data': {
                'created_users': created_users,
                'created_push_orders': created_push_orders,
                'errors': errors if errors else None
            }
        })
        
    except Exception as e:
        print(f'导入过程发生错误: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({
            'code': 500,
            'message': '导入失败',
            'error': str(e)
        }), 500

@app.route('/delivery-orders/import-history', methods=['POST'])
@login_required
def import_history_delivery_orders(user_id):
    """
    导入历史发货单数据
    Excel格式要求：
    数量表：
    - 日期
    - 客户名称
    - 商品
    - 颜色
    - 商品数量
    
    单价表：
    - 客户名称
    - 商品
    - 单价
    """
    try:
        print('开始处理历史发货单导入请求...')
        if 'file' not in request.files:
            print('错误：没有上传文件')
            return jsonify({'error': '没有上传文件'}), 400
            
        file = request.files['file']
        print(f'接收到文件: {file.filename}, 类型: {file.content_type}')
        
        if not file.filename.endswith(('.xlsx', '.xls')):
            print(f'错误：不支持的文件类型: {file.filename}')
            return jsonify({'error': '只支持Excel文件'}), 400

        # 读取Excel文件
        try:
            # 读取数量表，指定日期列的格式
            df_quantity = pd.read_excel(file, sheet_name='数量', parse_dates=['日期'])
            print(f'成功读取数量表，共 {len(df_quantity)} 行数据')
            print('数量表表头:', list(df_quantity.columns))
            print('日期列数据类型:', df_quantity['日期'].dtype)
            print('日期列示例值:', df_quantity['日期'].head())
            
            # 读取单价表
            df_price = pd.read_excel(file, sheet_name='单价')
            print(f'成功读取单价表，共 {len(df_price)} 行数据')
            print('单价表表头:', list(df_price.columns))
            
        except Exception as e:
            print(f'读取Excel文件失败: {str(e)}')
            return jsonify({'error': f'读取Excel文件失败: {str(e)}'}), 400
        
        # 验证必要的列是否存在
        quantity_required_columns = ['日期', '客户名称', '商品', '颜色', '商品数量']
        price_required_columns = ['客户名称', '商品', '单价']
        
        for col in quantity_required_columns:
            if col not in df_quantity.columns:
                return jsonify({'error': f'数量表缺少必要的列: {col}'}), 400
                
        for col in price_required_columns:
            if col not in df_price.columns:
                return jsonify({'error': f'单价表缺少必要的列: {col}'}), 400
        
        created_orders = 0
        errors = []
        # 按日期和客户名称分组处理数据
        for (delivery_date, customer_name), group in df_quantity.groupby(['日期', '客户名称']):
            print(f'处理发货单: 日期 {delivery_date}, 客户 {customer_name}')
            try:
                delivery_date = str(delivery_date).strip()
                customer_name = str(customer_name).strip()
                print(f'处理发货单: 日期 {delivery_date}, 客户 {customer_name}')
                
                # 查找用户是否已存在
                user = User.query.filter_by(nickname=customer_name).first()
                
                if not user:
                    error_msg = f'客户 {customer_name} 不存在，请先创建客户'
                    print(f'错误: {error_msg}')
                    errors.append(error_msg)
                    continue
                
                # 将日期字符串转换为datetime对象
                try:
                    delivery_date_obj = datetime.strptime(delivery_date, '%Y-%m-%d %H:%M:%S')
                    print(f'转换后的日期对象: {delivery_date_obj}')
                except Exception as e:
                    error_msg = f'日期格式错误: {delivery_date}'
                    print(f'错误: {error_msg}')
                    errors.append(error_msg)
                    continue
                
                # 检查是否已存在同一天同一客户的采购单
                existing_purchase_order = PurchaseOrder.query.filter(
                    PurchaseOrder.user_id == user.id,
                    PurchaseOrder.created_at >= delivery_date_obj.replace(hour=0, minute=0, second=0, microsecond=0),
                    PurchaseOrder.created_at <= delivery_date_obj.replace(hour=23, minute=59, second=59, microsecond=999999)
                ).first()
                
                if existing_purchase_order:
                    print(f'找到已存在的采购单: {existing_purchase_order.order_number}')
                    purchase_order = existing_purchase_order
                else:
                    # 创建新的采购单
                    try:
                        order_number = f"PO{datetime.now().strftime('%Y%m%d%H%M%S')}{random.randint(100, 999)}"
                        purchase_order = PurchaseOrder(
                            order_number=order_number,
                            user_id=user.id,
                            total_amount=0,  # 初始总金额为0
                            status=2,  
                            created_at=delivery_date_obj,  # 使用Excel中的日期
                            handler_id=user_id  # 使用 handler_id 字段
                        )
                        db.session.add(purchase_order)
                        db.session.flush()
                        print(f'创建新采购单: {order_number}')
                    except Exception as e:
                        error_msg = f'创建采购单失败: {str(e)}'
                        print(f'错误: {error_msg}')
                        errors.append(error_msg)
                        db.session.rollback()
                        continue
                
                # 处理该客户的所有商品
                purchase_items = []  # 用于计算采购单总金额
                for _, row in group.iterrows():
                    product_name = str(row['商品']).strip()
                    color = str(row['颜色']).strip()
                    quantity = int(row['商品数量']) if not pd.isna(row['商品数量']) else 0
                    
                    # 获取商品单价
                    price_row = df_price[
                        (df_price['客户名称'] == customer_name) & 
                        (df_price['商品'] == product_name)
                    ]
                    print(f'客户名称: {customer_name}, 商品名称: {product_name}')
                    price = float(price_row['单价'].iloc[0]) if not price_row.empty else 0
                    print(f'获取商品单价: {price}')
                    # 查找商品
                    product = Product.query.filter_by(name=product_name).first()
                    
                    if not product:
                        # 商品不存在，创建新商品
                        try:
                            # 生成新的商品ID，格式为 TP{number}
                            all_products = Product.query.filter(
                                Product.id.like('TP%')
                            ).all()
                            
                            max_number = 0
                            for p in all_products:
                                try:
                                    num = int(p.id[2:])  # 跳过 'TP' 前缀
                                    if num > max_number:
                                        max_number = num
                                except ValueError:
                                    continue
                            
                            new_number = str(max_number + 1)
                            new_product_id = f'TP{new_number}'
                            print(f'创建新商品ID: {new_product_id}')
                            
                            # 创建默认规格
                            specs = [{
                                'color': color,
                                'image': '',
                                'stock': 0
                            }]
                            
                            # 创建新商品
                            new_product = Product(
                                id=new_product_id,
                                name=product_name,
                                description='',
                                price=price,
                                price_b=price,
                                price_c=price,
                                price_d=price,
                                specs=json.dumps(specs),
                                type=5,
                                created_at=datetime.now(),
                                is_public=0,
                                status=0,
                                size='-',
                                weight='0',
                                yarn='-',
                                composition='-'
                            )
                            db.session.add(new_product)
                            db.session.flush()
                            product = new_product
                            print(f'创建新商品 {product_name}，价格: {price}')
                        except Exception as e:
                            error_msg = f'创建商品 {product_name} 失败: {str(e)}'
                            print(f'错误: {error_msg}')
                            errors.append(error_msg)
                            db.session.rollback()
                            continue
                    
                    # 检查采购单中是否已存在相同的商品
                    existing_purchase_item = PurchaseOrderItem.query.filter_by(
                        order_id=purchase_order.id,
                        product_id=product.id,
                        color=color
                    ).first()
                    
                    if existing_purchase_item:
                        # 更新现有商品的数量
                        existing_purchase_item.quantity += quantity
                        print(f'更新采购单商品数量: {product_name}, 颜色: {color}, 新数量: {existing_purchase_item.quantity}')
                    else:
                        # 创建采购单商品
                        try:
                            purchase_item = PurchaseOrderItem(
                                order_id=purchase_order.id,
                                product_id=product.id,
                                quantity=quantity,
                                price=price,
                                color=color,
                                logo_price=0.0,  # 加标价格
                                accessory_price=0.0,  # 辅料价格
                                packaging_price=0.0  # 包装价格
                            )
                            db.session.add(purchase_item)
                            purchase_items.append(purchase_item)
                            print(f'创建采购单商品: {product_name}, 颜色: {color}, 数量: {quantity}, 价格: {price}')
                        except Exception as e:
                            error_msg = f'创建采购单商品失败: {str(e)}'
                            print(f'错误: {error_msg}')
                            errors.append(error_msg)
                            db.session.rollback()
                            continue
                
                # 更新采购单总金额
                if purchase_items:
                    total_amount = sum(item.price * item.quantity for item in purchase_items)
                    purchase_order.total_amount = total_amount
                    print(f'更新采购单总金额: {total_amount}')
                
                # 创建发货单
                try:
                    # 生成发货单号
                    order_number = f"DO{datetime.now().strftime('%Y%m%d%H%M%S')}{random.randint(100, 999)}"
                    
                    # 创建发货单
                    delivery_order = DeliveryOrder(
                        order_number=order_number,
                        customer_id=user.id,
                        customer_name=customer_name,
                        delivery_date=delivery_date_obj.date(),  # 只保存日期部分
                        status=1,  # 已完成
                        created_at=delivery_date_obj,  # 使用与采购单相同的时间
                        created_by=user_id
                    )
                    db.session.add(delivery_order)
                    db.session.flush()
                    print(f'创建新发货单: {order_number}')
                    
                    # 添加发货单商品
                    for purchase_item in purchase_items:
                        delivery_item = DeliveryItem(
                            delivery_id=delivery_order.id,
                            order_number=purchase_order.order_number,  # 关联采购单号
                            product_id=purchase_item.product_id,
                            quantity=purchase_item.quantity,
                            color=purchase_item.color
                        )
                        db.session.add(delivery_item)
                        created_orders += 1
                        print(f'创建发货单商品: {product_name}, 颜色: {color}, 数量: {quantity}')
                    
                except Exception as e:
                    error_msg = f'创建发货单失败: {str(e)}'
                    print(f'错误: {error_msg}')
                    errors.append(error_msg)
                    db.session.rollback()
                    continue
                
                # 提交当前发货单的事务
                db.session.commit()
                print(f'成功处理发货单: {delivery_order.order_number}')
                
            except Exception as e:
                error_msg = f'处理发货单时出错: {str(e)}'
                print(f'错误: {error_msg}')
                errors.append(error_msg)
                db.session.rollback()
        
        print(f'\n导入完成: 创建/更新 {created_orders} 个发货单商品，失败 {len(errors)} 条')
            
        return jsonify({
            'code': 200,
            'message': '历史发货单导入成功',
            'data': {
                'created_orders': created_orders,
                'errors': errors if errors else None
            }
        })
        
    except Exception as e:
        print(f'导入过程发生错误: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({
            'code': 500,
            'message': '导入失败',
            'error': str(e)
        }), 500

@app.route('/customer/daily-stats', methods=['GET'])
@login_required
def get_customer_daily_stats(user_id):
    """
    获取客户每日统计数据
    返回数据包括：
    - 今日下单数量
    - 今日实发数量
    - 今日实发金额
    - 累计发货总量
    - 累计货款总额
    - 已付金额
    """
    try:
        # 获取今日的采购单统计
        today_purchase_stats = db.session.query(
            func.count(PurchaseOrder.id).label('order_count'),
            func.sum(PurchaseOrderItem.quantity).label('total_quantity'),
            func.sum(PurchaseOrder.total_amount).label('total_amount')
        ).join(
            PurchaseOrderItem, 
            PurchaseOrder.id == PurchaseOrderItem.order_id
        ).filter(
            PurchaseOrder.user_id == user_id,
            func.date(PurchaseOrder.created_at) == func.current_date()
        ).first()

        # 获取今日的发货单统计
        today_delivery_stats = db.session.query(
            func.sum(DeliveryItem.quantity).label('delivered_quantity'),
            func.sum(PurchaseOrderItem.price * DeliveryItem.quantity).label('delivered_amount')
        ).join(
            DeliveryOrder, 
            DeliveryItem.delivery_id == DeliveryOrder.id
        ).join(
            PurchaseOrder,
            DeliveryItem.order_number == PurchaseOrder.order_number
        ).join(
            PurchaseOrderItem,
            db.and_(
                PurchaseOrder.id == PurchaseOrderItem.order_id,
                PurchaseOrderItem.product_id == DeliveryItem.product_id,
                PurchaseOrderItem.color == DeliveryItem.color
            )
        ).filter(
            PurchaseOrder.user_id == user_id,
            func.date(DeliveryOrder.created_at) == func.current_date(),
            DeliveryOrder.status.in_([1, 2])  # 已发货或已完成
        ).first()

        # 获取累计统计数据
        total_stats = db.session.query(
            func.sum(DeliveryItem.quantity).label('total_delivered_quantity'),
            func.sum(PurchaseOrderItem.price * DeliveryItem.quantity).label('total_delivered_amount'),
            func.sum(Payment.amount).label('paid_amount')
        ).join(
            DeliveryOrder, 
            DeliveryItem.delivery_id == DeliveryOrder.id
        ).join(
            PurchaseOrder,
            DeliveryItem.order_number == PurchaseOrder.order_number
        ).join(
            PurchaseOrderItem,
            db.and_(
                PurchaseOrder.id == PurchaseOrderItem.order_id,
                PurchaseOrderItem.product_id == DeliveryItem.product_id,
                PurchaseOrderItem.color == DeliveryItem.color
            )
        ).outerjoin(
            Payment,
            Payment.customer_id == PurchaseOrder.user_id
        ).filter(
            PurchaseOrder.user_id == user_id,
            DeliveryOrder.status.in_([1, 2])  # 已发货或已完成
        ).first()

        return jsonify({
            'code': 0,
            'data': {
                'day_total_count': today_purchase_stats.order_count or 0,  # 今日下单数量
                'day_total_quantity': today_delivery_stats.delivered_quantity or 0,  # 今日实发数量
                'day_total_amount': today_delivery_stats.delivered_amount or 0,  # 今日实发金额
                'total_delivered_quantity': total_stats.total_delivered_quantity or 0,  # 累计发货总量
                'total_delivered_amount': total_stats.total_delivered_amount or 0,  # 累计货款总额
                'paid_amount': total_stats.paid_amount or 0,  # 已付金额
                'pending_payment': float(total_stats.total_delivered_amount) - float(total_stats.paid_amount) or 0  # 剩余应付金额
            }
        })

    except Exception as e:
        print(f'获取客户每日统计数据失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({
            'code': 500,
            'message': '获取统计数据失败',
            'error': str(e)
        }), 500

@app.route('/customer/daily-details', methods=['GET'])
@login_required
def get_customer_daily_details(user_id):
    """
    获取客户每日详细数据
    参数：
    - type: 查询类型
        - day_total_count: 今日下单明细
        - day_total_quantity: 今日实发明细
        - day_total_amount: 今日实发金额明细
    """
    try:
        query_type = request.args.get('type')
        if not query_type:
            return jsonify({'code': 400, 'message': '缺少查询类型参数'}), 400

        if query_type == 'day_total_count':
            # 获取今日下单明细
            details = db.session.query(
                Product.id.label('product_id'),
                Product.name.label('product_name'),
                PurchaseOrderItem.color,
                PurchaseOrderItem.quantity,
                PurchaseOrderItem.price
            ).join(
                PurchaseOrderItem,
                Product.id == PurchaseOrderItem.product_id
            ).join(
                PurchaseOrder,
                PurchaseOrderItem.order_id == PurchaseOrder.id
            ).filter(
                PurchaseOrder.user_id == user_id,
                func.date(PurchaseOrder.created_at) == func.current_date()
            ).all()
        else:
            # 获取今日实发明细
            details = db.session.query(
                Product.id.label('product_id'),
                Product.name.label('product_name'),
                DeliveryItem.color,
                DeliveryItem.quantity,
                PurchaseOrderItem.price
            ).join(
                DeliveryOrder,
                DeliveryItem.delivery_id == DeliveryOrder.id
            ).join(
                PurchaseOrder,
                DeliveryItem.order_number == PurchaseOrder.order_number
            ).join(
                PurchaseOrderItem,
                db.and_(
                    PurchaseOrder.id == PurchaseOrderItem.order_id,
                    PurchaseOrderItem.product_id == DeliveryItem.product_id,
                    PurchaseOrderItem.color == DeliveryItem.color
                )
            ).join(
                Product,
                Product.id == DeliveryItem.product_id
            ).filter(
                PurchaseOrder.user_id == user_id,
                func.date(DeliveryOrder.created_at) == func.current_date(),
                DeliveryOrder.status.in_([1, 2])  # 已发货或已完成
            ).all()

        # 转换查询结果为字典列表
        result = [{
            'product_id': item.product_id,
            'product_name': item.product_name,
            'color': item.color,
            'quantity': item.quantity,
            'price': float(item.price) if item.price else 0
        } for item in details]

        return jsonify({
            'code': 0,
            'data': result
        })

    except Exception as e:
        print(f'获取客户每日详细数据失败: {str(e)}')
        print(f'错误追踪:\n{traceback.format_exc()}')
        return jsonify({
            'code': 500,
            'message': '获取详细数据失败',
            'error': str(e)
        }), 500

