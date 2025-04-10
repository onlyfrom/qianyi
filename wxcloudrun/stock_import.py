import pandas as pd
import json
import traceback
import random
import string
from datetime import datetime
from flask import jsonify, request
from wxcloudrun.views import login_required, db, app
from wxcloudrun.model import Product, StockRecord, User, PushOrder, PushOrderProduct, UserRole

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
                            
                            # 为每个颜色创建推送单商品
                            for spec in specs:
                                color = spec.get('color', '默认')
                                
                                # 创建推送单商品
                                push_order_product = PushOrderProduct(
                                    push_order_id=push_order.id,
                                    product_id=product.id,
                                    price=price,
                                    specs=json.dumps([spec]),  # 只包含当前颜色
                                    specs_info=json.dumps({'color': color}),
                                    created_at=datetime.now()
                                )
                                db.session.add(push_order_product)
                            
                            created_push_orders += 1
                            print(f'为商品 {product_name} 创建推送单商品，价格: {price}')
                        else:
                            error_msg = f'商品 {product_name} 不存在，跳过'
                            print(f'警告: {error_msg}')
                            errors.append(error_msg)
                    
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