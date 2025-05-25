from flask import Blueprint, request, jsonify
from wxcloudrun import db
from wxcloudrun.model import Product, ColorStock, ManufacturePlan, ManufactureStatusHistory, Yarn
from sqlalchemy import or_, func
from datetime import datetime, timedelta

manufacture_bp = Blueprint('manufacture', __name__)

# 状态名称映射
STATUS_MAPPING = {
    'weaving': '机织',
    'flat_sewing': '平车',
    'cuff_sewing': '套口',
    'handwork': '手工',
    'washing': '下水',
    'entry': '进场'
}

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
                weaving=0,
                flat_sewing=0,
                cuff_sewing=0,
                handwork=0,
                washing=0,
                entry=0
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
            'images': product.images if product.images else '',            
            'quantity': plan.quantity,
            'color': plan.color,
            'weaving': plan.weaving or 0,
            'flat_sewing': plan.flat_sewing or 0,
            'cuff_sewing': plan.cuff_sewing or 0,
            'handwork': plan.handwork or 0,
            'washing': plan.washing or 0,
            'entry': plan.entry or 0,
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
        if status_type in ['weaving', 'flat_sewing', 'cuff_sewing', 'handwork', 'washing', 'entry']:
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
            if status_type in STATUS_MAPPING:
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
            '机织': plan.weaving or 0,
            '平车': plan.flat_sewing or 0,
            '套口': plan.cuff_sewing or 0,
            '手工': plan.handwork or 0,
            '下水': plan.washing or 0,
            '进场': plan.entry or 0,
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
        if status_type not in ['weaving', 'flat_sewing', 'cuff_sewing', 'handwork', 'washing', 'entry']:
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
            'weaving': {
                'total': ManufacturePlan.query.filter_by(weaving=0).count(),
                'completed': ManufacturePlan.query.filter_by(weaving=1).count()
            },
            'flat_sewing': {
                'total': ManufacturePlan.query.filter_by(flat_sewing=0).count(),
                'completed': ManufacturePlan.query.filter_by(flat_sewing=1).count()
            },
            'cuff_sewing': {
                'total': ManufacturePlan.query.filter_by(cuff_sewing=0).count(),
                'completed': ManufacturePlan.query.filter_by(cuff_sewing=1).count()
            },
            'handwork': {
                'total': ManufacturePlan.query.filter_by(handwork=0).count(),
                'completed': ManufacturePlan.query.filter_by(handwork=1).count()
            },
            'washing': {    
                'total': ManufacturePlan.query.filter_by(washing=0).count(),
                'completed': ManufacturePlan.query.filter_by(washing=1).count()
            },
            'entry': {
                'total': ManufacturePlan.query.filter_by(entry=0).count(),
                'completed': ManufacturePlan.query.filter_by(entry=1).count()
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
                '机织': '已完成' if plan.weaving == 1 else '未完成',
                '平车': '已完成' if plan.flat_sewing == 1 else '未完成',
                '套口': '已完成' if plan.cuff_sewing == 1 else '未完成',
                '手工': '已完成' if plan.handwork == 1 else '未完成',
                '下水': '已完成' if plan.washing == 1 else '未完成',
                '进场': '已完成' if plan.entry == 1 else '未完成',
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
def get_plan_status_history(plan_id):
    """获取制造计划状态修改历史"""
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

@manufacture_bp.route('/api/yarn/list', methods=['GET'])
def get_yarn_list():
    """获取纱线列表"""
    page = int(request.args.get('page', 1))
    page_size = int(request.args.get('page_size', 10))
    search = request.args.get('search', '')
    filter_material = request.args.get('filter', '')

    # 构建查询
    query = Yarn.query

    # 搜索条件
    if search:
        query = query.filter(
            or_(
                Yarn.name.like(f'%{search}%'),
                Yarn.specification.like(f'%{search}%')
            )
        )

    # 材质筛选
    if filter_material:
        query = query.filter(Yarn.material == filter_material)

    # 分页查询
    pagination = query.paginate(page=page, per_page=page_size)
    yarns = pagination.items

    # 构建返回数据
    result = []
    for yarn in yarns:
        result.append({
            'id': yarn.id,
            'name': yarn.name,
            'material': yarn.material,
            'weight': float(yarn.weight),
            'color': yarn.color,
            'color_code': yarn.color_code,
            'specification': yarn.specification,
            'supplier': yarn.supplier,
            'stock': yarn.stock,
            'remark': yarn.remark,
            'created_at': yarn.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'updated_at': yarn.updated_at.strftime('%Y-%m-%d %H:%M:%S')
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

@manufacture_bp.route('/api/yarn', methods=['POST'])
def create_yarn():
    """创建纱线"""
    data = request.get_json()
    if not data:
        return jsonify({'code': 1, 'message': '参数错误'})

    try:
        # 验证必要字段
        required_fields = ['name', 'material', 'weight', 'color', 'color_code', 'specification', 'supplier', 'stock']
        for field in required_fields:
            if field not in data:
                return jsonify({'code': 1, 'message': f'缺少必要参数: {field}'})

        # 创建纱线记录
        yarn = Yarn(
            name=data['name'],
            material=data['material'],
            weight=data['weight'],
            color=data['color'],
            color_code=data['color_code'],
            specification=data['specification'],
            supplier=data['supplier'],
            stock=data['stock'],
            remark=data.get('remark', '')
        )
        db.session.add(yarn)
        db.session.commit()

        return jsonify({
            'code': 0,
            'message': '创建成功',
            'data': {
                'id': yarn.id
            }
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'code': 1,
            'message': f'创建失败: {str(e)}'
        })

@manufacture_bp.route('/api/yarn/<int:yarn_id>', methods=['PUT'])
def update_yarn(yarn_id):
    """更新纱线信息"""
    data = request.get_json()
    if not data:
        return jsonify({'code': 1, 'message': '参数错误'})

    try:
        yarn = Yarn.query.get(yarn_id)
        if not yarn:
            return jsonify({'code': 1, 'message': '纱线不存在'})

        # 更新字段
        fields = ['name', 'material', 'weight', 'color', 'color_code', 'specification', 'supplier', 'stock', 'remark']
        for field in fields:
            if field in data:
                setattr(yarn, field, data[field])

        db.session.commit()
        return jsonify({
            'code': 0,
            'message': '更新成功'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'code': 1,
            'message': f'更新失败: {str(e)}'
        })

@manufacture_bp.route('/api/yarn/<int:yarn_id>', methods=['DELETE'])
def delete_yarn(yarn_id):
    """删除纱线"""
    try:
        yarn = Yarn.query.get(yarn_id)
        if not yarn:
            return jsonify({'code': 1, 'message': '纱线不存在'})

        db.session.delete(yarn)
        db.session.commit()
        return jsonify({
            'code': 0,
            'message': '删除成功'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'code': 1,
            'message': f'删除失败: {str(e)}'
        })

@manufacture_bp.route('/api/yarn/template', methods=['GET'])
def download_yarn_template():
    """下载纱线导入模板"""
    try:
        import pandas as pd
        from io import BytesIO
        from flask import send_file

        # 创建示例数据
        data = {
            '纱厂': ['示例纱厂1', '示例纱厂2'],
            '纱线': ['示例纱线1', '示例纱线2'],
            '色号': ['#FFFFFF', '#000000'],
            '颜色名称': ['白色', '黑色'],
            '备注': ['示例备注1', '示例备注2']
        }
        
        # 创建DataFrame
        df = pd.DataFrame(data)
        
        # 创建Excel文件
        output = BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='纱线导入模板')
        
        output.seek(0)
        
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name='纱线导入模板.xlsx'
        )
    except Exception as e:
        return jsonify({
            'code': 1,
            'message': f'下载模板失败: {str(e)}'
        })

@manufacture_bp.route('/api/yarn/import', methods=['POST'])
def import_yarn():
    """导入纱线数据"""
    try:
        if 'file' not in request.files:
            return jsonify({'code': 1, 'message': '未上传文件'})
        
        file = request.files['file']
        if not file or file.filename == '':
            return jsonify({'code': 1, 'message': '未选择文件'})
            
        if not file.filename.endswith(('.xlsx', '.xls')):
            return jsonify({'code': 1, 'message': '只支持Excel文件(.xlsx或.xls)'})
        
        import pandas as pd
        from werkzeug.utils import secure_filename
        
        # 读取Excel文件
        try:
            df = pd.read_excel(file)
        except Exception as e:
            return jsonify({'code': 1, 'message': f'Excel文件读取失败: {str(e)}'})
        
        # 验证必要的列是否存在
        required_columns = ['纱厂', '纱线', '色号', '颜色名称']
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            return jsonify({'code': 1, 'message': f'缺少必要的列: {", ".join(missing_columns)}'})
        
        # 验证数据是否为空
        if df.empty:
            return jsonify({'code': 1, 'message': 'Excel文件中没有数据'})
        
        # 处理数据
        success_count = 0
        error_count = 0
        error_messages = []
        
        print('开始导入，总行数:', len(df))
        
        for index, row in df.iterrows():
            try:
                # 数据验证
                if pd.isna(row['纱厂']) or pd.isna(row['纱线']) or pd.isna(row['色号']) or pd.isna(row['颜色名称']):
                    raise ValueError('必填字段不能为空')
                
                # 检查是否已存在相同的纱线
                existing_yarn = Yarn.query.filter_by(
                    name=str(row['纱线']).strip(),
                    color_code=str(row['色号']).strip()
                ).first()
                
                if existing_yarn:
                    raise ValueError('该纱线已存在')
                
                # 创建纱线记录
                yarn = Yarn(
                    name=str(row['纱线']).strip(),
                    material='',  # 留空
                    weight=0,     # 留空
                    color=str(row['颜色名称']).strip(),
                    color_code=str(row['色号']).strip(),
                    specification='',  # 留空
                    supplier=str(row['纱厂']).strip(),
                    stock=0,      # 留空
                    remark=str(row.get('备注', '')).strip() if not pd.isna(row.get('备注', '')) else ''  # 备注可选
                )
                
                print(f'处理第{index + 2}行:', {
                    'name': yarn.name,
                    'color': yarn.color,
                    'color_code': yarn.color_code,
                    'supplier': yarn.supplier
                })
                
                db.session.add(yarn)
                success_count += 1
                
                # 每100条提交一次，避免事务太大
                if success_count % 100 == 0:
                    db.session.commit()
                    print(f'已成功导入{success_count}条记录')
                
            except Exception as e:
                error_count += 1
                error_msg = f'第{index + 2}行导入失败: {str(e)}'
                error_messages.append(error_msg)
                print(error_msg)
                continue
        
        # 最终提交
        try:
            db.session.commit()
            print('导入完成，最终提交成功')
        except Exception as e:
            db.session.rollback()
            print('最终提交失败:', str(e))
            return jsonify({
                'code': 1,
                'message': f'数据保存失败: {str(e)}',
                'data': {
                    'success_count': success_count,
                    'error_count': error_count,
                    'error_messages': error_messages
                }
            })
        
        return jsonify({
            'code': 0,
            'message': f'导入完成，成功: {success_count}条，失败: {error_count}条',
            'data': {
                'success_count': success_count,
                'error_count': error_count,
                'error_messages': error_messages
            }
        })
    except Exception as e:
        db.session.rollback()
        print('导入过程发生错误:', str(e))
        return jsonify({
            'code': 1,
            'message': f'导入失败: {str(e)}'
        }) 