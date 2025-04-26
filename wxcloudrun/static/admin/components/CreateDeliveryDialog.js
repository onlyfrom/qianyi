const CreateDeliveryDialog = {
    template: `
        <el-dialog 
            v-model="dialogVisible" 
            title="新建发货单" 
            width="900px"
            destroy-on-close
            @close="handleDialogClose">
            <el-form :model="deliveryForm" label-width="100px">
                <el-tabs v-model="activeTab">
                    <el-tab-pane label="基本信息" name="basic">
                        <el-form-item label="客户姓名">
                            <el-input v-model="deliveryForm.customerName" disabled></el-input>
                        </el-form-item>
                        <el-form-item label="联系电话">
                            <el-input v-model="deliveryForm.customerPhone" disabled></el-input>
                        </el-form-item>
                        <el-form-item label="发货日期">
                            <el-date-picker
                                v-model="deliveryForm.deliveryDate"
                                type="date"
                                placeholder="选择日期"
                                style="width: 100%">
                            </el-date-picker>
                        </el-form-item>
                        <el-form-item label="物流公司" required>
                            <el-select
                                v-model="deliveryForm.logistics_company"
                                placeholder="请选择物流公司"
                                allow-create
                                filterable
                                style="width: 100%">
                                <el-option
                                    v-for="item in logisticsOptions"
                                    :key="item.value"
                                    :label="item.label"
                                    :value="item.value">
                                </el-option>
                            </el-select>
                        </el-form-item>
                        <el-form-item label="物流单号">
                            <el-input 
                                v-model="deliveryForm.tracking_number"
                                placeholder="请输入物流单号">
                            </el-input>
                        </el-form-item>
                        <el-form-item label="备注">
                            <el-input 
                                v-model="deliveryForm.remark" 
                                type="textarea" 
                                :rows="3"
                                placeholder="请输入备注信息">
                            </el-input>
                        </el-form-item>
                    </el-tab-pane>
                    
                    <el-tab-pane label="商品信息" name="products">
                        <div v-for="(pkg, pkgIndex) in deliveryForm.packages" :key="pkgIndex" class="package-section">
                            <div class="package-header">
                                <h3>包裹 {{ pkgIndex + 1 }}</h3>
                                <div class="package-actions">
                                    
                                </div>
                            </div>
                            
                            <el-table :data="pkg.items" border>
                                <el-table-column prop="product_name" label="商品名称"></el-table-column>
                                <el-table-column label="颜色" width="120">
                                    <template #default="scope">
                                        <el-input v-model="scope.row.color" placeholder="输入颜色"></el-input>
                                    </template>
                                </el-table-column>
                                <el-table-column label="数量" width="150">
                                    <template #default="scope">
                                        <el-input-number 
                                            v-model="scope.row.quantity"                                            
                                            :max="scope.row.max_quantity"
                                            size="small">
                                        </el-input-number>
                                    </template>
                                </el-table-column>
                                <el-table-column label="操作" width="100">
                                    <template #default="scope">
                                        <el-button 
                                            type="danger" 
                                            size="small" 
                                            @click="removeItem(pkgIndex, scope.$index)">
                                            删除
                                        </el-button>
                                    </template>
                                </el-table-column>
                            </el-table>
                            
                            <div class="add-item-row">
                            <el-button 
                                        type="danger" 
                                        size="small" 
                                        @click="deletePackage(pkgIndex)"
                                        :disabled="deliveryForm.packages.length <= 1">
                                        删除包裹
                                    </el-button>
                                <el-button 
                                    type="primary" 
                                    size="small" 
                                    @click="showAddProductPopup(pkgIndex)">
                                    添加商品
                                </el-button>
                            </div>
                        </div>
                        
                        <div class="add-package-row">
                            <el-button 
                                type="primary" 
                                @click="addPackage">
                                添加新包裹
                            </el-button>
                        </div>
                    </el-tab-pane>
                    
                    <el-tab-pane label="打包图片">
                        <el-upload
                            action="#"
                            list-type="picture-card"
                            :auto-upload="false"
                            :file-list="deliveryImageFiles"
                            :on-preview="handlePictureCardPreview"
                            :on-remove="handleDeliveryImageRemove">
                            <i class="el-icon-plus"></i>
                        </el-upload>
                    </el-tab-pane>
                </el-tabs>
                
                <div style="text-align: right; margin-top: 20px;">
                    <el-button @click="handleClose">取消</el-button>
                    <el-button type="primary" @click="submitDeliveryForm">确定</el-button>
                </div>
            </el-form>
        </el-dialog>
        
        <!-- 添加商品对话框 -->
        <el-dialog v-model="addProductPopupVisible" title="选择商品" width="70%">
            <div class="popup-header">
                <el-button type="primary" class="add-all-btn" @click="addAllProducts">添加全部</el-button>
            </div>
            
            <el-table :data="availableProducts" border @selection-change="handleProductSelectionChange" class="product-table">
                <el-table-column type="selection" width="55">
                    <template #default="scope">
                        <el-checkbox 
                            :model-value="selectedProductMap.has(scope.row.product_id + '-' + scope.row.color)"
                            @change="(val) => handleProductSelect(val, scope.row)">
                        </el-checkbox>
                    </template>
                </el-table-column>
                <el-table-column prop="productName" label="商品名称" min-width="180">
                    <template #default="scope">
                        <div>
                            {{ scope.row.product_name }}
                            <div class="service-tags">
                                <el-tag v-if="scope.row.packaging_price > 0" size="small" type="info">包装</el-tag>
                                <el-tag v-if="scope.row.logo_price > 0" size="small" type="info">打标</el-tag>
                                <el-tag v-if="scope.row.accessory_price > 0" size="small" type="info">辅料</el-tag>
                            </div>
                        </div>
                    </template>
                </el-table-column>
                <el-table-column prop="color" label="颜色" width="120" >
                    <template #default="scope">
                        <el-tag size="small" type="info">{{ scope.row.color }}</el-tag>
                    </template>
                </el-table-column>
                <el-table-column prop="max_quantity" label="待发数量" width="120" >
                    <template #default="scope">
                        <el-tag size="small" type="info">{{ scope.row.max_quantity }}</el-tag>
                    </template>
                </el-table-column>
            </el-table>
            
            <template #footer>
                <span class="dialog-footer">
                    <el-button @click="addProductPopupVisible = false">取消</el-button>
                    <el-button type="primary" @click="confirmAddProducts">确定</el-button>
                </span>
            </template>
        </el-dialog>
    `,
    
    props: {
        modelValue: {
            type: Boolean,
            default: false
        },
        order: {
            type: Object,
            default: () => null
        }
    },
    
    emits: ['update:modelValue', 'success'],
    
    data() {
        return {
            dialogVisible: false,
            activeTab: 'basic',
            deliveryForm: {
                customerName: '',
                customerPhone: '',
                deliveryDate: new Date().toISOString().split('T')[0],
                remark: '',
                logistics_company: '',
                tracking_number: '',
                packages: [{
                    items: []
                }]
            },
            deliveryImageFiles: [],
            addProductPopupVisible: false,
            currentPackageIndex: 0,
            productSearch: {
                keyword: ''
            },
            availableProducts: [],
            productLoading: false,
            selectedProducts: [],
            selectedProductMap: new Map(),
            logisticsOptions: [
                { value: '宇捷物流', label: '宇捷物流' },
                { value: '鹏腾物流', label: '鹏腾物流' },
                { value: '顺丰速运', label: '顺丰速运' },
                { value: '圆通速递', label: '圆通速递' },
                { value: '中通快递', label: '中通快递' },
                { value: '韵达快递', label: '韵达快递' },
                { value: '申通快递', label: '申通快递' },
                { value: '百世快递', label: '百世快递' },
                { value: 'EMS', label: 'EMS' }
            ]
        }
    },
    
    watch: {
        modelValue: {
            immediate: true,
            handler(val) {
                this.dialogVisible = val;
                if (val && this.order) {
                    this.initForm();
                }
            }
        },
        dialogVisible(val) {
            this.$emit('update:modelValue', val);
        }
    },
    
    methods: {
        initForm() {
            this.deliveryForm = {
                customerName: this.order.user?.nickname || '无',
                customerPhone: this.order.user?.phone || '',
                deliveryDate: new Date().toISOString().split('T')[0],
                remark: '',
                logistics_company: '',
                tracking_number: '',
                packages: [{
                    items: []
                }],
                orderNumber: this.order.order_number
            };
            
            // 自动添加所有未发货的商品到第一个包裹
            const firstPackage = this.deliveryForm.packages[0];
            if (this.order && this.order.items) {
                this.order.items.forEach(item => {
                    // 如果商品有规格
                    if (item.specs && item.specs.length > 0) {
                        item.specs.forEach(spec => {
                            const pendingQuantity = spec.quantity - (spec.shipped_quantity || 0);
                            if (pendingQuantity !== 0) {
                                firstPackage.items.push({
                                    product_id: item.product_id,
                                    product_name: item.product_name,
                                    color: spec.color,
                                    quantity: pendingQuantity,
                                    max_quantity: pendingQuantity,
                                    price: spec.price || item.price,
                                    packaging_price: spec.packaging_price || item.packaging_price || 0,
                                    logo_price: spec.logo_price || item.logo_price || 0,
                                    accessory_price: spec.accessory_price || item.accessory_price || 0,
                                    spec_id: spec.id
                                });
                            }
                        });
                    } else {
                        // 如果商品没有规格
                        const pendingQuantity = item.quantity - (item.shipped_quantity || 0);
                        if (pendingQuantity > 0) {
                            firstPackage.items.push({
                                product_id: item.product_id,
                                product_name: item.product_name,
                                color: '',
                                quantity: pendingQuantity,
                                max_quantity: pendingQuantity,
                                price: item.price,
                                packaging_price: item.packaging_price || 0,
                                logo_price: item.logo_price || 0,
                                accessory_price: item.accessory_price || 0
                            });
                        }
                    }
                });
            }
        },
        
        handleDialogClose() {
            this.dialogVisible = false;
            this.$emit('update:modelValue', false);
            // 重置表单数据
            this.deliveryForm = {
                customerName: '',
                customerPhone: '',
                deliveryDate: new Date().toISOString().split('T')[0],
                remark: '',
                logistics_company: '',
                tracking_number: '',
                packages: [{
                    items: []
                }]
            };
            this.selectedProducts = [];
            this.selectedProductMap.clear();
            this.addProductPopupVisible = false;
        },
        
        addPackage() {
            this.deliveryForm.packages.push({
                items: []
            });
            ElementPlus.ElMessage.success('新包裹已添加');
        },
        
        deletePackage(index) {
            if (this.deliveryForm.packages.length <= 1) {
                ElementPlus.ElMessage.warning('至少保留一个包裹');
                return;
            }
            
            ElementPlus.ElMessageBox.confirm('确定要删除此包裹吗？', '提示', {
                confirmButtonText: '确定',
                cancelButtonText: '取消',
                type: 'warning'
            }).then(() => {
                this.deliveryForm.packages.splice(index, 1);
            }).catch(() => {});
        },
        
        removeItem(packageIndex, itemIndex) {
            this.deliveryForm.packages[packageIndex].items.splice(itemIndex, 1);
        },
        
        showAddProductPopup(packageIndex) {
            this.currentPackageIndex = packageIndex;
            this.addProductPopupVisible = true;
            this.searchProducts();
        },
        
        hideAddProductPopup() {
            this.addProductPopupVisible = false;
        },
        
        async searchProducts() {
            this.productLoading = true;
            try {
                // 获取当前包裹
                const currentPackage = this.deliveryForm.packages[this.currentPackageIndex];
                if (!currentPackage) {
                    this.availableProducts = [];
                    return;
                }

                // 创建一个Map来跟踪每个商品ID和颜色组合已分配的数量
                const allocatedQuantities = new Map();
                
                // 遍历所有包裹，统计已分配的商品数量
                this.deliveryForm.packages.forEach(pkg => {
                    pkg.items.forEach(item => {
                        const key = `${item.product_id}-${item.color}`;
                        const currentQty = allocatedQuantities.get(key) || 0;
                        allocatedQuantities.set(key, currentQty + (parseInt(item.quantity) || 0));
                    });
                });

                // 从订单中筛选出可选商品
                const available = [];
                
                if (this.order && this.order.items && this.order.items.length > 0) {
                    this.order.items.forEach(orderItem => {
                        if (orderItem.specs && orderItem.specs.length > 0) {
                            // 处理有规格的商品
                            orderItem.specs.forEach(spec => {
                                if (!spec) return;
                                
                                const key = `${orderItem.product_id}-${spec.color}`;
                                const allocatedQty = allocatedQuantities.get(key) || 0;
                                const totalQuantity = parseInt(spec.quantity) || 0;
                                const shippedQuantity = parseInt(spec.shipped_quantity) || 0;
                                const pendingQuantity = totalQuantity - shippedQuantity - allocatedQty;

                                if (pendingQuantity > 0) {
                                    available.push({
                                        product_id: orderItem.product_id,
                                        product_name: orderItem.product_name || '',
                                        color: spec.color || '',
                                        max_quantity: pendingQuantity,
                                        packaging_price: spec.packaging_price || orderItem.packaging_price || 0,
                                        logo_price: spec.logo_price || orderItem.logo_price || 0,
                                        accessory_price: spec.accessory_price || orderItem.accessory_price || 0,
                                        spec_id: spec.id,
                                        price: spec.price || orderItem.price
                                    });
                                }
                            });
                        } else {
                            // 处理没有规格的商品
                            const key = `${orderItem.product_id}-`;
                            const allocatedQty = allocatedQuantities.get(key) || 0;
                            const totalQuantity = parseInt(orderItem.quantity) || 0;
                            const shippedQuantity = parseInt(orderItem.shipped_quantity) || 0;
                            const pendingQuantity = totalQuantity - shippedQuantity - allocatedQty;

                            if (pendingQuantity > 0) {
                                available.push({
                                    product_id: orderItem.product_id,
                                    product_name: orderItem.product_name || '',
                                    color: '',
                                    max_quantity: pendingQuantity,
                                    packaging_price: orderItem.packaging_price || 0,
                                    logo_price: orderItem.logo_price || 0,
                                    accessory_price: orderItem.accessory_price || 0,
                                    price: orderItem.price
                                });
                            }
                        }
                    });
                }

                this.availableProducts = available;
                
            } catch (error) {
                console.error('加载可选商品失败:', error);
                ElementPlus.ElMessage.error('加载商品失败');
                this.availableProducts = [];
            } finally {
                this.productLoading = false;
            }
        },
        
        handleProductSelect(selected, product) {
            const key = product.product_id + '-' + product.color;
            if (selected) {
                this.selectedProductMap.set(key, product);
                this.selectedProducts = Array.from(this.selectedProductMap.values());
            } else {
                this.selectedProductMap.delete(key);
                this.selectedProducts = Array.from(this.selectedProductMap.values());
            }
        },
        
        confirmAddProducts() {
            if (this.selectedProducts.length === 0) {
                ElementPlus.ElMessage.warning('请选择要添加的商品');
                return;
            }

            const currentPackage = this.deliveryForm.packages[this.currentPackageIndex];
            if (!currentPackage) {
                ElementPlus.ElMessage.error('当前包裹不存在');
                return;
            }

            // 检查是否有重复商品
            const existingItems = new Set(
                currentPackage.items.map(item => item.product_id + '-' + item.color)
            );

            this.selectedProducts.forEach(item => {
                const key = item.product_id + '-' + item.color;
                if (!existingItems.has(key)) {
                    currentPackage.items.push({
                        product_id: item.product_id,
                        product_name: item.product_name,
                        color: item.color,
                        quantity: item.max_quantity,
                        max_quantity: item.max_quantity,
                        price: item.price,
                        packaging_price: item.packaging_price || 0,
                        logo_price: item.logo_price || 0,
                        accessory_price: item.accessory_price || 0,
                        spec_id: item.spec_id
                    });
                }
            });

            this.addProductPopupVisible = false;
            this.selectedProducts = [];
            this.selectedProductMap.clear();
        },
        
        handlePictureCardPreview(file) {
            // 处理图片预览
        },
        
        handleDeliveryImageRemove(file, fileList) {
            this.deliveryImageFiles = fileList;
        },
        
        async submitDeliveryForm() {
            try {
                // 验证表单
                if (!this.deliveryForm.deliveryDate) {
                    ElementPlus.ElMessage.warning('请选择发货日期');
                    return;
                }
                // 添加物流公司验证
                if (!this.deliveryForm.logistics_company) {
                    ElementPlus.ElMessage.warning('请选择物流公司');
                    return;
                }
                // 检查是否有商品
                let hasItems = false;
                for (const pkg of this.deliveryForm.packages) {
                    if (pkg.items.length > 0) {
                        hasItems = true;
                        break;
                    }
                }
                
                if (!hasItems) {
                    ElementPlus.ElMessage.warning('请至少添加一个商品');
                    return;
                }
                
                // 检查数量是否超出
                const exceededItems = [];
                let hasExceededQuantity = false;
                
                this.deliveryForm.packages.forEach((pkg, pkgIndex) => {
                    pkg.items.forEach(item => {
                        if (item.quantity > item.max_quantity) {
                            const exceedPercentage = Math.round((item.quantity - item.max_quantity) / item.max_quantity * 100);
                            if (exceedPercentage > 10) {
                                hasExceededQuantity = true;
                                exceededItems.push({
                                    packageIndex: pkgIndex + 1,
                                    productName: item.product_name,
                                    color: item.color,
                                    quantity: item.quantity,
                                    maxQuantity: item.max_quantity,
                                    exceedPercentage
                                });
                            }
                        }
                    });
                });
                
                if (hasExceededQuantity) {
                    let message = '以下商品数量超过待发数量10%：\n\n';
                    exceededItems.forEach(item => {
                        message += `包裹${item.packageIndex} - ${item.productName}${item.color ? `(${item.color})` : ''}\n`;
                        message += `数量: ${item.quantity}, 待发: ${item.maxQuantity}, 超出: ${item.exceedPercentage}%\n\n`;
                    });
                    message += '是否确认提交？';
                    
                    await ElementPlus.ElMessageBox.confirm(message, '数量超出提示', {
                        confirmButtonText: '确认提交',
                        cancelButtonText: '返回修改',
                        type: 'warning'
                    });
                }
                
                // 按包裹ID分组商品
                const packageArrays = this.deliveryForm.packages.map((pkg, index) => {
                    return pkg.items
                        .filter(item => parseInt(item.quantity) !== 0)
                        .map(item => ({
                            product_id: item.product_id,
                            quantity: parseInt(item.quantity),
                            color: item.color || '',
                            package_id: index + 1,
                            spec_id: item.spec_id,
                            logo_price: item.logo_price,
                            packaging_price: item.packaging_price,
                            accessory_price: item.accessory_price
                        }));
                }).filter(items => items.length > 0);
                
                const deliveryData = {
                    customer_name: this.deliveryForm.customerName,
                    customer_id: this.order.user.id,
                    customer_phone: this.deliveryForm.customerPhone || '',
                    order_number: this.deliveryForm.orderNumber,
                    delivery_date: this.deliveryForm.deliveryDate,
                    logistics_company: this.deliveryForm.logistics_company,
                    tracking_number: this.deliveryForm.tracking_number,
                    status: 1,
                    remark: this.deliveryForm.remark || '',
                    packages: packageArrays
                };
                
                const response = await axios.post('/delivery_orders', deliveryData);
                if (response.status === 201 || response.status === 200) {
                    ElementPlus.ElMessage.success('发货单已提交成功');
                    this.$emit('success');
                    this.handleDialogClose();
                }
            } catch (error) {
                if (error !== 'cancel') {
                    console.error('提交发货单失败:', error);
                    ElementPlus.ElMessage.error('提交发货单失败');
                }
            }
        },
        
        addAllProducts() {
            if (this.availableProducts && this.availableProducts.length > 0) {
                this.selectedProductMap.clear();
                this.availableProducts.forEach(product => {
                    const key = product.product_id + '-' + product.color;
                    this.selectedProductMap.set(key, product);
                });
                this.selectedProducts = Array.from(this.selectedProductMap.values());
            }
        },
        
        handleProductSelectionChange(selection) {
            console.log('selection changed:', selection);
        },
        
        handleClose() {
            this.handleDialogClose();
        }
    }
};

// 添加样式
const style = document.createElement('style');
style.textContent = `
    .popup-header {
        display: flex;
        justify-content: flex-end;
        margin-bottom: 20px;
    }

    .add-all-btn {
        margin-left: auto;
    }

    .product-table {
        margin-bottom: 20px;
    }

    .service-tags {
        margin-top: 8px;
    }

    .service-tags .el-tag {
        margin-right: 8px;
    }

    .dialog-footer {
        padding-top: 20px;
    }

    .package-section {
        margin-bottom: 24px;
    }

    .package-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 16px;
    }

    .add-item-row {
        margin-top: 16px;
        display: flex;
        justify-content: space-between;
    }

    .add-package-row {
        margin-top: 24px;
        text-align: center;
    }
`;
document.head.appendChild(style);

window.CreateDeliveryDialog = CreateDeliveryDialog;