const PurchaseOrderDetail = {
    template: `
        <el-dialog 
            v-model="visible" 
            title="采购单详情" 
            width="800px"
            destroy-on-close
            @close="handleClose">
            <div v-if="orderData && orderData.order">
                <el-descriptions :column="2" border>
                    <el-descriptions-item label="采购单号">{{ orderData.order.order_number }}</el-descriptions-item>
                    <el-descriptions-item label="创建时间">{{ formatDate(orderData.order.created_at) }} {{ orderData.order.handler.nickname }}</el-descriptions-item>
                    <el-descriptions-item label="状态">
                        <el-tag :type="getStatusType(orderData.order.status)">
                            {{ getStatusText(orderData.order.status) }}
                        </el-tag>
                    </el-descriptions-item>
                    <el-descriptions-item label="客户信息">
                        <div>
                            <div>姓名：{{ orderData.order.user?.nickname || orderData.order.user?.username || '未知' }}</div>
                            <div>电话：{{ orderData.order.user?.phone || '无' }}</div>
                        </div>
                    </el-descriptions-item>
                    <el-descriptions-item label="备注" :span="2">{{ orderData.order.remark || '无' }}</el-descriptions-item>
                </el-descriptions>

                <el-divider>商品明细</el-divider>

                <el-table :data="expandedItems" border>
                    <el-table-column prop="product_name" label="商品名称">
                        <template #default="scope">
                            <div style="display: flex; align-items: center; gap: 8px;">
                                <text @click="editProduct(scope.row)">{{ scope.row.product_name }}</text>
                                <div style="display: flex; gap: 4px;">
                                    <el-tag size="small" type="success" v-if="scope.row.currentSpec.packaging_price > 0">包装</el-tag>
                                    <el-tag size="small" type="warning" v-if="scope.row.currentSpec.logo_price > 0">打标</el-tag>
                                </div>
                            </div>
                        </template>
                    </el-table-column>
                    <el-table-column prop="product_id" label="款号" width="60"></el-table-column>
                    <el-table-column label="颜色" width="120">
                        <template #default="scope">
                            <template v-if="isEditing">
                                <el-select 
                                    v-model="scope.row.currentSpec.color" 
                                    placeholder="选择颜色"
                                    filterable
                                    style="width: 100%">
                                    <el-option
                                        v-for="color in availableProductColors"
                                        :key="color"
                                        :label="color"
                                        :value="color">
                                    </el-option>
                                </el-select>
                            </template>
                            <template v-else>
                                {{ scope.row.currentSpec.color }}
                            </template>
                        </template>
                    </el-table-column>
                    <el-table-column label="数量" :width="isEditing ? '150px' : '80px'">
                        <template #default="scope">
                            <template v-if="isEditing">
                                <el-input-number
                                    v-model="scope.row.currentSpec.quantity"
                                    :min="0"
                                    :max="999"
                                    size="small"
                                    style="width: 100%">
                                </el-input-number>
                            </template>
                            <template v-else>
                                {{ scope.row.currentSpec.quantity }}
                            </template>
                        </template>
                    </el-table-column>
                    <el-table-column label="待发货" width="80">
                        <template #default="scope">
                            {{ scope.row.currentSpec.quantity - (scope.row.currentSpec.shipped_quantity || 0) }}
                        </template>
                    </el-table-column>
                    <el-table-column label="已发货" width="80">
                        <template #default="scope">
                            {{ scope.row.currentSpec.shipped_quantity || 0 }}
                        </template>
                    </el-table-column>
                     <el-table-column label="单价" width="80" v-if="isAdmin">
                        <template #default="scope">
                            <template v-if="isEditing">
                                <el-input-number
                                    v-model="scope.row.currentSpec.price"
                                    :min="0"
                                    :max="999"
                                    size="small"
                                    style="width: 100%">
                                </el-input-number>
                            </template>
                            <template v-else>
                                {{ scope.row.currentSpec.price }}
                            </template>
                        </template>
                    </el-table-column>

                    <el-table-column label="总金额" width="120" v-if="isAdmin">
                        <template #default="scope">
                            ¥{{ ((scope.row.total_amount || 0) / scope.row.total_quantity * scope.row.currentSpec.quantity).toFixed(2) }}
                            <text style="font-size: 12px; color: #999;" v-if = "scope.row.currentSpec.extra > 0">+{{ scope.row.currentSpec.extra }}</text>
                        </template>
                    </el-table-column>
                    <el-table-column v-if="isEditing" label="操作" width="80">
                        <template #default="scope">
                            <el-button type="danger" size="small" @click="removeItem(scope.$index)">删除</el-button>
                        </template>
                    </el-table-column>
                </el-table>
                <div style="margin-top: 10px; width: 100%; text-align: right;">                
                <el-button 
                        v-if="isEditing"
                        type="primary"
                        @click="showAddItemDialog">
                        添加商品
                </el-button>
                </div>
                <div class="total-amount" style="margin-top: 20px;">
                    <div>商品总数：{{ orderData.order.total_quantity }}件</div>
                    <div v-if="isAdmin">总金额：¥{{ orderData.order.total_amount.toFixed(2) }} + {{ orderData.order.total_amount_extra.toFixed(2) }}</div>
                    
                </div>

                <el-divider>发货记录</el-divider>
                
                <el-table :data="deliveryOrders" border v-loading="loadingDeliveries">
                    <el-table-column prop="order_number" label="发货单号" width="180">
                        <template #default="scope">
                            <el-button link type="primary" @click="viewDeliveryDetail(scope.row)">
                                {{ scope.row.orderNumber }}
                            </el-button>
                        </template>
                    </el-table-column>
                    <el-table-column prop="createdAt" label="发货时间" width="180">
                        <template #default="scope">
                            {{ formatDate(scope.row.createdAt) }}
                        </template>
                    </el-table-column>
                    <el-table-column prop="creator.nickname" label="发货人" width="120">
                        <template #default="scope">
                            {{ scope.row.creator?.nickname || scope.row.creator?.username || '未知' }}
                        </template>
                    </el-table-column>
                    <el-table-column prop="total_quantity" label="发货数量" width="100">
                        <template #default="scope">
                            {{ scope.row.total_quantity }}
                        </template>
                    </el-table-column>
                    <el-table-column prop="status" label="状态" width="100">
                        <template #default="scope">
                            <el-tag :type="getDeliveryStatusType(scope.row.status)">
                                {{ getDeliveryStatusText(scope.row.status) }}
                            </el-tag>
                        </template>
                    </el-table-column>
                </el-table>

                <div class="dialog-footer" style="margin-top: 20px; text-align: right;">
                    <el-button @click="handleClose">关闭</el-button>
                    <el-button 
                        v-if="orderData.order.status === 0"
                        type="success" 
                        @click="handleAccept">
                        接受订单
                    </el-button>
                    <el-button 
                        v-if="orderData.order.status === 0 || orderData.order.status === 1"
                        type="danger"
                        @click="handleCancel">
                        取消订单
                    </el-button>
                    <el-button 
                        v-if="orderData.order.status === 0 || orderData.order.status === 1"
                        type="primary"
                        @click="toggleEdit">
                        {{ isEditing ? '完成编辑' : '编辑订单' }}
                    </el-button>
                </div>
            </div>

            <!-- 商品编辑对话框 -->
            <el-dialog
                v-model="itemEditVisible"
                title="编辑商品"
                width="500px"
                append-to-body>
                <el-form :model="editingItem" label-width="100px">
                    <el-form-item label="商品名称">
                        <span>{{ editingItem?.product_name }}</span>
                    </el-form-item>
                    <el-form-item label="规格">
                        <div v-if="editingItem">
                            <div v-for="(spec, index) in editingItem.specs" :key="index" style="margin-bottom: 10px; display: flex; align-items: center; gap: 10px;">
                                <el-select 
                                    v-model="spec.color" 
                                    placeholder="选择颜色"
                                    filterable
                                    style="width: 120px">
                                    <el-option
                                        v-for="color in availableProductColors"
                                        :key="color"
                                        :label="color"
                                        :value="color">
                                    </el-option>
                                </el-select>
                                <el-input-number
                                    v-model="spec.quantity"
                                    :min="0"
                                    :max="999"
                                    size="small"
                                    style="width: 120px">
                                </el-input-number>
                                <el-button 
                                    type="danger" 
                                    size="small" 
                                    circle
                                    @click="removeSpec(index)">
                                    <el-icon><Delete /></el-icon>
                                </el-button>
                            </div>
                            <div style="margin-top: 10px;">
                                <el-button 
                                    type="primary" 
                                    size="small"
                                    @click="addNewSpec"
                                    :disabled="!hasUnusedColors">
                                    添加规格
                                </el-button>
                            </div>
                        </div>
                    </el-form-item>
                </el-form>
                <template #footer>
                    <span class="dialog-footer">
                        <el-button @click="itemEditVisible = false">取消</el-button>
                        <el-button type="primary" @click="saveItemEdit">确定</el-button>
                    </span>
                </template>
            </el-dialog>

            <!-- 添加商品对话框 -->
            <el-dialog
                v-model="addItemVisible"
                title="添加商品"
                width="70%"
                append-to-body>
                <div class="search-bar" style="margin-bottom: 20px;">
                    <el-input
                        v-model="searchKeyword"
                        placeholder="搜索商品名称或编号"
                        @keyup.enter="searchProducts"
                        clearable>
                        <template #append>
                            <el-button @click="searchProducts">搜索</el-button>
                        </template>
                    </el-input>
                </div>

                <el-table 
                    :data="searchResults"
                    v-loading="searching"
                    border>
                    <el-table-column prop="name" label="商品名称"></el-table-column>
                    <el-table-column prop="id" label="款号" width="100"></el-table-column>
                    <el-table-column label="规格选择" width="300">
                        <template #default="scope">
                            <div v-for="spec in scope.row.specs" :key="spec.color" style="margin: 5px 0;">
                                <el-input-number 
                                    v-model="spec.selectedQuantity" 
                                    :min="0"
                                    :max="999"
                                    size="small"
                                    style="width: 100px">
                                </el-input-number>
                                <el-tag size="small" style="margin-left: 5px">{{ spec.color }}</el-tag>
                            </div>
                            <div style="margin-top: 5px;">
                                <el-button 
                                    type="primary" 
                                    size="small" 
                                    link
                                    @click="addCustomSpec(scope.row)">
                                    添加自定义规格
                                </el-button>
                            </div>
                        </template>
                    </el-table-column>
                    <el-table-column label="操作" width="120">
                        <template #default="scope">
                            <el-button 
                                type="primary" 
                                size="small"
                                @click="addToOrder(scope.row)">
                                添加
                            </el-button>
                        </template>
                    </el-table-column>
                </el-table>
            </el-dialog>

            <!-- 添加自定义规格对话框 -->
            <el-dialog
                v-model="customSpecVisible"
                title="添加规格"
                width="400px"
                append-to-body>
                <el-form :model="customSpec" label-width="80px">
                    <el-form-item label="颜色">
                        <el-select 
                            v-model="customSpec.color" 
                            placeholder="选择颜色"
                            filterable
                            style="width: 100%">
                            <el-option
                                v-for="color in availableColors"
                                :key="color"
                                :label="color"
                                :value="color">
                            </el-option>
                        </el-select>
                    </el-form-item>
                    <el-form-item label="数量">
                        <el-input-number 
                            v-model="customSpec.quantity" 
                            :min="0"
                            :max="999"
                            style="width: 100%">
                        </el-input-number>
                    </el-form-item>
                </el-form>
                <template #footer>
                    <span class="dialog-footer">
                        <el-button @click="customSpecVisible = false">取消</el-button>
                        <el-button type="primary" @click="confirmAddCustomSpec">确定</el-button>
                    </span>
                </template>
            </el-dialog>
        </el-dialog>
    `,

    props: {
        visible: {
            type: Boolean,
            required: true
        },
        orderData: {
            type: Object,
            required: true
        },
        isAdmin: {
            type: Boolean,
            default: false
        }
    },

    emits: ['update:visible', 'accept', 'cancel', 'save', 'view-delivery'],

    data() {
        return {
            isEditing: false,
            itemEditVisible: false,
            addItemVisible: false,
            editingItem: null,
            editingItemIndex: -1,
            searchKeyword: '',
            searchResults: [],
            searching: false,
            customSpecVisible: false,
            customSpec: {
                color: '',
                quantity: 0
            },
            currentEditingProduct: null,
            availableColors: [],
            availableProductColors: [],
            deliveryOrders: [],
            loadingDeliveries: false
        }
    },

    computed: {
        expandedItems() {
            if (!this.orderData?.order?.items) return [];
            
            return this.orderData.order.items.reduce((acc, item) => {
                if (!item.specs || !Array.isArray(item.specs)) return acc;
                
                return acc.concat(item.specs.map(spec => ({
                    ...item,
                    currentSpec: spec,
                    originalSpecs: item.specs
                })));
            }, []);
        },
        hasUnusedColors() {
            if (!this.editingItem || !this.editingItem.specs) return false;
            const usedColors = new Set(this.editingItem.specs.map(s => s.color));
            const availableColors = this.availableProductColors.filter(c => !usedColors.has(c));
            return availableColors.length > 0;
        }
    },

    watch: {
        visible(newVal) {
            if (newVal) {
                this.loadDeliveryOrders();
            }
        }
    },

    methods: {
        formatDate(dateStr) {
            if (!dateStr) return '';
            const date = new Date(dateStr);
            return date.toLocaleString('zh-CN', {
                year: 'numeric',
                month: '2-digit',
                day: '2-digit',
                hour: '2-digit',
                minute: '2-digit',
                hour12: false
            }).replace(/\//g, '-');
        },

        getStatusType(status) {
            const types = {
                0: 'info',
                1: 'warning',
                2: 'success',
                3: 'danger'
            };
            return types[status] || 'info';
        },

        getStatusText(status) {
            const texts = {
                0: '待处理',
                1: '已确认',
                2: '已完成',
                3: '已取消'
            };
            return texts[status] || '未知状态';
        },

        handleClose() {
            if (this.isEditing) {
                ElementPlus.ElMessageBox.confirm('确定要退出编辑模式吗？未保存的修改将会丢失', '提示', {
                    confirmButtonText: '确定',
                    cancelButtonText: '取消',
                    type: 'warning'
                }).then(() => {
                    this.isEditing = false;
                    this.$emit('update:visible', false);
                }).catch(() => {});
            } else {
                this.$emit('update:visible', false);
            }
        },

        handleAccept() {
            this.$emit('accept', this.orderData.order);
        },

        handleCancel() {
            this.$emit('cancel', this.orderData.order);
        },

        async toggleEdit() {
            if (this.isEditing) {
                try {
                    // 验证数据
                    const hasInvalidQuantity = this.expandedItems.some(item => 
                        !item.currentSpec.quantity || item.currentSpec.quantity <= 0
                    );
                    if (hasInvalidQuantity) {
                        ElementPlus.ElMessage.error('商品数量必须大于0');
                        return;
                    }

                    // 验证每个商品内的颜色是否重复
                    const productColorMap = new Map();
                    for (const item of this.expandedItems) {
                        if (!productColorMap.has(item.product_id)) {
                            productColorMap.set(item.product_id, new Set());
                        }
                        
                        const colorSet = productColorMap.get(item.product_id);
                        if (colorSet.has(item.currentSpec.color)) {
                            ElementPlus.ElMessage.error(`商品"${item.product_name}"中存在重复的颜色"${item.currentSpec.color}"，请检查`);
                            return;
                        }
                        
                        colorSet.add(item.currentSpec.color);
                    }

                    // 更新每个商品的总金额
                    this.orderData.order.items.forEach(item => {
                        let totalAmount = 0;
                        let totalAmountExtra = 0;
                        let totalQuantity = 0;
                        
                        item.specs.forEach(spec => {
                            const quantity = spec.quantity || 0;
                            const price = spec.price || 0;
                            const extra = spec.extra || 0;
                            
                            totalAmount += quantity * price;
                            totalAmountExtra += extra;
                            totalQuantity += quantity;
                        });
                        
                        item.total_amount = totalAmount;
                        item.total_amount_extra = totalAmountExtra;
                        item.total_quantity = totalQuantity;
                    });

                    // 更新订单总金额
                    this.orderData.order.total_amount = this.orderData.order.items.reduce(
                        (sum, item) => sum + (item.total_amount || 0), 
                        0
                    );
                    this.orderData.order.total_amount_extra = this.orderData.order.items.reduce(
                        (sum, item) => sum + (item.total_amount_extra || 0), 
                        0
                    );
                    this.orderData.order.total_quantity = this.orderData.order.items.reduce(
                        (sum, item) => sum + (item.total_quantity || 0), 
                        0
                    );

                    // 保存编辑
                    await this.$emit('save', this.orderData.order);
                    ElementPlus.ElMessage.success('保存成功');
                    this.isEditing = false;
                } catch (error) {
                    ElementPlus.ElMessage.error('保存失败');
                    return;
                }
            } else {
                // 进入编辑模式时，加载所有可用颜色
                this.loadAllProductColors();
                this.isEditing = true;
            }
        },

        async loadAllProductColors() {
            try {
                // 获取所有商品的颜色
                const productIds = [...new Set(this.orderData.order.items.map(item => item.product_id))];
                const colors = new Set();
                
                for (const productId of productIds) {
                    const productDetail = await this.loadProductDetail(productId);
                    if (productDetail && productDetail.specs) {
                        productDetail.specs.forEach(spec => colors.add(spec.color));
                    }
                }
                
                this.availableProductColors = Array.from(colors);
            } catch (error) {
                console.error('加载颜色列表失败:', error);
                ElementPlus.ElMessage.error('加载颜色列表失败');
            }
        },

        removeItem(index) {
            ElementPlus.ElMessageBox.confirm('确定要删除这个商品吗？', '提示', {
                confirmButtonText: '确定',
                cancelButtonText: '取消',
                type: 'warning'
            }).then(() => {
                const item = this.expandedItems[index];
                const originalIndex = this.orderData.order.items.findIndex(i => i.product_id === item.product_id);
                if (originalIndex > -1) {
                    this.orderData.order.items.splice(originalIndex, 1);
                }
            }).catch(() => {});
        },

        showAddItemDialog() {
            this.addItemVisible = true;
            this.searchKeyword = '';
            this.searchResults = [];
        },

        async searchProducts() {
            if (!this.searchKeyword.trim()) {
                ElementPlus.ElMessage.warning('请输入搜索关键词');
                return;
            }

            this.searching = true;
            try {
                const response = await axios.get('/products', {
                    params: {
                        keyword: this.searchKeyword,
                        page: 1,
                        page_size: 10
                    }
                });

                if (response.status === 200) {
                    // 获取搜索结果中每个商品的详细信息
                    const productsWithDetails = await Promise.all(
                        response.data.products.map(async product => {
                            const detail = await this.loadProductDetail(product.id);
                            return {
                                ...product,
                                specs: (detail?.specs || []).map(spec => ({
                                    ...spec,
                                    selectedQuantity: 0
                                }))
                            };
                        })
                    );
                    this.searchResults = productsWithDetails;
                }
            } catch (error) {
                ElementPlus.ElMessage.error('搜索商品失败');
                console.error('搜索商品失败:', error);
            } finally {
                this.searching = false;
            }
        },

        addToOrder(product) {
            const selectedSpecs = product.specs.filter(spec => spec.selectedQuantity > 0);
            if (selectedSpecs.length === 0) {
                ElementPlus.ElMessage.warning('请选择商品数量');
                return;
            }

            const newItem = {
                product_id: product.id,
                product_name: product.name,
                price: product.price || 0,
                logo_price: product.logo_price || 0,
                accessory_price: product.accessory_price || 0,
                packaging_price: product.packaging_price || 0,
                specs: selectedSpecs.map(spec => ({
                    color: spec.color,
                    quantity: spec.selectedQuantity,
                    shipped_quantity: 0
                })),
                total_quantity: selectedSpecs.reduce((sum, spec) => sum + spec.selectedQuantity, 0)
            };

            this.orderData.order.items.push(newItem);
            
            // 更新订单总数量
            this.orderData.order.total_quantity = this.orderData.order.items.reduce(
                (sum, item) => sum + (parseInt(item.total_quantity) || 0), 
                0
            );
            
            ElementPlus.ElMessage.success('商品添加成功');
            this.addItemVisible = false;

            // 重置选择的数量
            product.specs.forEach(spec => spec.selectedQuantity = 0);
        },

        addCustomSpec(product) {
            // 获取商品详情以确保使用正确的颜色
            this.loadProductDetail(product.id).then(productDetail => {
                if (productDetail && productDetail.specs) {
                    // 找出未使用的颜色
                    const usedColors = new Set(product.specs.map(s => s.color));
                    const availableSpecs = productDetail.specs.filter(s => !usedColors.has(s.color));
                    
                    if (availableSpecs.length > 0) {
                        this.currentEditingProduct = product;
                        this.availableColors = availableSpecs.map(s => s.color);
                        this.customSpec = {
                            color: this.availableColors[0] || '',
                            quantity: 0
                        };
                        this.customSpecVisible = true;
                    } else {
                        ElementPlus.ElMessage.warning('已添加所有可用颜色');
                    }
                }
            });
        },

        confirmAddCustomSpec() {
            if (!this.customSpec.color) {
                ElementPlus.ElMessage.warning('请输入颜色');
                return;
            }
            
            if (this.currentEditingProduct) {
                // 检查颜色是否已存在
                const colorExists = this.currentEditingProduct.specs.some(
                    spec => spec.color === this.customSpec.color
                );
                
                if (colorExists) {
                    ElementPlus.ElMessage.warning('该颜色已存在');
                    return;
                }
                
                // 添加新规格
                this.currentEditingProduct.specs.push({
                    color: this.customSpec.color,
                    selectedQuantity: this.customSpec.quantity,
                    quantity: 0,
                    shipped_quantity: 0
                });
            }
            
            this.customSpecVisible = false;
            this.currentEditingProduct = null;
        },

        async loadProductDetail(productId) {
            try {
                const response = await axios.get(`/products/${productId}`);
                if (response.status === 200) {
                    return response.data.product;
                }
                return null;
            } catch (error) {
                console.error('获取商品详情失败:', error);
                ElementPlus.ElMessage.error('获取商品详情失败');
                return null;
            }
        },

        getDeliveryStatusType(status) {
            const types = {
                0: 'info',    // 已开单
                1: 'warning', // 已发货
                2: 'success', // 已完成
                3: 'danger'   // 已取消
            };
            return types[status] || 'info';
        },

        getDeliveryStatusText(status) {
            const texts = {
                0: '已开单',
                1: '已发货',
                2: '已完成',
                3: '已取消'
            };
            return texts[status] || '未知状态';
        },

        async loadDeliveryOrders() {
            if (!this.orderData?.order?.order_number) return;
            
            this.loadingDeliveries = true;
            try {
                const response = await axios.get('/delivery_orders', {
                    params: {
                        order_number: this.orderData.order.order_number
                    }
                });
                
                if (response.status === 200) {
                    this.deliveryOrders = response.data.orders;
                }
            } catch (error) {
                console.error('获取发货单列表失败:', error);
                ElementPlus.ElMessage.error('获取发货单列表失败');
            } finally {
                this.loadingDeliveries = false;
            }
        },

        viewDeliveryDetail(delivery) {
            // 触发全局事件，让父组件处理查看发货单详情
            this.$emit('view-delivery', delivery);
        }
    }
};

// 注册组件
window.PurchaseOrderDetail = PurchaseOrderDetail; 