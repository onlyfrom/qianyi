const DeliveryOrderDetail = {
    template: `
        <el-dialog 
            v-model="visible" 
            title="发货单详情" 
            width="800px"
            destroy-on-close
            @close="handleClose">
            <div v-if="orderData && orderData.order">
                <el-descriptions :column="2" border>
                    <el-descriptions-item label="发货单号">{{ orderData.order.orderNumber }}</el-descriptions-item>
                    <el-descriptions-item label="创建时间">{{ formatDate(orderData.order.createdAt) }}</el-descriptions-item>
                    <el-descriptions-item label="状态">
                        <el-tag :type="getStatusType(orderData.order.status)">
                            {{ getStatusText(orderData.order.status) }}
                        </el-tag>
                    </el-descriptions-item>
                    <el-descriptions-item label="客户信息">
                        <div>
                            <div>姓名：{{ orderData.order.customerName }}</div>
                            <div>电话：{{ orderData.order.customerPhone || '无' }}</div>
                        </div>
                    </el-descriptions-item>
                    <el-descriptions-item label="物流信息" :span="2">
                        <div>{{ orderData.order.logistics_company}}
                            {{ orderData.order.tracking_number }}
                        </div>
                    </el-descriptions-item>
                    <el-descriptions-item label="附加费用" :span="2">
                        <template v-if="isEditing">
                            <el-input-number
                                v-model="orderData.order.additional_fee"
                                :min="0"
                                :precision="2"
                                :step="0.1"
                                size="small"
                                style="width: 200px">
                            </el-input-number>
                        </template>
                        <template v-else>
                            {{ orderData.order.additional_fee || 0 }}
                        </template>
                    </el-descriptions-item>
                    <el-descriptions-item label="备注" :span="2">{{ orderData.order.remark || '无' }}</el-descriptions-item>
                </el-descriptions>

                <el-divider>商品明细</el-divider>

                <el-table :data="orderData.items" border>
                    <el-table-column prop="product_name" label="商品名称">
                        <template #default="scope">
                            <div style="display: flex; align-items: center; gap: 8px;">
                                <text>{{ scope.row.product_name }}</text>
                                <div style="display: flex; gap: 4px;">
                                    <el-tag size="small" type="success" v-if="scope.row.packaging_price > 0">包装</el-tag>
                                    <el-tag size="small" type="warning" v-if="scope.row.logo_price > 0">打标</el-tag>
                                </div>
                            </div>
                        </template>
                    </el-table-column>
                    <el-table-column prop="product_id" label="款号" width="80"></el-table-column>
                    <el-table-column prop="color" label="颜色" width="100">
                        <template #default="scope">
                            <template v-if="isEditing">
                                <el-select 
                                    v-model="scope.row.color" 
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
                                {{ scope.row.color }}
                            </template>
                        </template>
                    </el-table-column>
                    <el-table-column label="数量" width="100">
                        <template #default="scope">
                            <template v-if="isEditing">
                                <el-input-number
                                    v-model="scope.row.quantity"
                                    :min="1"
                                    :max="999"
                                    size="small"
                                    style="width: 100%">
                                </el-input-number>
                            </template>
                            <template v-else>
                                {{ scope.row.quantity }}
                            </template>
                        </template>
                    </el-table-column>
                    <el-table-column label="单价" width="100" v-if="isAdmin">
                        <template #default="scope">
                            <template v-if="isEditing">
                                <el-input-number
                                    v-model="scope.row.price"
                                    :min="0"
                                    :precision="2"
                                    :step="0.1"
                                    size="small"
                                    style="width: 100%">
                                </el-input-number>
                            </template>
                            <template v-else>
                                {{ scope.row.price }}
                            </template>
                        </template>
                    </el-table-column>
                    <el-table-column label="包装费" width="100" v-if="isAdmin">
                        <template #default="scope">
                            <template v-if="isEditing">
                                <el-input-number
                                    v-model="scope.row.packaging_price"
                                    :min="0"
                                    :precision="2"
                                    :step="0.1"
                                    size="small"
                                    style="width: 100%">
                                </el-input-number>
                            </template>
                            <template v-else>
                                {{ scope.row.packaging_price }}
                            </template>
                        </template>
                    </el-table-column>
                    <el-table-column label="打标费" width="100" v-if="isAdmin">
                        <template #default="scope">
                            <template v-if="isEditing">
                                <el-input-number
                                    v-model="scope.row.logo_price"
                                    :min="0"
                                    :precision="2"
                                    :step="0.1"
                                    size="small"
                                    style="width: 100%">
                                </el-input-number>
                            </template>
                            <template v-else>
                                {{ scope.row.logo_price }}
                            </template>
                        </template>
                    </el-table-column>
                    <el-table-column label="总金额" width="120" v-if="isAdmin">
                        <template #default="scope">
                            ¥{{ ((scope.row.price + scope.row.packaging_price + scope.row.logo_price) * scope.row.quantity).toFixed(2) }}
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
                    <div v-if="isAdmin">
                        <div>总金额：¥{{ orderData.order.total_amount.toFixed(2) }} {{ orderData.order.additional_fee > 0 ? '（含附加费用）' : '' }}</div>
                       
                    </div>
                </div>

                <div class="dialog-footer" style="margin-top: 20px; text-align: right;">
                    <el-button @click="handleClose">关闭</el-button>
                    <el-button 
                        type="primary"
                        @click="toggleEdit">
                        {{ isEditing ? '完成编辑' : '编辑配送单' }}
                    </el-button>
                </div>
            </div>

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

    emits: ['update:visible', 'start', 'complete', 'cancel', 'save'],

    data() {
        return {
            isEditing: false,
            addItemVisible: false,
            searchKeyword: '',
            searchResults: [],
            searching: false,
            availableProductColors: []
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
                0: 'info',    // 已开单
                1: 'warning', // 已发货
                2: 'success', // 已完成
                3: 'danger'   // 已取消
            };
            return types[status] || 'info';
        },

        getStatusText(status) {
            const texts = {
                0: '已开单',
                1: '已发货',
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

        handleStart() {
            this.$emit('start', this.orderData.order);
        },

        handleComplete() {
            this.$emit('complete', this.orderData.order);
        },

        handleCancel() {
            this.$emit('cancel', this.orderData.order);
        },

        async toggleEdit() {
            if (this.isEditing) {
                try {
                    // 验证数据
                    const hasInvalidQuantity = this.orderData.items.some(item => 
                        !item.quantity || item.quantity <= 0
                    );
                    if (hasInvalidQuantity) {
                        ElementPlus.ElMessage.error('商品数量必须大于0');
                        return;
                    }

                    // 验证每个商品的颜色是否重复
                    const colorMap = new Map();
                    for (const item of this.orderData.items) {
                        if (!colorMap.has(item.product_id)) {
                            colorMap.set(item.product_id, new Set());
                        }
                        
                        const colorSet = colorMap.get(item.product_id);
                        if (colorSet.has(item.color)) {
                            ElementPlus.ElMessage.error(`商品"${item.product_name}"中存在重复的颜色"${item.color}"，请检查`);
                            return;
                        }
                        
                        colorSet.add(item.color);
                    }

                    // 计算总金额
                    const totalAmount = this.orderData.items.reduce((sum, item) => {
                        const itemTotal = (item.price + item.packaging_price + item.logo_price) * item.quantity;
                        return sum + itemTotal;
                    }, 0) + (this.orderData.order.additional_fee || 0);

                    // 更新订单数据
                    this.orderData.order.total_amount = totalAmount;
                    this.orderData.order.total_quantity = this.orderData.items.reduce(
                        (sum, item) => sum + item.quantity, 
                        0
                    );

                    // 直接保存数据
                    const updateData = {
                        customer_name: this.orderData.order.customer_name,
                        customer_phone: this.orderData.order.customer_phone,
                        delivery_address: this.orderData.order.delivery_address,
                        delivery_date: this.orderData.order.delivery_date,
                        delivery_time_slot: this.orderData.order.delivery_time_slot,
                        logistics_company: this.orderData.order.logistics_company,
                        tracking_number: this.orderData.order.tracking_number,
                        remark: this.orderData.order.remark,
                        additional_fee: this.orderData.order.additional_fee || 0,
                        items: this.orderData.items.map(item => ({
                            product_id: item.product_id,
                            quantity: item.quantity,
                            color: item.color,
                            package_id: item.package_id || 0
                        }))
                    };

                    const response = await axios.put(`/delivery_orders/${this.orderData.order.id}`, updateData);
                    if (response.status === 200) {
                        ElementPlus.ElMessage.success('保存成功');
                        this.isEditing = false;
                    } else {
                        throw new Error('保存失败');
                    }
                } catch (error) {
                    console.error('保存失败:', error);
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
                const productIds = [...new Set(this.orderData.items.map(item => item.product_id))];
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
                this.orderData.items.splice(index, 1);
                // 更新订单总数量
                this.orderData.order.total_quantity = this.orderData.items.reduce(
                    (sum, item) => sum + (parseInt(item.quantity) || 0), 
                    0
                );
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

            // 添加选中的规格作为新的商品项
            selectedSpecs.forEach(spec => {
                const newItem = {
                    product_id: product.id,
                    product_name: product.name,
                    color: spec.color,
                    quantity: spec.selectedQuantity,
                    price: product.price || 0,
                    logo_price: product.logo_price || 0,
                    accessory_price: product.accessory_price || 0,
                    packaging_price: product.packaging_price || 0
                };
                this.orderData.items.push(newItem);
            });

            // 更新订单总数量
            this.orderData.order.total_quantity = this.orderData.items.reduce(
                (sum, item) => sum + (parseInt(item.quantity) || 0), 
                0
            );

            ElementPlus.ElMessage.success('商品添加成功');
            this.addItemVisible = false;

            // 重置选择的数量
            product.specs.forEach(spec => spec.selectedQuantity = 0);
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
        }
    }
};

// 注册组件
window.DeliveryOrderDetail = DeliveryOrderDetail; 