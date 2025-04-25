// 商品选择组件
const ProductSelector = {
    template: `
        <div class="product-selector">
            <el-dialog 
                v-model="visible" 
                :title="title" 
                width="600px" 
                height="750px"
                @close="handleClose"
                :modal-append-to-body="false"
                :append-to-body="true"
                custom-class="right-dialog">
                <div class="product-search">
                    <el-input v-model="searchKeyword" placeholder="搜索商品名称" clearable @keyup.enter="searchProducts">
                        <template #append>
                            <el-button @click="searchProducts">搜索</el-button>
                        </template>
                    </el-input>
                    
                    <div class="service-options" style="margin-top: 10px;">
                        <el-checkbox v-model="globalPackaging" @change="updateAllServicePrices">包装</el-checkbox>
                        <el-checkbox v-model="globalLogo" @change="updateAllServicePrices">打标</el-checkbox>
                    </div>
                </div>
                
                <el-table :data="filteredProducts" v-loading="loading" border stripe style="margin-top: 15px;">
                    <el-table-column prop="id" label="商品ID" width="100"></el-table-column>
                    <el-table-column prop="name" label="商品名称" width="200">
                    </el-table-column>
                    <el-table-column label="颜色" width="150">
                        <template #default="scope">
                            <el-select v-model="scope.row.selectedColor" placeholder="选择颜色" filterable style="width: 100%">
                                <el-option v-for="spec in getProductSpecs(scope.row)" 
                                    :key="spec.color" 
                                    :label="spec.color" 
                                    :value="spec.color">
                                </el-option>
                            </el-select>
                        </template>
                    </el-table-column>
                    <el-table-column label="数量" width="160" v-if="false">
                        <template #default="scope">
                            <el-input-number v-model="scope.row.quantity" :min="1" :max="999"></el-input-number>
                        </template>
                    </el-table-column>
                    <el-table-column label="价格" width="80" v-if="false">
                        <template #default="scope">
                            {{ getPrice(scope.row) }}
                        </template>
                    </el-table-column>
                    <el-table-column label="操作" width="100">
                        <template #default="scope">
                            <el-button type="primary" size="small" @click="addProduct(scope.row)">添加</el-button>
                        </template>
                    </el-table-column>
                </el-table>
                
                <div class="pagination-container" style="margin-top: 15px;">
                    <el-pagination 
                        v-model:current-page="pagination.currentPage"
                        v-model:page-size="pagination.pageSize" 
                        :total="pagination.total"
                        @current-change="handlePageChange" 
                        layout="total, prev, pager, next">
                    </el-pagination>
                </div>
                
                <template #footer>
                    <div class="dialog-footer">
                        <el-button @click="visible = false">取消</el-button>
                        <el-button type="primary" @click="handleConfirm">确定</el-button>
                    </div>
                </template>
            </el-dialog>
        </div>
    `,
    
    props: {
        modelValue: {
            type: Boolean,
            default: false
        },
        title: {
            type: String,
            default: '选择商品'
        },
        initialProducts: {
            type: Array,
            default: () => []
        },
        existingItems: {
            type: Array,
            default: () => []
        },
        userType: {
            type: Number,
            default: 0
        },
        userId: {
            type: Number,
            default: 0
        }
    },
    
    data() {
        return {
            visible: this.modelValue,
            searchKeyword: '',
            loading: false,
            products: [],
            pagination: {
                currentPage: 1,
                pageSize: 10,
                total: 0
            },
            globalPackaging: false,
            globalLogo: false
        }
    },
    
    computed: {
        filteredProducts() {
            return this.products.map(product => ({
                ...product,
                selectedColor: product.selectedColor || (this.getProductSpecs(product)[0]?.color || '默认'),
                quantity: product.quantity || 1,
                price: product.price || 0,
                packaging: this.globalPackaging,
                logo: this.globalLogo,
                packaging_price: this.globalPackaging ? 0.3 : 0,
                logo_price: this.globalLogo ? 0.3 : 0
            }));
        }
    },
    
    watch: {
        modelValue(newVal) {
            this.visible = newVal;
            if (newVal) {
                this.loadProducts();
                if (this.initialProducts.length > 0) {
                    this.products = this.initialProducts.map(p => ({
                        ...p,
                        selectedColor: p.color || (this.getProductSpecs(p)[0]?.color || '默认'),
                        quantity: p.quantity || 1,
                        price: p.price || 0,
                        packaging_price: this.globalPackaging ? 0.3 : 0,
                        logo_price: this.globalLogo ? 0.3 : 0
                    }));
                }
            }
        },
        visible(newVal) {
            this.$emit('update:modelValue', newVal);
        }
    },
    
    methods: {
        async loadProducts() {
            try {
                this.loading = true;
                const response = await axios.get('/products', {
                    params: {
                        keyword: this.searchKeyword,
                        page: this.pagination.currentPage,
                        page_size: this.pagination.pageSize,
                        status: 1 // 只查询上架商品
                    }
                });
                
                // 如果有用户类型，获取该用户的所有商品自定义价格
                let userPrices = {};
                    try {
                        const priceResponse = await axios.get('/user-product-prices/all', {
                            params: {
                                customer_id: this.userId
                            }
                        });
                        console.log('priceResponse',priceResponse);
                        if (priceResponse.status === 200 && priceResponse.data.code === 0) {
                            userPrices = priceResponse.data.prices.reduce((acc, item) => {
                                acc[item.productId] = item.price;
                                return acc;
                            }, {});
                        }
                    } catch (error) {
                        console.error('获取用户自定义价格失败:', error);
                    }
                                
                if (response.status === 200) {
                    // 处理商品数据，确保每个商品都有正确的颜色选项
                    this.products = response.data.products.map(product => {
                        const specs = this.getProductSpecs(product);
                        return {
                            ...product,
                            selectedColor: product.color || (specs[0]?.color || '默认'),
                            quantity: product.quantity || 1,
                            price: userPrices[product.id] || product.price || 0, // 优先使用用户自定义价格
                            specs: specs,  // 保存规格数据
                            packaging: this.globalPackaging,
                            logo: this.globalLogo,
                            packaging_price: this.globalPackaging ? 0.3 : 0,
                            logo_price: this.globalLogo ? 0.3 : 0,
                            customPrice: userPrices[product.id] // 保存自定义价格
                        };
                    });
                    this.pagination.total = response.data.total;
                }
            } catch (error) {
                console.error('加载商品失败:', error);
                ElementPlus.ElMessage.error('加载商品失败');
            } finally {
                this.loading = false;
            }
        },
        
        searchProducts() {
            this.pagination.currentPage = 1;
            this.loadProducts();
        },
        
        handlePageChange(page) {
            this.pagination.currentPage = page;
            this.loadProducts();
        },
        
        getProductSpecs(product) {
            try {
                // 如果product.specs已经是数组，直接返回
                if (Array.isArray(product.specs)) {
                    return product.specs;
                }
                // 否则尝试解析JSON字符串
                return JSON.parse(product.specs || '[]');
            } catch (e) {
                console.error('解析商品规格失败:', e);
                return [];
            }
        },
        
        updateAllServicePrices() {
            // 更新所有商品的附加服务状态
            this.products.forEach(product => {
                product.packaging = this.globalPackaging;
                product.logo = this.globalLogo;
                product.packaging_price = this.globalPackaging ? 0.3 : 0;
                product.logo_price = this.globalLogo ? 0.3 : 0;
            });
        },
        
        getPrice(product) {
            // 根据用户类型返回对应价格
            switch(this.userType) {
                case 2:  // A类客户
                    return product.price_b === 0 ? '讯价' : '¥' + product.price_b;
                case 3:  // B类客户
                    return product.price_c === 0 ? '讯价' : '¥' + product.price_c;
                case 4:  // C类客户
                    return product.price_d === 0 ? '讯价' : '¥' + product.price_d;
                default: // 其他客户
                    return product.price === 0 ? '讯价' : '¥' + product.price;
            }
        },
        
        addProduct(product) {
            if (!product.selectedColor) {
                ElementPlus.ElMessage.warning('请选择颜色');
                return;
            }
            
            // 优先使用自定义价格，如果没有则根据用户类型获取对应价格
            let price;
            if (product.customPrice !== undefined && product.customPrice !== null) {
                price = product.customPrice;
            } else {
                switch(this.userType) {
                    case 2:
                        price = product.price_b;
                        break;
                    case 3:
                        price = product.price_c;
                        break;
                    case 4:
                        price = product.price_d;
                        break;
                    default:
                        price = product.price;
                }
            }
            
            // 检查是否已存在相同商品（包括名称、颜色和附加服务）
            const existingItemIndex = this.existingItems.findIndex(item => 
                item.id  === product.id && 
                item.color === product.selectedColor &&
                item.packaging === product.packaging &&
                item.logo === product.logo
            );
            if (existingItemIndex !== -1) {
                // 如果商品已存在，更新数量
                this.$emit('update-quantity', {
                    index: existingItemIndex,
                    quantity: this.existingItems[existingItemIndex].quantity + product.quantity
                });
                ElementPlus.ElMessage.success('商品数量已更新');
            } else {
                // 如果商品不存在，添加新商品
                const selectedProduct = {
                    id: product.id,
                    name: product.name,
                    color: product.selectedColor,
                    quantity: 10,
                    price: price,
                    packaging: product.packaging,
                    logo: product.logo,
                    packaging_price: product.packaging_price,
                    logo_price: product.logo_price,
                    customPrice: product.customPrice // 添加自定义价格字段
                };           
                this.$emit('add-product', selectedProduct);
                ElementPlus.ElMessage.success('商品已添加');
            }
        },
        
        handleConfirm() {
            this.$emit('confirm');
            this.visible = false;
        },
        
        handleClose() {
            this.$emit('close');
        }
    },
    
    mounted() {
        // 添加自定义样式
        const style = document.createElement('style');
        style.textContent = `
            .right-dialog {
                position: fixed !important;
                right: 0 !important;
                margin-right: 0 !important;
                margin-top: 0 !important;
                height: 100vh !important;
            }
            .right-dialog .el-dialog__body {
                height: calc(100vh - 240px);
                overflow-y: auto;
            }
        `;
        document.head.appendChild(style);
    }
};

// 导出组件
window.ProductSelector = ProductSelector; 