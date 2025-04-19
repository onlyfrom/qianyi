// 设置 axios 默认配置
const isDevelopment = window.location.hostname === 'localhost' || 
                     window.location.hostname === '127.0.0.1';

axios.defaults.baseURL = isDevelopment ? 'http://127.0.0.1' : '';

// 请求拦截器
axios.interceptors.request.use(config => {
    console.log('准备发送请求:', {
        url: config.url,
        method: config.method,
        params: config.params,
        data: config.data
    });

    const token = localStorage.getItem('token');
    if (token) {
        config.headers['Authorization'] = `Bearer ${token}`;
    } else {
        console.warn('未找到token');
    }
    config.headers['Cache-Control'] = 'no-cache';
    config.headers['Pragma'] = 'no-cache';
    return config;
}, error => {
    console.error('请求拦截器错误:', error);
    return Promise.reject(error);
});

// 响应拦截器
axios.interceptors.response.use(response => {
    return response;
}, error => {
    console.group('请求失败详情');
    console.error('请求失败:', {
        url: error.config?.url,
        method: error.config?.method,
        headers: error.config?.headers,
        params: error.config?.params,
        data: error.config?.data
    });

    if (error.response) {
        console.error('服务器响应:', {
            status: error.response.status,
            data: error.response.data,
            headers: error.response.headers
        });

        switch (error.response.status) {
            case 401:
                console.warn('认证失败，需要重新登录');
                ElementPlus.ElMessage.error('登录已过期，请重新登录');
                localStorage.removeItem('token');
                localStorage.removeItem('userInfo');
                window.location.href = '/admin/index.html';
                break;
            case 403:
                console.warn('权限不足');
                ElementPlus.ElMessage.error('没有权限访问');
                break;
            default:
                console.error('其他错误:', error.response.data.error || '请求失败');
                ElementPlus.ElMessage.error(error.response.data.error || '请求失败');
        }
    } else if (error.request) {
        console.error('未收到响应:', error.request);
        ElementPlus.ElMessage.error('网络错误，请稍后重试');
    } else {
        console.error('请求配置错误:', error.message);
        ElementPlus.ElMessage.error('请求配置错误');
    }

    console.groupEnd();
    return Promise.reject(error);
});

const app = Vue.createApp({
    data() {
        return {
            activeTab: '0',
            userInfo: JSON.parse(localStorage.getItem('userInfo') || '{}'),
            productSearch: {
                keyword: '',
                sortField: '',
                sortOrder: ''
            },
            productLoading: false,
            currentPage: '1',
            uploadedFiles: 0,
            userDialogStatus: 'edit',
            products: [],
            pagination: {
                currentPage: 1,
                pageSize: 20,
                total: 0
            },
            pageSizeOptions: [10, 25, 50],
            dialogVisible: false,
            dialogType: 'add',
            editingProductId: '',
            uploadHeaders: {
                Authorization: `Bearer ${localStorage.getItem('token')}`
            },
            fileList: [],
            styleOptions: [
                { value: 1, label: '披肩' },
                { value: 2, label: '围巾' },
                { value: 3, label: '帽子' },
                { value: 4, label: '三角巾' },
                { value: 5, label: '其他' }
            ],
            tempUploadData:[],
            productForm: {
                id: '',
                name: '',
                price: 0,
                cost_price: 0,
                price_b: 0,
                price_c: 0,
                price_d: 0,
                style: 1,
                colors: ['灰色', '黑色'],  // 默认颜色
                specs: [                 // 初始化 specs 数组
                    { color: '灰色', stock: 0 },
                    { color: '黑色', stock: 0 }
                ],
                images: [],
                description: '暂时没有',
                stock: 0,
                stock_warning: 10,
                size: '',               // 尺寸
                weight: 0,              // 克重
                yarn: '',               // 材质
                composition: '',         // 成分
                status: 1,          // 默认上架
                is_public: 0            // 默认私密
            },
            // ... 其他数据属性
        }
    },
    created() {
        // 检查登录状态
        const token = localStorage.getItem('token');
        if (!token) {
            ElementPlus.ElMessage.warning('请先登录');
            window.location.href = '/admin/index.html';
            return;
        }

        // 获取当前用户信息并初始化数据
        this.getCurrentUserInfo();
        // 加载款式选项
        this.loadStyleOptions();
        this.loadFilterOptions();
        
        // 初始化加载
        this.loadProducts();
        this.$nextTick(() => {
            this.initSortable();
        });
    },
    methods: {
        // ... 所有方法的实现
        handleSelect(index) {
            this.currentPage = index;
            if (index === '1') {
                this.loadProducts();
            } else if (index === '2') {
                this.loadUsers();
            } else if (index === '3') {
                this.loadPurchaseOrders();
            } else if (index === '4') {
                this.loadDeliveryOrders();
            } else if (index === '5') {
                // 加载系统设置
            } else if (index === '6') {
                this.loadStatistics();
            } else if (index === '7') {
                this.loadPushOrders();
            }
        },
        // ... 其他方法的实现
    }
});

// 注册所有图标组件
for (const [key, component] of Object.entries(ElementPlusIconsVue)) {
    app.component(key, component)
}

// 使用 Element Plus
app.use(ElementPlus, {
    size: 'default',
    zIndex: 3000
})

app.mount('#app') 