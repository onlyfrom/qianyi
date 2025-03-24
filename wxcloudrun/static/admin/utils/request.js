// axios 配置
const isDevelopment = window.location.hostname === 'localhost' || 
                     window.location.hostname === '127.0.0.1';

const request = axios.create({
    baseURL: isDevelopment ? 'http://127.0.0.1' : ''
});

// 请求拦截器
request.interceptors.request.use(config => {
    const token = localStorage.getItem('token');
    if (token) {
        config.headers['Authorization'] = `Bearer ${token}`;
    }
    return config;
}, error => {
    return Promise.reject(error);
});

// 响应拦截器
request.interceptors.response.use(response => {
    return response;
}, error => {
    if (error.response?.status === 401) {
        ElementPlus.ElMessage.error('登录已过期，请重新登录');
        localStorage.removeItem('token');
        localStorage.removeItem('userInfo');
        window.location.href = '/admin/index.html';
    }
    return Promise.reject(error);
});

export default request; 