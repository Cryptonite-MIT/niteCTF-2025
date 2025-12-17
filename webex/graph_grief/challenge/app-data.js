const products = Array.from({ length: 60 }, (_, i) => ({
  id: `user-${i + 1}`,
  name: `Quantum Product ${i + 1}`,
  specs: `Advanced quantum specs for product ${i + 1}`,
}));

const users = Array.from({ length: 20 }, (_, i) => ({
  id: `user-${i + 1}`,
  username: `quantum_user_${i + 1}`,
  fullName: `User Name ${i + 1}`,
  role: ['customer', 'support', 'staff', 'admin'][Math.floor(Math.random() * 4)],
}));

const profiles = users.map((user) => ({
  id: `profile-${user.id}`,
  userId: `user-${user.id.split('-')[1]}`,
  bio: `Profile bio for ${user.fullName}. Interested in quantum computing and advanced APIs.`,
  avatarUrl: `https://api.aethercorp.local/avatars/${user.id}.png`,
}));

const orders = [
  { id: 'order-1', userId: 'user-1', productId: 'user-5', status: 'completed', createdAt: '2024-01-15T10:30:00Z' },
  { id: 'order-2', userId: 'user-2', productId: 'user-12', status: 'pending', createdAt: '2024-01-20T14:45:00Z' },
  { id: 'order-3', userId: 'user-3', productId: 'user-8', status: 'shipped', createdAt: '2024-01-18T09:20:00Z' },
  { id: 'order-4', userId: 'user-5', productId: 'user-15', status: 'completed', createdAt: '2024-01-10T16:00:00Z' },
  { id: 'order-5', userId: 'user-7', productId: 'user-22', status: 'pending', createdAt: '2024-01-22T11:15:00Z' },
  { id: 'order-6', userId: 'user-10', productId: 'user-3', status: 'completed', createdAt: '2024-01-12T13:30:00Z' },
  { id: 'order-7', userId: 'user-15', productId: 'user-18', status: 'shipped', createdAt: '2024-01-19T15:45:00Z' },
  { id: 'order-8', userId: 'user-18', productId: 'user-25', status: 'pending', createdAt: '2024-01-21T10:00:00Z' },
  { id: 'order-9', userId: 'user-20', productId: 'user-35', status: 'completed', createdAt: '2024-01-14T12:20:00Z' },
  { id: 'order-10', userId: 'user-12', productId: 'user-42', status: 'shipped', createdAt: '2024-01-17T14:30:00Z' },
];

const auditLogs = [
  { id: 'log-1', action: 'LOGIN', actorId: 'user-1', targetNodeId: 'user-1', timestamp: '2024-01-15T10:00:00Z', details: 'User login from 192.168.1.100' },
  { id: 'log-2', action: 'VIEW_PRODUCT', actorId: 'user-2', targetNodeId: 'user-5', timestamp: '2024-01-15T10:15:00Z', details: 'Viewed product details' },
  { id: 'log-3', action: 'CREATE_ORDER', actorId: 'user-3', targetNodeId: 'order-1', timestamp: '2024-01-15T10:30:00Z', details: 'New order created' },
  { id: 'log-4', action: 'UPDATE_PROFILE', actorId: 'user-5', targetNodeId: 'profile-user-5', timestamp: '2024-01-15T11:00:00Z', details: 'Profile bio updated' },
  { id: 'log-5', action: 'LOGIN', actorId: 'user-7', targetNodeId: 'user-7', timestamp: '2024-01-15T11:20:00Z', details: 'User login from 192.168.1.101' },
  { id: 'log-6', action: 'VIEW_PRODUCT', actorId: 'user-10', targetNodeId: 'user-12', timestamp: '2024-01-15T11:45:00Z', details: 'Viewed product details' },
  { id: 'log-7', action: 'ACCESS_DENIED', actorId: 'user-8', targetNodeId: 'user-20', timestamp: '2024-01-15T12:00:00Z', details: 'Insufficient permissions' },
  { id: 'log-8', action: 'DATA_EXPORT', actorId: 'user-1', targetNodeId: 'user-5', timestamp: '2024-01-15T12:30:00Z', details: 'User data exported' },
  { id: 'log-9', action: 'SUSPICIOUS_ACCESS', actorId: 'user-9', targetNodeId: 'admin-config-1', timestamp: '2024-01-15T13:00:00Z', details: 'Attempted access to restricted resource' },
  { id: 'log-10', action: 'VIEW_PRODUCT', actorId: 'user-15', targetNodeId: 'user-30', timestamp: '2024-01-15T13:30:00Z', details: 'Viewed product details' },
  { id: 'log-11', action: 'LOGIN', actorId: 'user-18', targetNodeId: 'user-18', timestamp: '2024-01-15T14:00:00Z', details: 'User login from 192.168.1.102' },
  { id: 'log-12', action: 'API_QUERY', actorId: 'user-12', targetNodeId: 'admin-config-1', timestamp: '2024-01-15T14:30:00Z', details: 'GraphQL query executed on restricted node' },
  { id: 'log-13', action: 'VIEW_PRODUCT', actorId: 'user-20', targetNodeId: 'user-55', timestamp: '2024-01-15T15:00:00Z', details: 'Viewed product details' },
  { id: 'log-14', action: 'LOGOUT', actorId: 'user-5', targetNodeId: 'user-5', timestamp: '2024-01-15T15:30:00Z', details: 'User logged out' },
  { id: 'log-15', action: 'SYSTEM_ALERT', actorId: 'system', targetNodeId: 'secret:flag', timestamp: '2024-01-15T16:00:00Z', details: 'Attempted unauthorized access to system resource' },
];

const secretNode = {
  id: 'secret:flag',
  hint: 'Access restricted to authorized users only.',
  flag: process.env.WOW_FLAG || 'CTF{dummy_flag_for_dev}',
  level: 'super-secret',
};

module.exports = {
  products,
  users,
  profiles,
  orders,
  auditLogs,
  secretNode,
};
