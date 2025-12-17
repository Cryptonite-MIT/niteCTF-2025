function createResolvers({
  products,
  users,
  profiles,
  orders,
  auditLogs,
  secretNode,
  encodeGlobalId,
  decodeGlobalId,
  isAuthorizedForSecret,
}) {
  function getSecretNode(rawId, req) {
    if (rawId !== 'secret:flag' && rawId !== 'flag') return null;

    if (!isAuthorizedForSecret(req)) {
      return {
        id: secretNode.id,
        hint: secretNode.hint,
        flag: null,
        level: 'redacted',
      };
    }

    return secretNode;
  }

  return {
    Query: {
      about: () => `
  AetherCorp GraphQL Gateway v3.2
`,

      products: () =>
        products.map((product) => ({
          ...product,
          id: encodeGlobalId('Product', product.id),
        })),

      users: () =>
        users.map((user) => ({
          ...user,
          id: encodeGlobalId('User', user.id),
        })),

      profiles: () =>
        profiles.map((profile) => ({
          ...profile,
          id: encodeGlobalId('Profile', profile.id),
          userId: encodeGlobalId('User', profile.userId),
        })),

      orders: () =>
        orders.map((order) => ({
          ...order,
          id: encodeGlobalId('Order', order.id),
          userId: encodeGlobalId('User', order.userId),
          productId: encodeGlobalId('Product', order.productId),
        })),

      auditLogs: () =>
        auditLogs.map((log) => ({
          ...log,
          id: encodeGlobalId('AuditLog', log.id),
          targetNodeId: log.targetNodeId,
        })),

      node: (parent, { id }, context) => {
        const decoded = decodeGlobalId(id);
        if (!decoded) return null;

        const { type, id: nodeId } = decoded;

        switch (type) {
          case 'Product': {
            const product = products.find((p) => p.id === nodeId);
            return product ? { ...product, id: encodeGlobalId('Product', product.id) } : null;
          }

          case 'User': {
            const user = users.find((u) => u.id === nodeId);
            return user ? { ...user, id: encodeGlobalId('User', user.id) } : null;
          }

          case 'Profile': {
            const profile = profiles.find((p) => p.id === nodeId);
            return profile
              ? {
                ...profile,
                id: encodeGlobalId('Profile', profile.id),
                userId: encodeGlobalId('User', profile.userId),
              }
              : null;
          }

          case 'Order': {
            const order = orders.find((o) => o.id === nodeId);
            return order
              ? {
                ...order,
                id: encodeGlobalId('Order', order.id),
                userId: encodeGlobalId('User', order.userId),
                productId: encodeGlobalId('Product', order.productId),
              }
              : null;
          }

          case 'AuditLog': {
            const log = auditLogs.find((l) => l.id === nodeId);
            return log
              ? {
                ...log,
                id: encodeGlobalId('AuditLog', log.id),
                targetNodeId: log.targetNodeId,
              }
              : null;
          }

          case 'secret': {
            return getSecretNode(nodeId, context.req);
          }

          default:
            return null;
        }
      },
    },

    Node: {
      __resolveType(obj) {
        if (obj.flag !== undefined && obj.level !== undefined && obj.hint !== undefined) {
          return 'secret';
        }
        if (obj.action && obj.targetNodeId !== undefined && !obj.productId) {
          return 'AuditLog';
        }
        if (obj.username) {
          return 'User';
        }
        if (obj.userId && obj.bio !== undefined && obj.avatarUrl !== undefined) {
          return 'Profile';
        }
        if (obj.userId && obj.productId && obj.status) {
          return 'Order';
        }
        if (obj.name && obj.specs !== undefined) {
          return 'Product';
        }
        return null;
      },
    },
  };
}

module.exports = createResolvers;
