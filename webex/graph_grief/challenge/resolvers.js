const createResolvers = require("./resolvers-private");
const { products, users, profiles, orders, auditLogs, secretNode } = require("./app-data");

const encodeGlobalId = (type, id) => {
  return Buffer.from(`${type}:${id}`).toString("base64");
};

const decodeGlobalId = (globalId) => {
  try {
    const decoded = Buffer.from(globalId, "base64").toString("utf-8");
    const [type, id] = decoded.split(":");
    return { type, id };
  } catch (error) {
    return null;
  }
};

const isAuthorizedForSecret = (req) => {
  const ip = (req.ip || req.connection.remoteAddress || '').replace('::ffff:', '');
  return ip === '127.0.0.1' || ip === '::1';
};

const resolvers = createResolvers({
  products,
  users,
  profiles,
  orders,
  auditLogs,
  secretNode,
  encodeGlobalId,
  decodeGlobalId,
  isAuthorizedForSecret,
});

module.exports = resolvers;