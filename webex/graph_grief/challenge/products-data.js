const noiseHead = Array.from({ length: 60 }, (_, i) => ({
  id: `user-${String(i + 1).padStart(0, "0")}`,
  name: `User ${String(i + 1).padStart(0, "0")}`,
}));

const products = [...noiseHead];

module.exports = products;