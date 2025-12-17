from scipy.spatial.distance import pdist
from scipy.cluster.hierarchy import linkage
import numpy as np
latent_vectors = np.load('latent_vectors.npy')

dist_matrix = pdist(latent_vectors, metric='euclidean')
Z_avg = linkage(dist_matrix, method='average')

N = latent_vectors.shape[0]
REQUIRED_SIZE = 6

def get_original_indices(cluster_index, Z, N):
    members = []
    stack = [cluster_index]
    while stack:
        idx = stack.pop()
        if idx < N:
            members.append(idx)
        else:
            row = Z[int(idx) - N]
            stack.append(row[0])
            stack.append(row[1])
    return members

min_avg_linkage_dist = float('inf')
best_cluster_index = -1

for i in range(len(Z_avg)):
    linkage_dist = Z_avg[i, 2]
    size = int(Z_avg[i, 3])

    if size == REQUIRED_SIZE:
        if linkage_dist < min_avg_linkage_dist:
            min_avg_linkage_dist = linkage_dist
            best_cluster_index = N + i

if best_cluster_index != -1:
    best_cluster_indices = get_original_indices(best_cluster_index, Z_avg, N)
    best_cluster_indices.sort()
    result_indices = [int(i) for i in best_cluster_indices]

    print(f"Minimum Average Linkage Distance for Size {REQUIRED_SIZE} Cluster: {min_avg_linkage_dist:.4f}")
    print(f"Node Numbers (0-indexed) for Densest Cluster: {result_indices}")
else:
    print(f"Could not find a cluster of size exactly {REQUIRED_SIZE}.")
