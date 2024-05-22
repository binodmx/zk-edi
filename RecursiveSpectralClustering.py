from sklearn.cluster import SpectralClustering

class RecursiveSpectralClustering:
    def __init__(self, n_clusters=8, affinity="rbf", assign_labels="kmeans"):
        self.n_clusters = n_clusters
        self.affinity = affinity
        self.assign_labels = assign_labels
        self.labels_ = None

    def __get_clusters(self, adjacency_matrix):
        clustering = SpectralClustering(n_clusters=2, 
                                        affinity="precomputed", 
                                        assign_labels=self.assign_labels)
        clustering.fit(adjacency_matrix)
        clusters = {}
        for i in range(len(clustering.labels_)):
            if clustering.labels_[i] not in clusters:
                clusters[clustering.labels_[i]] = []
            clusters[clustering.labels_[i]].append(i)
        return list(clusters.values())

    def __recursive_clustering(self, n, m, X, A, indices):
        if n/m <= 1:
            return [indices]
        temp_clusters = self.__get_clusters(X)
        L = len(temp_clusters[0])
        R = len(temp_clusters[1])
        if L%m == 0 or R%m == 0:
            indices_L = temp_clusters[0]
            indices_R = temp_clusters[1]
        else:
            if L > R:
                total_scores = {}
                for i in temp_clusters[0]:
                    total_scores[i] = 0
                    for j in temp_clusters[1]:
                        total_scores[i] += X[i][j] + X[j][i]
                sorted_scores = sorted(total_scores.items(), key=lambda x: x[1], reverse=True)
                if L > m:
                    indices_L = [i for i, _ in sorted_scores[L%m:]]
                    indices_R = temp_clusters[1] + [i for i, _ in sorted_scores[:L%m]]
                else:
                    indices_L = [i for i, _ in sorted_scores[m-R:]]
                    indices_R = temp_clusters[1] + [i for i, _ in sorted_scores[:m-R]]
            else:
                total_scores = {}
                for i in temp_clusters[1]:
                    total_scores[i] = 0
                    for j in temp_clusters[0]:
                        total_scores[i] += X[i][j] + X[j][i]
                sorted_scores = sorted(total_scores.items(), key=lambda x: x[1], reverse=True)
                if R > m:
                    indices_L = temp_clusters[0] + [i for i, _ in sorted_scores[:R%m]]
                    indices_R = [i for i, _ in sorted_scores[R%m:]]
                else:
                    indices_L = temp_clusters[0] + [i for i, _ in sorted_scores[:m-L]]
                    indices_R = [i for i, _ in sorted_scores[m-L:]]
        P = X[indices_L][:, indices_L]
        Q = X[indices_R][:, indices_R]
        temp_clusters_L = self.__recursive_clustering(P.shape[0], m, P, A, [indices[i] for i in indices_L])
        temp_clusters_R = self.__recursive_clustering(Q.shape[0], m, Q, A, [indices[i] for i in indices_R])
        clusters = temp_clusters_L + temp_clusters_R
        return clusters

    def fit(self, X):
        n = X.shape[0]
        m = round(n/self.n_clusters)
        X = X if self.affinity == "precomputed" else SpectralClustering(n_clusters=self.n_clusters, affinity=self.affinity).fit(X).affinity_matrix_
        clusters = self.__recursive_clustering(n, m, X, X, list(range(n)))
        labels = [0]*n
        label = 0
        for c in clusters:
            for i in c:
                labels[i] = label
            label += 1
        self.labels_ = labels
        return labels
