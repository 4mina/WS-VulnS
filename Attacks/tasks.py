from __future__ import absolute_import, unicode_literals
import os
import re
import copy
import numpy as np
from celery import shared_task, current_task, group
from ahocorapy.keywordtree import KeywordTree
from difflib import SequenceMatcher
from time import sleep
from numpy import linalg
from pandas import DataFrame
from nltk import WordNetLemmatizer, word_tokenize, pos_tag
from nltk.corpus import wordnet, wordnet_ic
from nltk.util import ngrams
from sklearn.metrics.pairwise import cosine_distances
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans, AgglomerativeClustering
from scipy import sparse
from scipy.cluster.hierarchy import linkage, fcluster
from scipy.spatial.distance import squareform
from spherecluster import SphericalKMeans
from collections import OrderedDict

from Attacks.choices import PATTERN_SEPARATORS, HTTP_STATUS_CODES_SERVER_SIDE, IGNORE_WORDS, SIMILARITY_COEFFICIENT, \
    WORD_ORDER_THRESHOLD, DOS_HTTP_STATUS_CODES_SERVER_SIDE, ANOMALY_THRESHOLD, REQUEST_RESPONSE_SIMILARITY_THRESHOLD
from REST.views import RestMaliciousRequestsGeneration, RestValidRequestsGeneration
from SOAP.views import SoapMaliciousRequestsGeneration, SoapValidRequestsGeneration
from REST.models import Path
from SOAP.models import Operation
from WS_VulnS.settings import BASE_DIR

''' Injection detection '''


# Get error patterns from the previous constructed file
def extract_error_patterns_from_file(file_name):
    errors = []
    with open(os.path.join(BASE_DIR, 'Attacks/Word_Lists', file_name), 'r') as f:
        for line in f:
            if not "#" in line:
                errors.append(line.strip())
    return errors


def similar(a, b):
    return SequenceMatcher(None, a, b).ratio()


def create_aho_corasick_trie(errors):
    # Error Pattern Matching Algorithm : Aho-Corasick
    kwtree = KeywordTree(case_insensitive=True)
    for i in errors:
        kwtree.add(i)
    kwtree.finalize()
    return kwtree


def inj_static_detection(response, errors):
    kwtree = create_aho_corasick_trie(errors)
    results = kwtree.search_all(response)
    for result in results:
        end_index = result[1] + len(result[0])
        i = result[1]
        while (response[i] not in PATTERN_SEPARATORS) and (i != 0):
            i -= 1
        sim = similar(result[0].lower(), response[i:end_index].lower())
        if sim == 1:
            return True
        else:
            if sim >= ANOMALY_THRESHOLD:
                return True
    return False


def extract_meaningful_words(text, stop_words, tagged):
    # Remove HTML / XML tags and JSON keys
    text = re.sub(r'<.*?>|".*?"\s*:|{|}', ' ', text)
    # Remove punctuation (Bof bof ?)
    # text = text.translate(str.maketrans('', '', string.punctuation))
    # Tokenization (From text to words)
    words = [word.lower() for word in word_tokenize(text) if word.lower() not in stop_words]
    # Lemmatization
    lemmatizer = WordNetLemmatizer()

    if tagged:
        # Return tagged words
        tagged_words = pos_tag(words)
        meaningful_words = [(lemmatizer.lemmatize(word), tag) for (word, tag) in tagged_words]
    else:
        meaningful_words = [lemmatizer.lemmatize(word) for word in words]

    return meaningful_words


# This function tokenizes text to bag of n-grams, n being the number of grams
def bag_of_n_grams(text, ignore_words, n):
    words = extract_meaningful_words(text, ignore_words, False)
    words = list(OrderedDict.fromkeys(words))
    words = list(ngrams(words, n)) if len(words) > 1 else [(words[0], ' ')]
    for i, j in zip(range(len(words)), words):
        words[i] = ' '.join(j)

    return list(OrderedDict.fromkeys(words))


def convert_nltk_tag_to_wordnet_tag(tag):
    if tag.startswith('J'):
        return wordnet.ADJ
    elif tag.startswith('N'):
        return wordnet.NOUN
    elif tag.startswith('R'):
        return wordnet.ADV
    elif tag.startswith('V'):
        return wordnet.VERB

    return None


def max_lin_similarity(word, tag, common_vocabulary, info_content):
    max_similarity_value = 0.0
    most_similar_word = ''

    word_synsets_1 = wordnet.synsets(word, pos=convert_nltk_tag_to_wordnet_tag(tag))

    if len(word_synsets_1) > 0:
        word_element_1 = word_synsets_1[0]

        for w, t in common_vocabulary.items():
            # Same Part Of Speech
            if (tag == t) and (tag.startswith('N') or tag.startswith('V')):
                word_synsets_2 = wordnet.synsets(w, pos=convert_nltk_tag_to_wordnet_tag(t))
                if len(word_synsets_2) > 0:
                    word_element_2 = word_synsets_2[0]
                    similarity = word_element_1.lin_similarity(word_element_2, info_content)
                    if similarity > max_similarity_value:
                        max_similarity_value = similarity
                        most_similar_word = w

    return max_similarity_value, most_similar_word


def create_semantic_vector(text_words, common_vocabulary, info_content):
    text_semantic_vector = np.zeros(len(common_vocabulary))

    i = 0
    for word, tag in common_vocabulary.items():
        if word in text_words and tag == text_words[word]:
            text_semantic_vector[i] = 1.0
        else:
            modified_common_vocabulary = common_vocabulary.copy()
            del modified_common_vocabulary[word]
            max_similarity, most_similar_word = max_lin_similarity(word, tag, modified_common_vocabulary, info_content)
            text_semantic_vector[i] = max_similarity

        i += 1

    return text_semantic_vector


def create_word_order_vector(text_words, common_vocabulary, info_content):
    text_word_order_vector = np.zeros(len(common_vocabulary))

    i = 0
    for word, tag in common_vocabulary.items():
        if word in text_words and tag == text_words[word]:
            text_word_order_vector[i] = list(text_words.keys()).index(word) + 1
        else:
            modified_common_vocabulary = common_vocabulary.copy()
            del modified_common_vocabulary[word]
            max_similarity, most_similar_word = max_lin_similarity(word, tag, modified_common_vocabulary, info_content)
            if max_similarity >= WORD_ORDER_THRESHOLD:
                text_word_order_vector[i] = list(common_vocabulary.keys()).index(most_similar_word) + 1
            else:
                text_word_order_vector[i] = 0

        i += 1

    return text_word_order_vector


def generate_responses_sets(valid_responses, fuzzed_responses, malicious_responses):
    responses_set_1 = []
    responses_set_2 = []
    responses_set_3 = []
    length_set_1 = 0
    length_set_2 = 0
    length_set_3 = 0

    for resp in valid_responses:
        if resp.content.__len__() != 0:
            responses_set_1.append(resp)
            length_set_1 += 1

    for resp in fuzzed_responses:
        if resp.content.__len__() != 0:
            responses_set_2.append(resp)
            length_set_2 += 1

    for resp in malicious_responses:
        if resp.content.__len__() != 0:
            if ('bad request' not in resp.content.lower()) or (int(resp.http_status_code) != 400):
                responses_set_3.append(resp)
                length_set_3 += 1
    return responses_set_1, responses_set_2, responses_set_3, length_set_1, length_set_2, length_set_3


def compute_clustering_threshold(data, precomputed_distances, distance_matrix=None):
    if precomputed_distances and distance_matrix is not None:
        length_set_1 = data.filter(regex='^Set_1', axis=0).shape[0]
        length_set_2 = data.filter(regex='^Set_2', axis=0).shape[0]

        return min(distance_matrix[0:length_set_1, 0:length_set_1].max(),
                   distance_matrix[length_set_1:length_set_1 + length_set_2,
                   length_set_1:length_set_1 + length_set_2].max())
    else:
        responses_vectors_set_1 = data.filter(regex='^Set_1', axis=0)
        responses_vectors_set_2 = data.filter(regex='^Set_2', axis=0)
        if responses_vectors_set_1.shape[0] != 0 and responses_vectors_set_2.shape[0] != 0:
            distances_set_1 = cosine_distances(sparse.csr_matrix(responses_vectors_set_1.values))
            distances_set_2 = cosine_distances(sparse.csr_matrix(responses_vectors_set_2.values))
            return min(distances_set_1.max(), distances_set_2.max())

        else:
            if responses_vectors_set_1.shape[0] != 0 and responses_vectors_set_2.shape[0] == 0:
                distances_set_1 = cosine_distances(sparse.csr_matrix(responses_vectors_set_1.values))
                return distances_set_1.max()

            elif responses_vectors_set_1.shape[0] == 0 and responses_vectors_set_2.shape[0] != 0:
                distances_set_2 = cosine_distances(sparse.csr_matrix(responses_vectors_set_2.values))
                return distances_set_2.max()

            else:
                return 0


def preprocessing_method_1(responses, length_set_1, length_set_2, length_set_3):
    vocabulary = []

    for resp in responses:
        if resp.content.__len__() != 0:
            vocabulary.extend(bag_of_n_grams(resp.content, IGNORE_WORDS, 2))

    if len(vocabulary) > 0:
        vocabulary = list(OrderedDict.fromkeys(vocabulary))
        # Create vectorizer using bag of 2-grams and TF-IDF representation
        vectorizer = TfidfVectorizer(stop_words=IGNORE_WORDS, ngram_range=(2, 2), vocabulary=vocabulary)

        vectors = vectorizer.fit_transform([' '.join(extract_meaningful_words(resp.content, IGNORE_WORDS, False))
                                            for resp in responses if resp.content.__len__() != 0])

        data_structure = DataFrame(data=vectors.toarray(), columns=vectorizer.get_feature_names(),
                                   index=['Set_1_Resp_' + str(i) for i in range(length_set_1)] +
                                         ['Set_2_Resp_' + str(i) for i in range(length_set_2)] +
                                         ['Set_3_Resp_' + str(i) for i in range(length_set_3)])
        return True, data_structure

    else:
        return False, DataFrame()


def preprocessing_method_2(responses, length_set_1, length_set_2, length_set_3, info_content):
    temporary = []
    responses_words = []
    responses_similarity_vectors = []
    responses_word_order_vectors = []

    for resp in responses:
        if resp.content.__len__() != 0:
            response_words = OrderedDict(extract_meaningful_words(resp.content, IGNORE_WORDS, True))
            responses_words.append(response_words)
            temporary += list(response_words.items())

    if len(temporary) > 0:
        vocabulary = OrderedDict(temporary)

        for resp in responses_words:
            responses_similarity_vectors.append(create_semantic_vector(resp, vocabulary, info_content))
            responses_word_order_vectors.append(create_word_order_vector(resp, vocabulary, info_content))

        dimension = len(responses_words)
        distance_matrix = np.zeros(shape=(dimension, dimension))
        for i in range(dimension):
            for j in range(0, dimension):
                if i > j:
                    distance_matrix[i][j] = \
                        SIMILARITY_COEFFICIENT \
                        * cosine_distances([responses_similarity_vectors[i]], [responses_similarity_vectors[j]])[0][0] \
                        + (1 - SIMILARITY_COEFFICIENT) \
                        * (linalg.norm(responses_word_order_vectors[i] - responses_word_order_vectors[j]
                                       / linalg.norm(responses_word_order_vectors[i] +
                                                     responses_word_order_vectors[j])))

        distance_matrix = distance_matrix + distance_matrix.T - np.diag(distance_matrix.diagonal())
        data_structure = DataFrame(columns=list(vocabulary.keys()),
                                   index=['Set_1_Resp_' + str(i) for i in range(length_set_1)] +
                                         ['Set_2_Resp_' + str(i) for i in range(length_set_2)] +
                                         ['Set_3_Resp_' + str(i) for i in range(length_set_3)])

        return True, data_structure, distance_matrix

    else:
        return False, DataFrame(), np.zeros(shape=(0, 0))


def compute_clusters_centers(data, clusters_number, labels, clusters_centers):
    for i in range(1, clusters_number):
        clusters_points = data[labels == i]
        clusters_mean = np.mean(clusters_points, axis=0)
        clusters_centers[i, :] = clusters_mean
    return clusters_centers


def get_objects_by_cluster(data, labels):
    objects = {data.index.values[i]: labels[i] for i in range(data.index.values.size)}
    objects_by_cluster = {}
    for key, value in sorted(objects.items()):
        objects_by_cluster.setdefault(value, []).append(key)
    return objects_by_cluster


def cluster_is_vulnerable(objects_by_cluster, clusters, responses_set_3, attack):
    if len(clusters) != len(objects_by_cluster.keys()):
        clusters = [i for i in objects_by_cluster.keys()]
    for key in objects_by_cluster:
        if 'Set_1' in '\t'.join(objects_by_cluster[key]) or 'Set_2' in '\t'.join(objects_by_cluster[key]):
            clusters.remove(key)
    if len(clusters) == 0:
        return False, 0, {}
    else:
        vulnerable_clusters = []
        vulnerable_objects_by_cluster = {}
        nb_vulnerabilities = 0
        nb_vulnerabilities_per_type = {}
        nb_vulnerabilities_per_type[attack] = {}
        if attack == 'sqli':
            nb_vulnerabilities_per_type[attack]['nb_tautology'] = 0
            nb_vulnerabilities_per_type[attack]['nb_union'] = 0
            nb_vulnerabilities_per_type[attack]['nb_piggy_backed'] = 0
            nb_vulnerabilities_per_type[attack]['nb_incorrect_queries'] = 0
        elif attack == 'xmli':
            nb_vulnerabilities_per_type[attack]['nb_malformed'] = 0
            nb_vulnerabilities_per_type[attack]['nb_replicating'] = 0
            nb_vulnerabilities_per_type[attack]['nb_xpath'] = 0

        # Loop trough the remaining clusters
        for i in clusters:
            cluster_i_objects = objects_by_cluster[i]
            # pick the first response
            cluster_i_sample_label = cluster_i_objects[0]
            cluster_i_sample_object = responses_set_3[int(re.sub('Set_3_Resp_', '', cluster_i_sample_label))]
            cluster_i_sample_response = re.sub(r'<.*?>|".*?"\s*:|{|}', ' ', cluster_i_sample_object.content)
            #If the response doesn't contain more than threshold % of the request pattern
            if SequenceMatcher(None, cluster_i_sample_object.request.pattern,
                              cluster_i_sample_response).ratio() <= REQUEST_RESPONSE_SIMILARITY_THRESHOLD:
                vulnerable_clusters.append(i)
                vulnerable_objects_by_cluster.update({i: cluster_i_objects})
                if attack == 'sqli':
                    for label in cluster_i_objects:
                        if responses_set_3[int(re.sub('Set_3_Resp_', '', label))].request.attack_type.type == 'Taut':
                            nb_vulnerabilities_per_type[attack]['nb_tautology'] += 1
                            nb_vulnerabilities += 1
                        elif responses_set_3[int(re.sub('Set_3_Resp_', '', label))].request.attack_type.type == 'Union':
                            nb_vulnerabilities_per_type[attack]['nb_union'] += 1
                            nb_vulnerabilities += 1
                        elif responses_set_3[int(re.sub('Set_3_Resp_', '', label))].request.attack_type.type == 'PiggyB':
                            nb_vulnerabilities_per_type[attack]['nb_piggy_backed'] += 1
                            nb_vulnerabilities += 1
                        elif responses_set_3[int(re.sub('Set_3_Resp_', '', label))].request.attack_type.type == 'IncQ':
                            nb_vulnerabilities_per_type[attack]['nb_incorrect_queries'] += 1
                            nb_vulnerabilities += 1
                elif attack == 'xmli':
                    for label in cluster_i_objects:
                        if responses_set_3[int(re.sub('Set_3_Resp_', '', label))].request.attack_type.type == \
                                'Malformed':
                            nb_vulnerabilities_per_type[attack]['nb_malformed'] += 1
                            nb_vulnerabilities += 1
                        elif responses_set_3[int(re.sub('Set_3_Resp_', '', label))].request.attack_type.type == \
                                'Replicating':
                            nb_vulnerabilities_per_type[attack]['nb_replicating'] += 1
                            nb_vulnerabilities += 1
                        elif responses_set_3[int(re.sub('Set_3_Resp_', '', label))].request.attack_type.type == 'XPath':
                            nb_vulnerabilities_per_type[attack]['nb_xpath'] += 1
                            nb_vulnerabilities += 1

        return True, nb_vulnerabilities, nb_vulnerabilities_per_type


def detection_k_means(data, clusters_number, initialization='k-means++'):
    k_means = KMeans(n_clusters=clusters_number, init=initialization)
    k_means.fit(data)
    clusters = [i for i in range(clusters_number)]
    objects_by_cluster = get_objects_by_cluster(data, k_means.labels_)

    # 3-D plot using PCA
    # pca = PCA(n_components=3)
    # pca.fit(data)
    # reduced_data = DataFrame(pca.transform(data))
    # colors = list(zip(*sorted((tuple(matplotlib_colors.rgb_to_hsv(matplotlib_colors.to_rgba(color)[:3])), name)
    #                           for name, color in dict(matplotlib_colors.BASE_COLORS,
    #                                                   **matplotlib_colors.CSS4_COLORS).items())))[1]
    # skips = math.floor(len(colors[5: -5]) / clusters_number)
    # clusters_colors = colors[5: -5: skips]
    # fig = plt.figure()
    # ax = fig.add_subplot(111, projection='3d')
    # ax.set_title('K-Means')
    # ax.scatter(reduced_data[0], reduced_data[1], reduced_data[2], c=list(map(lambda label: clusters_colors[label],
    #                                                                          k_means.labels_)))
    # str_labels = list(map(lambda label: '% s' % label, k_means.labels_))
    # list(map(lambda data1, data2, data3, str_label:
    #          ax.text(data1, data2, data3, s=str_label, size=16.5, zorder=20, color='k'),
    #          reduced_data[0], reduced_data[1], reduced_data[2], str_labels))
    # plt.show()

    # 2-D plot using MDS
    # mds = MDS(n_components=2, random_state=1)
    # output = mds.fit_transform(data)
    # fig, ax = plt.subplots()
    # ax.set_title('K-Means')
    # ax.scatter(output[:, 0], output[:, 1], c=k_means.labels_)
    # ax.scatter(k_means.cluster_centers_[:, 0], k_means.cluster_centers_[:, 1], c='black', s=200, alpha=0.5)
    # plt.show()

    # Plot by choosing columns...
    # fig, ax = plt.subplots()
    # ax.set_title('K-Means')
    # ax.scatter(data.iloc[:, 2], data.iloc[:, 3], c=k_means.labels_, cmap='rainbow')
    # ax.scatter(k_means.cluster_centers_[:, 2], k_means.cluster_centers_[:, 3], c='black', s=200, alpha=0.5)
    # plt.show()
    return objects_by_cluster, clusters, k_means.cluster_centers_#interia, len(clusters)


def detection_spherical_k_means(data, clusters_number, initialization='k-means++'):
    spherical_k_means = SphericalKMeans(n_clusters=clusters_number, init=initialization)
    spherical_k_means.fit(data)
    clusters = [i for i in range(clusters_number)]
    interia = spherical_k_means.inertia_
    objects_by_cluster = get_objects_by_cluster(data, spherical_k_means.labels_)

    # 3-D plot using PCA
    # pca = PCA(n_components=3)
    # pca.fit(data)
    # reduced_data = DataFrame(pca.transform(data))
    # colors = list(zip(*sorted((tuple(matplotlib_colors.rgb_to_hsv(matplotlib_colors.to_rgba(color)[:3])), name)
    #                           for name, color in dict(matplotlib_colors.BASE_COLORS,
    #                                                   **matplotlib_colors.CSS4_COLORS).items())))[1]
    # skips = math.floor(len(colors[5: -5]) / clusters_number)
    # clusters_colors = colors[5: -5: skips]
    # fig = plt.figure()
    # ax = fig.add_subplot(111, projection='3d')
    # ax.set_title('Spherical K-Means')
    # ax.scatter(reduced_data[0], reduced_data[1], reduced_data[2], c=list(map(lambda label: clusters_colors[label],
    #                                                                          spherical_k_means.labels_)))
    # str_labels = list(map(lambda label: '% s' % label, spherical_k_means.labels_))
    # list(map(lambda data1, data2, data3, str_label:
    #          ax.text(data1, data2, data3, s=str_label, size=16.5, zorder=20, color='k'),
    #          reduced_data[0], reduced_data[1], reduced_data[2], str_labels))
    # plt.show()

    # 2-D plot using MDS
    # mds = MDS(n_components=2, random_state=1)
    # output = mds.fit_transform(data)
    # fig, ax = plt.subplots()
    # ax.set_title('Spherical K-Means')
    # ax.scatter(output[:, 0], output[:, 1], c=spherical_k_means.labels_)
    # ax.scatter(spherical_k_means.cluster_centers_[:, 0], spherical_k_means.cluster_centers_[:, 1], c='black', s=200,
    #            alpha=0.5)
    # plt.show()

    # Plot by choosing columns...
    # fig, ax = plt.subplots()
    # ax.set_title('Spherical K-Means')
    # ax.scatter(data.iloc[:, 2], data.iloc[:, 3], c=spherical_k_means.labels_, cmap='rainbow')
    # ax.scatter(spherical_k_means.cluster_centers_[:, 2], spherical_k_means.cluster_centers_[:, 3], c='black', s=200,
    #            alpha=0.5)
    # plt.show()

    return objects_by_cluster, clusters, spherical_k_means.cluster_centers_#, interia, len(clusters)


def detection_hierarchical_clustering(data, clusters_number=None, distance_matrix=None):
    if clusters_number is not None:
        if distance_matrix is not None:
            hierarchical_clustering = AgglomerativeClustering(n_clusters=clusters_number, affinity='precomputed',
                                                              linkage='average')
            hierarchical_clustering.fit_predict(distance_matrix)
            clusters = [i for i in range(clusters_number)]
            clusters_centers = np.zeros(shape=(clusters_number, data.shape[1]))
            objects_by_cluster = get_objects_by_cluster(data, hierarchical_clustering.labels_)

        else:
            hierarchical_clustering = AgglomerativeClustering(n_clusters=clusters_number, affinity='cosine',
                                                              linkage='average')
            hierarchical_clustering.fit_predict(data)
            clusters = [i for i in range(clusters_number)]
            clusters_centers = np.zeros(shape=(clusters_number, data.shape[1]))
            objects_by_cluster = get_objects_by_cluster(data, hierarchical_clustering.labels_)
            clusters_centers = compute_clusters_centers(data, clusters_number, hierarchical_clustering.labels_,
                                                        clusters_centers)

        # fig, ax = plt.subplots()
        # ax.set_title('Hierarchical Clustering')
        # ax.scatter(data.iloc[:, 2], data.iloc[:, 3], c=hierarchical_clustering.labels_, cmap='rainbow')
        # ax.scatter(clusters_centers[:, 2], clusters_centers[:, 3], c='black', s=200, alpha=0.5)
        # fig.tight_layout()
        # plt.show()

    else:
        if distance_matrix is not None:
            linkage_matrix = linkage(y=squareform(distance_matrix), method='average')
            #fig, ax = plt.subplots()
            #ax.set_title('Dendrogram')
            #dendrogram(linkage_matrix)
            #fig.tight_layout()
            #plt.show()
            clusters_labels = fcluster(Z=linkage_matrix, t=compute_clustering_threshold(data, True, distance_matrix),
                                       criterion='distance')
            clusters = [i + 1 for i in range(clusters_labels.max())]
            clusters_centers = np.zeros(shape=(clusters_labels.max(), data.shape[1]))
            objects_by_cluster = get_objects_by_cluster(data, clusters_labels)

        else:
            linkage_matrix = linkage(y=data.values, method='average', metric='cosine')
            #fig, ax = plt.subplots()
            #ax.set_title('Dendrogram')
            #dendrogram(linkage_matrix)
            #fig.tight_layout()
            #plt.show()
            clusters_labels = fcluster(Z=linkage_matrix, t=compute_clustering_threshold(data, False),
                                       criterion='distance')
            clusters = [i + 1 for i in range(clusters_labels.max())]
            clusters_centers = np.zeros(shape=(clusters_labels.max(), data.shape[1]))
            objects_by_cluster = get_objects_by_cluster(data, clusters_labels)
            clusters_centers = compute_clusters_centers(data, clusters_labels.max(), clusters_labels, clusters_centers)

        # fig, ax = plt.subplots()
        # ax.set_title('Hierarchical Clustering')
        # ax.scatter(data.iloc[:, 2], data.iloc[:, 3], c=clusters_labels, cmap='rainbow')
        # fig.tight_layout()
        # plt.show()
    return objects_by_cluster, clusters, clusters_centers


def detection_hybrid_clustering(data):
    initial_objects, initial_clusters, initial_centers = detection_hierarchical_clustering(data=data)
    objects_by_cluster, clusters, clusters_centers = detection_k_means(data=data, clusters_number=len(initial_clusters),
                                                                       initialization=initial_centers)
    return objects_by_cluster, clusters, clusters_centers


@shared_task
def dynamic_detection_injections(operation_id, attack, ws_type, number_non_malicious_requests, methods_choice,
                                 number_clusters=None):
    static_detection_result, malicious_responses = static_detection_injections(operation_id, attack, ws_type)
    if static_detection_result['sure_not_vuln']:
        return static_detection_result

    else:
        if ws_type == 'soap':
            operation = Operation.objects.get(id=operation_id)
            non_malicious_requests_generator = SoapValidRequestsGeneration()
        else:
            operation = Path.objects.get(id=operation_id)
            non_malicious_requests_generator = RestValidRequestsGeneration()
        total = 100
        vulns_found = {}
        nb_success_attacks = 0
        nb_malicious_requests = 0
        nb_valid_requests = 0

        current_task.update_state(state='PROGRESS',
                                  meta={'current': 1, 'total': total,
                                        'percent': 1,
                                        'detection_type': 'dynamic',
                                        'nb_success_attacks': nb_success_attacks,
                                        'vulns_found': vulns_found,
                                        'nb_sent_attacks': nb_malicious_requests,
                                        'nb_valid_requests': nb_valid_requests})
        sleep(0.5)
        current_task.update_state(state='PROGRESS',
                                  meta={'current': 2, 'total': total,
                                        'percent': 2,
                                        'detection_type': 'dynamic',
                                        'nb_success_attacks': nb_success_attacks,
                                        'vulns_found': vulns_found,
                                        'nb_sent_attacks': nb_malicious_requests,
                                        'nb_valid_requests': nb_valid_requests
                                        })

        valid_responses = non_malicious_requests_generator.send_valid_request(operation, number_non_malicious_requests)
        fuzzed_responses = []

        if attack == "sqli":
            fuzzed_responses = non_malicious_requests_generator.send_fuzzed_request(operation,
                                                                                    number_non_malicious_requests)

        if ws_type == 'soap':
            nb_valid_requests = len(valid_responses)
        else:
            for j in [len(valid_responses[i]) for i in valid_responses]:
                nb_valid_requests += j

        nb_valid_requests *= 2

        current_task.update_state(state='PROGRESS',
                                  meta={'current': 5, 'total': total,
                                        'percent': 5,
                                        'detection_type': 'dynamic',
                                        'nb_success_attacks': nb_success_attacks,
                                        'vulns_found': vulns_found,
                                        'nb_sent_attacks': nb_malicious_requests,
                                        'nb_valid_requests': nb_valid_requests
                                        })

        if ws_type == 'soap':
            nb_malicious_requests = len(malicious_responses[attack])
        else:
            for j in [len(malicious_responses[attack][i]) for i in malicious_responses[attack].keys()]:
                nb_malicious_requests += j

        current_task.update_state(state='PROGRESS',
                                  meta={'current': 5, 'total': total,
                                        'percent': 5,
                                        'detection_type': 'dynamic',
                                        'nb_success_attacks': nb_success_attacks,
                                        'vulns_found': vulns_found,
                                        'nb_sent_attacks': nb_malicious_requests,
                                        'nb_valid_requests': nb_valid_requests
                                        })
        if ws_type == 'soap':
            responses_set_1, responses_set_2, responses_set_3, length_set_1, length_set_2, length_set_3 = \
                generate_responses_sets(valid_responses, fuzzed_responses, malicious_responses[attack])
            responses = responses_set_1 + responses_set_2 + responses_set_3
            if len(responses) > 0:
                current_task.update_state(state='PROGRESS',
                                          meta={'current': 10, 'total': total,
                                                'percent': 10,
                                                'detection_type': 'dynamic',
                                                'nb_success_attacks': nb_success_attacks,
                                                'vulns_found': vulns_found,
                                                'nb_sent_attacks': nb_malicious_requests,
                                                'nb_valid_requests': nb_valid_requests
                                                })
                objects = {}
                clusters = []
                if 'preprocessing_method_1' in methods_choice:
                    is_not_empty, data = preprocessing_method_1(responses, length_set_1, length_set_2, length_set_3)
                    if is_not_empty:
                        data = data[(data.T != 0).any()]
                        if data.shape[0] != 0:
                            if number_clusters is not None and data.shape[0] < number_clusters:
                                print('Warning ! Clusters number has changed from ', number_clusters, ' to ',
                                      data.shape[0])
                                number_clusters = data.shape[0]
                            current_task.update_state(state='PROGRESS',
                                                      meta={'current': 20, 'total': total,
                                                            'percent': 20,
                                                            'detection_type': 'dynamic',
                                                            'nb_success_attacks': nb_success_attacks,
                                                            'vulns_found': vulns_found,
                                                            'nb_sent_attacks': nb_malicious_requests,
                                                            'nb_valid_requests': nb_valid_requests
                                                            })

                            if 'k_means' in methods_choice['preprocessing_method_1']:
                                objects, clusters, centers = detection_k_means(data=data, clusters_number=number_clusters)
                            elif 'spherical_k_means' in methods_choice['preprocessing_method_1']:
                                objects, clusters, centers = detection_spherical_k_means(data=data, clusters_number=number_clusters)
                            elif 'cah' in methods_choice['preprocessing_method_1']:
                                objects, clusters, centers = detection_hierarchical_clustering(data=data)
                            elif 'hybrid' in methods_choice['preprocessing_method_1']:
                                objects, clusters, centers = detection_hybrid_clustering(data=data)
                            current_task.update_state(state='PROGRESS',
                                                      meta={'current': 40, 'total': total,
                                                            'percent': 40,
                                                            'detection_type': 'dynamic',
                                                            'nb_success_attacks': nb_success_attacks,
                                                            'vulns_found': vulns_found,
                                                            'nb_sent_attacks': nb_malicious_requests,
                                                            'nb_valid_requests': nb_valid_requests
                                                            })
                            sleep(0.5)
                            current_task.update_state(state='PROGRESS',
                                                      meta={'current': 60, 'total': total,
                                                            'percent': 60,
                                                            'detection_type': 'dynamic',
                                                            'nb_success_attacks': nb_success_attacks,
                                                            'vulns_found': vulns_found})
                            is_vulnerable, nb_objects, nb_objects_per_type = cluster_is_vulnerable(objects, clusters,
                                                                                                   responses_set_3,
                                                                                                   attack)
                            if is_vulnerable:
                                nb_success_attacks += nb_objects
                                if operation.name not in vulns_found.keys():
                                    vulns_found[operation.name] = {}
                                    if attack == 'xmli':
                                        vulns_found[operation.name]['Malformed'] = nb_objects_per_type[attack][
                                            'nb_malformed']
                                        vulns_found[operation.name]['Replicating'] = nb_objects_per_type[attack][
                                            'nb_replicating']
                                        vulns_found[operation.name]['XPath'] = nb_objects_per_type[attack]['nb_xpath']
                                    elif attack == 'sqli':
                                        vulns_found[operation.name]['Taut'] = nb_objects_per_type[attack][
                                            'nb_tautology']
                                        vulns_found[operation.name]['Union'] = nb_objects_per_type[attack]['nb_union']
                                        vulns_found[operation.name]['PiggyB'] = nb_objects_per_type[attack][
                                            'nb_piggy_backed']
                                        vulns_found[operation.name]['IncQ'] = nb_objects_per_type[attack][
                                            'nb_incorrect_queries']
                                else:
                                    if 'Malformed' not in vulns_found[operation.name] and attack == 'xmli':
                                        vulns_found[operation.name].update(
                                            {'Malformed': nb_objects_per_type[attack]['nb_malformed']})
                                    if 'Replicating' not in vulns_found[operation.name] and attack == 'xmli':
                                        vulns_found[operation.name].update(
                                            {'Replicating': nb_objects_per_type[attack]['nb_replicating']})
                                    if 'XPath' not in vulns_found[operation.name] and attack == 'xmli':
                                        vulns_found[operation.name].update(
                                            {'XPath': nb_objects_per_type[attack]['nb_xpath']})
                                    if 'Taut' not in vulns_found[operation.name] and attack == 'sqli':
                                        vulns_found[operation.name].update(
                                            {'Taut': nb_objects_per_type[attack]['nb_tautology']})
                                    if 'Union' not in vulns_found[operation.name] and attack == 'sqli':
                                        vulns_found[operation.name].update(
                                            {'Union': nb_objects_per_type[attack]['nb_union']})
                                    if 'PiggyB' not in vulns_found[operation.name] and attack == 'sqli':
                                        vulns_found[operation.name].update(
                                            {'PiggyB': nb_objects_per_type[attack]['nb_piggy_backed']})
                                    if 'IncQ' not in vulns_found[operation.name] and attack == 'sqli':
                                        vulns_found[operation.name].update(
                                            {'IncQ': nb_objects_per_type[attack]['nb_incorrect_queries']})
                                    else:
                                        if attack == 'xmli':
                                            vulns_found[operation.name]['Malformed'] += nb_objects_per_type[attack][
                                                'nb_malformed']
                                            vulns_found[operation.name]['Replicating'] += nb_objects_per_type[attack][
                                                'nb_replicating']
                                            vulns_found[operation.name]['XPath'] += nb_objects_per_type[attack][
                                                'nb_xpath']
                                        elif attack == 'sqli':
                                            vulns_found[operation.name]['Taut'] += nb_objects_per_type[attack][
                                                'nb_tautology']
                                            vulns_found[operation.name]['Union'] += nb_objects_per_type[attack][
                                                'nb_union']
                                            vulns_found[operation.name]['PiggyB'] += nb_objects_per_type[attack][
                                                'nb_piggy_backed']
                                            vulns_found[operation.name]['IncQ'] += nb_objects_per_type[attack][
                                                'nb_incorrect_queries']

                            current_task.update_state(state='PROGRESS',
                                                      meta={'current': 80, 'total': total,
                                                            'percent': 80,
                                                            'detection_type': 'dynamic',
                                                            'nb_success_attacks': nb_success_attacks,
                                                            'vulns_found': vulns_found,
                                                            'nb_sent_attacks': nb_malicious_requests,
                                                            'nb_valid_requests': nb_valid_requests
                                                            })
                            sleep(0.5)
                            current_task.update_state(state='PROGRESS',
                                                      meta={'current': 100, 'total': total,
                                                            'percent': 100,
                                                            'detection_type': 'dynamic',
                                                            'nb_success_attacks': nb_success_attacks,
                                                            'vulns_found': vulns_found,
                                                            'nb_sent_attacks': nb_malicious_requests,
                                                            'nb_valid_requests': nb_valid_requests})

                        else:
                            print('Clustering is not possible because the resulting vectors are filled with zeros !')

                    else:
                        print('Clustering is not possible because the preprocessed responses are empty !')

                elif 'preprocessing_method_2' in methods_choice:
                    info_content = wordnet_ic.ic('ic-brown.dat')
                    is_not_empty, data, distance_matrix = preprocessing_method_2(responses, length_set_1, length_set_2,
                                                                                 length_set_3, info_content)
                    if is_not_empty:
                        if distance_matrix.shape[0] != 0:
                            current_task.update_state(state='PROGRESS',
                                                      meta={'current': 20, 'total': total,
                                                            'percent': 20,
                                                            'detection_type': 'dynamic',
                                                            'nb_success_attacks': nb_success_attacks,
                                                            'vulns_found': vulns_found,
                                                            'nb_sent_attacks': nb_malicious_requests,
                                                            'nb_valid_requests': nb_valid_requests
                                                            })

                            if 'cah' in methods_choice['preprocessing_method_2']:
                                objects, clusters, centers = detection_hierarchical_clustering(data=data,
                                                                                               distance_matrix=distance_matrix)

                            current_task.update_state(state='PROGRESS',
                                                      meta={'current': 40, 'total': total,
                                                            'percent': 40,
                                                            'detection_type': 'dynamic',
                                                            'nb_success_attacks': nb_success_attacks,
                                                            'vulns_found': vulns_found,
                                                            'nb_sent_attacks': nb_malicious_requests,
                                                            'nb_valid_requests': nb_valid_requests
                                                            })
                            sleep(0.5)
                            current_task.update_state(state='PROGRESS',
                                                      meta={'current': 60, 'total': total,
                                                            'percent': 60,
                                                            'detection_type': 'dynamic',
                                                            'nb_success_attacks': nb_success_attacks,
                                                            'vulns_found': vulns_found,
                                                            'nb_sent_attacks': nb_malicious_requests,
                                                            'nb_valid_requests': nb_valid_requests
                                                            })

                            is_vulnerable, nb_objects, nb_objects_per_type = cluster_is_vulnerable(objects, clusters,
                                                                                                   responses_set_3,
                                                                                                   attack)
                            if is_vulnerable:
                                nb_success_attacks += nb_objects
                                if operation.name not in vulns_found.keys():
                                    if attack == 'xmli':
                                        vulns_found.update({operation.name: {
                                            'Malformed': nb_objects_per_type[attack]['nb_malformed']}})
                                        vulns_found.update({operation.name: {
                                            'Replicating': nb_objects_per_type[attack]['nb_replicating']}})
                                        vulns_found.update(
                                            {operation.name: {'XPath': nb_objects_per_type[attack]['nb_xpath']}})
                                    elif attack == 'sqli':
                                        vulns_found.update(
                                            {operation.name: {'Taut': nb_objects_per_type[attack]['nb_tautology']}})
                                        vulns_found.update(
                                            {operation.name: {'Union': nb_objects_per_type[attack]['nb_union']}})
                                        vulns_found.update({operation.name: {
                                            'PiggyB': nb_objects_per_type[attack]['nb_piggy_backed']}})
                                        vulns_found.update({operation.name: {
                                            'IncQ': nb_objects_per_type[attack]['nb_incorrect_queries']}})
                                else:
                                    if 'Malformed' not in vulns_found[operation.name] and attack == 'xmli':
                                        vulns_found[operation.name].update(
                                            {'Malformed': nb_objects_per_type[attack]['nb_malformed']})
                                    if 'Replicating' not in vulns_found[operation.name] and attack == 'xmli':
                                        vulns_found[operation.name].update(
                                            {'Replicating': nb_objects_per_type[attack]['nb_replicating']})
                                    if 'XPath' not in vulns_found[operation.name] and attack == 'xmli':
                                        vulns_found[operation.name].update(
                                            {'XPath': nb_objects_per_type[attack]['nb_xpath']})
                                    if 'Taut' not in vulns_found[operation.name] and attack == 'sqli':
                                        vulns_found[operation.name].update(
                                            {'Taut': nb_objects_per_type[attack]['nb_tautology']})
                                    if 'Union' not in vulns_found[operation.name] and attack == 'sqli':
                                        vulns_found[operation.name].update(
                                            {'Union': nb_objects_per_type[attack]['nb_union']})
                                    if 'PiggyB' not in vulns_found[operation.name] and attack == 'sqli':
                                        vulns_found[operation.name].update(
                                            {'PiggyB': nb_objects_per_type[attack]['nb_piggy_backed']})
                                    if 'IncQ' not in vulns_found[operation.name] and attack == 'sqli':
                                        vulns_found[operation.name].update(
                                            {'IncQ': nb_objects_per_type[attack]['nb_incorrect_queries']})
                                    else:
                                        if attack == 'xmli':
                                            vulns_found[operation.name]['Malformed'] += nb_objects_per_type[attack][
                                                'nb_malformed']
                                            vulns_found[operation.name]['Replicating'] += nb_objects_per_type[attack][
                                                'nb_replicating']
                                            vulns_found[operation.name]['XPath'] += nb_objects_per_type[attack][
                                                'nb_xpath']
                                        elif attack == 'sqli':
                                            vulns_found[operation.name]['Taut'] += nb_objects_per_type[attack][
                                                'nb_tautology']
                                            vulns_found[operation.name]['Union'] += nb_objects_per_type[attack][
                                                'nb_union']
                                            vulns_found[operation.name]['PiggyB'] += nb_objects_per_type[attack][
                                                'nb_piggy_backed']
                                            vulns_found[operation.name]['IncQ'] += nb_objects_per_type[attack][
                                                'nb_incorrect_queries']

                            current_task.update_state(state='PROGRESS',
                                                      meta={'current': 80, 'total': total,
                                                            'percent': 80,
                                                            'detection_type': 'dynamic',
                                                            'nb_success_attacks': nb_success_attacks,
                                                            'vulns_found': vulns_found,
                                                            'nb_sent_attacks': nb_malicious_requests,
                                                            'nb_valid_requests': nb_valid_requests
                                                            })
                            sleep(0.5)
                            current_task.update_state(state='PROGRESS',
                                                      meta={'current': 100, 'total': total,
                                                            'percent': 100,
                                                            'detection_type': 'dynamic',
                                                            'nb_success_attacks': nb_success_attacks,
                                                            'vulns_found': vulns_found,
                                                            'nb_sent_attacks': nb_malicious_requests,
                                                            'nb_valid_requests': nb_valid_requests
                                                            })
                        else:
                            print('Clustering is not possible because the resulting vectors are filled with zeros !')

                    else:
                        print('Clustering is not possible because the preprocessed responses are empty !')

            else:
                print('Clustering is not possible because the responses are empty !')

        # REST
        else:
            number_methods = len(malicious_responses[attack].keys())
            for method, j in zip(malicious_responses[attack].keys(), range(number_methods)):
                if isinstance(fuzzed_responses, dict):
                    responses_set_1, responses_set_2, responses_set_3, length_set_1, length_set_2, length_set_3 = \
                        generate_responses_sets(valid_responses[method], fuzzed_responses[method],
                                                malicious_responses[attack][method])
                else:
                    responses_set_1, responses_set_2, responses_set_3, length_set_1, length_set_2, length_set_3 = \
                        generate_responses_sets(valid_responses[method], fuzzed_responses,
                                                malicious_responses[attack][method])
                responses = responses_set_1 + responses_set_2 + responses_set_3

                if len(responses) > 0:
                    objects = {}
                    clusters = []

                    if 'preprocessing_method_1' in methods_choice:
                        is_not_empty, data = preprocessing_method_1(responses, length_set_1, length_set_2, length_set_3)
                        if is_not_empty:
                            data = data[(data.T != 0).any()]

                            if data.shape[0] != 0:
                                if number_clusters is not None and data.shape[0] < number_clusters:
                                    print('Warning ! Clusters number has changed from ', number_clusters, ' to ',
                                          data.shape[0])
                                    number_clusters = data.shape[0]

                                if 'k_means' in methods_choice['preprocessing_method_1']:
                                    objects, clusters, centers = detection_k_means(data=data, clusters_number=number_clusters)
                                elif 'spherical_k_means' in methods_choice['preprocessing_method_1']:
                                    objects, clusters, centers = detection_spherical_k_means(data=data, clusters_number=number_clusters)
                                elif 'cah' in methods_choice['preprocessing_method_1']:
                                    objects, clusters, centers = detection_hierarchical_clustering(data=data)
                                elif 'hybrid' in methods_choice['preprocessing_method_1']:
                                    objects, clusters, centers = detection_hybrid_clustering(data=data)

                                is_vulnerable, nb_objects, nb_objects_per_type = cluster_is_vulnerable(objects, clusters,
                                                                                                       responses_set_3,
                                                                                                       attack)
                                if is_vulnerable:
                                    nb_success_attacks += nb_objects
                                    if operation.name not in vulns_found.keys():
                                        if attack == 'xmli':
                                            vulns_found.update({operation.name: {
                                                'Malformed': nb_objects_per_type[attack]['nb_malformed']}})
                                            vulns_found.update({operation.name: {
                                                'Replicating': nb_objects_per_type[attack]['nb_replicating']}})
                                            vulns_found.update(
                                                {operation.name: {'XPath': nb_objects_per_type[attack]['nb_xpath']}})
                                        elif attack == 'sqli':
                                            vulns_found.update(
                                                {operation.name: {'Taut': nb_objects_per_type[attack]['nb_tautology']}})
                                            vulns_found.update(
                                                {operation.name: {'Union': nb_objects_per_type[attack]['nb_union']}})
                                            vulns_found.update({operation.name: {
                                                'PiggyB': nb_objects_per_type[attack]['nb_piggy_backed']}})
                                            vulns_found.update({operation.name: {
                                                'IncQ': nb_objects_per_type[attack]['nb_incorrect_queries']}})
                                    else:
                                        if 'Malformed' not in vulns_found[operation.name] and attack == 'xmli':
                                            vulns_found[operation.name].update(
                                                {'Malformed': nb_objects_per_type[attack]['nb_malformed']})
                                        if 'Replicating' not in vulns_found[operation.name] and attack == 'xmli':
                                            vulns_found[operation.name].update(
                                                {'Replicating': nb_objects_per_type[attack]['nb_replicating']})
                                        if 'XPath' not in vulns_found[operation.name] and attack == 'xmli':
                                            vulns_found[operation.name].update(
                                                {'XPath': nb_objects_per_type[attack]['nb_xpath']})
                                        if 'Taut' not in vulns_found[operation.name] and attack == 'sqli':
                                            vulns_found[operation.name].update(
                                                {'Taut': nb_objects_per_type[attack]['nb_tautology']})
                                        if 'Union' not in vulns_found[operation.name] and attack == 'sqli':
                                            vulns_found[operation.name].update(
                                                {'Union': nb_objects_per_type[attack]['nb_union']})
                                        if 'PiggyB' not in vulns_found[operation.name] and attack == 'sqli':
                                            vulns_found[operation.name].update(
                                                {'PiggyB': nb_objects_per_type[attack]['nb_piggy_backed']})
                                        if 'IncQ' not in vulns_found[operation.name] and attack == 'sqli':
                                            vulns_found[operation.name].update(
                                                {'IncQ': nb_objects_per_type[attack]['nb_incorrect_queries']})
                                        else:
                                            if attack == 'xmli':
                                                vulns_found[operation.name]['Malformed'] += nb_objects_per_type[attack][
                                                    'nb_malformed']
                                                vulns_found[operation.name]['Replicating'] += nb_objects_per_type[attack][
                                                    'nb_replicating']
                                                vulns_found[operation.name]['XPath'] += nb_objects_per_type[attack][
                                                    'nb_xpath']
                                            elif attack == 'sqli':
                                                vulns_found[operation.name]['Taut'] += nb_objects_per_type[attack][
                                                    'nb_tautology']
                                                vulns_found[operation.name]['Union'] += nb_objects_per_type[attack][
                                                    'nb_union']
                                                vulns_found[operation.name]['PiggyB'] += nb_objects_per_type[attack][
                                                    'nb_piggy_backed']
                                                vulns_found[operation.name]['IncQ'] += nb_objects_per_type[attack][
                                                    'nb_incorrect_queries']

                            else:
                                print('Clustering is not possible because the resulting vectors are filled with zeros !')

                        else:
                            print('Clustering is not possible because the preprocessed responses are empty !')

                    elif 'preprocessing_method_2' in methods_choice:
                        info_content = wordnet_ic.ic('ic-brown.dat')
                        is_not_empty, data, distance_matrix = preprocessing_method_2(responses, length_set_1, length_set_2,
                                                                                     length_set_3, info_content)
                        if is_not_empty:
                            if distance_matrix.shape[0] != 0:
                                if 'cah' in methods_choice['preprocessing_method_2']:
                                    objects, clusters, centers = detection_hierarchical_clustering(data=data,
                                                                                                   distance_matrix=distance_matrix)
                                is_vulnerable, nb_objects, nb_objects_per_type = cluster_is_vulnerable(objects, clusters,
                                                                                                       responses_set_3,
                                                                                                       attack)
                                if is_vulnerable:
                                    nb_success_attacks += nb_objects
                                    if operation.name not in vulns_found.keys():
                                        if attack == 'xmli':
                                            vulns_found.update({operation.name: {
                                                'Malformed': nb_objects_per_type[attack]['nb_malformed']}})
                                            vulns_found.update({operation.name: {
                                                'Replicating': nb_objects_per_type[attack]['nb_replicating']}})
                                            vulns_found.update(
                                                {operation.name: {'XPath': nb_objects_per_type[attack]['nb_xpath']}})
                                        elif attack == 'sqli':
                                            vulns_found.update(
                                                {operation.name: {'Taut': nb_objects_per_type[attack]['nb_tautology']}})
                                            vulns_found.update(
                                                {operation.name: {'Union': nb_objects_per_type[attack]['nb_union']}})
                                            vulns_found.update({operation.name: {
                                                'PiggyB': nb_objects_per_type[attack]['nb_piggy_backed']}})
                                            vulns_found.update({operation.name: {
                                                'IncQ': nb_objects_per_type[attack]['nb_incorrect_queries']}})
                                    else:
                                        if 'Malformed' not in vulns_found[operation.name] and attack == 'xmli':
                                            vulns_found[operation.name].update(
                                                {'Malformed': nb_objects_per_type[attack]['nb_malformed']})
                                        if 'Replicating' not in vulns_found[operation.name] and attack == 'xmli':
                                            vulns_found[operation.name].update(
                                                {'Replicating': nb_objects_per_type[attack]['nb_replicating']})
                                        if 'XPath' not in vulns_found[operation.name] and attack == 'xmli':
                                            vulns_found[operation.name].update(
                                                {'XPath': nb_objects_per_type[attack]['nb_xpath']})
                                        if 'Taut' not in vulns_found[operation.name] and attack == 'sqli':
                                            vulns_found[operation.name].update(
                                                {'Taut': nb_objects_per_type[attack]['nb_tautology']})
                                        if 'Union' not in vulns_found[operation.name] and attack == 'sqli':
                                            vulns_found[operation.name].update(
                                                {'Union': nb_objects_per_type[attack]['nb_union']})
                                        if 'PiggyB' not in vulns_found[operation.name] and attack == 'sqli':
                                            vulns_found[operation.name].update(
                                                {'PiggyB': nb_objects_per_type[attack]['nb_piggy_backed']})
                                        if 'IncQ' not in vulns_found[operation.name] and attack == 'sqli':
                                            vulns_found[operation.name].update(
                                                {'IncQ': nb_objects_per_type[attack]['nb_incorrect_queries']})
                                        else:
                                            if attack == 'xmli':
                                                vulns_found[operation.name]['Malformed'] += nb_objects_per_type[attack][
                                                    'nb_malformed']
                                                vulns_found[operation.name]['Replicating'] += nb_objects_per_type[attack][
                                                    'nb_replicating']
                                                vulns_found[operation.name]['XPath'] += nb_objects_per_type[attack][
                                                    'nb_xpath']
                                            elif attack == 'sqli':
                                                vulns_found[operation.name]['Taut'] += nb_objects_per_type[attack][
                                                    'nb_tautology']
                                                vulns_found[operation.name]['Union'] += nb_objects_per_type[attack][
                                                    'nb_union']
                                                vulns_found[operation.name]['PiggyB'] += nb_objects_per_type[attack][
                                                    'nb_piggy_backed']
                                                vulns_found[operation.name]['IncQ'] += nb_objects_per_type[attack][
                                                    'nb_incorrect_queries']

                            else:
                                print('Clustering is not possible because the resulting vectors are filled with zeros !')

                        else:
                            print('Clustering is not possible because preprocessed the responses are empty !')

                else:
                    print('Clustering is not possible because the responses are empty !')

                current_task.update_state(state='PROGRESS',
                                          meta={'current': 5 + j * (95 / number_methods), 'total': total,
                                                'percent': int((float(5 + j * (95 / number_methods)) / total * 100)),
                                                'detection_type': 'dynamic',
                                                'nb_success_attacks': nb_success_attacks,
                                                'vulns_found': vulns_found})
       # Merge the results found by the static and dynamic detection
        vulns_found_static = copy.deepcopy(static_detection_result['vulns_found'])
        total_success_attacks = nb_success_attacks + static_detection_result['nb_success_attacks']
        if vulns_found.get(operation.name) and static_detection_result['vulns_found'].get(operation.name):
            total_vulns_found = copy.deepcopy(static_detection_result['vulns_found'])
            for key, value in vulns_found[operation.name].items():
                if key not in total_vulns_found[operation.name].keys():
                    total_vulns_found[operation.name].update({key: value})
                else:
                    total_vulns_found[operation.name][key] += value
        elif static_detection_result['vulns_found'].get(operation.name):
            total_vulns_found = static_detection_result['vulns_found']
            vulns_found.update({operation.name: {}})
        else:
            total_vulns_found = vulns_found
            vulns_found_static.update({operation.name: {}})
        # if nb_success_attacks >= static_detection_result['nb_success_attacks']:
        #     total_success_attacks = nb_success_attacks
        # else:
        #     total_success_attacks = static_detection_result['nb_success_attacks']
        # # return vulnerabilities found by both method (the union without repetition !)
        # if vulns_found.get(operation.name) and static_detection_result['vulns_found'].get(operation.name):
        #     total_vulns_found = static_detection_result['vulns_found'].copy()
        #     for key, value in vulns_found[operation.name].items():
        #         if key not in total_vulns_found[operation.name].keys():
        #             total_vulns_found[operation.name].update({key: value})
        #         else:
        #             if value > total_vulns_found[operation.name][key]:
        #                 total_vulns_found[operation.name][key] = value
        # elif static_detection_result['vulns_found'].get(operation.name):
        #     total_vulns_found = static_detection_result['vulns_found']
        # else:
        #     total_vulns_found = vulns_found
        return {'current': total, 'total': total, 'percent': 100, 'detection_type': 'dynamic',
                'nb_success_attacks': nb_success_attacks,
                'nb_sent_attacks': nb_malicious_requests,
                'total_success_attacks': total_success_attacks,
                'total_sent_attacks': nb_malicious_requests + static_detection_result['nb_sent_attacks'],
                'nb_valid_requests': nb_valid_requests,
                'vulns_found': vulns_found,
                'vulns_found_static': vulns_found_static,
                'total_vulns_found': total_vulns_found}


def static_detection_injections(operation_id, attack, ws_type):
    if attack == 'sqli':
        errors = extract_error_patterns_from_file('common_sqli_errors_dbms.txt')
    # XMLi
    else:
        errors = extract_error_patterns_from_file('common_sqli_errors_dbms.txt') + extract_error_patterns_from_file(
            'common_xmli_errors_parsers.txt')
    if ws_type == 'rest':
        operation = Path.objects.get(id=operation_id)
        malicious_generator = RestMaliciousRequestsGeneration()
    else:
        operation = Operation.objects.get(id=operation_id)
        malicious_generator = SoapMaliciousRequestsGeneration()
    total = 100
    vulns_found = {}
    nb_success_attacks = 0
    nb_malicious_requests = 0
    # "Sure" is made to know if the tested operation/path is really not vulnerable by getting its http returned code
    sure = True
    current_task.update_state(state='PROGRESS',
                              meta={'current': 1, 'total': total,
                                    'percent': 1,
                                    'detection_type': 'static',
                                    'nb_success_attacks': nb_success_attacks,
                                    'nb_sent_attacks': nb_malicious_requests,
                                    'sure_not_vuln': sure,
                                    'vulns_found': vulns_found})
    sleep(0.5)
    current_task.update_state(state='PROGRESS',
                              meta={'current': 2, 'total': total,
                                    'percent': 2,
                                    'detection_type': 'static',
                                    'nb_success_attacks': nb_success_attacks,
                                    'nb_sent_attacks': nb_malicious_requests,
                                    'sure_not_vuln': sure,
                                    'vulns_found': vulns_found})
    responses = malicious_generator.send_malicious_request([attack], operation)
    current_task.update_state(state='PROGRESS',
                              meta={'current': 5, 'total': total,
                                    'percent': 5,
                                    'detection_type': 'static',
                                    'nb_success_attacks': nb_success_attacks,
                                    'nb_sent_attacks': nb_malicious_requests,
                                    'sure_not_vuln': sure,
                                    'vulns_found': vulns_found})
    if ws_type == 'rest':
        total = 5
        for j in [len(responses[attack][i]) for i in responses[attack].keys()]:
            total += j
        nb_malicious_requests = total - 5
        x = 5
        for key in responses[attack].keys():
            for resp, i in zip(responses[attack][key], range(len(responses[attack][key]))):
                if resp.content.__len__() != 0:
                    # Preprocessing of response to take off tags and some structural patterns like [ and { etc: have
                    # more efficiency in detection
                    resp.content = re.sub(r'((<.*?>)|[a-zA-Z0-9" _\']*(:|: )*{|\}|[a-zA-Z0-9" _\']*(:| : )*\[|\]|\n)',
                                          ' ',
                                          resp.content)
                    resp.content = re.sub(r' +', ' ', resp.content.strip())
                    # static detection
                    if inj_static_detection(resp.content, errors):
                        nb_success_attacks += 1
                        if operation.name not in vulns_found.keys():
                            vulns_found.update({operation.name: {resp.request.attack_type.type: 1}})
                        else:
                            if resp.request.attack_type.type not in vulns_found[operation.name]:
                                vulns_found[operation.name].update({resp.request.attack_type.type: 1})
                            else:
                                vulns_found[operation.name][resp.request.attack_type.type] += 1
                    # In case of client side error then it's sure that it is not a vuln because it did not get to server side !
                    else:
                        # Server affected (crashed) means that it has processed the sent data as it was sent without
                        # sanitization !
                        if int(resp.http_status_code) in HTTP_STATUS_CODES_SERVER_SIDE:
                            nb_success_attacks += 1
                            if operation.name not in vulns_found.keys():
                                vulns_found.update({operation.name: {resp.request.attack_type.type: 1}})
                            else:
                                if resp.request.attack_type.type not in vulns_found[operation.name]:
                                    vulns_found[operation.name].update({resp.request.attack_type.type: 1})
                                else:
                                    vulns_found[operation.name][resp.request.attack_type.type] += 1
                        else:
                            # Bad request ! it didn't affect the server !
                            if int(resp.http_status_code) != 400:
                                sure = False
                else:
                    if int(resp.http_status_code) in HTTP_STATUS_CODES_SERVER_SIDE:
                        nb_success_attacks += 1
                        if operation.name not in vulns_found.keys():
                            vulns_found.update({operation.name: {resp.request.attack_type.type: 1}})
                        else:
                            if resp.request.attack_type.type not in vulns_found[operation.name]:
                                vulns_found[operation.name].update({resp.request.attack_type.type: 1})
                            else:
                                vulns_found[operation.name][resp.request.attack_type.type] += 1
                    else:
                        if int(resp.http_status_code) != 400:
                            sure = False
                current_task.update_state(state='PROGRESS',
                                          meta={'current': x + i,
                                                'total': total,
                                                'percent': int(float((x + i) / total) * 100),
                                                'detection_type': 'static',
                                                'nb_success_attacks': nb_success_attacks,
                                                'nb_sent_attacks': nb_malicious_requests,
                                                'sure_not_vuln': sure,
                                                'vulns_found': vulns_found})
            x += len(responses[attack][key])
        current_task.update_state(state='PROGRESS',
                                  meta={'current': total,
                                        'percent': 100,
                                        'detection_type': 'static',
                                        'nb_success_attacks': nb_success_attacks,
                                        'nb_sent_attacks': nb_malicious_requests,
                                        'sure_not_vuln': sure,
                                        'vulns_found': vulns_found})

    else:
        nb_malicious_requests = len(responses[attack])
        total = nb_malicious_requests + 5
        for resp, i in zip(responses[attack], range(len(responses[attack]))):
            if resp.content.__len__() != 0:
                resp.content = re.sub(r'((<.*?>)|[a-zA-Z0-9" _\']*(:|: )*{|\}|[a-zA-Z0-9" _\']*(:| : )*\[|\]|\n)', ' ',
                                      resp.content)
                resp.content = re.sub(r' +', ' ', resp.content.strip())
                if inj_static_detection(resp.content, errors):
                    nb_success_attacks += 1
                    if operation.name not in vulns_found.keys():
                        vulns_found.update({operation.name: {resp.request.attack_type.type: 1}})
                    else:
                        if resp.request.attack_type.type not in vulns_found[operation.name]:
                            vulns_found[operation.name].update({resp.request.attack_type.type: 1})
                        else:
                            vulns_found[operation.name][resp.request.attack_type.type] += 1
                else:
                    if int(resp.http_status_code) in HTTP_STATUS_CODES_SERVER_SIDE:
                        nb_success_attacks += 1
                        if operation.name not in vulns_found.keys():
                            vulns_found.update({operation.name: {resp.request.attack_type.type: 1}})
                        else:
                            if resp.request.attack_type.type not in vulns_found[operation.name]:
                                vulns_found[operation.name].update({resp.request.attack_type.type: 1})
                            else:
                                vulns_found[operation.name][resp.request.attack_type.type] += 1
                    else:
                        if int(resp.http_status_code) != 400:
                            sure = False
            else:
                if int(resp.http_status_code) in HTTP_STATUS_CODES_SERVER_SIDE:
                    nb_success_attacks += 1
                    if operation.name not in vulns_found.keys():
                        vulns_found.update({operation.name: {resp.request.attack_type.type: 1}})
                    else:
                        if resp.request.attack_type.type not in vulns_found[operation.name]:
                            vulns_found[operation.name].update({resp.request.attack_type.type: 1})
                        else:
                            vulns_found[operation.name][resp.request.attack_type.type] += 1
                else:
                    if int(resp.http_status_code) != 400:
                        sure = False
            current_task.update_state(state='PROGRESS',
                                      meta={'current': 6 + i, 'total': total,
                                            'percent': int((float((6 + i) / total) * 100)),
                                            'detection_type': 'static',
                                            'nb_success_attacks': nb_success_attacks,
                                            'nb_sent_attacks': nb_malicious_requests,
                                            'sure_not_vuln': sure,
                                            'vulns_found': vulns_found})

        current_task.update_state(state='PROGRESS',
                                  meta={'current': total,
                                        'percent': 100,
                                        'detection_type': 'static',
                                        'nb_success_attacks': nb_success_attacks,
                                        'nb_sent_attacks': nb_malicious_requests,
                                        'sure_not_vuln': sure,
                                        'vulns_found': vulns_found})
    return {'current': total, 'total': total, 'percent': 100, 'detection_type': 'static',
            'nb_success_attacks': nb_success_attacks, 'nb_sent_attacks': nb_malicious_requests,
            'sure_not_vuln': sure, 'vulns_found': vulns_found}, responses


''' DoS detection '''


def calculate_average_ttfb(responses, n):
    sum_ = 0
    for resp in responses:
        if resp.time_to_first_byte >= 0:
            sum_ += resp.time_to_first_byte
    return sum_ / n


def check_server_down(responses):
    for resp in responses:
        if resp.http_status_code in HTTP_STATUS_CODES_SERVER_SIDE:
            return True
    return False


@shared_task
def simulate_dos_attack(operation_id, attacks, ws_type):
    if ws_type == 'rest':
        operation = Path.objects.get(id=operation_id)
        malicious_generator = RestMaliciousRequestsGeneration()
        malicious_responses = malicious_generator.send_malicious_request(attacks, operation)
        dos_attack = {}

        for method in operation.get_methods_accept_xml():
            dos_attack.update(
                {method.name: {}})
            for attack in attacks:
                dos_attack[method.name].update(
                    {attack: {'ttfbs': [],
                              'http_status_codes': []}})
                for resp in malicious_responses[attack][method.name]:
                    dos_attack.get(method.name).get(attack).get('ttfbs').append(resp.time_to_first_byte)
                    dos_attack.get(method.name).get(attack).get('http_status_codes').append(resp.http_status_code)
    else:
        operation = Operation.objects.get(id=operation_id)
        malicious_generator = SoapMaliciousRequestsGeneration()
        malicious_responses = malicious_generator.send_malicious_request(attacks, operation)
        dos_attack = {}
        for attack in attacks:
            dos_attack.update({attack: {
                'ttfbs': [],
                'http_status_codes': []
            }})
            for resp in malicious_responses[attack]:
                dos_attack.get(attack).get('ttfbs').append(resp.time_to_first_byte)
                dos_attack.get(attack).get('http_status_codes').append(resp.http_status_code)
    return dos_attack


@shared_task
def simulate_legitimate_users(operation_id, num_req, ws_type):
    if ws_type == 'rest':
        operation = Path.objects.get(id=operation_id)
        non_malicious_generator = RestValidRequestsGeneration()
        simulation_responses = non_malicious_generator.send_valid_request(operation, num_req, simulate=True)
        simulation = {}
        for method in operation.get_methods_accept_xml():
            simulation.update(
                {method.name: {'ttfbs': [],
                               'http_status_codes': []}})
            for resp in simulation_responses[method.name]:
                simulation[method.name]['ttfbs'].append(resp.time_to_first_byte)
                simulation[method.name]['http_status_codes'].append(resp.http_status_code)
    # Soap
    else:
        operation = Operation.objects.get(id=operation_id)
        non_malicious_generator = SoapValidRequestsGeneration()
        simulation_responses = non_malicious_generator.send_valid_request(operation, num_req, simulate=True)
        simulation = {'ttfbs': [],
                      'http_status_codes': []}
        for resp in simulation_responses:
            simulation['ttfbs'].append(resp.time_to_first_byte)
            simulation['http_status_codes'].append(resp.http_status_code)
    return simulation


# default values : threshold_1 = 7, threshold_2 = 5, threshold_3 = 5, threshold_4 = 3, n_valid_requests = 5
@shared_task
def dos_detection(operation_id, attacks, ws_type, n_valid_requests, threshold_1, threshold_2, threshold_3, threshold_4):
    nb_success_attacks = 0
    nb_malicious_requests = 0
    # Number of valid requests to send
    n = n_valid_requests
    nb_non_malicious_requests = 4 * n
    # Max total would be 4*n + 3 (BIL + internal entity + external entity) + 2 (oversizedxml + oversizedpayload) | if
    # all attack types have been selected
    if 'xmlb' in attacks:
        nb_malicious_requests += 3
    if 'overxml' in attacks:
        nb_malicious_requests += 1
    if 'overpayload' in attacks:
        nb_malicious_requests += 1
    if ws_type == 'rest':
        operation = Path.objects.get(id=operation_id)
        non_malicious_generator = RestValidRequestsGeneration()
        number_parameters = 0
        for method in operation.get_methods_accept_xml():
            if method.parameters:
                number_parameters += len(method.parameters)
        if number_parameters != 0:
            nb_malicious_requests *= number_parameters
        nb_non_malicious_requests *= len(operation.get_methods_accept_xml())
        total = nb_malicious_requests + nb_non_malicious_requests
    # Soap
    else:
        operation = Operation.objects.get(id=operation_id)
        non_malicious_generator = SoapValidRequestsGeneration()
        if operation.parameters['input']:
            nb_malicious_requests *= len(list(operation.parameters['input'].keys()))
        total = nb_malicious_requests + nb_non_malicious_requests
    current_task.update_state(state='PROGRESS',
                              meta={'current': 1, 'total': total,
                                    'percent': 1,
                                    'nb_success_attacks': nb_success_attacks,
                                    'nb_sent_attacks': nb_malicious_requests,
                                    'nb_valid_requests': 0})
    valid_responses = non_malicious_generator.send_valid_request(operation, n)
    current_task.update_state(state='PROGRESS',
                              meta={'current': n, 'total': total,
                                    'percent': int((float(n) / total * 100)),
                                    'nb_success_attacks': nb_success_attacks,
                                    'nb_sent_attacks': nb_malicious_requests,
                                    'nb_valid_requests': nb_non_malicious_requests/4})
    # Calculate average ttfb
    # If rest then it will be method by method of the tested path if soap then it's for the entire operation
    if ws_type == 'rest':
        average_normal_ttfb = {}
        for method in operation.method_set.all():
            average_normal_ttfb.update({method.name: calculate_average_ttfb(valid_responses[method.name], n)})
    # Soap
    else:
        average_normal_ttfb = calculate_average_ttfb(valid_responses, n)
    # Send attacks and valid requests in parallel (simulate legitimate client accesses while attacking the web service)
    job = group([
        simulate_dos_attack.subtask((operation_id, attacks, ws_type)),
        simulate_legitimate_users.subtask((operation_id, n * 2, ws_type)),
    ])
    result = job.delay()
    # Task state
    current_task.update_state(state='PROGRESS',
                              meta={'current': 3 * n + nb_malicious_requests, 'total': total,
                                    'percent': int((float(3 * n + nb_malicious_requests) / total * 100)),
                                    'nb_success_attacks': nb_success_attacks,
                                    'nb_sent_attacks': nb_malicious_requests,
                                    'nb_valid_requests': 3*nb_non_malicious_requests/4})
    dos_attack, simulation = result.join()
    if ws_type == 'rest':
        for method in operation.get_methods_accept_xml():
            if average_normal_ttfb[method.name] <= 0.5:
                for i in range(len(simulation[method.name]["ttfbs"])):
                    if (simulation[method.name]['ttfbs'][i] >= threshold_1 * average_normal_ttfb[method.name] + 1) or \
                            (simulation[method.name]['http_status_codes'][i] in DOS_HTTP_STATUS_CODES_SERVER_SIDE):
                        nb_success_attacks += 1
            elif 0.5 < average_normal_ttfb[method.name] < 1:
                for i in range(len(simulation[method.name]["ttfbs"])):
                    if (simulation[method.name]['ttfbs'][i] >= threshold_2 * average_normal_ttfb[method.name] + 1) or \
                            (simulation[method.name]['http_status_codes'][i] in DOS_HTTP_STATUS_CODES_SERVER_SIDE):
                        nb_success_attacks += 1
            elif 1 <= average_normal_ttfb[method.name] <= 2:
                for i in range(len(simulation[method.name]["ttfbs"])):
                    if (simulation[method.name]['ttfbs'][i] >= threshold_3 * average_normal_ttfb[method.name]) or \
                            (simulation[method.name]['http_status_codes'][i] in DOS_HTTP_STATUS_CODES_SERVER_SIDE):
                        nb_success_attacks += 1
            else:
                for i in range(len(simulation[method.name]["ttfbs"])):
                    if (simulation[method.name]['ttfbs'][i] >= threshold_4 * average_normal_ttfb[method.name]) or \
                            (simulation[method.name]['http_status_codes'][i] in DOS_HTTP_STATUS_CODES_SERVER_SIDE):
                        nb_success_attacks += 1
    # Soap
    else:
        if average_normal_ttfb <= 0.5:
            for i in range(len(simulation["ttfbs"])):
                if (simulation['ttfbs'][i] >= threshold_1 * average_normal_ttfb + 1) or \
                        (simulation['http_status_codes'][i] in DOS_HTTP_STATUS_CODES_SERVER_SIDE):
                    nb_success_attacks += 1
        elif 0.5 < average_normal_ttfb < 1:
            for i in range(len(simulation["ttfbs"])):
                if (simulation['ttfbs'][i] >= threshold_2 * average_normal_ttfb + 1) or \
                        (simulation['http_status_codes'][i] in DOS_HTTP_STATUS_CODES_SERVER_SIDE):
                    nb_success_attacks += 1
        elif 1 <= average_normal_ttfb <= 2:
            for i in range(len(simulation["ttfbs"])):
                if (simulation['ttfbs'][i] >= threshold_3 * average_normal_ttfb) or \
                        (simulation['http_status_codes'][i] in DOS_HTTP_STATUS_CODES_SERVER_SIDE):
                    nb_success_attacks += 1
        else:
            for i in range(len(simulation["ttfbs"])):
                if (simulation['ttfbs'][i] >= threshold_4 * average_normal_ttfb) or \
                        (simulation['http_status_codes'][i] in DOS_HTTP_STATUS_CODES_SERVER_SIDE):
                    nb_success_attacks += 1
    # Send valid requests after attacks to check if server is still up !
    sleep(0.5)
    post_attack_valid_responses = non_malicious_generator.send_valid_request(operation, n)
    if ws_type == 'rest':
        for method in operation.get_methods_accept_xml():
            if average_normal_ttfb[method.name] <= 0.5:
                for resp in post_attack_valid_responses[method.name]:
                    if (resp.time_to_first_byte >= threshold_1 * average_normal_ttfb[method.name] + 1) or \
                            (int(resp.http_status_code) in DOS_HTTP_STATUS_CODES_SERVER_SIDE):
                        nb_success_attacks += 1
            elif 0.5 < average_normal_ttfb[method.name] < 1:
                for resp in post_attack_valid_responses[method.name]:
                    if (resp.time_to_first_byte >= threshold_2 * average_normal_ttfb[method.name] + 1) or \
                            (int(resp.http_status_code) in DOS_HTTP_STATUS_CODES_SERVER_SIDE):
                        nb_success_attacks += 1
            elif 1 <= average_normal_ttfb[method.name] <= 2:
                for resp in post_attack_valid_responses[method.name]:
                    if (resp.time_to_first_byte >= threshold_3 * average_normal_ttfb[method.name]) or \
                            (int(resp.http_status_code) in DOS_HTTP_STATUS_CODES_SERVER_SIDE):
                        nb_success_attacks += 1
            else:
                for resp in post_attack_valid_responses[method.name]:
                    if (resp.time_to_first_byte >= threshold_4 * average_normal_ttfb[method.name]) or \
                            (int(resp.http_status_code) in DOS_HTTP_STATUS_CODES_SERVER_SIDE):
                        nb_success_attacks += 1
    # Soap
    else:
        if average_normal_ttfb <= 0.5:
            for resp in post_attack_valid_responses:
                if (resp.time_to_first_byte >= threshold_1 * average_normal_ttfb + 1) or \
                        (int(resp.http_status_code) in DOS_HTTP_STATUS_CODES_SERVER_SIDE):
                    nb_success_attacks += 1
        elif 0.5 < average_normal_ttfb < 1:
            for resp in post_attack_valid_responses:
                if (resp.time_to_first_byte >= threshold_2 * average_normal_ttfb + 1) or \
                        (int(resp.http_status_code) in DOS_HTTP_STATUS_CODES_SERVER_SIDE):
                    nb_success_attacks += 1
        elif 1 <= average_normal_ttfb <= 2:
            for resp in post_attack_valid_responses:
                if (resp.time_to_first_byte >= threshold_3 * average_normal_ttfb) or \
                        (int(resp.http_status_code) in DOS_HTTP_STATUS_CODES_SERVER_SIDE):
                    nb_success_attacks += 1
        else:
            for resp in post_attack_valid_responses:
                if (resp.time_to_first_byte >= threshold_4 * average_normal_ttfb) or \
                        (int(resp.http_status_code) in DOS_HTTP_STATUS_CODES_SERVER_SIDE):
                    nb_success_attacks += 1
    return {'current': total, 'total': total, 'percent': 100, 'nb_success_attacks': nb_success_attacks,
            'nb_sent_attacks': nb_malicious_requests, 'nb_valid_requests': nb_non_malicious_requests,
            'average_normal_ttfb': average_normal_ttfb}
