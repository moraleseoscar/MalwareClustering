import argparse
import os
import networkx
from networkx.drawing.nx_pydot import write_dot
import itertools
import pefile

def jaccard(set1, set2):
    intersection = set1.intersection(set2)
    intersection_length = float(len(intersection))
    union = set1.union(set2)
    union_length = float(len(union))
    return intersection_length / union_length

def getstrings(fullpath):
    strings = os.popen("strings '{0}'".format(fullpath)).read()
    strings = set(strings.split("\n"))
    return strings

def get_function_calls_from_pe(fullpath):
    function_calls = set()
    try:
        pe = pefile.PE(fullpath)
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for function in entry.imports:
                function_calls.add(function.name.decode('utf-8'))
    except Exception as e:
        print(f"Error extracting function calls from {fullpath}: {e}")
    return function_calls

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Malware similarity analysis')
    parser.add_argument('malware_directory', type=str, help='Directory containing malware samples')
    parser.add_argument('--output_directory', type=str, default='./Results/FunctionCalls/', help='Output directory for dot files')
    parser.add_argument('--feature', type=str, default='strings', choices=['strings', 'function_calls'], help='Feature to analyze')
    args = parser.parse_args()

    target_directory = args.malware_directory
    output_directory = args.output_directory
    feature = args.feature

    # Umbral de índice de Jaccard
    thresholds = [0.6, 0.75, 0.9]

    malware_paths = []
    malware_attributes = dict()
    graphs = []

    for root, dirs, paths in os.walk(target_directory):
        for path in paths:
            full_path = os.path.join(root, path)
            malware_paths.append(full_path)

    for path in malware_paths:
        if feature == 'strings':
            attributes = getstrings(path)
        elif feature == 'function_calls':
            attributes = get_function_calls_from_pe(path)
        else:
            print(f"Unsupported feature: {feature}")
            exit(1)
        print(f"Extracted {len(attributes)} {feature} from {path} ...")
        malware_attributes[path] = attributes

    for threshold in thresholds:
        output_dot_file = os.path.join(output_directory, f"umbral_{threshold}_{feature}.dot")
        graph = networkx.Graph()
        graphs.append(graph)

        for path in malware_paths:
            graph.add_node(path, label=os.path.split(path)[-1][:10])

        for malware1, malware2 in itertools.combinations(malware_paths, 2):
            jaccard_index = jaccard(malware_attributes[malware1], malware_attributes[malware2])
            if jaccard_index > threshold:
                graph.add_edge(malware1, malware2, penwidth=1 + (jaccard_index - threshold) * 10)

        write_dot(graph, output_dot_file)

    print("Analysis complete. Dot files saved in:", output_directory)