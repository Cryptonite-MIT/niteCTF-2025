import dill
import numpy as np
import hashlib

# identical to given func since XOR is reversible
def reverse_evil_intern_shenanigans(encrypted_hex, path_bits):
    
    if not path_bits:
        raise ValueError('No path bits provided')
    
    encrypted_bytes = bytes.fromhex(encrypted_hex)
    result = bytearray(encrypted_bytes)
    
    path_bytes = np.packbits(np.array(path_bits, dtype=np.uint8)).tobytes()
    key_hash = hashlib.sha256(path_bytes).digest()
    key_int = int.from_bytes(key_hash, byteorder='big')
    
    while key_int > 0:
        key_len = (key_int.bit_length() + 7) // 8
        key_bytes = key_int.to_bytes(max(key_len, 1), byteorder='big')
        
        for i in range(len(result)):
            result[i] ^= key_bytes[i % len(key_bytes)]
        
        key_int = key_int << 1
        
        if key_int.bit_length() > 256:
            break
    
    return bytes(result).decode('utf-8', errors='ignore')

def get_all_leaf_nodes(tree):
    leaf_nodes = []
    n_nodes = tree.node_count
    
    for node_id in range(n_nodes):
        if tree.children_left[node_id] == -1 and tree.children_right[node_id] == -1:
            leaf_nodes.append(node_id)
    
    return leaf_nodes

def main():
    # Load the dill file
    with open('./model.dill', 'rb') as f:
        loaded = dill.load(f)
    
    print("Loaded objects keys:", loaded.keys())
    print()
    
    # Extract the model and functions
    model = loaded['model']
    decision_path_for_debugging = loaded['decision_path_for_debugging']
    
    # Get the tree
    tree = model.tree_
    
    # class names (encrypted)
    class_names = model.classes_
    
    print(f"Total classes: {len(class_names)}")
    print(f"\nSample encrypted class names:")
    for i, cn in enumerate(class_names[:5]):
        print(f"  Class {i}: {cn}")
    
    # all leaf node indices
    leaf_nodes = get_all_leaf_nodes(tree)
    
    # For EACH class, find which leaf uses it
    # and decrypt it with the path to that leaf
    for class_idx, encrypted_class_name in enumerate(class_names):
        # Find a leaf node that predicts this class
        found_leaf = None
        for leaf_node_id in leaf_nodes:
            # Check if this leaf predicts this class
            predicted_class_idx = np.argmax(tree.value[leaf_node_id])
            if predicted_class_idx == class_idx:
                found_leaf = leaf_node_id
                break
        
        if found_leaf is None:
            print(f"Class {class_idx}: No leaf found for this class")
            continue
        
        try:
            # path bits to this leaf
            path_bits = decision_path_for_debugging(tree, found_leaf)
            
            print(f"Class {class_idx} (Leaf Node {found_leaf}):")
            print(f"  Path bits ({len(path_bits)} bits): {path_bits[:15]}{'...' if len(path_bits) > 15 else ''}")
            print(f"  Encrypted: {encrypted_class_name}")
            
            decrypted = reverse_evil_intern_shenanigans(encrypted_class_name, path_bits)
            print(f"  Decrypted: {decrypted}")
            
            if '{' in decrypted and '}' in decrypted:
                print(f"\nFLAG: {decrypted}\n")
                exit()
            
            print()
            
        except Exception as e:
            print(f"  Error: {e}")
            print()

if __name__ == "__main__":
    main()
