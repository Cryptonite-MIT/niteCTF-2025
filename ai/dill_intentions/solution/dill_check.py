import dill

def main():
    # Load the dill file
    with open('./model.dill', 'rb') as f:
        loaded = dill.load(f)
    
    # Debug: check what we actually loaded
    print(f"Loaded object type: {type(loaded)}")
    print(f"Loaded object: {loaded}")
    
    if hasattr(loaded, '__dict__'):
        print(f"Object __dict__: {loaded.__dict__}")
    
    if hasattr(loaded, 'keys'):
        print(f"Object keys: {loaded.keys()}")

if __name__ == "__main__":
    main()