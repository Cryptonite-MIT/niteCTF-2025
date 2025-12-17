import gdb

# Configuration: (Output Filename, Variable Name, Float Count)
ARRAYS = [
    ("W0.txt", "d_embed_weight",      39 * 32),
    ("W1.txt", "d_pos_embed_weight",  29 * 32),
    
    # Position Weights
    ("W2.txt", "d_pos_fc1_weight",    29 * 64 * 32),
    ("W3.txt", "d_pos_fc1_bias",      29 * 64),
    ("W4.txt", "d_pos_fc2_weight",    29 * 1 * 64),
    ("W5.txt", "d_pos_fc2_bias",      29 * 1),
    
    # Global Weights
    ("G0.txt", "d_global_fc1_weight", 32 * 64),
    ("G1.txt", "d_global_fc1_bias",   64),
    ("G2.txt", "d_global_fc2_weight", 64 * 1)
]

class DumpWeightsTxt(gdb.Command):
    """
    Automates dumping weights to .txt files using the 'print' command.
    Usage: dump_txt
    """
    def __init__(self):
        super(DumpWeightsTxt, self).__init__("dump_txt", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        # 1. Configure GDB for massive printing
        gdb.execute("set pagination off")
        gdb.execute("set print elements 0")
        gdb.execute("set print repeats 0")
        gdb.execute("set max-value-size unlimited") # Fixes the truncation error
        
        print("\n[+] Starting Automated Text Dump...")
        
        for filename, var_name, count in ARRAYS:
            print(f"    Printing {var_name} ({count} floats) -> {filename}...")
            
            try:
                # 2. Set the log file
                gdb.execute(f"set logging file {filename}")
                
                # 3. Turn logging ON
                # Note: Newer GDB uses "set logging enabled on", older uses "set logging on"
                # We use the newer syntax which is safer.
                gdb.execute("set logging enabled on")
                
                # 4. Print to log
                # We cast to (@global float*) to ensure GDB reads from GPU memory
                gdb.execute(f"print *(@global float*){var_name}@{count}")
                
                # 5. Turn logging OFF
                gdb.execute("set logging enabled off")
                
            except Exception as e:
                print(f"    [!] Error dumping {var_name}: {e}")
                # Attempt to reset logging if it failed
                try: gdb.execute("set logging enabled off")
                except: pass

        print("[+] Text dump complete. Run convert_txt_dumps.py now.\n")

DumpWeightsTxt()
