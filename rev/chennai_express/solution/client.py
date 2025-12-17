import socket
import json
import struct
import threading
import tkinter as tk
import math
import sys
import time

# Configuration
# HOST = 'o9876tfvbnmklkjhgfdertyuillkjhgfdsdfghj.chals.nitephase.live'
HOST = 'localhost'
PORT = 1337

# Layout Configuration (Must match Server)
CENTER_X = 400
CENTER_Y = 300
RADII = [100, 200, 300]
TRACK_COLOR = "#444"
TRAIN_COLORS = {1: "cyan", 2: "magenta"}
SWITCH_COLOR_STRAIGHT = "red"
SWITCH_COLOR_DIVERGED = "green"

class GameState:
    def __init__(self):
        self.lock = threading.Lock()
        self.trains = {} # Id -> {X, Y, Name}
        self.switches = {} # Id -> {X, Y, IsSwitched}
        self.critical_failure = False
        self.flag_message = None
        
        # PPS Tracking
        self.packets_received = 0
        self.pps = 0.0
        self.last_pps_time = time.time()
        self.window_packets = 0

    def register_packet(self):
        self.packets_received += 1
        self.window_packets += 1
        
        # Update PPS every 1s roughly (or check frequently)
        now = time.time()
        dt = now - self.last_pps_time
        if dt >= 1.0:
            self.pps = self.window_packets / dt
            self.window_packets = 0
            self.last_pps_time = now

class AtomicClient:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.running = True
        self.state = GameState()
        self.ticket = None  # Will be set by server
        self.send_lock = threading.Lock()  # Lock for sending packets
        self.recv_lock = threading.Lock()  # Lock for receiving packets

    def connect(self):
        try:
            self.sock.connect((HOST, PORT))
            print(f"[*] Connected to {HOST}:{PORT}")
            
            # Send empty auth request - server will generate ticket
            self.send_packet(1, {})
            
            # Wait for AuthResponse with ticket
            data = self.recv_packet()
            if data:
                packet = json.loads(data)
                if packet.get("Type") == 5:  # AuthResponse
                    payload = json.loads(packet.get("Payload", "{}"))
                    self.ticket = payload.get("Ticket")
                    print(f"[*] Received Ticket: {self.ticket}")
                else:
                    print(f"[!] Unexpected response type: {packet.get('Type')}")
                    sys.exit(1)
        except Exception as e:
            print(f"[!] Connection failed: {e}")
            sys.exit(1)

    def recv_packet(self):
        """Receive a single length-prefixed packet (thread-safe)."""
        with self.recv_lock:
            try:
                len_buf = b''
                while len(len_buf) < 4:
                    chunk = self.sock.recv(4 - len(len_buf))
                    if not chunk: 
                        return None
                    len_buf += chunk
                
                msg_len = struct.unpack('<I', len_buf)[0]
                
                # Sanity check: reasonable packet size (max 1MB)
                if msg_len > 1_000_000 or msg_len == 0:
                    print(f"[!] Invalid packet length: {msg_len} (raw: {len_buf.hex()})")
                    return None
                
                data = b''
                while len(data) < msg_len:
                    chunk = self.sock.recv(msg_len - len(data))
                    if not chunk: 
                        return None
                    data += chunk
                
                return data
            except Exception as e:
                if self.running:
                    print(f"[!] recv_packet error: {e}")
                return None

    def send_packet(self, packet_type, payload_dict):
        """Send a packet (thread-safe)."""
        with self.send_lock:
            try:
                payload_str = json.dumps(payload_dict)
                packet = {
                    "Type": packet_type,
                    "Payload": payload_str
                }
                data = json.dumps(packet).encode('utf-8')
                length = struct.pack('<I', len(data))
                self.sock.sendall(length + data)
            except Exception as e:
                if self.running:
                    print(f"[!] Send failed: {e}")

    def switch_request(self, switch_id, target_state):
        print(f"[*] Requesting Switch {switch_id} -> {target_state}")
        # PacketType.SetSwitch = 3
        self.send_packet(3, {"SwitchId": switch_id, "TargetSwitched": target_state})

    def start_receiver(self):
        t = threading.Thread(target=self.receive_loop)
        t.daemon = True
        t.start()

    def receive_loop(self):
        try:
            while self.running:
                data = self.recv_packet()
                if data is None:
                    return  # Connection closed
                self.handle_packet(data)
        except Exception as e:
            if self.running:
                print(f"[!] Receive Loop Error: {e}")

    def handle_packet(self, data):
        try:
            packet = json.loads(data)
            p_type = packet.get("Type")
            payload_str = packet.get("Payload")
            if not payload_str: return
            payload = json.loads(payload_str)

            with self.state.lock:
                self.state.register_packet()
                if p_type == 2: # StateUpdate
                    # Update Trains
                    trains = payload.get("Trains", [])
                    self.state.trains = {t["Id"]: t for t in trains}
                    
                    # Update Switches
                    switches = payload.get("Switches", [])
                    # Use actual switch Id from server
                    self.state.switches = {s["Id"]: s for s in switches}
                    
                    self.state.critical_failure = payload.get("IsCriticalFailure", False)

                elif p_type == 99: # Flag
                    self.state.flag_message = f"{payload.get('Message')}\n{payload.get('Flag')}"
                    print(f"\n[FLAG] {self.state.flag_message}")

        except json.JSONDecodeError as e:
            print(f"[!] JSON Parse Error: {e}")
            print(f"    Raw data ({len(data)} bytes): {data[:100]}...")
        except UnicodeDecodeError as e:
            print(f"[!] UTF-8 Decode Error: {e}")
            print(f"    Raw data ({len(data)} bytes): {data[:50].hex()}")
        except Exception as e:
            print(f"[!] Parse Error: {e}")


class PassiveClient:
    """A client that doesn't do its own networking but visualizes state provided to it."""
    def __init__(self):
        self.state = GameState()
        self.running = True

    def switch_request(self, switch_id, target_state):
        # In passive mode, we don't send requests from the GUI
        print(f"[*] (Passive) GUI requested Switch {switch_id} -> {target_state} (Ignored)")
        pass

    def handle_packet(self, data):
        """Handle a packet payload (bytes or str) from an external source."""
        try:
            if isinstance(data, bytes):
                data = data.decode('utf-8')
            
            packet = json.loads(data)
            p_type = packet.get("Type")
            payload_str = packet.get("Payload")
            if not payload_str: return
            payload = json.loads(payload_str)

            with self.state.lock:
                self.state.register_packet()
                if p_type == 2: # StateUpdate
                    # Update Trains
                    trains = payload.get("Trains", [])
                    self.state.trains = {t["Id"]: t for t in trains}
                    
                    # Update Switches
                    switches = payload.get("Switches", [])
                    # Use actual switch Id from server
                    self.state.switches = {s["Id"]: s for s in switches}
                    
                    self.state.critical_failure = payload.get("IsCriticalFailure", False)

                elif p_type == 99: # Flag
                    self.state.flag_message = f"{payload.get('Message')}\n{payload.get('Flag')}"
                    print(f"\n[FLAG] {self.state.flag_message}")

        except Exception as e:
            print(f"[!] Passive Parse Error: {e}")
class RailwayGUI:
    def __init__(self, root, client):
        self.root = root
        self.client = client
        self.root.title("Atomic Railways Control")
        self.root.geometry("800x600")
        self.root.configure(bg="#222")

        self.canvas = tk.Canvas(root, bg="#111", highlightthickness=0)
        self.canvas.pack(fill=tk.BOTH, expand=True)
        
        # Bindings
        self.canvas.bind("<Button-1>", self.on_click)

        # Start Loop
        self.refresh()

    def refresh(self):
        self.draw()
        self.root.after(50, self.refresh)

    def draw(self):
        self.canvas.delete("all")
        
        # Draw Tracks (Static Circles)
        for r in RADII:
            coords = (CENTER_X - r, CENTER_Y - r, CENTER_X + r, CENTER_Y + r)
            self.canvas.create_oval(coords, outline=TRACK_COLOR, width=3)

        # Draw Switch Connections (hardcoded based on server layout)
        self.draw_switch_connections()

        with self.client.state.lock:
            # Draw Switches
            # We want them to be clickable.
            for s_id, sw in self.client.state.switches.items():
                x, y = sw["X"], sw["Y"]
                is_switched = sw["IsSwitched"]
                color = SWITCH_COLOR_DIVERGED if is_switched else SWITCH_COLOR_STRAIGHT
                
                # Draw Box
                size = 10
                self.canvas.create_rectangle(x - size, y - size, x + size, y + size, fill=color, outline="white", tags=f"switch_{s_id}")
                self.canvas.create_text(x, y - 20, text=f"SW{s_id}", fill="white", font=("Arial", 8))

            # Draw Trains
            for t_id, t in self.client.state.trains.items():
                x, y = t["X"], t["Y"]
                # Name removed, use ID
                name = f"Train {t_id}"
                color = TRAIN_COLORS.get(t_id, "white")
                
                # IsCrashed removed from per-train state, check global
                if self.client.state.critical_failure:
                    # Generic indication if we don't know which one crashed
                    pass 

                r = 8
                self.canvas.create_oval(x - r, y - r, x + r, y + r, fill=color, outline="white")
                self.canvas.create_text(x, y + 15, text=name, fill="white", font=("Arial", 9))

            # Overlay Flag
            if self.client.state.flag_message:
                self.canvas.create_text(400, 550, text=self.client.state.flag_message, fill="yellow", font=("Courier", 14, "bold"), justify=tk.CENTER)
            elif self.client.state.critical_failure:
                self.canvas.create_text(400, 50, text="SYSTEM CRITICAL FAILURE", fill="red", font=("Courier", 16, "bold"))

            # Draw Stats
            self.canvas.create_text(10, 10, text=f"PPS: {self.client.state.pps:.1f}", fill="lime", font=("Arial", 10), anchor=tk.NW)

    def draw_switch_connections(self):
        """Draw curved semi-circle arcs connecting tracks at switch positions"""
        conn_color = "#666"
        
        def draw_curved_switch(angle, inner_radius, outer_radius, arc_rotation=90):
            """
            Draw a curved semi-circle arc connecting two concentric tracks.
            
            Args:
                angle: The radial angle (in radians) where the switch is located
                inner_radius: Radius of the inner track
                outer_radius: Radius of the outer track
                arc_rotation: Rotation offset for the arc start angle (degrees).
                              90 = arc curves counter-clockwise from the radial
                              -90 = arc curves clockwise from the radial
            """
            # Calculate the arc radius (half the distance between tracks)
            arc_radius = (outer_radius - inner_radius) / 2
            
            # Calculate the center of the arc (midpoint between tracks on radial line)
            mid_radius = (inner_radius + outer_radius) / 2
            arc_center_x = CENTER_X + mid_radius * math.cos(angle)
            arc_center_y = CENTER_Y + mid_radius * math.sin(angle)
            
            # Create bounding box for the arc
            x0 = arc_center_x - arc_radius
            y0 = arc_center_y - arc_radius
            x1 = arc_center_x + arc_radius
            y1 = arc_center_y + arc_radius
            
            # Convert radial angle to degrees and add rotation offset
            start_angle_deg = math.degrees(angle) + arc_rotation
            
            # Draw a 180-degree arc (semi-circle)
            self.canvas.create_arc(
                x0, y0, x1, y1,
                start=start_angle_deg,
                extent=180,
                style=tk.ARC,
                outline=conn_color,
                width=2
            )
        
        # Switch 1 & -1: Inner (100) <-> Middle (200) at angle 0
        draw_curved_switch(0, RADII[0], RADII[1], arc_rotation=0)
        
        # Switch 2 & -2: Inner <-> Middle at angle π (opposite side)
        draw_curved_switch(math.pi, RADII[0], RADII[1], arc_rotation=180)
        
        # Switch 3 & -3: Inner (100) <-> Outer (300) at angle π/3
        draw_curved_switch(math.pi / 3, RADII[0], RADII[2], arc_rotation=-120)
        
        # Switch 4 & -4: Inner <-> Outer at angle 4π/3
        draw_curved_switch((4 * math.pi) / 3, RADII[0], RADII[2], arc_rotation=60)
        
        # Switch 5 & -5: Middle (200) <-> Outer (300) at angle 5π/3
        draw_curved_switch((5 * math.pi) / 3, RADII[1], RADII[2], arc_rotation=120)
        
        # Switch 6 & -6: Middle <-> Outer at angle 2π/3
        draw_curved_switch((2 * math.pi) / 3, RADII[1], RADII[2], arc_rotation=-60)

    def on_click(self, event):
        # Check if clicked on a switch
        with self.client.state.lock:
            for s_id, sw in self.client.state.switches.items():
                x, y = sw["X"], sw["Y"]
                if abs(event.x - x) < 15 and abs(event.y - y) < 15:
                    # Toggle
                    new_state = not sw["IsSwitched"]
                    self.client.switch_request(s_id, new_state)
                    return

if __name__ == "__main__":
    client = AtomicClient()
    
    print("Atomic Railways Client")

    client.connect()
    client.start_receiver()

    # Start Update Requester
    def update_loop():
        while client.running:
            client.send_packet(4, {})
            time.sleep(0.05)
    
    t_up = threading.Thread(target=update_loop)
    t_up.daemon = True
    t_up.start()

    root = tk.Tk()
    gui = RailwayGUI(root, client)
    
    try:
        root.mainloop()
    except KeyboardInterrupt:
        client.running = False
        root.destroy()
