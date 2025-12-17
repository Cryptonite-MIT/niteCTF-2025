from collections import Counter
import random

class SlotMachine:
    class Slots:

        def __init__(self,init_length=2**32-1):
            self.length = init_length
        
        def __len__(self):
            return self.length
        
        def __getitem__(self, index):
            if not 0 <= index < self.length:
                raise IndexError("Index out of range")
            return index
        
        def hehe(self):
            self.length -= 10000
    
    def __init__(self):
        self.slots = self.Slots()
        self.SYMBOLS = [
            '🍒', '🍋', '🍊', '🍇',
            '🍉', '🍓', '🍍', '🍎',
            '🍏', '🍐', '🍑', '🍈',
            '🍌', '🥭', '🥝', '🥥'
        ]
    
    def spin(self):
        global balance
        wheels = []
        for _ in range(2):
            outcome = random.choice(self.slots)
            for i in range(8):
                wheel = (outcome >> (i*4)) & 0xF
                wheels.append(self.SYMBOLS[wheel])
        winnings = self.calculate(wheels)
        self.slots.hehe()
        return wheels,winnings
    
    def calculate(self,wheels):
        counts = Counter(wheels)
        win = 0
        for w in wheels:
            win += counts[w]
        return win
    
    def display_wheels(self, wheels):
        print("\n╔" + "═" * 61 + "╗")
        print("║{:^59}║".format("🎰  S L O T   M A C H I N E  🎰"))
        print("╠" + "═" * 61 + "╣")

        print("║  ", end="")
        for i in range(16):
            print(wheels[i], end=" ")
            if (i + 1) % 4 == 0 and i != 15:
                print(" | ", end="")
        print("  ║")
        print("╚" + "═" * 61 + "╝")