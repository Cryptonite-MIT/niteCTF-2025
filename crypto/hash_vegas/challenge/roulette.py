import random
class Roulette:

    def __init__(self, n = 2**256-1):
        self.n = n

    def get(self):
        return random.randrange(0,self.n)
    
    def round(self):
        global balance
        num = self.get()
        guess = int(input('Enter your guess: '))
        color = input('Enter color(R or B): ') 
        winnings =0
        if color != 'R' and color != 'B':
            raise ValueError("wrong color")
        
        if num%2 == 0 and color == 'R':
            winnings += 1
        elif num%2 == 1 and color == 'B':
            winnings += 1
        else:
            winnings -= 1
        
        if num == guess:
            winnings += 1000
            print('RIGHT!')
        if num >> 253 == guess >> 253:
            print('Close, the number is ',num)
            winnings += 1
        else:
            winnings -= 1
            print('WRONG! the number is ',num)
        
        return winnings
