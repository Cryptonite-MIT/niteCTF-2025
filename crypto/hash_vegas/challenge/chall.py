from lottery import Lottery
from slotmachine import SlotMachine
from roulette import Roulette
from secret import flag

balance = 10000

SPIN_ROUNDS = 56
ROULETTE_ROUNDS = 64
nspin = 0
nroulette = 0

r = Roulette()
s = SlotMachine()
l = Lottery()

banner = r"""
 __    __   ______    ______   __    __        __     __  ________   ______    ______    ______  
/  |  /  | /      \  /      \ /  |  /  |      /  |   /  |/        | /      \  /      \  /      \ 
$$ |  $$ |/$$$$$$  |/$$$$$$  |$$ |  $$ |      $$ |   $$ |$$$$$$$$/ /$$$$$$  |/$$$$$$  |/$$$$$$  |
$$ |__$$ |$$ |__$$ |$$ \__$$/ $$ |__$$ |      $$ |   $$ |$$ |__    $$ | _$$/ $$ |__$$ |$$ \__$$/ 
$$    $$ |$$    $$ |$$      \ $$    $$ |      $$  \ /$$/ $$    |   $$ |/    |$$    $$ |$$      \ 
$$$$$$$$ |$$$$$$$$ | $$$$$$  |$$$$$$$$ |       $$  /$$/  $$$$$/    $$ |$$$$ |$$$$$$$$ | $$$$$$  |
$$ |  $$ |$$ |  $$ |/  \__$$ |$$ |  $$ |        $$ $$/   $$ |_____ $$ \__$$ |$$ |  $$ |/  \__$$ |
$$ |  $$ |$$ |  $$ |$$    $$/ $$ |  $$ |         $$$/    $$       |$$    $$/ $$ |  $$ |$$    $$/ 
$$/   $$/ $$/   $$/  $$$$$$/  $$/   $$/           $/     $$$$$$$$/  $$$$$$/  $$/   $$/  $$$$$$/  
                                                                                                 
                                                                                                                                                                                     
Welcome to Hash Vegas!
Win $1,000,000,000 to to get a special reward!
"""
print(banner)
user = input('Enter your username: ')
while True:
    print("Choose one of our following games:\n1) Spin the Slot Machine\n2) Play Roulette\n3) Lottery Ticket\n4) Redeem Voucher\n5) Get Balance\n6) Get Flag\n7) Exit")
    choice = int(input("Enter your choice: "))

    if choice == 1:
        if balance <= 0:
            print('haha you are broke')
            break
        if nspin >= SPIN_ROUNDS:
            print("The Slot Machine is broken...\n")
            continue
        nspin += 1
        print('Spinning the Slot Machine....')
        wheel,winnings = s.spin()
        s.display_wheels(wheel)
        balance += winnings
        print(f'Updated balance: ${balance}\n')
    
    elif choice == 2:
        if balance <= 0:
            print('haha you are broke')
            break
        if nroulette >= ROULETTE_ROUNDS:
            print("The roulette dealer seems to have disappeared....\n")
            continue
        nroulette += 1
        winnings = r.round()
        balance += winnings
        print(f'Updated balance: ${balance}\n')

    elif choice == 3:
        if balance <= 0:
            print('haha you are broke')
            break
        
        pay = int(input('How much are you going to pay for the lottery ticket?(The guy over there told me the more you pay, the higher the odds): '))
        if pay > balance:
            print('You do not have that much money!')
            continue
        if pay < 0:
            print('????')
            continue
        balance -= pay
        print('Buying lottery ticket...')

        result = l.buy_ticket(pay,user)

        if result:
            balance = 0
            print('Oops! I think you lost your wallet.')

    elif choice == 4:
        voucher_code = input('Enter voucher code(hex): ')
        voucher_data = input('Enter voucher data(hex): ')
        if not voucher_data.startswith(user.encode().hex()):
            print("Wait who are you???")
            continue
        winnings = l.redeem_voucher(voucher_code, voucher_data)
        balance += winnings
        if winnings == 0:
            print("looks like the voucher didn't work")
        print(f'Updated balance: ${balance}\n')

    elif choice == 5:
        print(f'Current balance: ${balance}\n')

    elif choice == 6:
        if balance >= 1000000000:
            print("JACKPOT! Here's your flag: ",flag,'\n')
        else:
            print('You do not have enough money. Keep gambling!\n')

    elif choice == 7:
        exit()

    else:
        print("Hey you can't do that!!")
