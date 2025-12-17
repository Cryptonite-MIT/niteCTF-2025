# Memlock Solution

You've been given two files given in the handout. One displays the hardware schematic with internal architecture of the device. The other file is the firmware raw binary.

## Extremely Essential Documentation
[1] [STM32F405 datasheet](https://www.st.com/resource/en/datasheet/dm00037051.pdf) 
[2] [STM32F405 Reference Manual](https://www.st.com/resource/en/reference_manual/rm0090-stm32f405415-stm32f407417-stm32f427437-and-stm32f429439-advanced-armbased-32bit-mcus-stmicroelectronics.pdf) 
[3] [ARM v7-M Reference Manual](https://www.pjrc.com/teensy/DDI0403Ee_arm_v7m_ref_manual.pdf) 

## Hardware schematic
Initially we understand from the Memlock schematic that it is a custom ALU function. The microcontroller used is STM32-F405RGTx and it's basic power up circuit has been assembled. 

The `PA0`-`PA7` pins on `GPIO A` and `PB0`-`PB7` pins on `GPIO B` on the STM32 are connected to the input of 4 separate computation units (top to bottom). The first unit comprises of two `74LS283` ICs, which are 4 bit binary full adders. They are connected to form a 8 bit binary full adder.

#### Computation Units
The second computation unit takes two 8 bit inputs, first from  `PA0`-`PA7` and second from `PB0`-`PB7`. The inputs are given into two `74LS283` ICs similar to the previous operation, however they are connected in a configuration with a carry in bit of 1 (in the IC adding the lower 4 bits), and the input bits from B are passed through a NOT gate (`74HC04` ICs). Hence this unit is connected to form a 8 bit binary full subtractor through 2s complement.

The third computation unit is a simple bitwise XOR operation performed with eight `74LS86` ICs with `PA0`-`PA7` and `PB0`-`PB7` serving as the input pins.

The fourth computational unit is a comprised of two `74LS194` ICs, which are dual input 4 bit universal shift registers. The `CLK` is connected to the `PA8` pin and it has 2 select lines connected to `PA9` and `PA10` pins. This unit is connected to form a 8 bit universal shift register with rotate right and left functions.

#### Operation Mode Selection
Finally, one of the four 8 bit outputs from the 4 computational units (i.e, output of one of the operations) described above are selected using four `74LS153` ICs (a dual 4 bit input 4:1 multiplexer) and sent to the `GPIO C` pins `PC0`-`PC7`. The select lines of the MUX are connected to the `PB8` and `PB9` pins. The wiring has been done such that `00` corresponds to XOR, `01` to add, `10` to subtract and `11` to rotate operations.

## Firmware Binary

#### Disassembling
We load this firmware file into a disassembler like Ghidra/IDA, and define the architecture set ARM Cortex M4, Little Endian (ensuring Thumb mode instruction is selected). The loading address and offset is taken as `0x08000000`, a standard flash base address for the STM32.

The first structure we encounter is the interrupt vector table at `0x08000000`. The initial stack pointer is set to `0x20020000`, indicating 128KB of RAM. Reset handler is the first thing we look at when the microcontroller is powered on.

#### `Reset_handler`
We understand that this is the main loop of the function. The `CPSIE, I` instruction enables interrupts globally, this becomes relevant as we understand the function further. R3 is the GPIO base address as per the `0x40020000` (Refer Pg 74, [1]). 

By subtracting `0xD000` from the GPIO base address, it arrives at `0x40013000`, which is the EXTI base address (Pg 75, [1]). 

First it writes the value `0x55` to offset `0x414` from that base, which is the GPIO B Output Data Register (`GPIOB_ODR`). The code then writes `1` to three different offsets, out of which two are kind of relevant to us:
- Offset `0xC00` is `EXTI_IMR` (Interrupt Mask Register), which unmasks EXTI line 0
- Offset `0xC14` is `EXTI_PR` (Pending Register), which clears any pending interrupt

Then the code writes `0x40` to the `NVIC_ISER0` register at address `0xE000E100` (Pg B3-626, [3]). The value `0x40` is binary `01000000`, which sets bit 6, enabling IRQ6 in the NVIC (Pg 375, [2]). This enables the possibility to set an interrupt. Then it writes `1` to offset `0xC10`, which is `EXTI_SWIER` (Software Interrupt Event Register). This immediately invokes the EXTI0 interrupt handler after initialization. Hence we jump to `IRQ_6_handler`.

#### `IRQ_6_handler`
We see that it calls `sub_800008E`, wherein lies the core encryption pipeline of the challenge that we need to reverse.

Initial basic register definitions:
Register Allocation:

R1 = `0x40020000` (base pointer for GPIO registers)
R10 = Pointer to input data in flash
R6 = Output data pointer (`0x08800800`)
R11 = 0x40013000 (base pointer for EXTI registers)
R5 = `NVIC_ICSR` register (interrupt status) = 1
R4 = `NVIC_IABR0` (interrupt active bit register)
R7 = `EXTI_PR` (pending register bit 0) = 1 
R8 = Current encrypted byte being processed
R9 = Derived index value = 6

For simplifying the explanation of the pipeline we look at pseudocode for the working flow of the lock based on the disassembly.

#### First Layer

To obtain the index, we find the interrupt number and subtract it by 16, to obtain 6.
```
R5 = NVIC_ICSR & 0xFF
R9 = (R5 - 0x10) & 0xFF
```

Now, it sets `PA0`-`PA7` to transformed index value. Then the following conditional is introduced,

```
R7 = EXTI_PR & 1
if (R7 == 0): 
	mask = 0xC3 
else: 
	mask = 0x5C 
R12 = R8 ^ mask
```

Since the LSB of `EXTI_PR` is 1 (pending interrupt is set), the mask XORed with R8 (the current byte in buffer), used to obtain R12, is `0x5C` throughout the operation.

```
R4 = (NVIC_IABR0 >> R9) & 1
R0 = (R9 & 1) | (R4 << 1)

GPIOB_ODR = (GPIOB_ODR & ~0xFF) | R12

sub_800005C(R0)
```
 
Obtain a 2 bit operation selector from index LSB and interrupt active bit and store it in R0. Here since the interrupt is active (1), and R9=6 which is even, we get the operation as subtraction (`11`). Also R12 is written to `GPIOB_ODR` register at `PB0`-`PB7`. 

```
if (R0 == 3):
       GPIOA_ODR |= 0x600
       pulse_PA8()
       shift_mode = R8 ^ R9
       GPIOA_ODR bits[9:10] = shift_mode[0:1]
       pulse_PA8()
```

When shift operation (`11` in binary) is selected, configures `PA9`-`PA10` (shift register mode lines) and pulses `PA8` twice (once to parallel load the values, then to bit rotate them).

#### Second Layer

```
alu_result_1 = GPIOC_IDR
GPIOA_ODR = alu_result_1
   
intermediate = saved_GPIOB ^ (R9 << 3)
GPIOB_ODR = intermediate & 0xFF
   
sub_800005C(0)
```

The first byte result output at `GPIOC_IDR` is used as an input for the next loop's `GPIOA_ODR`. 
As R9 is 6, `GPIOB_ODR` is changed to the `GPIOB_ODR` saved at R3 at the start of the iteration XORed with `0x30`.

`sub_800005C` is a helper function that controls the MUX select lines by clearing bits and then setting the values from `R0`(represents operation to be selected) into `GPIOB_ODR` register at bits 8 and 9. So in the second layer, the XOR operation is selected.

`sub_8000074` is another helper function that generates the clock pulse for the shift registers by setting and resetting the bit 8 on `GPIOA_ODR` register.

#### Third Layer

```
alu_result_2 = GPIOC_IDR
GPIOA_ODR = alu_result_2
   
GPIOB_ODR = (R5 ^ 0x55) & 0xFF
   
if (R7 == R4):
    operation = 2
else:
    operation = 1
   
   sub_800005C(operation)
```
 
 Similar to the previous layer, the result of the second layer is used as input for the third layer at `GPIOA_ODR`. Then the `GPIOB_ODR`

Finally the operation is decided to be a subtraction (`10` in binary) as the `EXTI_PR` LSB (1) will always be equal to `NVIC_IABR0` which is also 1 (interrupt is active). Otherwise, addition operation would have take place.

#### Bit Banding & Recovery

```
final_byte = GPIOC_IDR & 0xFF
   
for bit in range(8):
    output_buffer[R6 + bit*4] = (final_byte >> bit) & 1
R6 += 8

if (R6 != 0x8800900):
       goto next_byte
```
Hence the same pipeline continues for all bytes, from `0x8800900` till `0x8800800` = `0x100` bytes processed (256 bytes). 

ARM Cortex M4 based STM32 have a memory aliasing feature called bit banding (Pg 68, [2]). Each bit in a bitband region can be accessed as a full 32 bit word in an "alias region".

The alias address being written to is derived using the formula as follows: 
`alias_addr = alias_base + (byte_offset × 32) + (bit_number × 4)`

So basically the 256 bytes being written in this case, point us to a total of 256/8=**32 bytes** of relevance we need to look into.

#### Encrypted bytes
There are 32 decrypted bytes at hex offset `0x080000EC`, which are `93 98 83 94 8A BC C6 8E BC C2 BC FF 81 98 8E BC C3 BF BF C2 93 8E BC 88 C4 83 C2 81 C0 94 C4 AC`.

## Solve
Using the obtained the constant values and reversing the encryption pipeline, we obtain the decrypted flag.

Note since `irq_n` = 6 for all 32 bytes, `B3` = `0x16` ^ `0x55` = `0x43` (since `0x10`+`0x06`=`0x16` is the value of R5 we took). Also note that we have deduced all the 3 operations by basic intuition instead of scripting all possibilities in the 3 layers to simplify our work.

The final obtained flag is **`nite{m7_m3m0ri_m4pp3d_my5t3r1e5}`**

The solve script can be found [here](solve.py).
