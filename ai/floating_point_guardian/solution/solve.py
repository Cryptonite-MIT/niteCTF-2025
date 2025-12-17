#!/usr/bin/env python3

import numpy as np
from scipy.optimize import fsolve
import math

INPUT_SIZE = 15
HIDDEN1_SIZE = 8
HIDDEN2_SIZE = 6
OUTPUT_SIZE = 1
TARGET_PROBABILITY = 0.7331337420

XOR_KEYS = [
    0x42, 0x13, 0x37, 0x99, 0x21, 0x88, 0x45, 0x67,
    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE
]

W1 = np.array([
    [0.523, -0.891, 0.234, 0.667, -0.445, 0.789, -0.123, 0.456],
    [-0.334, 0.778, -0.556, 0.223, 0.889, -0.667, 0.445, -0.221],
    [0.667, -0.234, 0.891, -0.445, 0.123, 0.556, -0.789, 0.334],
    [-0.778, 0.445, -0.223, 0.889, -0.556, 0.234, 0.667, -0.891],
    [0.123, -0.667, 0.889, -0.334, 0.556, -0.778, 0.445, 0.223],
    [-0.891, 0.556, -0.445, 0.778, -0.223, 0.334, -0.667, 0.889],
    [0.445, -0.123, 0.667, -0.889, 0.334, -0.556, 0.778, -0.234],
    [-0.556, 0.889, -0.334, 0.445, -0.778, 0.667, -0.223, 0.123],
    [0.778, -0.445, 0.556, -0.667, 0.223, -0.889, 0.334, -0.445],
    [-0.223, 0.667, -0.778, 0.334, -0.445, 0.556, -0.889, 0.778],
    [0.889, -0.334, 0.445, -0.556, 0.667, -0.223, 0.123, -0.667],
    [-0.445, 0.223, -0.889, 0.778, -0.334, 0.445, -0.556, 0.889],
    [0.334, -0.778, 0.223, -0.445, 0.889, -0.667, 0.556, -0.123],
    [-0.667, 0.889, -0.445, 0.223, -0.556, 0.778, -0.334, 0.667],
    [0.556, -0.223, 0.778, -0.889, 0.445, -0.334, 0.889, -0.556]
])

B1 = np.array([0.1, -0.2, 0.3, -0.15, 0.25, -0.35, 0.18, -0.28])

W2 = np.array([
    [0.712, -0.534, 0.823, -0.445, 0.667, -0.389],
    [-0.623, 0.889, -0.456, 0.734, -0.567, 0.445],
    [0.534, -0.712, 0.389, -0.823, 0.456, -0.667],
    [-0.889, 0.456, -0.734, 0.567, -0.623, 0.823],
    [0.445, -0.667, 0.823, -0.389, 0.712, -0.534],
    [-0.734, 0.623, -0.567, 0.889, -0.456, 0.389],
    [0.667, -0.389, 0.534, -0.712, 0.623, -0.823],
    [-0.456, 0.823, -0.667, 0.445, -0.889, 0.734]
])

B2 = np.array([0.05, -0.12, 0.18, -0.08, 0.22, -0.16])

W3 = np.array([[0.923], [-0.812], [0.745], [-0.634], [0.856], [-0.723]])

B3 = np.array([0.42])

def inverse_sigmoid(y):
    if y <= 0 or y >= 1:
        raise ValueError("Sigmoid inverse undefined for y <= 0 or y >= 1")
    return np.log(y / (1 - y))

def inverse_tanh(y):
    if abs(y) >= 1:
        raise ValueError("Tanh inverse undefined for |y| >= 1")
    return 0.5 * np.log((1 + y) / (1 - y))

def inverse_cos(y):
    if abs(y) > 1:
        raise ValueError("Cos inverse undefined for |y| > 1")
    return np.arccos(y)

def inverse_sinh(y):
    return np.arcsinh(y) * 10.0

def inverse_xor(y, key):
    long_val = int(y * 1000000)
    long_val ^= key
    return long_val / 1000000.0

def xor_activate(x, key):
    long_val = int(x * 1000000)
    long_val ^= key
    return long_val / 1000000.0

def forward_pass(inputs):
    hidden1 = np.zeros(HIDDEN1_SIZE)
    
    for j in range(HIDDEN1_SIZE):
        for i in range(INPUT_SIZE):
            if i % 4 == 0:
                activated = xor_activate(inputs[i], XOR_KEYS[i])
            elif i % 4 == 1:
                activated = np.tanh(inputs[i])
            elif i % 4 == 2:
                activated = np.cos(inputs[i])
            else:
                activated = np.sinh(inputs[i] / 10.0)
            hidden1[j] += activated * W1[i][j]
        hidden1[j] += B1[j]
        hidden1[j] = np.tanh(hidden1[j])
    
    hidden2 = np.dot(hidden1, W2) + B2
    hidden2 = np.tanh(hidden2)
    
    output = np.dot(hidden2, W3)[0] + B3[0]
    output = 1.0 / (1.0 + np.exp(-output))
    
    return output


def reverse_network():
    output_before_sigmoid = inverse_sigmoid(TARGET_PROBABILITY)
    output_minus_bias = output_before_sigmoid - B3[0]
    W3_flat = W3.flatten()
    hidden2_activated = np.linalg.pinv(W3.T) @ np.array([output_minus_bias])
    hidden2_raw = np.array([inverse_tanh(val) for val in hidden2_activated])
    hidden2_minus_bias = hidden2_raw - B2
    hidden1_activated = np.linalg.pinv(W2.T) @ hidden2_minus_bias
    hidden1_raw = np.array([inverse_tanh(val) for val in hidden1_activated])
    hidden1_minus_bias = hidden1_raw - B1
    activated_inputs = np.linalg.pinv(W1.T) @ hidden1_minus_bias
    raw_inputs = np.zeros(INPUT_SIZE)
    
    for i in range(INPUT_SIZE):
        if i % 4 == 0:
            raw_inputs[i] = inverse_xor(activated_inputs[i], XOR_KEYS[i])
        elif i % 4 == 1:
            raw_inputs[i] = inverse_tanh(activated_inputs[i])
        elif i % 4 == 2:
            raw_inputs[i] = inverse_cos(activated_inputs[i])
        else:
            raw_inputs[i] = inverse_sinh(activated_inputs[i])
    
    return raw_inputs

def main():
    try:
        solution = reverse_network()
        actual_output = forward_pass(solution)
        for val in solution:
            print(f"{val:.10f}")
    except Exception as e:
        pass

if __name__ == "__main__":
    main()