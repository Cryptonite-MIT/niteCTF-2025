#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>

#define INPUT_SIZE 15
#define HIDDEN1_SIZE 8
#define HIDDEN2_SIZE 6
#define OUTPUT_SIZE 1
#define TARGET_PROBABILITY 0.7331337420
#define EPSILON 0.00001


void print_flag(){
    FILE *fp = fopen("flag.txt", "r");
    if (fp == NULL) {
        printf("Error: Could not open flag.txt\n");
        return;
    }
    char flag[256];
    printf("You are the master! Here is your flag:\n");
    if (fgets(flag, sizeof(flag), fp) != NULL) {
        printf("%s\n", flag);
    }
    fclose(fp);
}

const unsigned char XOR_KEYS[INPUT_SIZE] = {
    0x42, 0x13, 0x37, 0x99, 0x21, 0x88, 0x45, 0x67,
    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE
};

double W1[INPUT_SIZE][HIDDEN1_SIZE] = {
    {0.523, -0.891, 0.234, 0.667, -0.445, 0.789, -0.123, 0.456},
    {-0.334, 0.778, -0.556, 0.223, 0.889, -0.667, 0.445, -0.221},
    {0.667, -0.234, 0.891, -0.445, 0.123, 0.556, -0.789, 0.334},
    {-0.778, 0.445, -0.223, 0.889, -0.556, 0.234, 0.667, -0.891},
    {0.123, -0.667, 0.889, -0.334, 0.556, -0.778, 0.445, 0.223},
    {-0.891, 0.556, -0.445, 0.778, -0.223, 0.334, -0.667, 0.889},
    {0.445, -0.123, 0.667, -0.889, 0.334, -0.556, 0.778, -0.234},
    {-0.556, 0.889, -0.334, 0.445, -0.778, 0.667, -0.223, 0.123},
    {0.778, -0.445, 0.556, -0.667, 0.223, -0.889, 0.334, -0.445},
    {-0.223, 0.667, -0.778, 0.334, -0.445, 0.556, -0.889, 0.778},
    {0.889, -0.334, 0.445, -0.556, 0.667, -0.223, 0.123, -0.667},
    {-0.445, 0.223, -0.889, 0.778, -0.334, 0.445, -0.556, 0.889},
    {0.334, -0.778, 0.223, -0.445, 0.889, -0.667, 0.556, -0.123},
    {-0.667, 0.889, -0.445, 0.223, -0.556, 0.778, -0.334, 0.667},
    {0.556, -0.223, 0.778, -0.889, 0.445, -0.334, 0.889, -0.556}
};

double B1[HIDDEN1_SIZE] = {0.1, -0.2, 0.3, -0.15, 0.25, -0.35, 0.18, -0.28};

double W2[HIDDEN1_SIZE][HIDDEN2_SIZE] = {
    {0.712, -0.534, 0.823, -0.445, 0.667, -0.389},
    {-0.623, 0.889, -0.456, 0.734, -0.567, 0.445},
    {0.534, -0.712, 0.389, -0.823, 0.456, -0.667},
    {-0.889, 0.456, -0.734, 0.567, -0.623, 0.823},
    {0.445, -0.667, 0.823, -0.389, 0.712, -0.534},
    {-0.734, 0.623, -0.567, 0.889, -0.456, 0.389},
    {0.667, -0.389, 0.534, -0.712, 0.623, -0.823},
    {-0.456, 0.823, -0.667, 0.445, -0.889, 0.734}
};

double B2[HIDDEN2_SIZE] = {0.05, -0.12, 0.18, -0.08, 0.22, -0.16};

double W3[HIDDEN2_SIZE][OUTPUT_SIZE] = {
    {0.923},
    {-0.812},
    {0.745},
    {-0.634},
    {0.856},
    {-0.723}
};

double B3[OUTPUT_SIZE] = {0.42};


double xor_activate(double x, unsigned char key) {
    long long_val = (long)(x * 1000000);
    long_val ^= key;
    return (double)long_val / 1000000.0;
}

double tanh_activate(double x) {
    return tanh(x);
}

double cos_activate(double x) {
    return cos(x);
}

double sinh_activate(double x) {
    return sinh(x / 10.0);
}

double sigmoid(double x) {
    return 1.0 / (1.0 + exp(-x));
}


double forward_pass(double inputs[INPUT_SIZE]) {
    double hidden1[HIDDEN1_SIZE] = {0};
    double hidden2[HIDDEN2_SIZE] = {0};
    double output = 0;
    

    for (int j = 0; j < HIDDEN1_SIZE; j++) {
        for (int i = 0; i < INPUT_SIZE; i++) {
            double activated;
            switch(i % 4) {
                case 0: activated = xor_activate(inputs[i], XOR_KEYS[i]); break;
                case 1: activated = tanh_activate(inputs[i]); break;
                case 2: activated = cos_activate(inputs[i]); break;
                case 3: activated = sinh_activate(inputs[i]); break;
            }
            hidden1[j] += activated * W1[i][j];
        }
        hidden1[j] += B1[j];
        hidden1[j] = tanh_activate(hidden1[j]);
    }
    

    for (int j = 0; j < HIDDEN2_SIZE; j++) {
        for (int i = 0; i < HIDDEN1_SIZE; i++) {
            hidden2[j] += hidden1[i] * W2[i][j];
        }
        hidden2[j] += B2[j];
        hidden2[j] = tanh_activate(hidden2[j]);
    }
    
  
    for (int i = 0; i < HIDDEN2_SIZE; i++) {
        output += hidden2[i] * W3[i][0];
    }
    output += B3[0];
    output = sigmoid(output);
    
    return output;
}




int main() {
    double inputs[INPUT_SIZE];
    
    printf("I am the AI Gatekeeper.\n");
    printf("Enter your details so I know you are my Master.\n");
    printf("Answer these questions with EXACT precision...\n\n");
    
    printf("[Q1]  What is your height in centimeters? ");
    scanf("%lf", &inputs[0]);
    
    printf("[Q2]  What is your weight in kilograms? ");
    scanf("%lf", &inputs[1]);
    
    printf("[Q3]  What is your age in years? ");
    scanf("%lf", &inputs[2]);
    
    printf("[Q4]  What is your heart rate (bpm)? ");
    scanf("%lf", &inputs[3]);
    
    printf("[Q5]  How many hours do you sleep per night? ");
    scanf("%lf", &inputs[4]);
    
    printf("[Q6]  What is your body temperature in Celsius? ");
    scanf("%lf", &inputs[5]);
    
    printf("[Q7]  How many steps do you walk per day? ");
    scanf("%lf", &inputs[6]);
    
    printf("[Q8]  What is your systolic blood pressure? ");
    scanf("%lf", &inputs[7]);
    
    printf("[Q9]  How many calories do you consume daily? ");
    scanf("%lf", &inputs[8]);
    
    printf("[Q10] What is your BMI (Body Mass Index)? ");
    scanf("%lf", &inputs[9]);
    
    printf("[Q11] How many liters of water do you drink daily? ");
    scanf("%lf", &inputs[10]);
    
    printf("[Q12] What is your resting metabolic rate (kcal/day)? ");
    scanf("%lf", &inputs[11]);
    
    printf("[Q13] How many hours do you exercise per week? ");
    scanf("%lf", &inputs[12]);
    
    printf("[Q14] What is your blood glucose level (mg/dL)? ");
    scanf("%lf", &inputs[13]);
    
    printf("[Q15] Rate this CTF challenge out of 10: ");
    scanf("%lf", &inputs[14]);
    
    printf("\n\nProcessing through neural network layers...\n");

    
    double probability = forward_pass(inputs);
    
    printf("========================================\n");
    printf("MASTER PROBABILITY: %.10f\n", probability);
    printf("========================================\n");
    
    if (fabs(probability - TARGET_PROBABILITY) < EPSILON) {
        print_flag();
    } else {
        printf("\nYou are NOT the Master.\n");
        printf("The neural network has rejected your identity.\n");
    }
    return 0;
}

