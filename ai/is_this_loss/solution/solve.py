import re
import ssl
import socket
from dataclasses import dataclass
from typing import Optional, Tuple

import numpy as np
import onnx
import onnxruntime as ort
from onnx import numpy_helper


REMOTE_HOST = "loss.chalz.nitectf25.live"
REMOTE_PORT = 1337


@dataclass
class QueryResult:
    input_vec: np.ndarray
    prediction: float
    latent_vec: np.ndarray
    latent_magnitude: float
    grad_sq_raw: float
    grad_sq_sigmoid: float
    loss_label0: float
    loss_label1: float


class RemoteOracle:
    def __init__(self, hostname: str = REMOTE_HOST, port_num: int = REMOTE_PORT):
        self.hostname = hostname
        self.port_num = port_num
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        self.connection: Optional[socket.socket] = None
        self.response_buffer = b""
        self.output_pattern = re.compile(r"Output:\s*([-+0-9.]+)\s+Loss:\s*([-+0-9.]+)")

    def establish_connection(self) -> None:
        if self.connection is not None:
            return
        raw_socket = socket.socket()
        wrapped_socket = self.ssl_context.wrap_socket(raw_socket, server_hostname=self.hostname)
        wrapped_socket.settimeout(10)
        wrapped_socket.connect((self.hostname, self.port_num))
        self.connection = wrapped_socket
        self._receive_data(allow_timeout=True)

    def terminate_connection(self) -> None:
        if self.connection is not None:
            try:
                self.connection.close()
            finally:
                self.connection = None

    def _receive_data(self, allow_timeout: bool = False) -> None:
        assert self.connection is not None
        try:
            data_chunk = self.connection.recv(4096)
        except (TimeoutError, socket.timeout):
            if allow_timeout:
                return
            raise
        if data_chunk:
            self.response_buffer += data_chunk

    def evaluate(self, input_vector: np.ndarray, target_label: int) -> Tuple[float, float]:
        self.establish_connection()
        assert self.connection is not None

        value_strings = [f"{float(val):.8f}" for val in input_vector.tolist()]
        query_parts = value_strings + [str(int(target_label))]
        query_message = " ".join(query_parts) + "\n"
        self.connection.sendall(query_message.encode())

        decoded_text = self.response_buffer.decode("utf-8", "replace")
        starting_position = len(decoded_text)
        
        for _ in range(300):
            decoded_text = self.response_buffer.decode("utf-8", "replace")
            pattern_matches = list(self.output_pattern.finditer(decoded_text, pos=starting_position))
            if pattern_matches:
                final_match = pattern_matches[-1]
                output_value = float(final_match.group(1))
                loss_value = float(final_match.group(2))
                match_end_pos = final_match.end()
                self.response_buffer = decoded_text[match_end_pos:].encode("utf-8")
                return output_value, loss_value
            self._receive_data(allow_timeout=False)
        
        raise RuntimeError("Failed to parse oracle response")


class NeuralNetwork:
    def __init__(self, model_filepath: str):
        self.inference_session = ort.InferenceSession(
            model_filepath, providers=["CPUExecutionProvider"]
        )
        self.input_identifier = self.inference_session.get_inputs()[0].name

        loaded_model = onnx.load(model_filepath)
        initializers = {
            tensor.name: numpy_helper.to_array(tensor).astype(np.float64)
            for tensor in loaded_model.graph.initializer
        }
        
        self.weight_layer1 = initializers["fc1.weight"]
        self.bias_layer1 = initializers["fc1.bias"]
        self.weight_layer2 = initializers["fc2.weight"]
        self.bias_layer2 = initializers["fc2.bias"]
        self.weight_layer3 = initializers["fc3.weight"]
        self.bias_layer3 = initializers["fc3.bias"]

    def predict(self, input_data: np.ndarray) -> Tuple[float, np.ndarray]:
        input_batch = np.asarray(input_data, dtype=np.float32)[None, :]
        output_logit, latent_output = self.inference_session.run(
            None, {self.input_identifier: input_batch}
        )
        return float(output_logit[0, 0]), latent_output[0].astype(np.float64)

    def compute_intermediate_states(
        self, input_data: np.ndarray
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        input_vec = np.asarray(input_data, dtype=np.float64)
        
        preactivation_h = self.weight_layer1 @ input_vec + self.bias_layer1
        activation_h = np.tanh(preactivation_h)
        
        preactivation_z = self.weight_layer2 @ activation_h + self.bias_layer2
        activation_z = np.tanh(preactivation_z)
        
        return activation_h, activation_z, preactivation_h, preactivation_z

    def compute_gradient_norm_squared(self, input_data: np.ndarray) -> float:
        hidden_activation, latent_activation, _, _ = self.compute_intermediate_states(input_data)
        
        diagonal_latent = np.diag(1.0 - latent_activation * latent_activation)
        diagonal_hidden = np.diag(1.0 - hidden_activation * hidden_activation)
        
        jacobian_matrix = (
            self.weight_layer3 @ diagonal_latent @ self.weight_layer2 @ diagonal_hidden @ self.weight_layer1
        )
        gradient_vector = jacobian_matrix.reshape(-1)
        
        return float(np.dot(gradient_vector, gradient_vector))

    @staticmethod
    def apply_sigmoid(value: float) -> float:
        return float(1.0 / (1.0 + np.exp(-float(value))))

    def compute_gradient_norm_squared_sigmoid(self, input_data: np.ndarray) -> float:
        logit_value, _ = self.predict(input_data)
        raw_gradient_sq = self.compute_gradient_norm_squared(input_data)
        
        probability = self.apply_sigmoid(logit_value)
        scaling_factor = (probability * (1.0 - probability)) ** 2
        
        return float(scaling_factor * raw_gradient_sq)


def stable_softplus(input_val: np.ndarray | float) -> np.ndarray | float:
    array_input = np.asarray(input_val, dtype=np.float64)
    return np.log1p(np.exp(-np.abs(array_input))) + np.maximum(array_input, 0)


def binary_crossentropy_logits(logit: float, true_label: int) -> float:
    logit_value = float(logit)
    if true_label == 1:
        return float(stable_softplus(-logit_value))
    return float(stable_softplus(logit_value))


def generate_minimal_latent_input(
    network: NeuralNetwork, num_restarts: int = 200, max_iterations: int = 50000
) -> np.ndarray:
    w1, b1 = network.weight_layer1, network.bias_layer1
    w2, b2 = network.weight_layer2, network.bias_layer2

    def forward_preactivation(input_vec: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        preact_h = w1 @ input_vec + b1
        activ_h = np.tanh(preact_h)
        preact_z = w2 @ activ_h + b2
        return activ_h, preact_z, preact_h

    def gradient_preactivation_norm(input_vec: np.ndarray) -> np.ndarray:
        activ_h, preact_z, _ = forward_preactivation(input_vec)
        diag_h = np.diag(1.0 - activ_h * activ_h)
        jac = w2 @ diag_h @ w1
        return (2.0 * preact_z) @ jac

    optimal_solution = None
    random_gen = np.random.default_rng(77)
    
    for _ in range(num_restarts):
        current_x = random_gen.normal(0.0, 10.0, size=8).astype(np.float64)
        momentum_first = np.zeros_like(current_x)
        momentum_second = np.zeros_like(current_x)
        learning_rate = 0.05
        
        for step in range(1, max_iterations + 1):
            grad = gradient_preactivation_norm(current_x)
            
            momentum_first = 0.9 * momentum_first + 0.1 * grad
            momentum_second = 0.999 * momentum_second + 0.001 * (grad * grad)
            
            bias_corrected_first = momentum_first / (1.0 - 0.9**step)
            bias_corrected_second = momentum_second / (1.0 - 0.999**step)
            
            current_x = current_x - learning_rate * bias_corrected_first / (
                np.sqrt(bias_corrected_second) + 1e-8
            )
            
            if step in (15000, 30000, 45000):
                learning_rate *= 0.5
        
        _, final_latent = network.predict(current_x)
        latent_norm = float(np.linalg.norm(final_latent))
        
        if optimal_solution is None or latent_norm < optimal_solution[0]:
            optimal_solution = (latent_norm, current_x)

    assert optimal_solution is not None
    return optimal_solution[1]


def compute_coefficient_ratio(
    logit: float, loss_0: float, loss_1: float, supervised_loss_fn
) -> float:
    difference_observed = loss_0 - loss_1
    difference_theoretical = supervised_loss_fn(logit, 0) - supervised_loss_fn(logit, 1)
    return float(difference_observed / difference_theoretical)


def check_composite_regime(
    logit: float, loss_0: float, loss_1: float, coeff_beta: float, supervised_loss_fn
) -> bool:
    residual_0 = loss_0 - coeff_beta * supervised_loss_fn(logit, 0)
    residual_1 = loss_1 - coeff_beta * supervised_loss_fn(logit, 1)
    return abs(residual_0 - residual_1) < 1e-4


def identify_regime(input_vec: np.ndarray, coeff_beta: float, network, oracle, supervised_loss_fn) -> str:
    logit_pred, _ = network.predict(input_vec)
    _, loss_val_0 = oracle.evaluate(input_vec, 0)
    _, loss_val_1 = oracle.evaluate(input_vec, 1)
    
    is_composite = check_composite_regime(logit_pred, loss_val_0, loss_val_1, coeff_beta, supervised_loss_fn)
    return "COMPOSITE" if is_composite else "SIMPLE"


def execute_recovery():
    model_network = NeuralNetwork("isthisloss_handout/weights.onnx")
    remote_service = RemoteOracle()

    supervised_criterion = binary_crossentropy_logits

    input_simple_regime = generate_minimal_latent_input(model_network)
    logit_simple, latent_simple = model_network.predict(input_simple_regime)
    _, loss_simple_0 = remote_service.evaluate(input_simple_regime, 0)
    _, loss_simple_1 = remote_service.evaluate(input_simple_regime, 1)
    
    coefficient_alpha = compute_coefficient_ratio(
        logit_simple, loss_simple_0, loss_simple_1, supervised_criterion
    )

    rng_generator = np.random.default_rng(1337)
    beta_estimates = []
    
    for _ in range(20):
        random_input = rng_generator.uniform(-2.0, 2.0, size=8).astype(np.float64)
        logit_val, _ = model_network.predict(random_input)
        _, eval_loss_0 = remote_service.evaluate(random_input, 0)
        _, eval_loss_1 = remote_service.evaluate(random_input, 1)
        
        ratio = compute_coefficient_ratio(logit_val, eval_loss_0, eval_loss_1, supervised_criterion)
        beta_estimates.append(ratio)
    
    coefficient_beta = float(np.median(beta_estimates))

    print("\nInferred alpha:", coefficient_alpha)
    print("Inferred beta :", coefficient_beta)

    lower_bound_input = input_simple_regime.copy()
    upper_bound_input = None
    
    for _ in range(2000):
        activ_h, activ_z, _, _ = model_network.compute_intermediate_states(lower_bound_input)
        
        diag_z = np.diag(1.0 - activ_z * activ_z)
        diag_h = np.diag(1.0 - activ_h * activ_h)
        jacobian = diag_z @ model_network.weight_layer2 @ diag_h @ model_network.weight_layer1
        
        gradient_direction = (2.0 * activ_z) @ jacobian
        gradient_magnitude = float(np.linalg.norm(gradient_direction) + 1e-12)
        
        candidate_input = lower_bound_input + 0.01 * (gradient_direction / gradient_magnitude)

        candidate_logit, _ = model_network.predict(candidate_input)
        _, candidate_loss_0 = remote_service.evaluate(candidate_input, 0)
        _, candidate_loss_1 = remote_service.evaluate(candidate_input, 1)
        
        if check_composite_regime(
            candidate_logit, candidate_loss_0, candidate_loss_1, coefficient_beta, supervised_criterion
        ):
            upper_bound_input = candidate_input
            break
        
        lower_bound_input = candidate_input

    if upper_bound_input is None:
        raise RuntimeError("Failed to find COMPOSITE-regime point when bracketing threshold")

    assert identify_regime(lower_bound_input, coefficient_beta, model_network, remote_service, supervised_criterion) == "SIMPLE"
    assert identify_regime(upper_bound_input, coefficient_beta, model_network, remote_service, supervised_criterion) == "COMPOSITE"
    
    for _ in range(22):
        midpoint_input = 0.5 * (lower_bound_input + upper_bound_input)
        regime_type = identify_regime(midpoint_input, coefficient_beta, model_network, remote_service, supervised_criterion)
        
        if regime_type == "SIMPLE":
            lower_bound_input = midpoint_input
        else:
            upper_bound_input = midpoint_input

    threshold_lower = float(np.linalg.norm(model_network.predict(lower_bound_input)[1]))
    threshold_upper = float(np.linalg.norm(model_network.predict(upper_bound_input)[1]))
    threshold_estimate = 0.5 * (threshold_lower + threshold_upper)
    
    print("Threshold bracket:", threshold_lower, threshold_upper)

    composite_samples = []
    
    for _ in range(40):
        sample_input = rng_generator.uniform(-2.0, 2.0, size=8).astype(np.float64)
        _, sample_latent = model_network.predict(sample_input)
        
        if float(np.linalg.norm(sample_latent)) <= threshold_upper:
            continue
        
        sample_logit, _ = model_network.predict(sample_input)
        _, sample_loss_0 = remote_service.evaluate(sample_input, 0)
        _, sample_loss_1 = remote_service.evaluate(sample_input, 1)
        
        if not check_composite_regime(
            sample_logit, sample_loss_0, sample_loss_1, coefficient_beta, supervised_criterion
        ):
            continue
        
        avg_residual = 0.5 * (
            (sample_loss_0 - coefficient_beta * supervised_criterion(sample_logit, 0))
            + (sample_loss_1 - coefficient_beta * supervised_criterion(sample_logit, 1))
        )
        gradient_penalty = model_network.compute_gradient_norm_squared(sample_input)
        
        composite_samples.append((gradient_penalty, avg_residual))
        
        if len(composite_samples) >= 12:
            break
    
    if len(composite_samples) < 8:
        raise RuntimeError("Not enough COMPOSITE points to fit parameters")

    design_matrix = np.asarray(
        [[1.0, grad_pen] for grad_pen, _ in composite_samples], dtype=np.float64
    )
    response_vector = np.asarray([resid for _, resid in composite_samples], dtype=np.float64)
    
    coefficients, *_ = np.linalg.lstsq(design_matrix, response_vector, rcond=None)
    coefficient_gamma = float(coefficients[0])
    coefficient_delta = float(coefficients[1])

    remote_service.terminate_connection()

    print("\nRecovered (raw):")
    print("  alpha:", coefficient_alpha)
    print("  beta :", coefficient_beta)
    print("  gamma:", coefficient_gamma)
    print("  delta:", coefficient_delta)
    print("  tau  :", threshold_estimate)

    print("\nObserved constant contrast contribution (gamma*L_contrast):", coefficient_gamma)

    rounded_alpha = round(coefficient_alpha, 1)
    rounded_beta = round(coefficient_beta, 1)
    rounded_gamma = round(coefficient_gamma, 1)
    rounded_delta = round(coefficient_delta, 2)
    rounded_threshold = round(threshold_estimate, 2)

    print("\nRounded parameters (per submission format):")
    print(" ", rounded_alpha, rounded_beta, rounded_gamma, rounded_delta, f"{rounded_threshold:.2f}")
    print(f"\nFLAG: nite{{{rounded_alpha}_{rounded_beta}_{rounded_gamma}_{rounded_delta}_{rounded_threshold:.2f}}}")

    alternate_gamma = round(-coefficient_gamma, 1)
    print(f"ALT FLAG (if L_contrast is negated): nite{{{rounded_alpha}_{rounded_beta}_{alternate_gamma}_{rounded_delta}_{rounded_threshold:.2f}}}")


if __name__ == "__main__":
    execute_recovery()