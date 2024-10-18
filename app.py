import json
import math
import random

def parse_swhe_params(file_path):
    """
    Parses all common parameters related to the SWHE scheme from the given file.
    """
    with open(file_path, 'r') as file:
        data = json.load(file)
    
    swhe_data = data['SWHE']
    
    public_params = swhe_data['Public Parameters']
    
    eta = int(public_params['eta'])
    gamma = int(public_params['gamma'])
    rho = int(public_params['rho'])
    tau = int(public_params['tau'])
    
    pk = [int(val) for val in public_params['pk']]
    
    sk = int(swhe_data['sk'])
    
    #plaintext_vector = data['Plaintext Vector']
    
    return {
        'eta': eta,
        'gamma': gamma,
        'rho': rho,
        'tau': tau,
        'pk': pk,
        'sk': sk
    }

def parse_plaintext_vector(file_path):
    """
    Parses the plaintext vector from the given file.
    """
    with open(file_path, 'r') as file:
        data = json.load(file)
    
    return data['Plaintext Vector']

def parse_ciphertext_collection(file_path):
    """
    Parses the ciphertext collection from the given file.
    """
    with open(file_path, 'r') as file:
        data = json.load(file)
    
    return data['Ciphertext Collection']

def q_p(z, p):
    """
    Computes the quotient of z divided by p, rounding to the nearest integer.
    """
    return round(z / p)

def mod_p(z, p):
    """
    Computes the modulo operation as per the SWHE scheme, which returns a value in the range (-p/2, p/2].
    """
    return z - q_p(z, p) * p

def encrypt_bit(m, pk, rho, tau):
    """
    Encrypt a single bit using the somewhat homomorphic encryption scheme.
    
    Args:
      m: The plaintext bit (0 or 1).
      pk: Public key (list of integers).
      rho: Noise parameter (integer).
      tau: Number of elements in the public key (integer).
    
    Returns:
      c: The encrypted ciphertext (integer).
    """
    x0 = int(pk[0])  # x0 is the first element of the public key
    x_values = [int(pk[i]) for i in range(1, tau + 1)]  # x1 to x_tau

    # Sample a random subset S ⊆ {1, ..., tau}
    S = random.sample(range(1, tau + 1), random.randint(1, tau))
    
    # Sample a random integer r in the range (-2^(2*rho), 2^(2*rho))
    r = random.randint(-2**(2*rho), 2**(2*rho))
    
    # Compute the summation over the selected subset S
    sum_x_S = sum(x_values[i - 1] for i in S)  # i-1 because S indexes from 1 to tau

    # Compute the ciphertext, use the previously defined modulo operation
    c = mod_p((m + 2 * r + 2 * sum_x_S), x0)
    return c

def encrypt_vector(plaintext_vector, pk, rho, tau):
    """
    Encrypt a plaintext vector bitwise.
    
    Args:
      plaintext_vector: List of binary values (0 or 1).
      pk: Public key (list of integers).
      rho: Noise parameter (integer).
      tau: Number of elements in the public key (integer).
    
    Returns:
      encrypted_vector: List of encrypted ciphertexts.
    """
    encrypted_vector = [encrypt_bit(m, pk, rho, tau) for m in plaintext_vector]
    return encrypted_vector

def decrypt(sk, c):
    """
    Decrypts a ciphertext c using the secret key sk.
    
    Args:
      sk: Secret key (integer).
      c: Ciphertext (integer).
    
    Returns:
      Decrypted bit (0 or 1).
    """
    # Compute (c mod p) mod 2, where the value of p is from the variable sk
    c_mod_sk = mod_p(c, sk)
    decrypted_message = mod_p(c_mod_sk, 2)
    return decrypted_message

def homomorphic_xor(c1, c2, x0):
    """
    Perform homomorphic XOR (ciphertext addition) on two ciphertexts.
    
    Args:
      c1: First ciphertext (integer).
      c2: Second ciphertext (integer).
      x0: First element of the public key (integer).
    
    Returns:
      Resulting ciphertext after XOR.
    """
    return mod_p(c1 + c2, x0)

def homomorphic_and(c1, c2, x0):
    """
    Perform homomorphic AND (ciphertext multiplication) on two ciphertexts.
    
    Args:
      c1: First ciphertext (integer).
      c2: Second ciphertext (integer).
      x0: First element of the public key (integer).
    
    Returns:
      Resulting ciphertext after AND.
    """
    return mod_p(c1 * c2, x0)

def test_operations(ciphertext, sk, x0, max_iterations=100):
    """
    Test the number of supported XOR and AND operations before decryption fails.
    
    Args:
      ciphertext: The starting ciphertext (integer).
      sk: Secret key (integer).
      x0: First element of the public key (integer).
      max_iterations: Maximum number of operations to attempt.
    
    Returns:
      num_xor: Number of successful XOR operations before failure.
      num_and: Number of successful AND operations before failure.
    """
    original_message = decrypt(sk, ciphertext)
    
    # Test XOR operations
    current_ct_xor = ciphertext
    num_xor = 0
    for _ in range(max_iterations):
        current_ct_xor = homomorphic_xor(current_ct_xor, ciphertext, x0)
        if decrypt(sk, current_ct_xor) != original_message:
            break
        num_xor += 1
    
    # Test AND operations
    current_ct_and = ciphertext
    num_and = 0
    for _ in range(max_iterations):
        current_ct_and = homomorphic_and(current_ct_and, ciphertext, x0)
        if decrypt(sk, current_ct_and) != original_message:
            break
        num_and += 1
    
    return num_xor, num_and

def run_task1(json_file_path):
    return 1 # TODO move code related to task 1 here

def run_task2(json_file_path):
    """
    For each ciphertext, evaluates the number of supported
    XOR and AND operations as described in Section 2.2.
    States for each noise level and for both operations
    the number of supported iterations using the parameters
    for the scheme stated in the JSON file.
    """
    parsed_swhe_params = parse_swhe_params(json_file_path)

    pk = parsed_swhe_params['pk']
    sk = parsed_swhe_params['sk']

    ciphertext_collection = parse_ciphertext_collection(json_file_path)

    # x0 is the first element of the public key
    x0 = int(pk[0])

    # Iterate through the ciphertexts and test each one
    for i, ct in enumerate(ciphertext_collection):
        ciphertext = int(ct["Ciphertext"])
        noise_bitlength = ct["Noise Bitlength"]
    
        num_xor, num_and = test_operations(ciphertext, sk, x0, 200000)
        
        print(f"Ciphertext {i + 1} (Noise Bitlength: {noise_bitlength}) supports:")
        print(f"  XOR operations: {num_xor}")
        print(f"  AND operations: {num_and}")
    return

def main():
    json_file_path = 'input/swhe-task1.json'
    parsed_swhe_params = parse_swhe_params(json_file_path)

    eta = parsed_swhe_params['eta']
    gamma = parsed_swhe_params['gamma']
    rho = parsed_swhe_params['rho']
    tau = parsed_swhe_params['tau']
    pk = parsed_swhe_params['pk']
    sk = parsed_swhe_params['sk']

    plaintext_vector = parse_plaintext_vector(json_file_path)

    #print(f"eta: {eta}, gamma: {gamma}, rho: {rho}, tau: {tau}")
    #print(f"Public key (pk): {pk}")
    #print(f"Secret key (sk): {sk}")
    #print(f"Plaintext vector: {plaintext_vector}")

    # Encrypt the plaintext vector
    #encrypted_vector = encrypt_vector(plaintext_vector, pk, rho, tau)
    #print(f"Encrypted vector: {encrypted_vector}")
    # TODO print the encrypted vector to the json file

    run_task2('input/swhe-task2.json')


if __name__ == '__main__':
   main()