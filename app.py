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
    
    plaintext_vector = data['Plaintext Vector']
    
    return {
        'eta': eta,
        'gamma': gamma,
        'rho': rho,
        'tau': tau,
        'pk': pk,
        'sk': sk,
        'plaintext_vector': plaintext_vector
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
    # Compute (c mod p) mod 2
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

    print(f"eta: {eta}, gamma: {gamma}, rho: {rho}, tau: {tau}")
    print(f"Public key (pk): {pk}")
    print(f"Secret key (sk): {sk}")
    print(f"Plaintext vector: {plaintext_vector}")

    # Encrypt the plaintext vector
    encrypted_vector = encrypt_vector(plaintext_vector, pk, rho, tau)
    print(f"Encrypted vector: {encrypted_vector}")
    # TODO print the encrypted vector to the json file




if __name__ == '__main__':
   main()