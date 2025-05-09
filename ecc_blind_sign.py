import random

p = 23  # A small prime modulus
a = 1   # Curve parameter
b = 1   # Curve parameter

def is_on_curve(point):
    """Checks if a point (x, y) is on the curve y^2 = x^3 + ax + b (mod p)."""
    if point is None:
        return True
    x, y = point
    return (y**2 % p) == (x**3 + a*x + b) % p

def point_add(P, Q):
    """Adds two points P and Q on the elliptic curve."""
    if P is None:
        return Q
    if Q is None:
        return P
    if P == Q:
        return point_double(P)
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and y1 != y2:
        return None

    slope = ((y2 - y1) * pow(x2 - x1, p - 2, p)) % p
    x3 = (slope**2 - x1 - x2) % p
    y3 = (slope * (x1 - x3) - y1) % p
    return (x3, y3)

def point_double(P):
    """Doubles a point P on the elliptic curve."""
    if P is None:
        return None
    x1, y1 = P
    slope = ((3 * x1**2 + a) * pow(2 * y1, p - 2, p)) % p
    x3 = (slope**2 - 2 * x1) % p
    y3 = (slope * (x1 - x3) - y1) % p
    return (x3, y3)

def scalar_multiply(k, P):
    """Multiplies a point P by a scalar k."""
    result = None
    while k > 0:
        if k % 2 == 1:
            result = point_add(result, P)
        P = point_double(P)
        k //= 2
    return result

class ECCUser:
    def __init__(self, generator_point):
        self.G = generator_point
        self.blinding_factor = random.randint(1, p - 1)
        self.message_point = None
        self.blinded_point = None

    def blind_message(self, message_scalar):
        """Blinds the message (represented as a scalar)."""
        # In a real scenario, the message would be hashed and mapped to a curve point.
        # Here, we'll just treat the scalar as a representative.
        self.message_point = scalar_multiply(message_scalar, self.G)
        self.blinding_factor_point = scalar_multiply(self.blinding_factor, self.G)
        self.blinded_point = point_add(self.message_point, self.blinding_factor_point)
        return self.blinded_point, self.blinding_factor

    def unblind_signature(self, signed_blinded_point, signer_public_key):
        """Unblinds the signature."""
        # The signer signs s*B = s*(M + rG) where s is the secret key.
        # The user receives S = s*(M + rG).
        # To get the signature on M (which would be s*M), the user needs to remove s*(rG).
        # This requires knowing the blinding factor 'r'.

        # In our simplified "signing", the signer returns k*blinded_point.
        # So, signed_blinded_point = signer_private_key * (message_point + blinding_factor_point)
        # To unblind, we need to subtract signer_private_key * blinding_factor_point.

        # This is a highly simplified and insecure unblinding.
        unblinded_signature = point_add(signed_blinded_point, scalar_multiply(-self.blinding_factor, signer_public_key))
        return unblinded_signature

class ECCSigner:
    def __init__(self, generator_point):
        self.G = generator_point
        self.private_key = random.randint(1, p - 1)
        self.public_key = scalar_multiply(self.private_key, self.G)

    def sign_blinded_point(self, blinded_point):
        """Signs the blinded point."""
        # In a real scheme, the signing would involve the private key and potentially
        # a hash of the blinded message. Here, we'll do a simple scalar multiplication.
        signed_blinded_point = scalar_multiply(self.private_key, blinded_point)
        return signed_blinded_point

if __name__ == "__main__":
    # Define a generator point on our insecure curve
    G = (2, 5)
    assert is_on_curve(G)

    user = ECCUser(G)
    signer = ECCSigner(G)

    original_message = 10  # Representing the message as a scalar
    print(f"Original Message (scalar): {original_message}")

    # User blinds the message
    blinded_point, blinding_factor = user.blind_message(original_message)
    print(f"Blinded Point sent to Signer: {blinded_point}")

    # Signer signs the blinded point
    signed_blinded_point = signer.sign_blinded_point(blinded_point)
    print(f"Signed Blinded Point received by User: {signed_blinded_point}")

    # User unblinds the signature
    signature_on_message = user.unblind_signature(signed_blinded_point, signer.public_key)
    expected_signature = scalar_multiply(signer.private_key, user.message_point) # What the signature should ideally be

    print(f"Unblinded Signature on the Original Message: {signature_on_message}")
    print(f"Expected Signature (for comparison): {expected_signature}")
