import random

class User:
    def __init__(self):
        self.blinding_factor = None
        self.blinded_message = None

    def blind_message(self, message):
        """Blinds the message using a random blinding factor."""
        self.blinding_factor = random.randint(1, 100)  # A simple random number
        self.blinded_message = message * self.blinding_factor
        return self.blinded_message

    def unblind_signature(self, signed_blinded_message, signer_public_factor):
        """Unblinds the signature to get the signature on the original message."""
        if self.blinding_factor is None or self.blinded_message is None:
            return "Error: No message has been blinded."
        return signed_blinded_message // self.blinding_factor # Simple division for unblinding

class Signer:
    def __init__(self):
        self.secret_factor = random.randint(1, 100) # A simplified secret key
        self.public_factor = self.secret_factor * 2 # A simplified public key relation (not cryptographically sound)

    def sign_blinded_message(self, blinded_message):
        """Signs the blinded message using the secret factor."""
        signed_blinded_message = blinded_message + self.secret_factor # A very basic "signing" operation
        return signed_blinded_message


if __name__ == "__main__":
    user = User()
    signer = Signer()

    original_message = 15 
    print(f"Original Message: {original_message}")

    # User blinds the message
    blinded_message = user.blind_message(original_message)
    print(f"Blinded Message sent to Signer: {blinded_message}")

    # Signer signs the blinded message
    signed_blinded_message = signer.sign_blinded_message(blinded_message)
    print(f"Signed Blinded Message received by User: {signed_blinded_message}")

    # User unblinds the signature
    signature = user.unblind_signature(signed_blinded_message, signer.public_factor)
    print(f"Unblinded Signature on the Original Message: {signature}")

  
