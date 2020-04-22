## Mitigating Chosen Ciphertext Attack on Apple's iMessage

My code implements the solution that Apple implemented to avoid this security threat where it acts as a formatting oracle for an attacker trying to gain access to an AES key that is used to encrypt and decrypt iMessage messages from person A to B.

In my code, I implement the RSA encryption of an AES key that is sent as an RSA ciphertext to the recipient along with the AES-CTR ciphertext. The RSA ciphertext contains the AES key needed to decrypt the AES-CTR ciphertext, hence, it is important that this be protected. To mitigate the oracle attack, like Apple, I implemented a list of previously received RSA ciphertexts, so that we can blacklist any RSA ciphertext that has already been seen before in a request, in order to avoid acting as an oracle that can tell the attacker which ciphertext is valid and which is not. It is also important to fail silently in case we do receive a ciphertext that has already been seen before, hence we just return the function with no further action taken. Note that the very first thing the decrypt function must check for is if the received ciphertext has ever been seen before, so that there is no processing until we can confirm that we are not being attacked.

Hence, my code mirrors a baseline implementation of what Apple did to fix the problem outlines in my explanation of the attack in the previous part of this paper. However, since I only built one component of the entire technology, there are some limitations here. For example, the RSA ciphertext was concatenated to include the AES-CTR ciphertext as well, since Apple saves some space by stuffing AES-CTR ciphertext into the available space at the end of the RSA ciphertext. This I did not implement in my code, so that I can keep my threat mitigation example simple and show the implementation that was used to avoid the attack.
