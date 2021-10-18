# By Gargi Chaurasia 2019059
import random


class Operations:

    @classmethod
    def rabinMiller(self, n, d):
        a = random.randint(2, (n - 2) - 2)
        x = pow(a, int(d), n)  # a^d%n
        if x == 1 or x == n - 1:
            return True

        # square x
        while d != n - 1:
            x = pow(x, 2, n)
            d *= 2

            if x == 1:
                return False
            elif x == n - 1:
                return True

        # is not prime
        return False

    @classmethod
    def isPrime(self, n):
        """
        Check if the given number is prime or not.
        Parameters:
        n (int): Prime number 
        Returns:
        bool: Returns True if n is prime, otherwise returns False
        """

        # 0, 1, -ve numbers not prime
        if n < 2:
            return False

        # low prime numbers to save time
        lowPrimes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443,
                     449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997]

        # if in lowPrimes
        if n in lowPrimes:
            return True

        # if low primes divide into n
        for prime in lowPrimes:
            if n % prime == 0:
                return False

        # find number c such that c * 2 ^ r = n - 1
        c = n - 1  # c even bc n not divisible by 2
        while c % 2 == 0:
            c /= 2  # make c odd

        # prove not prime 128 times
        for _ in range(128):
            if not self.rabinMiller(n, c):
                return False

        return True

    @classmethod
    def isCoPrime(self, p, q):
        """
        Check if the given numbers are coprimes.
        Parameters:
        p,q (int): Prime number 
        Returns:
        bool: Returns True if p and q are coprime, otherwise returns False
        """

        return self.gcd(p, q) == 1

    @classmethod
    def gcd(self, a, b):
        """
        Calculates the gcd of a and b
        Parameters:
        a,b (int):  Positive integers
        Returns:
        int: Returns gcd value of a and b
        """

        a, b = abs(a), abs(b)
        if a < b:
            a, b = b, a

        remainder = gcd = b
        while (remainder != 0):
            gcd = remainder
            remainder = a % b
            a = b
            b = remainder

        return gcd

    @classmethod
    def modInverse(self, a, m):
        """
        Calculates the modular multiplicative inverse of a using mod m
        Parameters:
        a,m (int): Positive integers
        Returns:
        int: Returns x such that a*x mod m = 1 mod m
        """

        m0 = m
        y = 0
        x = 1

        if (m == 1):
            return 0

        while (a > 1):

            # q is quotient
            q = a // m

            t = m

            # m is remainder now, process
            # same as Euclid's algo
            m = a % m
            a = t
            t = y

            # Update x and y
            y = x - q * y
            x = t

        # Make x positive
        if (x < 0):
            x = x + m0

        return x

    @classmethod
    def modulo_operation(self, a, b):
        # Return a mod b
        return a % b

    @classmethod
    def xor_operation(self, a, b):
        # Returns a xor b
        return a ^ b

    @classmethod
    def shift_operation(self, a, b, direction='left'):
        """
        Shifts the bits of the number to the left or right as directed
        Parameters:
        a,b (int): Numbers for shift operation
        Returns:
        int: Returns left or right shifted number
        """
        if direction == "left":
            return a << b
        elif direction == "right":
            return a >> b
        else:
            print("Mention the direction as either 'left' or 'right' !!")
            return a

    @classmethod
    def circular_left_shift(self, num, shift_amount=4):
        """
        Rotates the bits of the given number to the left
        Parameters:
        num (int): Prime number 
        shift_amount(int): No of bits to be shifted
        Returns:
        int: Returns the integer form of the shifted bit string
        """
        binary_rep = "{0:08b}".format(num)  # converting the int num to binary

        # As in our case shift_amount is 4, therefore swapping the two nibbles
        ans = binary_rep[shift_amount:] + binary_rep[:shift_amount]
        return int(ans, 2)
