"""Egyszerű RSA implementáció.

Az IBIZA gyakorlatokon tanult algoritmusok megvalósításával felépített
RSA titkosítás.

Ez az implementáció semmiképpen sem megfelelő a gyakorlatban való használatra;
célja csupán, hogy könnyen olvasható kód formájában szemléltesse az órákon tanultakat.

A fájl lentről felfelé felépítéssel rendelkezik, azaz előbb a kicsi építőkövek szerepelnek,
majd ezeket követi a kulcsgenerálás, a titkosítás és a visszafejtés, valamint ezek használata egy
main függvényben.
"""

import secrets

def extended_euclidean_algorithm(a: int, b: int) -> (int, int, int):
    """Kibővített euklideszi algoritmus a legnagyobb közös osztó meghatározására.

    A

      gcd = x * a + y * b
    
    kifejezésben meghatározza a gcd (legnagyobb közös osztó), x és y
    értékeket, és ugyanilyen sorrendben visszaadja őket.

    Algoritmus: https://observablehq.com/@battila7/kibovitett-euklideszi-algoritmus
    """
    k = 0
    x, prevx = 0, 1
    y, prevy = 1, 0
    r, prevr = b, a

    while r != 0:
        k += 1

        q = prevr // r

        prevr, r = r, prevr % r

        prevx, x = x, x * q + prevx
        prevy, y = y, y * q + prevy

    gcd = prevr
    x = prevx * ((-1) ** k)
    y = prevy * ((-1) ** (k + 1))
    
    return gcd, x, y 

def modular_inverse(a: int, modulus: int) -> int:
    """Meghatározza egy szám multiplikatív inverzét adott modulusra nézve.

    Adott a és modulus esetén visszaadja azt a b értéket, melyre az

      a * b = 1 mod modulus

    kongruencia teljesül.
    """

    _, inverse, _ = extended_euclidean_algorithm(a, modulus)

    if inverse < 0:
        inverse = modulus + inverse

    return inverse

def modular_exponentiation(base: int, exponent: int, modulus: int) -> int:
    """Gyorshatványozással kiszámolja a base^exponent mod modulus értéket.

    Algoritmus: https://observablehq.com/@battila7/gyorshatvanyozas-fast-modular-exponentiation
    """
    result = 1

    base = base % modulus

    # A jegyzetben található (és órán használt) algoritmustól itt picit eltérünk.
    # Míg ott külön lépés volt a hatványalap bináris alakjának felírása, az
    # ismételt négyzetre emelés, majd a maradékok összeszorzása, addig
    # itt mindezt összevonjuk a lenti ciklus formájában.
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        
        exponent //= 2

        base = (base * base) % modulus
    
    return result

def decompose_into_two_and_odd_product(a: int) -> (int, int):
    """Felbontja az a értéket a lehető legnagyobb kettőhatvány és egy páratlan szám szorzatára.
    """
    s = 0

    while a % 2 == 0:
        s += 1

        a //= 2

    return s, a

def miller_rabin_test(p: int, base: int) -> bool:
    """Egykörös Miller-Rabin prímteszt, mely True értéket ad vissza, ha p lehetséges prím, míg False-t, ha összetett.
    """
    s, d = decompose_into_two_and_odd_product(p - 1)

    for i in range(s):
        r = modular_exponentiation(base, (2 ** i) * d, p)

        if i == 0 and r == 1:
            return True

        if r == (p - 1):
            return True
        
    return False

def is_probable_prime(p: int) -> bool:
    """Prímteszt, mely True értéket ad vissza, ha p lehetséges prím, míg False-t, ha összetett.
    """

    # Abban a számtartományban, amiben dolgozunk, ezek a bázisok megfelelők.
    for base in [2, 3, 5, 7, 13]:
        if not miller_rabin_test(p, base):
            return False

    return True

def random_probable_prime_below(limit: int) -> int:
    """Generál egy véletlen, a limitnél kisebb számot, mely valószínűleg prím.
    """

    while True:
        # Figyeljük meg, hogy a véletlen értéket kriptográfiailag megfelelő forrásból generáljuk!
        # Dokumentáció: https://docs.python.org/3/library/secrets.html
        n = secrets.randbelow(limit)

        if is_probable_prime(n):
            return n

def are_relative_primes(a: int, b: int) -> bool:
    """Meghatározza, hogy a és b relatív prímek-e.
    """

    gcd, _, _ = extended_euclidean_algorithm(a, b)

    return gcd == 1

def choose_encryption_exponent(phi_n: int) -> int:
    """Kiválasztja a lehető legkisebb titkosító exponenst, mely relatív prím phi_n-nel.
    """

    for e in range(3, phi_n, 2):
        if (are_relative_primes(e, phi_n)):
            return e

# A véletlenül generált prímek nagyságára vonatkozó határ.
PRIME_LIMIT = 50

def setup() -> ((int, int), (int, int), int):
    """RSA inicializálást végez.

    Visszaadja a használt p, q prímeket, valamint a publikus és a privát kulcsot.

    Algoritmus: https://observablehq.com/@battila7/rsa
    """

    p = random_probable_prime_below(PRIME_LIMIT)
    q = p

    while q == p:
        q = random_probable_prime_below(PRIME_LIMIT)
    
    n = p * q
    phi_n = (p - 1) * (q - 1)

    e = choose_encryption_exponent(phi_n)

    d = modular_inverse(e, phi_n)

    return (p, q), (n, e), d

def encrypt(public_key: (int, int), message: int) -> int:
    """A megadott RSA publikus kulccsal titkosítja a message értéket.

    Algoritmus: https://observablehq.com/@battila7/rsa
    """

    n, e = public_key

    return modular_exponentiation(message, e, n)

def decrypt(private_key: int, primes: (int, int), ciphertext: int) -> int:
    """A megadott RSA privát kuccsal és prímekkel visszafejti a ciphertext titkosított értéket.

    Algoritmus: https://observablehq.com/@battila7/rsa
    """

    p, q = primes

    dp = private_key % (p - 1)
    dq = private_key % (q - 1)

    mp = modular_exponentiation(ciphertext, dp, p)
    mq = modular_exponentiation(ciphertext, dq, q)

    _, yp, yq = extended_euclidean_algorithm(p, q)

    return (mp * yq * q + mq * yp * p) % (p * q)

def main():
    primes, public_key, private_key = setup()

    print(f"A generált prímek: {primes}")
    print(f"Publikus kulcs: {public_key}")
    print(f"Privát kulcs: {private_key}\n")

    original_message = 21

    print(f"A titkosítandó üzenet: {original_message}\n")

    ciphertext = encrypt(public_key, original_message)

    print(f"A titkosított üzenet: {ciphertext}")

    decrypted_message = decrypt(private_key, primes, ciphertext)

    print(f"A visszafejtett üzenet: {decrypted_message}")


if __name__ == "__main__":
    main()
