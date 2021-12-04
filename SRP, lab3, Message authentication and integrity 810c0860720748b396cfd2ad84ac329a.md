# SRP, lab3, Message authentication and integrity

Cilj treće laboratorijske vježbe bio je da primjenimo teoretska znanja o osnovnim kriptografskim mehanizmima za autentikaciju i zaštitu integriteta poruka. Koristili smo simetrični kripto sustav: ***message authentication code (MAC).***

### IZAZOV 1

Otvaramo python virtualno okruženje:

```
python -m venv <ime>

```

Idućim smo se komandama pozicionirali u odgovarajući direktorij i pokrenuli skriptu.

```
cd <ime> ; 
cd .\\Scripts\\ ; 
.\\activate

```

Vraćamo se u svoje virtualno okruženje i komandom *code .* otvaramo vs code.

Cilj nam je bio implementacija zaštite integriteta sadržaja dane poruke uz primjenu odgovarajućeg MAC algoritma. Koristili smo HMAC mehanizam iz Python biblioteke cryptography.

Kreirali smo tekstualnu datoteku "message.txt" i u nju pohranili sadržaj čiji smo integritet željeli zaštititi.

Na temelju pročitanog sadržaja iz datoteke i proizvoljno unesenog ključa generirali smo MAC pomoću funkcije "generate_MAC" te smo ga spremili u file imena "message.mac".

U funkciji "verify_MAC" usporedili smo novi MAC s onim koji smo poslali kao argument funkcije

```

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature

def generate_MAC(key, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    signature = h.finalize()
    return signature

def verify_MAC(key, signature, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    try:
        h.verify(signature)
    except InvalidSignature:
        return False
    else:
        return True

if __name__ == "__main__":
    key = b"my secret password"
    with open("message.txt", "rb") as file:
        content = file.read()

    # mac = generate_MAC(key, content)

    # with open("message.mac", "wb") as file:
    #     file.write(mac)
		with open("message.mac", "rb") as file:
	       mac = file.read()

    is_authentic = verify_MAC(key, mac, content)

    print(is_authentic)

```

Vrijednost varijable *is_authentic* bit ce istinita (true). Ako promijenimo poruku (sadržaj datoteke "message.txt") ili signature, vrijednost će postati false.

## **IZAZOV 2**

Cilj drugog zadatka bilo je utvrditi vremenski ispravnu sekvenciju transakcija sa odgovarajućim dionicama. Nalozi za pojedine transakcije nalazili su se lokalnom web poslužitelju: [http://a507-server.local](http://a507-server.local/).

Pomoću GNU Wget softvera preuzeli smo potrebne file-ove s poslužitelja.

```
if __name__ == "__main__":
key = "strinic_mia".encode()
# with open("./challenges/strinic_mia/mac_challenge/order_2.txt", "rb") as file:
#     content = file.read()
# with open("./challenges/strinic_mia/mac_challenge/order_2.sig", "rb") as file:
#     mac = file.read()
for ctr in range(1, 11):
	msg_filename = f"./challenges/strinic_mia/mac_challenge/order_{ctr}.txt"
	sig_filename = f"./challenges/strinic_mia/mac_challenge/order_{ctr}.sig"
	with open(msg_filename, "rb") as file:
		content = file.read()
	with open(sig_filename, "rb") as file:
		mac = file.read()
	is_authentic = verify_MAC(key, mac, content)
	print(is_authentic)
	print(f'Message {key.decode():>45} {"OK" if is_authentic else "NOK":<6}')

```