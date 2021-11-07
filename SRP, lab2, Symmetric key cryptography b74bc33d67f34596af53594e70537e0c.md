# SRP, lab2, Symmetric key cryptography

Zadatak na ovim laboratorijskim vježbama bio je riješiti crypto challenge, odnosno dešifrirati ciphertext. Izazov je bio u tome što nismo imali pristup enkripcijskom ključu.

Na početku vježbe kreirali smo python virtualno okruzenje pod nazivom "env":

**python -m venv env**

Koristeći sljedeće naredbe:

 **cd env ; 
cd .\\Scripts\\ ;
.\\activate**
pozicionirali smo se u odgovarajući direktorij te smo pokrenuli skriptu.

Zatim smo instalirali biblioteku 'cryptography' (Python): **pip install cryptography**

te otvorili python interaktivni shell jednostavnom naredbom **python.**

Plaintext koji smo morali otkriti enkriptiran je korištenjem *high-level* sustava za simetričnu enkripciju iz biblioteke - **[Fernet](https://cryptography.io/en/latest/fernet/)**. 

Fernet jamči da se poruka šifrirana pomoću njega ne može izmanipulirati  niti čitati bez ključa.

**Generiranje ključa:** key = Fernet.generate_key( )

**Inicijalizacija pomoću dobivenog ključa:** f=Fernet(key)

**Enkripcija plaintexta:** ciphertext = f.encrypt(plaintext)

 // plaintext je izvorna poruka

// ciphertext je enkriptirana poruka, tj. kodirana

// enkripcija = postupak pretvaranja izvorne poruke u nečitljiv oblik

**Dekripcija ciphertexta:** deciphertext = f.decrypt(ciphertext)

Na serveru [http://a507-server.local](http://a507-server.local/) se nalaze imena file-ova (imena studenata) dobivena enkriptiranjem koristeći SHA-256 algoritam.

Pozicionirali smo se u vlastiti direktorij i kreirali skriptu.

U skriptu smo napisali idući kod:

**from cryptography.hazmat.primitives import hashes
def hash(input):
	if not isinstance(input, bytes):
		input = input.encode()
	digest = hashes.Hash(hashes.SHA256())
	digest.update(input)
	hash = digest.finalize()

	return hash.hex()
filename = hash('prezime_ime') + ".encrypted"**

Dalje smo koristili naredbu **python brute_force.py**  te uz pomoć funkcije

**if __name__ == "__main__":
	hash_value = hash("strinic_mia")
	print(hash_value)**

uspjeli dobiti da nam se izgenerira  naše hashirano ime.

Zatim, smo preuzeli našu datoteku i spremili u isti folder u koji nam je spremljen brute_force.py.

Za enkripciju smo koristili ključeve ograničene entropije - 22 bita, koji su generirani uz pomoć Ferneta. Cilj nam je bio saznati naš ključ.

Iterirali smo kroz ključeve, ispisivali isprobane pomocu: 

**if not(ctr + 1) % 1000:
	print(f"[*] Keys tested: {ctr +1:,}", end="\\r"**

Za uspješnu dekripciju našeg filea, uzeli smo ciphertext i "ubacili" ga u funkciju. Tako smo dekripcijom ciphertexta dobili željeni plaintext: **plaintext = decrypt(key, ciphertext)**

Kako bismo bili sigurni da smo dobili željeni plaintext, morali smo postaviti if uvjet koji je provjeravao je li slika u željenom formatu (PNG). Kad je uvjet istinit, isprinta se pronađeni ključ.

```python
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

def hash(input):
	if not isinstance(input, bytes):
		input = input.encode()
	digest = hashes.Hash(hashes.SHA256())
	digest.update(input)
	hash = digest.finalize()
	return hash.hex()

def test_png(header):
	if header.startswith(b"\\211PNG\\r\\n\\032\\n"):
		return True

def brute_force():
# Reading from a file
	filename = "9319a3b572e2f5ef8889ac16cad0b2921dacfc62cf84a67cc0df718464911cc0.encrypted"
	with open(filename, "rb") as file:
		ciphertext = file.read()
# Now do something with the ciphertext
	ctr = 0
	while True:
		key_bytes = ctr.to_bytes(32, "big")
		key = base64.urlsafe_b64encode(key_bytes)
		if not (ctr + 1) % 1000:
			print(f"[*] Keys tested: {ctr +1:,}", end = "\\r")
		try:
			plaintext = Fernet(key).decrypt(ciphertext)
			header = plaintext[:32]
			if test_png(header):
				print(f"[+] KEY FOUND: {key}")
				# Writing to a file
				with open("BINGO.png", "wb") as file:
					file.write(plaintext)
						break
		except Exception:
			pass
# Now initialize the Fernet system with the given key
# and try to decrypt your challenge.
# Think, how do you know that the key tested is the correct key
# (i.e., how do you break out of this infinite loop)?
		ctr += 1
if __name__ == "__main__":
	brute_force()

```