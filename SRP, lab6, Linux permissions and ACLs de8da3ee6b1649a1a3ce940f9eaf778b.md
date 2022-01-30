# SRP, lab6, Linux permissions and ACLs

U ovoj vježbi smo se upoznali s osnovnim postupkom upravljanja korisničkim računima na Linuxu. 

# Kreiranje korisničkog računa

U Linuxu svaka datoteka ili program ima vlasnika (*user or owner*). Svakom korisniku pridjeljen je jedinstveni identifikator *User ID (UID)*. Svaki korisnik mora pripadati barem jednoj grupi (*group*), a više korisnika može dijeliti istu grupu, koje također imaju jedinstvene identifikatore *Group ID (GID)*.

Otvorili smo shell i izvršili wsl naredbu.

Dodali smo novog korisnika narebom:

```jsx
sudo adduser alice5
```

te stvorili lozinku za alice5. (Ovo smo mogli napraviti jer imamo administratorske ovlasti, tj. pripadamo grupi sudo.)

Zatim smo se logirali kao alice5 i saznali odgovarajuće identifikatore korisnika i grupa kojima alice5 pripada.

```jsx
su - alice5
```

Nakon toga smo dodali još jednog korisnika, ‘**bob5**’ (postupak isti kao i kod alice5).

# Standardna prava pristupa datotekama

Logirali smo se kao alice5 i kreirali novi direktorij (srp), a u njemu dodali datoteku *security.txt*

```jsx
cd
mkdir srp
echo "Hello World" > security.txt
cat security.txt
```

Izlistali smo informacije o novom direktoriju i datoteci.

```jsx
ls -l .
ls -l srp
ls -l srp/security.txt

getfacl srp
getfacl srp/security.txt
getfacl -t srp/security.txt
```

Oduzeli smo pravo pristupa datoteci security.txt vlasniku datoteke modifikacijom dopuštenja. Za promjenu dopuštenja koristili smo naredbu chmod.

```jsx
chmod u-r security.txt
```

Pa smo vratili pravo ‘read’...

```jsx
chmod u+r security.txt
```

# **C. Kontrola pristupa korištenjem *Access Control Lists (ACL)***

Boba smo dodali u ACL kako bi on mogao čitati sadržaj datoteke security.txt

```jsx
sudo setfacl -m u:bob5:r /home/alice5/srp/security.txt
```

Na isti način smo ubacili cijelu grupu u ACL  i omogućili grupi pravo pristupa datoteci security.txt:

```jsx
sudo groupadd alice_reading_group5
sudo setfacl -m g:alice_reading_group5: r /home/alice5/srp/security.txt
```

# D. Linux procesi i kontrola pristupa

Oduzeli smo Bobu prava čitanja datoteke security.txt, mičući ga iz grupe koja ima ta prava:

```jsx
gpasswd -d bob5 alice_reading_group5
```

Zatim smo otvorili WSL shell i kreirali Python skriptu:

```jsx
import os
print('Real (R), effective (E) and saved (S) UIDs:')
print(os.getresuid())
with open('/home/alice5/srp/security.txt', 'r') as f:
print(f.read())
```

Izvršavanjem  ovoga dobili smo ‘permission denied’ jer nemamo nikakva prava nad tom datotekom. Međutim, kada smo pokrenuli skriptu kao Bob, pokretanje je bilo uspješno.