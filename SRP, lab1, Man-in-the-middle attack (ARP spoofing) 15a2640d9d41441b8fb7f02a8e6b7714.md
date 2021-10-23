# SRP, lab1, Man-in-the-middle attack  (ARP spoofing)

Na prvim laboratorijskim vježbama upoznali smo osnovne sigurnosne prijetnje i ranjivosti u računalnim mrežama te analizirali ranjivost Address Resolution Protocola (ARP) koja napadaču daje mogućnost izvođenja man-in-the-middle i denial of service napada na računa koja dijele zajedničku lokalnu mrežu (LAN).

Zadatak je bio realizirati *man in the middle* napad iskorištavanjem ranjivosti ARP protokola.

Testirali smo napad u virtualiziranoj Docker mreži koju čine 3 docker računala, odnosno dvije žrtve: station-1 i station-2 te napadač evil-station.

**KORACI**:

→ Pokrenuli smo Windows terminal aplikaciju i otvorili Ubuntu terminal na WSL sustavu.

→ Pozicionirali smo se u odgovarajući direktorij te klonirali GitHub repozitorij naredbom:                

    git clone https://github.com/mcagalj/SRP-2021-22

→ Naredbom cd ušli smo u direktorij *arp-spoofing/* u kojem se nalaze skripte **start.sh** i **stop.sh** koje služe za pokretanje i zaustavljanje docker kontejnera

POKRETANJE**:** $ ./start.sh, ZAUSTAVLJANJE**:** $ ./stop.sh

→ Pokrenuli smo shell station-1 i provjerili konfiguraciju mrežnog interface-a, 

    $ docker exec -it station-1 bash 

→ Izvršili smo provjeru konfiguracije mrežnog interface-a, $ifconfig -a

→ Provjerili smo nalazi li se i station-2 na istoj mreži te pokrenuli shell za station-2

→ Provjera mreže: $ ping station-2

→ Pokretanje shella station-2:  $ docker exec -it station-2 bash 

→ Ostvarili smo vezu između station-1 i station-2

→ Station-1 → server na portu 8000, $ netcat -1 -p 8000

→ Station 2 → client na hostname-u station-1 8000, $ netcat station-1 8000

→ Da bismo ostvarili napad, pokrenuli smo shell za evil-station i isprobali **tcpdump** i **arpspoof**.

→ Pokretanje shella evil-station, $ docker exec -it evil-station bash

→ Arpspoof, $ arpspoof -t station-1 station-2

→ Tcpdump, $ tcpdump

→Prekinuli smo vezu između station-1 i station-2 naredbom, echo 0 > /proc/sys/net/ipv4/ip_forward