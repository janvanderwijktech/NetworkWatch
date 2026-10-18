# NetworkWatch 1.4 — Python netwerkmonitor voor Linux

Een zelfstandige, GUI-gebaseerde toepassing geïnspireerd door SoftPerfect WiFi Guard,
met eigen broncode en eigen interface. Geen SoftPerfect-code of -assets.

## Wat zit erin?

- ARP-discovery op de gekozen bekabelde of draadloze Linux-interface.
- Ook hosts vinden die ICMP/ping blokkeren, zolang ze op hetzelfde lokale netwerk via ARP bereikbaar zijn.
- IP-adres, MAC-adres, hostnaam, fabrikant, eigen naam, laatste waarneming en online-status.
- Apparaten expliciet als vertrouwd markeren; identificatie op MAC-adres, niet op IP-adres.
- Apart aanvinken welke vertrouwde apparaten altijd online horen te zijn.
- Handmatig scannen of automatisch, met countdown en pauzeknop.
- Sorteren, zoeken, filteren, CSV-export, gebeurtenisgeschiedenis en optionele desktopmelding.
- Aparte HTTP-POST-triggers voor onbekende apparaten en bekende apparaten die offline gaan.
- JSON of form-urlencoded, eigen headers en invulvelden in de body.
- SQLite-opslag en een persistente HTTP-wachtrij met herpogingen.
- Netwerkprofielen met elk hun eigen apparaten en vertrouwenslijst.

Dit is een eigen implementatie van de kernfunctionaliteit, geen garantie van exacte
functiepariteit met alle versies van WiFi Guard. Er is geen passieve, onmiddellijke
join-detectie, systeemvakpictogram of ingebouwde SMTP-mailfunctie. Detectie gebeurt
bij een scan. Houd het venster geopend of geminimaliseerd; afsluiten stopt de bewaking.
Een HTTP-workflow kan desgewenst e-mail of andere meldingen verzorgen.

## Vereisten

Linux, Python 3.10+, Tkinter, iproute2, arp-scan 1.10+ (met libcap-ondersteuning).
Geen pip-pakketten nodig. De Python-standaardbibliotheek verzorgt GUI, database en HTTP.
`getent` wordt gebruikt voor optionele hostnaamresolutie. `notify-send` wordt gebruikt
als het beschikbaar is; anders blijven geluid, titel en gebeurtenissen beschikbaar.

### Debian / Ubuntu

```bash
sudo apt update
sudo apt install python3 python3-tk arp-scan iproute2 libcap2-bin libnotify-bin
```

### Arch / Omarchy

```bash
sudo pacman -S --needed python tk arp-scan iproute2 libcap libnotify
```

### Eenmalig toestemming voor ARP-pakketten

Controleer of het pakket de capability al heeft ingesteld:

```bash
getcap "$(command -v arp-scan)"
```

Als `cap_net_raw` ontbreekt:

```bash
sudo setcap cap_net_raw+p "$(command -v arp-scan)"
```

Dit geeft de **arp-scan executable** toestemming om raw netwerkpakketten te gebruiken.
De Python-GUI zelf draait als je normale gebruiker: start haar **zonder sudo**.
Een pakketupdate kan de capability verwijderen; controleer dit bij een rechtenfout.
Geef de Python-interpreter zelf geen capabilities.

## Starten

Pak het ZIP-bestand uit. Open een terminal in de uitgepakte map `netwerk_wacht`:

```bash
python3 netwerkwacht.py
```

Bij de eerste start opent Instellingen:

1. Geef het netwerk een eigen profielnaam, bijvoorbeeld `Thuis`.
2. Selecteer de juiste interface in de keuzelijst. Interface en CIDR-subnet worden ingevuld.
3. Laat gatewaycontrole eerst aan staan.
4. Stel bijvoorbeeld interval `60` en gemiste scans `3` in.
5. Sla op en klik **Scan nu**.
6. Klik in de kolom **Bekend** op ☐ om een apparaat als vertrouwd te markeren (☑).
   Klik opnieuw om het vinkje te verwijderen. De wijziging wordt meteen opgeslagen.
   Spatie wisselt het geselecteerde apparaat. Dubbelklik elders in de rij om een eigen naam in te vullen.
7. Vink bij een NAS, server of andere altijd-aan-host ook **offlinebewaking** aan.

De eerste scan markeert bewust **alle** gevonden apparaten als onbekend, inclusief
router en eigen computer. Als de onbekend-trigger dan aan staat, krijg je voor elk
apparaat een melding. Laat triggers eventueel uit tijdens de eerste inventarisatie.
Het later inschakelen van een trigger verstuurt geen oude gebeurtenissen opnieuw.

Voorbeeld: met 60 seconden interval en drie gemiste scans wordt een NAS na circa
2–3 minuten plus scantijd als offline beschouwd. Het interval telt vanaf het einde
van de vorige scan. Smartphones in slaapstand zijn meestal geen goede kandidaten
voor altijd-aan-bewaking.

## HTTP-triggers instellen

Open **Instellingen & triggers**. De tabbladen **Onbekend apparaat** en
**Bekend apparaat offline** hebben elk hun eigen URL, headers en body.

### JSON-webhook

Schakel de gewenste trigger in, vul jouw webhook-URL in en kies `json`.
Bijvoorbeeld `https://jouw-server.example/webhook/netwerkwacht` (vervang dit adres).

Headers, indien de ontvanger een bearer-token gebruikt:

```json
{
  "Authorization": "Bearer JOUW_TOKEN"
}
```

Body:

```json
{
  "event": "{event}",
  "ip": "{ip}",
  "mac": "{mac}",
  "name": "{name}",
  "message": "{message}",
  "timestamp": "{timestamp}",
  "event_id": "{event_id}",
  "profile": "{profile}"
}
```

Dit komt overeen met een verzoek in deze vorm:

```bash
curl --request POST 'https://jouw-server.example/webhook/netwerkwacht' \
  --header 'Authorization: Bearer JOUW_TOKEN' \
  --header 'Content-Type: application/json' \
  --data '{"event":"offline","ip":"192.168.2.25","name":"NAS"}'
```

De app gebruikt de Python HTTP-client; curl zelf is niet nodig.

### Formulier-POST

Kies `form` voor een endpoint dat formuliergegevens verwacht. Vul ook dan de body
in als JSON-object, bijvoorbeeld:

```json
{
  "token": "JOUW_TOKEN",
  "message": "{message}",
  "device": "{name}"
}
```

De app zet dit om naar `application/x-www-form-urlencoded`, vergelijkbaar met
`curl --data-urlencode`. Pas de veldnamen aan de API van de ontvanger aan.

Beschikbare invulvelden:

- `{event}`: `unknown` of `offline`.
- `{ip}`, `{mac}`, `{hostname}`, `{vendor}`.
- `{name}`: eigen naam, anders hostnaam, anders IP-adres.
- `{message}`: leesbare Nederlandse melding.
- `{timestamp}`: UTC-tijdstip in ISO 8601.
- `{event_id}`: unieke gebeurtenis-ID, gelijk bij herpogingen.
- `{network}`, `{profile}`.

Invulvelden worden alleen in bodywaarden vervangen, niet in URL's, headers of keys.
Waarden met quotes of regelovergangen worden correct gecodeerd. Geneste JSON-objecten
zijn toegestaan bij `json`; bij `form` gebruik je eenvoudige waarden.

**Verstuur echte test-POST** verzendt onmiddellijk een test naar de ingevulde URL,
ook als de trigger nog niet ingeschakeld of opgeslagen is. De test gebruikt
`192.0.2.123`, `TEST apparaat` en de eventsoort van het gekozen tabblad.
Een HTTP 2xx telt als succes; een API kan binnen een 200-response nog een eigen fout
teruggeven. De app interpreteert zulke dienstspecifieke responsebodies niet.

### Wanneer wordt een trigger verstuurd?

- Onbekend: bij eerste waarneming van een MAC-adres in dit profiel, en opnieuw
  als een nog steeds onbekend apparaat terugkomt nadat het als offline gold.
- Bekend offline: alleen bij de overgang van online naar offline, na het ingestelde
  aantal gemiste **succesvolle** scans, én als vertrouwd plus offlinebewaking aan staan.
- Een blijvend offline apparaat geeft niet iedere scan een nieuwe melding.
- Na terugkeer naar online kan een volgende uitval opnieuw een melding geven.
- Zet je bewaking pas aan bij een apparaat dat al offline is, dan volgt geen
  retrospectieve melding: het moet eerst weer online zijn gezien.
- Veranderende IP-adressen behouden bij hetzelfde MAC-adres de vertrouwde status.
- Foute, afgebroken of niet-verbonden scans wijzigen geen aanwezigheidsstatussen.

De HTTP-wachtrij probeert maximaal vier keer: direct, daarna na circa 10, 30 en 90
seconden. De wachtrij blijft bestaan bij een herstart. Elke event gebruikt de
triggerinstellingen die bij het ontstaan golden; uitschakelen van een trigger
annuleert al klaargezette verzoeken niet. Pauzeren pauzeert scans, niet de wachtrij.

Er is **at-least-once**-bezorging: bij bijvoorbeeld een timeout kan een ontvanger een
verzoek al verwerkt hebben. Gebruik `{event_id}` of de header
`X-NetwerkWacht-Event-ID` aan ontvangende kant om dubbele acties te voorkomen.
Na vier mislukte pogingen blijft de gebeurtenis zichtbaar als `failed`.
Er is geen automatische onbeperkte herhaling en geen handmatige resend-knop.

HTTPS controleert certificaten. Redirects worden geweigerd zodat geheime headers
niet naar een andere bestemming meegaan. Omgevingsproxy's worden niet gebruikt.
HTTP is ook toegestaan voor lokale endpoints; daarbij is het verkeer onversleuteld.

## Netwerkgedrag en beperkingen

ARP werkt op het **direct aangesloten IPv4-netwerk**. Deze app scant geen andere
VLANs via een router, geen IPv6 en geen netwerk achter client isolation.
De gekozen range moet bij de interface horen en het eigen IP bevatten.
De maximale range is /20 (4096 adressen); /24 is een gebruikelijke keuze.
Dit inventariseert alle bereikbare LAN-apparaten, dus ook bekabelde apparaten.

De gatewaycontrole verlangt dat een default gateway binnen het gekozen subnet
ook in de scan voorkomt. Zo worden veel massale valse offline-alarmen vermeden.
Bij een netwerk zonder gateway kun je de controle uitschakelen, maar dan kan
verbindingsverlies eerder als uitval van apparaten worden geïnterpreteerd.
Tijdens een scan worden interface, linkstatus en lokaal adres opnieuw gecontroleerd.
Een succesvolle scan is geen absoluut bewijs van aanwezigheid of afwezigheid.

Fabrikantnamen komen uit de lokale arp-scan-database. Bij privé/random MAC-adressen
is de fabrikant vaak onbekend. Een nieuw random MAC-adres is een nieuw apparaat.
MAC-adressen kunnen ook worden gespooft: “vertrouwd” is een inventarisatiestatus,
geen cryptografische authenticatie. De app blokkeert geen apparaten.

Hostnamen komen uit de systeemresolver (`getent`); ontbrekende DNS/PTR-records
leveren lege namen op. Je kunt altijd een eigen naam invullen. Naamopzoekingen
hebben een korte timeout en draaien parallel; uitschakelen versnelt grote scans.

Een profiel wordt bepaald door naam + interface + subnet. Gebruik voor een ander
fysiek netwerk een andere profielnaam, ook als de IP-range gelijk is. De app herkent
niet automatisch welk Wi-Fi-SSID of welke locatie je gebruikt.

## Launcher en automatisch starten

Zet de projectmap eerst op een vaste plek. Maak vervolgens als gewone gebruiker
een launcher in het applicatiemenu:

```bash
python3 install_launcher.py
```

Voor desktops die XDG Autostart ondersteunen:

```bash
python3 install_launcher.py --autostart
```

Autostart geldt na grafisch inloggen, niet vóór inloggen. Onder Hyprland/Omarchy
hangt XDG Autostart af van de sessieconfiguratie. Je kunt ook de absolute opdracht
`python3 /absoluut/pad/netwerk_wacht/netwerkwacht.py` aan je eigen sessie-autostart
toevoegen. Gebruik de syntaxis van jouw Hyprland-versie.
De app voorkomt een tweede gelijktijdige instantie voor dezelfde gebruiker.

## Gegevens en back-up

Alles staat standaard in:

```text
~/.local/share/netwerkwacht/
```

Als `XDG_DATA_HOME` is ingesteld, wordt die map gebruikt.

- `config.json`: instellingen, URLs, tokens/headers en bodytemplates.
- `devices.sqlite3`: apparaten, gebeurtenissen en HTTP-wachtrij.
- SQLite kan daarnaast `devices.sqlite3-wal` en `devices.sqlite3-shm` gebruiken.
- `app.lock`: voorkomt dubbele instanties.

De app maakt de gegevensmap privé (0700) en nieuwe bestanden privé (0600).
Tokens staan lokaal in leesbare vorm, niet in een sleutelkluis. Pending requests
bewaren een kopie van hun triggerinstellingen; bij afronding wordt die kopie uit de
actieve rij verwijderd. Dit is geen gegarandeerde forensische wisactie op SQLite.
HTTP-foutmeldingen bevatten geen requestbody of URL.

Sluit de app af voordat je een consistente back-up van de gegevensmap maakt.
Gebeurtenissen blijven bewaard; de GUI toont de laatste 500 per profiel. Er is geen
retentie-opruiming in deze versie. CSV-export bevat alle apparaten in het huidige
profiel, ongeacht het actieve zoekfilter, maar geen webhooktokens.

## Testen en validatiestatus

```bash
python3 -m unittest discover -s tests -v
```

De meegeleverde 41 tests controleren onder andere MAC-identiteit bij IP-wijziging,
herstart met opgeslagen staat, offline-drempel, herhaalde meldingen, netwerkprofielen,
scanvalidatie, gatewaycontrole, transactie-rollback en HTTP-verzoeken naar een lokale
testserver (JSON, form, redirects, outbox en herpoging).

Bij oplevering: alle 41 tests geslaagd en Python-bestanden gecompileerd.
ARP-scans zijn in tests gesimuleerd; er is niet op jouw netwerk gescand.
De grafische interface is in deze bouwomgeving niet interactief getest omdat er
geen grafische displayserver beschikbaar is. Test de eerste keer op jouw Linux-desktop.

## Bestanden

- `netwerkwacht.py`: GUI, scanplanning, apparaatbeheer, export en instellingen.
- `core.py`: ARP-scanner, netwerkcontrole, SQLite-statusmachine en HTTP-outbox.
- `install_launcher.py`: optionele applicatiemenu- en autostartlauncher.
- `tests/test_core.py`: regressietests zonder echte netwerkscan.
- `README.md`: deze Nederlandse handleiding.
- `LICENSE`: MIT-licentie voor deze eigen code.

## Bronnen voor het ontwerp

- WiFi Guard-productinformatie: https://www.softperfect.com/products/wifiguard/
- WiFi Guard-handleiding: https://www.softperfect.com/products/wifiguard/manual/
- arp-scan-project en capability-ondersteuning: https://github.com/royhills/arp-scan


## Update 1.1: direct afvinken

De kolom Bekend bevat nu aanklikbare selectievakjes. Het bewerkvenster blijft
beschikbaar en gebruikt dezelfde opgeslagen status. Bij uitvinken vervalt ook
eventuele offlinebewaking; opnieuw aanvinken schakelt die niet automatisch in.
Bij het filter Onbekend verdwijnt een zojuist vertrouwd apparaat direct uit beeld.

Sluit voor deze update de app af en vervang de programmabestanden door deze versie.
Je instellingen en apparaten staan buiten de projectmap en blijven behouden.

## Update 1.2: zichtbare en klikbare selectievakjes

De interface heet nu **NetworkWatch 1.2**. De kolom **Bekend** staat helemaal
links en gebruikt zelfgetekende afbeeldingen van lege vakjes en groene vinkjes.
Ze zijn onafhankelijk van het lettertype. Een klik in die kolom wisselt de status;
Spatie werkt ook. De klikafhandeling gebruikt de boomkolom van Tkinter.
Vijf aanvullende tests controleren de klikafhandeling met echte SQLite-opslag.
De grafische rendering is niet getest op een displayserver.

Start de nieuwe versie met `python3 networkwatch.py`. De oude startopdracht
`python3 netwerkwacht.py` blijft werken. Beide gebruiken bewust dezelfde bestaande
gegevensmap `~/.local/share/netwerkwacht`, zodat je apparaten en instellingen blijven.
Ook bestaande HTTP-eventheaders blijven ongewijzigd voor compatibiliteit.

Sluit de oude app eerst helemaal af en vervang alle programmabestanden.
Bovenaan het scherm moet daarna **NetworkWatch 1.2** staan. Staat daar nog
NetwerkWacht, dan draait een oude kopie of verwijst de launcher nog naar die kopie.

## Update 1.3: TCP- en UDP-poortoverzicht

Na ARP-discovery worden de gevonden IPv4-hosts gecontroleerd op de aangevraagde
poorten. Dit staat standaard aan, ook bij bestaande configuraties. Er zijn geen
extra pakketten of extra rootrechten nodig voor deze controle.

TCP: 20, 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 465,
993, 995, 3306, 5432, 5900, 6379, 8080, 8443.

UDP: 53, 67, 68, 123, 137, 138, 161, 389, 514.

Dit zijn 32 protocol/poort-combinaties: 53 en 389 worden via beide protocollen
gecontroleerd. De poortlijst is vastgelegd in `ports.py`.

Het algemene overzicht heeft nu:

- **Open poorten (bevestigd)**, bijvoorbeeld `22/tcp SSH, 443/tcp HTTPS`.
- **UDP onzeker** voor poorten die geen uitsluitsel geven.
- **Poortcheck (UTC)** met het tijdstip van de laatste controle.

Selecteer een host en klik **Poortdetails**, of dubbelklik op een poortkolom.
Je ziet alle gecontroleerde poorten met open, gesloten, onzeker of fout en de reden.
Servicenamen zijn gebruikelijke namen bij een poort, geen software-identificatie.
Een webserver op 22/tcp kan bijvoorbeeld nog steeds als poortnaam SSH hebben.

Bij TCP wordt een gewone verbinding geopend en meteen gesloten. Er worden geen
loginpogingen of applicatieopdrachten uitgevoerd. Een geaccepteerde verbinding
betekent open. Een geweigerde verbinding betekent gesloten. Een timeout of een
onbereikbaar netwerk is onzeker en wordt niet als gesloten voorgesteld.

Bij UDP wordt alleen een ontvangen UDP-antwoord als bewijs voor open gebruikt.
Er zijn twee pogingen. Een port-unreachable/weigering betekent gesloten; geen
antwoord betekent onzeker. Door filtering, ICMP-rate-limits, verloren pakketten
of een ongeschikte probe kan ook een gesloten of open poort onzeker blijven.
Er worden verbonden UDP-sockets gebruikt met tijdelijke bronpoorten.

DNS krijgt een root-NS-vraag zonder recursion desired, NTP een gewone tijdvraag.
De overige UDP-poorten krijgen lege datagrammen, zonder DHCP-broadcast of
leaseaanvraag, zonder SNMP-communitypogingen en zonder inhoudelijk syslogbericht.
**DHCP, SNMP, LDAP, NetBIOS en Syslog kunnen daardoor vaak niet als open worden
bevestigd, ook als ze actief zijn.** Dit is een beperkte UDP-bereikbaarheidscontrole,
geen volledige protocolspecifieke service-discovery. Een hogere timeout verandert
dat niet. Achtergrond over UDP-onzekerheid:
https://nmap.org/book/scan-methods-udp-scan.html

Onder **Instellingen & triggers → Poortcontrole** kun je de controle uitschakelen,
UDP afzonderlijk uitzetten of de timeout aanpassen (standaard 0,8 seconde,
toegestaan 0,1–5 seconden). Er worden maximaal 32 hosts tegelijk gecontroleerd,
per host één poort tegelijk. Bij veel hosts en timeouts kan dit tientallen seconden
tot minuten duren. De GUI blijft reageren; de volgende scan wordt na voltooiing
van de huidige scan plus het ingestelde interval gepland. Ook aanwezigheidsmeldingen
worden na voltooiing van de volledige scan verwerkt.

Bij offline/gemiste hosts staan eerdere open poorten met het voorvoegsel **Laatste:**.
Bij uitgeschakelde poortcontrole blijven eerdere metingen zichtbaar met hun datum.
Een gewijzigd IP-adres wist oude poortresultaten als geen nieuwe controle plaatsvond.
De database wordt automatisch uitgebreid met behoud van apparaten en instellingen.
CSV-export bevat de meetgegevens, tijdstippen en leesbare poortsamenvattingen.

**Update:** sluit de app volledig af, vervang alle programmabestanden (inclusief het
nieuwe `ports.py`) en start `python3 networkwatch.py`. Bovenaan staat NetworkWatch 1.3.
De gegevensmap blijft `~/.local/share/netwerkwacht`.

Validatie: 31 tests geslaagd. Nieuwe tests gebruiken echte lokale TCP- en UDP-sockets
voor open, gesloten en geen-antwoord-situaties. Ook de exacte poortlijst, UDP-uitstand,
databasemigratie, opgeslagen poortresultaten en IP-wijzigingen zijn gecontroleerd.
De GUI is niet op een grafische desktop getest; jouw netwerk is niet benaderd.

## Update 1.4: vermoedelijk besturingssysteem per host

In de apparatenlijst staat na het IP-adres de kolom **Vermoedelijk OS**.
Voorbeelden: `Linux (Ubuntu)`, `Linux (Debian)`, `Windows`, `FreeBSD`,
`Darwin/macOS`, `Onbekend` of `Onzeker (tegenstrijdig)`.
De eigen computer wordt lokaal herkend, bijvoorbeeld `Linux (lokaal)`.

Deze versie gebruikt **beperkte servicebannerherkenning**, geen volledige
TCP/IP-fingerprinting met Nmap. Alleen expliciete OS-aanwijzingen in SSH/FTP-banners
(poorten 22/21) en HTTP-serverheaders (80/8080) tellen mee. HTTP gebruikt een HEAD
op `/`; er worden geen inlogpogingen gedaan. HTTPS, SMB en andere poorten worden
niet gebruikt voor OS-herkenning. Alleen een open poort 445 of een generieke
OpenSSH-, nginx- of Apache-banner is onvoldoende om Windows of Linux te claimen.

Een netwerkresultaat is altijd een **indicatie**: een service kan in een container,
WSL-omgeving of achter een proxy draaien. Banners kunnen aangepast zijn. Het
resultaat bevestigt niet het besturingssysteem van de fysieke host en geeft geen
exacte OS-versie. Vooral telefoons, printers en apparaten zonder herkenbare
services zullen vaak Onbekend blijven. Tegenstrijdige OS-aanwijzingen blijven
zichtbaar als onzeker. Het lokaal uitgelezen OS vormt de uitzondering op deze
netwerkinschatting.

Via **Apparaat bewerken** zie je de gebruikte aanwijzing en de laatste OS-controle
in UTC. De velden `os_guess`, `os_evidence` en `os_checked` gaan ook mee in CSV.
De bestaande database wordt automatisch uitgebreid. Vertrouwde apparaten,
namen, offlinebewaking en instellingen blijven behouden.

Onder **Instellingen & triggers → OS-herkenning** kun je de functie uitschakelen.
Ze staat standaard aan. Als poortcontrole aan staat, worden alleen de relevante
bevestigd open poorten benaderd. Anders worden de vier bannerpoorten rechtstreeks
geprobeerd. Per verbinding geldt de ingestelde poorttimeout (standaard 0,8 seconde),
met een totale deadline en maximaal 4096 ontvangen bytes. Maximaal 16 hosts worden
parallel onderzocht. Dit kan scans langer maken.

Bij offline/gemiste hosts verschijnt `Laatste:` voor het vorige resultaat.
Bij uitschakelen van OS-herkenning blijven oude resultaten staan; het tijdstip in
Apparaat bewerken verandert dan niet. Een IP-wijziging zonder nieuwe OS-controle
wist de eerdere indicatie. Een nieuwe controle zonder aanwijzing wordt Onbekend,
zodat een oude gok niet als nieuwe detectie wordt hergebruikt.

Start met `python3 networkwatch.py`; bovenaan staat NetworkWatch 1.4.
Bij handmatig bijwerken moet ook het nieuwe bestand `osdetect.py` worden meegenomen.
De gegevensmap blijft `~/.local/share/netwerkwacht`.

Validatie: 41 tests geslaagd, inclusief herkenning, tegenstrijdige aanwijzingen,
geen gok op basis van generieke diensten, een lokale SSH-testserver, HTTP-header-
selectie, opslag en IP-wijzigingen. De GUI is niet interactief getest op een
Linux-desktop; jouw netwerk is niet gescand.

Achtergrond bij het verschil tussen service- en host-OS:
https://nmap.org/book/vscan-fileformat.html
