# RC6-DistributedComm
A secure distributed messaging system using RC6 symmetric encryption implemented from scratch in Python

RC6 lucrează cu:

Blocuri de 128 de biți (adică 16 bytes), care sunt împărțite în patru variabile de câte 32 de biți: A, B, C, D.

Chei care pot avea lungimi variabile, dar sunt procesate într-o structură numită cheie extinsă (expanded key), pentru a genera toate subcheile necesare algoritmului.

20 de runde de transformări, fiecare adăugând complexitate datelor, făcând criptarea foarte sigură.

1. Generarea subcheilor (Key Schedule)
Primul pas este transformarea cheii principale într-un set de subchei. Acest pas este esențial pentru securitate.

Se pornește de la două constante matematice (P32 și Q32).

Se generează un vector S care va conține 2r + 4 subchei (pentru 20 de runde → 44 subchei).

Se face apoi un proces de amestecare între cheia originală și vectorul S, folosind operații de rotire la stânga, adunare modulară și iterare circulară.
Această fază produce cheia extinsă, care va fi folosită la fiecare rundă de criptare sau decriptare.

2. Criptarea datelor
Blocul de 128 biți (A, B, C, D) este procesat astfel:

Se adaugă două subchei inițiale la valorile B și D.

Apoi, pentru fiecare dintre cele 20 de runde:

Se calculează două valori intermediare t și u folosind:

înmulțiri între B sau D și expresii derivate din ele, urmate de rotiri la stânga cu 5 poziții.

Se aplică operația XOR între A și t, respectiv între C și u, apoi rezultatul este rotit și se adaugă câte o subcheie.

În final, valorile A, B, C, D sunt rotite între ele într-un mod circular (schimbate între ele pentru diversitate).

După runde, ultimele două subchei se adaugă la A și C.

Rezultatul final este un bloc criptat care nu mai poate fi înțeles fără cheia corectă.

3. Decriptarea datelor
Procesul de decriptare este inversul criptării:

Se scad ultimele două subchei din valorile A și C.

Se parcurg runda cu runda invers (de la 20 la 1), desfăcând fiecare operație:

Se inversează rotirile.

Se aplică din nou XOR și se scad subcheile.

Valorile sunt rotite înapoi în sens opus criptării.

La final, se scad și primele două subchei pentru a recupera valorile originale B și D.

4. Tratarea textelor (nu doar cifre)
Pentru a cripta text, programul convertește string-ul în bytes și îl împarte în blocuri de câte 4 bytes. Dacă un bloc are mai puțin de 4 bytes, se completează cu \x00 (padding). Apoi fiecare bloc este criptat numeric cu RC6, iar rezultatul este convertit în text criptat.

Pentru decriptare, se face procesul invers: se citește textul criptat, se extrag numerele, se decriptează blocurile și se reface textul inițial, eliminând paddingul de la final.

