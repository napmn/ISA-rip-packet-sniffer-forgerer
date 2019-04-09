# RIP SNIFFER & RIP RESPONSE #

## POPIS PROGRAMOV ##

myripsniffer  - Nástroj na monitorovanie RIP komunikácie na určitom rozhraní.
                Program v nekonečnej slučke monitoruje komunikáciu a vypisuje
                zachytené pakety uživateľovi v ľahko čitatelnej forme.

myripresponse - Nástroj ktorý pomocout RIPv2 response správy podvrhuje zadanú
                routu na zadané rozhranie. Program odošle nanajvýš jednu RIPv2
                response správu a ukončí sa.

Obidva programy je nutné spúšťať ako správca!

## PRÍKLAD SPUSTENIA ##

./myripsniffer -i vboxnet0

./myripresponse -i vboxnet0 -r 2001:db8:0:abdd::/64 -t 10 -m 5 -n ::

## ZOZNAM ODOVZDANÝCH SÚBOROV ##

Makefile
README
manual.pdf
myripsniffer.cpp
myripsniffer.hpp
myripresponse.cpp
myripresponse.hpp