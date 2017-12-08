#!/bin/bash

echo "Downoading..."

wget -N http://standards.ieee.org/develop/regauth/oui/oui.txt
wget -N http://standards.ieee.org/develop/regauth/oui28/mam.txt
wget -N http://standards.ieee.org/develop/regauth/oui36/oui36.txt

echo "Processing..."

grep "(hex)" oui.txt | grep -v "public listing" | awk '{$2=""; print}' > ieee-mac-oui.csv.tmp
grep "(hex)" mam.txt | awk '{$2=""; print}' >> ieee-mac-oui.csv.tmp
grep "(hex)" oui36.txt  | awk '{$2=""; print}' >> ieee-mac-oui.csv.tmp

tr 'a-z' 'A-Z' < ieee-mac-oui.csv.tmp > ieee-mac-oui.csv.tmp2
sed -e 's/  /,"/' -re 's/([0-9A-F]+)-([0-9A-F]+)-/\1\2/' < ieee-mac-oui.csv.tmp2 > ieee-mac-oui.csv
sed -i 's/\r/"/' ieee-mac-oui.csv
sed -i '1i\'"Vendor_MAC,Manufacturer" ieee-mac-oui.csv

echo "Clean up..."

rm -f oui.txt mam.txt oui36.txt
rm -f ieee-mac-oui.csv.tmp
rm -f ieee-mac-oui.csv.tmp2

echo "Complete!"
