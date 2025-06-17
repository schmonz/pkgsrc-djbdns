#
while read -r NAME; do
	rm -f $NAME
done < TARGETS
