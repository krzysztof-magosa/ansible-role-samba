t=$(mktemp)

cat ./vars/main.yml|grep '^  \w' | sed 's/://' | awk '{print $1}' > $t
while read x ; do
  echo "{% if $x is defined %}"
  echo "{{ $x }}"
  echo "{% endif %}"
done < $t
