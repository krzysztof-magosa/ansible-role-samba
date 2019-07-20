#!/bin/bash

# Create temporary files
doc=$(mktemp)
readme=README.md
global=$(mktemp)
service=$(mktemp)
output=templates/smb.conf.j2

# Helper functions
function samba_to_ansible() {
  echo $@ | sed 's/ /_/g' | sed 's/:/_/g' | sed 's/__/_/g' | tr A-Z a-z
}

function va_to_delimiter() {
  case $1 in
    veto_files)
      echo '/'
      ;;
    veto_oplock_files)
      echo '/'
      ;;
    aio_write_behind)
      echo '/'
      ;;
    dont_descend)
      echo ','
      ;;
    usershare_prefix_allow_list)
      echo ','
      ;;
    usershare_prefix_deny_list)
      echo ','
      ;;
    *)
      echo ' '
      ;;
  esac
}

function va_to_enclosure() {
  case $1 in
    veto_files)
      echo '/'
      ;;
    veto_oplock_files)
      echo '/'
      ;;
    aio_write_behind)
      echo '/'
      ;;
    *)
      echo ''
      ;;
  esac
}

# Download documentation
lynx -dump https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html \
  | grep -v -- '-' \
  | grep -v 'DOMAIN' \
  | grep -v "idmap config" > ${doc}
cat ${doc} | grep -E '\((G|S)\)' | sed -E 's/ \((G|S)\)//g' | sort > ${global}
cat ${doc} | grep '(S)' | sed 's/ (S)//g' | sort > ${service}

# Macros
echo "{% macro format_samba_option(v, e, d) -%}" > ${output}
echo "{{- e -}}" >> ${output}
echo "{%- if v == true or v == false -%}" >> ${output}
echo "{{ v | ternary('yes', 'no') }}" >> ${output}
echo "{%- elif v is iterable and v is not string -%}" >> ${output}
echo "{{ v | join(d) }}" >> ${output}
echo "{%- else -%}" >> ${output}
echo "{{ v }}" >> ${output}
echo "{%- endif -%}" >> ${output}
echo "{{- e -}}" >> ${output}
echo "{%- endmacro %}" >> ${output}
echo "{{ ansible_managed | comment }}" >> ${output}
echo >> ${output}

# Global section
echo "[global]" >> ${output}
while read vs ; do
  van="$(samba_to_ansible ${vs})"
  va="samba_${van}"
  echo "{% if ${va} is defined %}" >> ${output}
  echo "  ${vs} = {{ format_samba_option(${va}, '$(va_to_enclosure ${van})', '$(va_to_delimiter ${van})') }}" >> ${output}
  echo "{% endif %}" >> ${output}
done < ${global}
echo "{% for config in samba_idmap_configs %}" >> ${output}
echo "  idmap config {{ config.domain }} : {{ config.option }} = {{ format_samba_option(config.value, ' ', '') }}" >> ${output}
echo "{% endfor %}" >> ${output}

# Delimiter
echo >> ${output}

# Shares/services
echo "{% for service_name, service_cfg in samba_shares.items() %}" >> ${output}
echo "[{{ service_name }}]" >> ${output}
while read vs ; do
  van="$(samba_to_ansible ${vs})"

  echo "{% set v = service_cfg.get('${van}', None) %}" >> ${output}
  echo "{% if v is not none %}" >> ${output}
  echo "  ${vs} = {{ format_samba_option(v, '$(va_to_enclosure ${van})', '$(va_to_delimiter ${van})') }}" >> ${output}
  echo "{% endif %}" >> ${output}
done < ${service}
echo "{% endfor %}" >> ${output}

# Generate documentation
cat README.md.pre > ${readme}
echo >> ${readme}
echo "## Global options" >> ${readme}
echo "|Samba option|Ansible variable|" >> ${readme}
echo "|------------|----------------|" >> ${readme}
while read vs ; do
  va="samba_$(samba_to_ansible ${vs})"
  echo "|${vs}|${va}|" >> ${readme}
done < ${global}
while read vs ; do
  va="samba_$(samba_to_ansible ${vs})"
  echo "|${vs}|${va}|" >> ${readme}
done < ${service}
echo "|idmap config DOMAIN : OPTION|samba_idmap_configs - [see usage](#idmap-config)|" >> ${readme}

echo >> ${readme}
echo "## Service/share options" >> ${readme}
echo "|Samba option|Ansible property|" >> ${readme}
echo "|------------|----------------|" >> ${readme}
while read vs ; do
  va="$(samba_to_ansible ${vs})"
  echo "|${vs}|${va}|" >> ${readme}
done < ${service}
cat README.md.post >> ${readme}
