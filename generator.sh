#!/bin/bash

# Create temporary files
doc=$(mktemp)
readme=README.md
global=$(mktemp)
service=$(mktemp)
global_tpl="templates/global.j2"
services_tpl="templates/services.j2"

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

# Synonyms not catched by regexes.
cat << EOF >> ${doc}
preload (G)
bind dns directory (G)
browsable (S)
casesignames (S)
create mode (S)
default (G)
directory mode (S)
group (S)
public (S)
only guest (S)
allow hosts (S)
deny hosts (S)
winbind gid (G)
winbind uid (G)
ldap password sync (G)
lock dir (G)
debuglevel (G)
socket address (G)
directory (S)
exec (S)
prefered master (G)
print ok (S)
printcap (G)
printer (S)
private directory (G)
root (G)
root dir (G)
max protocol (G)
protocol (G)
min protocol (G)
debug timestamp (G)
vfs object (S)
writable (S)
write ok (S)
EOF

# VFS
cat << EOF | grep -v '^#' >> ${doc}
# https://www.samba.org/samba/docs/current/man-html/vfs_acl_tdb.8.html
acl_xattr:ignore system acls (S)
acl_xattr:default acl style (S)
# https://www.samba.org/samba/docs/current/man-html/vfs_aio_fork.8.html
# https://www.samba.org/samba/docs/current/man-html/vfs_aio_pthread.8.html
aio_pthread:aio open (S)
# https://www.samba.org/samba/docs/current/man-html/vfs_audit.8.html
audit:facility (S)
audit:priority (S)
# https://www.samba.org/samba/docs/current/man-html/vfs_btrfs.8.html
btrfs: manipulate snapshots (S)
# https://www.samba.org/samba/docs/current/man-html/vfs_cacheprime.8.html
cacheprime:rsize (S)
# https://www.samba.org/samba/docs/current/man-html/vfs_cap.8.html
# https://www.samba.org/samba/docs/current/man-html/vfs_catia.8.html
catia:mappings (S)
# https://www.samba.org/samba/docs/current/man-html/vfs_ceph.8.html
ceph:config_file (S)
ceph:user_id (S)
# https://www.samba.org/samba/docs/current/man-html/vfs_commit.8.html
commit:dthresh (S)
# https://www.samba.org/samba/docs/current/man-html/vfs_crossrename.8.html
crossrename:sizelimit (S)
# https://www.samba.org/samba/docs/current/man-html/vfs_default_quota.8.html
default_quota:uid (S)
default_quota:gid (S)
default_quota:uid nolimit (S)
default_quota:gid nolimit (S)
# https://www.samba.org/samba/docs/current/man-html/vfs_dirsort.8.html
# https://www.samba.org/samba/docs/current/man-html/vfs_extd_audit.8.html
# https://www.samba.org/samba/docs/current/man-html/vfs_fake_perms.8.html
# https://www.samba.org/samba/docs/current/man-html/vfs_fileid.8.html
fileid:algorithm (S)
fileid:mapping (S)
fileid:fstype deny (S)
fileid:fstype allow (S)
fileid:mntdir deny (S)
fileid:mntdir allow (S)
fileid:nolockinode (S)
# https://www.samba.org/samba/docs/current/man-html/vfs_fruit.8.html
fruit:aapl (G)
fruit:nfs_aces (G)
fruit:copyfile (G)
fruit:zero_file_id (G)
fruit:model (G)
readdir_attr:aapl_rsize (S)
readdir_attr:aapl_finder_info (S)
readdir_attr:aapl_max_access (S)
fruit:resource (S)
fruit:time machine (S)
fruit:time machine max size (S)
fruit:metadata (S)
fruit:locking (S)
fruit:encoding (S)
fruit:veto_appledouble (S)
fruit:posix_rename (S)
readdir_attr:aapl_rsize (S)
readdir_attr:aapl_finder_info (S)
readdir_attr:aapl_max_access (S)
fruit:wipe_intentionally_left_blank_rfork (S)
fruit:delete_empty_adfiles (S)
# https://www.samba.org/samba/docs/current/man-html/vfs_full_audit.8.html
full_audit:prefix (S)
full_audit:success (S)
full_audit:failure (S)
full_audit:facility (S)
full_audit:priority (S)
full_audit:syslog (S)
full_audit:log_secdesc (S)
# https://www.samba.org/samba/docs/current/man-html/vfs_glusterfs.8.html
glusterfs:logfile (S)
glusterfs:loglevel (S)
glusterfs:volfile_server (S)
glusterfs:volume (S)
# https://www.samba.org/samba/docs/current/man-html/vfs_glusterfs_fuse.8.html
# https://www.samba.org/samba/docs/current/man-html/vfs_gpfs.8.html
gpfs:sharemodes (S)
gpfs:leases (S)
gpfs:hsm (S)
gpfs:recalls (S)
gpfs:getrealfilename (S)
gpfs:winattr (S)
gpfs:merge_writeappend (S)
gpfs:acl (S)
gpfs:check_fstype (S)
gpfs:refuse_dacl_protected (S)
gpfs:dfreequota (S)
gpfs:prealloc (S)
gpfs:settimes (S)
nfs4:mode (S)
nfs4:acedup (S)
nfs4:chown (S)
gpfs:syncio (S)
# https://www.samba.org/samba/docs/current/man-html/vfs_syncops.8.html
syncops:onclose (S)
syncops:disable (S)
syncops:onmeta (S)
# https://www.samba.org/samba/docs/current/man-html/vfs_media_harmony.8.html
# https://www.samba.org/samba/docs/current/man-html/vfs_netatalk.8.html
# https://www.samba.org/samba/docs/current/man-html/vfs_nfs4acl_xattr.8.html
nfs4acl_xattr:encoding (S)
nfs4acl_xattr:version (S)
nfs4acl_xattr:default acl style (S)
nfs4acl_xattr:xattr_name (S)
# https://www.samba.org/samba/docs/current/man-html/vfs_offline.8.html
# https://www.samba.org/samba/docs/current/man-html/vfs_prealloc.8.html
prealloc:EXT (S)
# https://www.samba.org/samba/docs/current/man-html/vfs_preopen.8.html
preopen:names (S)
preopen:num_bytes (S)
preopen:helpers (S)
preopen:queuelen (S)
# https://www.samba.org/samba/docs/current/man-html/vfs_readahead.8.html
readahead:offset (S)
readahead:length (S)
# https://www.samba.org/samba/docs/current/man-html/vfs_readonly.8.html
readonly:period (S)
# https://www.samba.org/samba/docs/current/man-html/vfs_recycle.8.html
recycle:repository (S)
recycle:directory_mode (S)
recycle:subdir_mode (S)
recycle:keeptree (S)
recycle:versions (S)
recycle:touch (S)
recycle:touch_mtime (S)
recycle:minsize (S)
recycle:maxsize (S)
recycle:exclude (S)
recycle:exclude_dir (S)
recycle:noversions (S)
# https://www.samba.org/samba/docs/current/man-html/vfs_shadow_copy.8.html
# https://www.samba.org/samba/docs/current/man-html/vfs_shadow_copy2.8.html
shadow:mountpoint (S)
shadow:snapdir (S)
shadow:basedir (S)
shadow:snapsharepath (S)
shadow:sort (S)
shadow:localtime (S)
shadow:format (S)
shadow:sscanf (S)
shadow:fixinodes (S)
shadow:snapdirseverywhere (S)
shadow:crossmountpoints (S)
shadow:snapprefix (S)
shadow:delimiter (S)
# https://www.samba.org/samba/docs/current/man-html/vfs_snapper.8.html
# https://www.samba.org/samba/docs/current/man-html/vfs_streams_depot.8.html
streams_depot:directory (S)
streams_depot:delete_lost (S)
https://www.samba.org/samba/docs/current/man-html/vfs_streams_xattr.8.html
streams_xattr:prefix (S)
streams_xattr:store_stream_type (S)
# https://www.samba.org/samba/docs/current/man-html/vfs_virusfilter.8.html
virusfilter:scanner (S)
virusfilter:socket path (S)
virusfilter:connect timeout (S)
virusfilter:io timeout (S)
virusfilter:scan on open (S)
virusfilter:scan on close (S)
virusfilter:max file size (S)
virusfilter:min file size (S)
virusfilter:infected file action (S)
virusfilter:infected file errno on open (S)
virusfilter:infected file errno on close (S)
virusfilter:quarantine directory (S)
virusfilter:quarantine prefix (S)
virusfilter:quarantine suffix (S)
virusfilter:rename prefix (S)
virusfilter:rename suffix (S)
virusfilter:quarantine keep tree (S)
virusfilter:quarantine keep name (S)
virusfilter:infected file command (S)
virusfilter:scan archive (S)
virusfilter:max nested scan archive (S)
virusfilter:scan mime (S)
virusfilter:scan error command (S)
virusfilter:exclude files (S)
virusfilter:block access on error (S)
virusfilter:scan error errno on open (S)
virusfilter:scan error errno on close (S)
virusfilter:cache entry limit (S)
virusfilter:cache time limit (S)
virusfilter:quarantine directory mode (S)
virusfilter:block suspected file (S)
# https://www.samba.org/samba/docs/current/man-html/vfs_unityed_media.8.html
unityed_media:clientid (S)
# https://www.samba.org/samba/docs/current/man-html/vfs_tsmsm.8.html
tsmsm:hsm script (S)
tsmsm:online ratio (S)
tsmsm:dmapi attribute (S)
tsmsm:dmapi value (S)
# https://www.samba.org/samba/docs/current/man-html/vfs_time_audit.8.html
time_audit:timeout (S)
# https://www.samba.org/samba/docs/current/man-html/vfs_shell_snap.8.html
shell_snap:check path command (S)
shell_snap:create command (S)
shell_snap:delete command (S)
# https://www.samba.org/samba/docs/current/man-html/vfs_worm.8.html
worm:grace_period (S)
# https://www.samba.org/samba/docs/current/man-html/vfs_xattr_tdb.8.html
xattr_tdb:file (S)
# https://www.samba.org/samba/docs/current/man-html/vfs_zfsacl.8.html
nfs4:mode (S)
nfs4:acedup (S)
nfs4:chown (S)
EOF

cat ${doc} | grep -E '\((G|S)\)' | sed -E 's/ \((G|S)\)//g' | sort | uniq > ${global}
cat ${doc} | grep '(S)' | sed 's/ (S)//g' | sort | uniq > ${service}

# Global section
echo "[global]" > ${global_tpl}
while read vs ; do
  van="$(samba_to_ansible ${vs})"
  va="samba_${van}"
  echo "{% if ${va} is defined %}" >> ${global_tpl}
  echo "  ${vs} = {{ format_samba_option(${va}, '$(va_to_enclosure ${van})', '$(va_to_delimiter ${van})') }}" >> ${global_tpl}
  echo "{% endif %}" >> ${global_tpl}
done < ${global}
echo "{% for config in samba_idmap_configs %}" >> ${global_tpl}
echo "  idmap config {{ config.domain }} : {{ config.option }} = {{ format_samba_option(config.value, ' ', '') }}" >> ${global_tpl}
echo "{% endfor %}" >> ${global_tpl}

# Shares/services
echo "{% for share in samba_shares %}" > ${services_tpl}
echo "[{{ share.name }}]" >> ${services_tpl}
while read vs ; do
  van="$(samba_to_ansible ${vs})"

  echo "{% set v = share.get('${van}', None) %}" >> ${services_tpl}
  echo "{% if v is not none %}" >> ${services_tpl}
  echo "  ${vs} = {{ format_samba_option(v, '$(va_to_enclosure ${van})', '$(va_to_delimiter ${van})') }}" >> ${services_tpl}
  echo "{% endif %}" >> ${services_tpl}
done < ${service}
echo "{% if not loop.last %}" >> ${services_tpl}
echo "" >> ${services_tpl}
echo "{% endif %}" >> ${services_tpl}
echo "{% endfor %}" >> ${services_tpl}

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
