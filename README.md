# samba

[![Build Status](https://travis-ci.org/krzysztof-magosa/ansible-role-samba.svg?branch=master)](https://travis-ci.org/krzysztof-magosa/ansible-role-samba)

## Description
Ansible role for Samba

## Requirements
* Ansible 2.5 or better

## Supported systems
* CentOS (tested on 7)
* Debian (tested on 6, 7, 8, 9, 10, 11)
* Ubuntu (tested on 14.04, 16.04, 18.04, 19.04)

# Data types
Role automatically converts specified values to format expected by Samba.
Boolean true (e.g. yes/true) is converted to `yes`, false (e.g. no/false) is converted to `no`.
Lists are handled depending on option because Samba expects various delimiters (spaces, commas).
Other values (strings, numbers) are passed as-is.

To achieve following Samba configuration...
```
workgroup = MSHOME
hosts allow = 192.168. 10.
veto files = /autorun.ini/autorun.inf/
```

...specify following Ansible configuration:
```
samba_workgroup: MSHOME
samba_hosts_allow:
  - 192.168.
  - 10.
samba_veto_files:
  - autorun.ini
  - autorun.inf
```

# Configuring shares/services
Shares/services are configured by `samba_shares` list.
`name` designates name of share/service and is obligatory, rest of parameters ([see list here](#serviceshare-options)) are optional.

Example:
```
samba_shares:
  - name: personal
    path: /data/secret
    valid_users:
      - boss
      - manager
  - name: public:
    path: /data/public
    create: true
    owner: root
    group: root
    mode: "0777"
```

If you want role to create share directory for you, set parameter `create` to `true` or set `samba_default_share_create` so role does it by default for all shares (unless explicitly stated `create: false`). You can optionally change owner/group or mode (aka chmod) by using `owner`, `group` and `mode` parameters. Note that in case it's unspecified it will probably default to root:root, 0755.

# Users and groups
Samba uses system wide-groups. They can be created using `samba_groups` like here:
```
samba_groups:
  - name: staff
    gid: 1234
  - name: friends
    # gid is optional
```

Creating users:
```
samba_users:
  - name: km
    uid: 1000 # uid is optional
    password: TopSecret1 # Use Ansible Vault to hide this
    create_unix: true # this is also optional
    groups: # groups are optional
      - staff
      - friends
```

Please note that Samba requires users to exist in system *prior* to creating them.
Parameter `create_unix` allows you to have it created by role.
If your use case is more complex (e.g. you use the same account for shell access)
I recommend to create user/groups externally, e.g. using my another role [identity](https://github.com/krzysztof-magosa/ansible-role-identity).
You can enable creating unix accounts by default by setting `samba_default_user_create_unix` to `true`, `create_unix` parameter will be still be respected
on single items.

# idmap config
`idmap config` is supported by `samba_idmap_configs` (note `s`) list. Each item has `domain`, `option` and `value` properties.

To achieve following Samba configuration...
```
idmap config CORP : backend = ad
idmap config CORP : range = 1000-999999
```

...specify following Ansible configuration:
```
samba_idmap_configs:
  - domain: CORP
    option: backend
    value: ad
  - domain: CORP
    option: range
    value: 1000-999999
```

## Global options
|Samba option|Ansible variable|
|------------|----------------|
|NIS homedir|samba_nis_homedir|
|abort shutdown script|samba_abort_shutdown_script|
|access based share enum|samba_access_based_share_enum|
|acl allow execute always|samba_acl_allow_execute_always|
|acl check permissions|samba_acl_check_permissions|
|acl group control|samba_acl_group_control|
|acl map full control|samba_acl_map_full_control|
|acl_xattr:default acl style|samba_acl_xattr_default_acl_style|
|acl_xattr:ignore system acls|samba_acl_xattr_ignore_system_acls|
|add group script|samba_add_group_script|
|add machine script|samba_add_machine_script|
|add share command|samba_add_share_command|
|add user script|samba_add_user_script|
|add user to group script|samba_add_user_to_group_script|
|addport command|samba_addport_command|
|addprinter command|samba_addprinter_command|
|admin users|samba_admin_users|
|administrative share|samba_administrative_share|
|afs share|samba_afs_share|
|afs token lifetime|samba_afs_token_lifetime|
|afs username map|samba_afs_username_map|
|aio max threads|samba_aio_max_threads|
|aio read size|samba_aio_read_size|
|aio write behind|samba_aio_write_behind|
|aio write size|samba_aio_write_size|
|aio_pthread:aio open|samba_aio_pthread_aio_open|
|algorithmic rid base|samba_algorithmic_rid_base|
|allocation roundup size|samba_allocation_roundup_size|
|allow dcerpc auth level connect|samba_allow_dcerpc_auth_level_connect|
|allow dns updates|samba_allow_dns_updates|
|allow hosts|samba_allow_hosts|
|allow insecure wide links|samba_allow_insecure_wide_links|
|allow nt4 crypto|samba_allow_nt4_crypto|
|allow trusted domains|samba_allow_trusted_domains|
|allow unsafe cluster upgrade|samba_allow_unsafe_cluster_upgrade|
|apply group policies|samba_apply_group_policies|
|async smb echo handler|samba_async_smb_echo_handler|
|audit:facility|samba_audit_facility|
|audit:priority|samba_audit_priority|
|auth event notification|samba_auth_event_notification|
|auto services|samba_auto_services|
|available|samba_available|
|bind dns directory|samba_bind_dns_directory|
|bind interfaces only|samba_bind_interfaces_only|
|binddns dir|samba_binddns_dir|
|block size|samba_block_size|
|blocking locks|samba_blocking_locks|
|browsable|samba_browsable|
|browse list|samba_browse_list|
|browseable|samba_browseable|
|btrfs: manipulate snapshots|samba_btrfs_manipulate_snapshots|
|cache directory|samba_cache_directory|
|cacheprime:rsize|samba_cacheprime_rsize|
|case sensitive|samba_case_sensitive|
|casesignames|samba_casesignames|
|catia:mappings|samba_catia_mappings|
|ceph:config_file|samba_ceph_config_file|
|ceph:user_id|samba_ceph_user_id|
|change notify|samba_change_notify|
|change share command|samba_change_share_command|
|check parent directory delete on close|samba_check_parent_directory_delete_on_close|
|check password script|samba_check_password_script|
|cldap port|samba_cldap_port|
|client NTLMv2 auth|samba_client_ntlmv2_auth|
|client ipc max protocol|samba_client_ipc_max_protocol|
|client ipc min protocol|samba_client_ipc_min_protocol|
|client ipc signing|samba_client_ipc_signing|
|client lanman auth|samba_client_lanman_auth|
|client ldap sasl wrapping|samba_client_ldap_sasl_wrapping|
|client max protocol|samba_client_max_protocol|
|client min protocol|samba_client_min_protocol|
|client plaintext auth|samba_client_plaintext_auth|
|client schannel|samba_client_schannel|
|client signing|samba_client_signing|
|client use spnego|samba_client_use_spnego|
|client use spnego principal|samba_client_use_spnego_principal|
|cluster addresses|samba_cluster_addresses|
|clustering|samba_clustering|
|comment|samba_comment|
|commit:dthresh|samba_commit_dthresh|
|config backend|samba_config_backend|
|config file|samba_config_file|
|copy|samba_copy|
|create krb5 conf|samba_create_krb5_conf|
|create mask|samba_create_mask|
|create mode|samba_create_mode|
|crossrename:sizelimit|samba_crossrename_sizelimit|
|csc policy|samba_csc_policy|
|ctdb locktime warn threshold|samba_ctdb_locktime_warn_threshold|
|ctdb timeout|samba_ctdb_timeout|
|ctdbd socket|samba_ctdbd_socket|
|cups connection timeout|samba_cups_connection_timeout|
|cups encrypt|samba_cups_encrypt|
|cups options|samba_cups_options|
|cups server|samba_cups_server|
|dcerpc endpoint servers|samba_dcerpc_endpoint_servers|
|deadtime|samba_deadtime|
|debug class|samba_debug_class|
|debug hires timestamp|samba_debug_hires_timestamp|
|debug pid|samba_debug_pid|
|debug prefix timestamp|samba_debug_prefix_timestamp|
|debug timestamp|samba_debug_timestamp|
|debug uid|samba_debug_uid|
|debuglevel|samba_debuglevel|
|dedicated keytab file|samba_dedicated_keytab_file|
|default|samba_default|
|default case|samba_default_case|
|default devmode|samba_default_devmode|
|default service|samba_default_service|
|default_quota:gid|samba_default_quota_gid|
|default_quota:gid nolimit|samba_default_quota_gid_nolimit|
|default_quota:uid|samba_default_quota_uid|
|default_quota:uid nolimit|samba_default_quota_uid_nolimit|
|defer sharing violations|samba_defer_sharing_violations|
|delete group script|samba_delete_group_script|
|delete readonly|samba_delete_readonly|
|delete share command|samba_delete_share_command|
|delete user from group script|samba_delete_user_from_group_script|
|delete user script|samba_delete_user_script|
|delete veto files|samba_delete_veto_files|
|deleteprinter command|samba_deleteprinter_command|
|deny hosts|samba_deny_hosts|
|dfree cache time|samba_dfree_cache_time|
|dfree command|samba_dfree_command|
|dgram port|samba_dgram_port|
|directory|samba_directory|
|directory mask|samba_directory_mask|
|directory mode|samba_directory_mode|
|directory name cache size|samba_directory_name_cache_size|
|directory security mask|samba_directory_security_mask|
|disable netbios|samba_disable_netbios|
|disable spoolss|samba_disable_spoolss|
|dmapi support|samba_dmapi_support|
|dns forwarder|samba_dns_forwarder|
|dns proxy|samba_dns_proxy|
|dns update command|samba_dns_update_command|
|dns zone scavenging|samba_dns_zone_scavenging|
|domain logons|samba_domain_logons|
|domain master|samba_domain_master|
|dont descend|samba_dont_descend|
|dos charset|samba_dos_charset|
|dos filemode|samba_dos_filemode|
|dos filetime resolution|samba_dos_filetime_resolution|
|dos filetimes|samba_dos_filetimes|
|dsdb event notification|samba_dsdb_event_notification|
|dsdb group change notification|samba_dsdb_group_change_notification|
|dsdb password event notification|samba_dsdb_password_event_notification|
|durable handles|samba_durable_handles|
|ea support|samba_ea_support|
|enable asu support|samba_enable_asu_support|
|enable core files|samba_enable_core_files|
|enable privileges|samba_enable_privileges|
|enable spoolss|samba_enable_spoolss|
|encrypt passwords|samba_encrypt_passwords|
|enhanced browsing|samba_enhanced_browsing|
|enumports command|samba_enumports_command|
|eventlog list|samba_eventlog_list|
|exec|samba_exec|
|fake directory create times|samba_fake_directory_create_times|
|fake oplocks|samba_fake_oplocks|
|fileid:algorithm|samba_fileid_algorithm|
|fileid:fstype allow|samba_fileid_fstype_allow|
|fileid:fstype deny|samba_fileid_fstype_deny|
|fileid:mapping|samba_fileid_mapping|
|fileid:mntdir allow|samba_fileid_mntdir_allow|
|fileid:mntdir deny|samba_fileid_mntdir_deny|
|fileid:nolockinode|samba_fileid_nolockinode|
|follow symlinks|samba_follow_symlinks|
|force create mode|samba_force_create_mode|
|force directory mode|samba_force_directory_mode|
|force directory security mode|samba_force_directory_security_mode|
|force group|samba_force_group|
|force printername|samba_force_printername|
|force security mode|samba_force_security_mode|
|force unknown acl user|samba_force_unknown_acl_user|
|force user|samba_force_user|
|fruit:aapl|samba_fruit_aapl|
|fruit:copyfile|samba_fruit_copyfile|
|fruit:delete_empty_adfiles|samba_fruit_delete_empty_adfiles|
|fruit:encoding|samba_fruit_encoding|
|fruit:locking|samba_fruit_locking|
|fruit:metadata|samba_fruit_metadata|
|fruit:model|samba_fruit_model|
|fruit:nfs_aces|samba_fruit_nfs_aces|
|fruit:posix_rename|samba_fruit_posix_rename|
|fruit:resource|samba_fruit_resource|
|fruit:time machine|samba_fruit_time_machine|
|fruit:time machine max size|samba_fruit_time_machine_max_size|
|fruit:veto_appledouble|samba_fruit_veto_appledouble|
|fruit:wipe_intentionally_left_blank_rfork|samba_fruit_wipe_intentionally_left_blank_rfork|
|fruit:zero_file_id|samba_fruit_zero_file_id|
|fss: prune stale|samba_fss_prune_stale|
|fss: sequence timeout|samba_fss_sequence_timeout|
|fstype|samba_fstype|
|full_audit:facility|samba_full_audit_facility|
|full_audit:failure|samba_full_audit_failure|
|full_audit:log_secdesc|samba_full_audit_log_secdesc|
|full_audit:prefix|samba_full_audit_prefix|
|full_audit:priority|samba_full_audit_priority|
|full_audit:success|samba_full_audit_success|
|full_audit:syslog|samba_full_audit_syslog|
|get quota command|samba_get_quota_command|
|getwd cache|samba_getwd_cache|
|glusterfs:logfile|samba_glusterfs_logfile|
|glusterfs:loglevel|samba_glusterfs_loglevel|
|glusterfs:volfile_server|samba_glusterfs_volfile_server|
|glusterfs:volume|samba_glusterfs_volume|
|gpfs:acl|samba_gpfs_acl|
|gpfs:check_fstype|samba_gpfs_check_fstype|
|gpfs:dfreequota|samba_gpfs_dfreequota|
|gpfs:getrealfilename|samba_gpfs_getrealfilename|
|gpfs:hsm|samba_gpfs_hsm|
|gpfs:leases|samba_gpfs_leases|
|gpfs:merge_writeappend|samba_gpfs_merge_writeappend|
|gpfs:prealloc|samba_gpfs_prealloc|
|gpfs:recalls|samba_gpfs_recalls|
|gpfs:refuse_dacl_protected|samba_gpfs_refuse_dacl_protected|
|gpfs:settimes|samba_gpfs_settimes|
|gpfs:sharemodes|samba_gpfs_sharemodes|
|gpfs:syncio|samba_gpfs_syncio|
|gpfs:winattr|samba_gpfs_winattr|
|gpo update command|samba_gpo_update_command|
|group|samba_group|
|guest account|samba_guest_account|
|guest ok|samba_guest_ok|
|guest only|samba_guest_only|
|hide dot files|samba_hide_dot_files|
|hide files|samba_hide_files|
|hide new files timeout|samba_hide_new_files_timeout|
|hide special files|samba_hide_special_files|
|hide unreadable|samba_hide_unreadable|
|hide unwriteable files|samba_hide_unwriteable_files|
|homedir map|samba_homedir_map|
|host msdfs|samba_host_msdfs|
|hostname lookups|samba_hostname_lookups|
|hosts allow|samba_hosts_allow|
|hosts deny|samba_hosts_deny|
|idmap backend|samba_idmap_backend|
|idmap cache time|samba_idmap_cache_time|
|idmap gid|samba_idmap_gid|
|idmap negative cache time|samba_idmap_negative_cache_time|
|idmap uid|samba_idmap_uid|
|include|samba_include|
|include system krb5 conf|samba_include_system_krb5_conf|
|inherit acls|samba_inherit_acls|
|inherit owner|samba_inherit_owner|
|inherit permissions|samba_inherit_permissions|
|init logon delay|samba_init_logon_delay|
|init logon delayed hosts|samba_init_logon_delayed_hosts|
|interfaces|samba_interfaces|
|invalid users|samba_invalid_users|
|iprint server|samba_iprint_server|
|keepalive|samba_keepalive|
|kerberos encryption types|samba_kerberos_encryption_types|
|kerberos method|samba_kerberos_method|
|kernel change notify|samba_kernel_change_notify|
|kernel oplocks|samba_kernel_oplocks|
|kernel share modes|samba_kernel_share_modes|
|kpasswd port|samba_kpasswd_port|
|krb5 port|samba_krb5_port|
|lanman auth|samba_lanman_auth|
|large readwrite|samba_large_readwrite|
|ldap admin dn|samba_ldap_admin_dn|
|ldap connection timeout|samba_ldap_connection_timeout|
|ldap debug level|samba_ldap_debug_level|
|ldap debug threshold|samba_ldap_debug_threshold|
|ldap delete dn|samba_ldap_delete_dn|
|ldap deref|samba_ldap_deref|
|ldap follow referral|samba_ldap_follow_referral|
|ldap group suffix|samba_ldap_group_suffix|
|ldap idmap suffix|samba_ldap_idmap_suffix|
|ldap machine suffix|samba_ldap_machine_suffix|
|ldap page size|samba_ldap_page_size|
|ldap passwd sync|samba_ldap_passwd_sync|
|ldap password sync|samba_ldap_password_sync|
|ldap replication sleep|samba_ldap_replication_sleep|
|ldap server require strong auth|samba_ldap_server_require_strong_auth|
|ldap ssl|samba_ldap_ssl|
|ldap ssl ads|samba_ldap_ssl_ads|
|ldap suffix|samba_ldap_suffix|
|ldap timeout|samba_ldap_timeout|
|ldap user suffix|samba_ldap_user_suffix|
|ldapsam:editposix|samba_ldapsam_editposix|
|ldapsam:trusted|samba_ldapsam_trusted|
|level2 oplocks|samba_level2_oplocks|
|lm announce|samba_lm_announce|
|lm interval|samba_lm_interval|
|load printers|samba_load_printers|
|local master|samba_local_master|
|lock dir|samba_lock_dir|
|lock directory|samba_lock_directory|
|lock spin time|samba_lock_spin_time|
|locking|samba_locking|
|log file|samba_log_file|
|log level|samba_log_level|
|log nt token command|samba_log_nt_token_command|
|log writeable files on exit|samba_log_writeable_files_on_exit|
|logging|samba_logging|
|logon drive|samba_logon_drive|
|logon home|samba_logon_home|
|logon path|samba_logon_path|
|logon script|samba_logon_script|
|lppause command|samba_lppause_command|
|lpq cache time|samba_lpq_cache_time|
|lpq command|samba_lpq_command|
|lpresume command|samba_lpresume_command|
|lprm command|samba_lprm_command|
|lsa over netlogon|samba_lsa_over_netlogon|
|machine password timeout|samba_machine_password_timeout|
|magic output|samba_magic_output|
|magic script|samba_magic_script|
|mangle prefix|samba_mangle_prefix|
|mangled names|samba_mangled_names|
|mangling char|samba_mangling_char|
|mangling method|samba_mangling_method|
|map acl inherit|samba_map_acl_inherit|
|map archive|samba_map_archive|
|map hidden|samba_map_hidden|
|map readonly|samba_map_readonly|
|map system|samba_map_system|
|map to guest|samba_map_to_guest|
|max connections|samba_max_connections|
|max disk size|samba_max_disk_size|
|max log size|samba_max_log_size|
|max mux|samba_max_mux|
|max open files|samba_max_open_files|
|max print jobs|samba_max_print_jobs|
|max protocol|samba_max_protocol|
|max reported print jobs|samba_max_reported_print_jobs|
|max smbd processes|samba_max_smbd_processes|
|max stat cache size|samba_max_stat_cache_size|
|max ttl|samba_max_ttl|
|max wins ttl|samba_max_wins_ttl|
|max xmit|samba_max_xmit|
|mdns name|samba_mdns_name|
|message command|samba_message_command|
|min print space|samba_min_print_space|
|min protocol|samba_min_protocol|
|min receivefile size|samba_min_receivefile_size|
|min wins ttl|samba_min_wins_ttl|
|mit kdc command|samba_mit_kdc_command|
|msdfs proxy|samba_msdfs_proxy|
|msdfs root|samba_msdfs_root|
|msdfs shuffle referrals|samba_msdfs_shuffle_referrals|
|multicast dns register|samba_multicast_dns_register|
|name cache timeout|samba_name_cache_timeout|
|name resolve order|samba_name_resolve_order|
|nbt client socket address|samba_nbt_client_socket_address|
|nbt port|samba_nbt_port|
|nbtd:wins_prepend1Bto1Cqueries|samba_nbtd_wins_prepend1bto1cqueries|
|nbtd:wins_randomize1Clist_mask|samba_nbtd_wins_randomize1clist_mask|
|nbtd:wins_wins_randomize1Clist|samba_nbtd_wins_wins_randomize1clist|
|ncalrpc dir|samba_ncalrpc_dir|
|netbios aliases|samba_netbios_aliases|
|netbios name|samba_netbios_name|
|netbios scope|samba_netbios_scope|
|neutralize nt4 emulation|samba_neutralize_nt4_emulation|
|nfs4:acedup|samba_nfs4_acedup|
|nfs4:chown|samba_nfs4_chown|
|nfs4:mode|samba_nfs4_mode|
|nfs4acl_xattr:default acl style|samba_nfs4acl_xattr_default_acl_style|
|nfs4acl_xattr:encoding|samba_nfs4acl_xattr_encoding|
|nfs4acl_xattr:version|samba_nfs4acl_xattr_version|
|nfs4acl_xattr:xattr_name|samba_nfs4acl_xattr_xattr_name|
|nmbd bind explicit broadcast|samba_nmbd_bind_explicit_broadcast|
|nsupdate command|samba_nsupdate_command|
|nt acl support|samba_nt_acl_support|
|nt pipe support|samba_nt_pipe_support|
|nt status support|samba_nt_status_support|
|ntlm auth|samba_ntlm_auth|
|ntp signd socket directory|samba_ntp_signd_socket_directory|
|ntvfs handler|samba_ntvfs_handler|
|null passwords|samba_null_passwords|
|obey pam restrictions|samba_obey_pam_restrictions|
|old password allowed period|samba_old_password_allowed_period|
|only guest|samba_only_guest|
|oplock break wait time|samba_oplock_break_wait_time|
|oplocks|samba_oplocks|
|os level|samba_os_level|
|os2 driver map|samba_os2_driver_map|
|pam password change|samba_pam_password_change|
|panic action|samba_panic_action|
|passdb backend|samba_passdb_backend|
|passdb expand explicit|samba_passdb_expand_explicit|
|passwd chat|samba_passwd_chat|
|passwd chat debug|samba_passwd_chat_debug|
|passwd chat timeout|samba_passwd_chat_timeout|
|passwd program|samba_passwd_program|
|password hash gpg key ids|samba_password_hash_gpg_key_ids|
|password hash userPassword schemes|samba_password_hash_userpassword_schemes|
|password server|samba_password_server|
|path|samba_path|
|perfcount module|samba_perfcount_module|
|pid directory|samba_pid_directory|
|posix locking|samba_posix_locking|
|postexec|samba_postexec|
|prealloc:EXT|samba_prealloc_ext|
|preexec|samba_preexec|
|preexec close|samba_preexec_close|
|prefered master|samba_prefered_master|
|preferred master|samba_preferred_master|
|prefork backoff increment|samba_prefork_backoff_increment|
|prefork children|samba_prefork_children|
|prefork maximum backoff|samba_prefork_maximum_backoff|
|preload|samba_preload|
|preload modules|samba_preload_modules|
|preopen:helpers|samba_preopen_helpers|
|preopen:names|samba_preopen_names|
|preopen:num_bytes|samba_preopen_num_bytes|
|preopen:queuelen|samba_preopen_queuelen|
|preserve case|samba_preserve_case|
|print command|samba_print_command|
|print notify backchannel|samba_print_notify_backchannel|
|print ok|samba_print_ok|
|printable|samba_printable|
|printcap|samba_printcap|
|printcap cache time|samba_printcap_cache_time|
|printcap name|samba_printcap_name|
|printer|samba_printer|
|printer name|samba_printer_name|
|printing|samba_printing|
|printjob username|samba_printjob_username|
|private dir|samba_private_dir|
|private directory|samba_private_directory|
|protocol|samba_protocol|
|public|samba_public|
|queuepause command|samba_queuepause_command|
|queueresume command|samba_queueresume_command|
|raw NTLMv2 auth|samba_raw_ntlmv2_auth|
|read list|samba_read_list|
|read only|samba_read_only|
|read raw|samba_read_raw|
|readahead:length|samba_readahead_length|
|readahead:offset|samba_readahead_offset|
|readdir_attr:aapl_finder_info|samba_readdir_attr_aapl_finder_info|
|readdir_attr:aapl_max_access|samba_readdir_attr_aapl_max_access|
|readdir_attr:aapl_rsize|samba_readdir_attr_aapl_rsize|
|readonly:period|samba_readonly_period|
|realm|samba_realm|
|recycle:directory_mode|samba_recycle_directory_mode|
|recycle:exclude|samba_recycle_exclude|
|recycle:exclude_dir|samba_recycle_exclude_dir|
|recycle:keeptree|samba_recycle_keeptree|
|recycle:maxsize|samba_recycle_maxsize|
|recycle:minsize|samba_recycle_minsize|
|recycle:noversions|samba_recycle_noversions|
|recycle:repository|samba_recycle_repository|
|recycle:subdir_mode|samba_recycle_subdir_mode|
|recycle:touch|samba_recycle_touch|
|recycle:touch_mtime|samba_recycle_touch_mtime|
|recycle:versions|samba_recycle_versions|
|registry shares|samba_registry_shares|
|reject md5 clients|samba_reject_md5_clients|
|reject md5 servers|samba_reject_md5_servers|
|remote announce|samba_remote_announce|
|remote browse sync|samba_remote_browse_sync|
|rename user script|samba_rename_user_script|
|require strong key|samba_require_strong_key|
|reset on zero vc|samba_reset_on_zero_vc|
|restrict anonymous|samba_restrict_anonymous|
|rndc command|samba_rndc_command|
|root|samba_root|
|root dir|samba_root_dir|
|root directory|samba_root_directory|
|root postexec|samba_root_postexec|
|root preexec|samba_root_preexec|
|root preexec close|samba_root_preexec_close|
|rpc big endian|samba_rpc_big_endian|
|rpc server dynamic port range|samba_rpc_server_dynamic_port_range|
|rpc server port|samba_rpc_server_port|
|rpc_daemon:DAEMON|samba_rpc_daemon_daemon|
|rpc_server:SERVER|samba_rpc_server_server|
|samba kcc command|samba_samba_kcc_command|
|security|samba_security|
|security mask|samba_security_mask|
|server max protocol|samba_server_max_protocol|
|server min protocol|samba_server_min_protocol|
|server multi channel support|samba_server_multi_channel_support|
|server role|samba_server_role|
|server schannel|samba_server_schannel|
|server services|samba_server_services|
|server signing|samba_server_signing|
|server string|samba_server_string|
|set primary group script|samba_set_primary_group_script|
|set quota command|samba_set_quota_command|
|shadow:basedir|samba_shadow_basedir|
|shadow:crossmountpoints|samba_shadow_crossmountpoints|
|shadow:delimiter|samba_shadow_delimiter|
|shadow:fixinodes|samba_shadow_fixinodes|
|shadow:format|samba_shadow_format|
|shadow:localtime|samba_shadow_localtime|
|shadow:mountpoint|samba_shadow_mountpoint|
|shadow:snapdir|samba_shadow_snapdir|
|shadow:snapdirseverywhere|samba_shadow_snapdirseverywhere|
|shadow:snapprefix|samba_shadow_snapprefix|
|shadow:snapsharepath|samba_shadow_snapsharepath|
|shadow:sort|samba_shadow_sort|
|shadow:sscanf|samba_shadow_sscanf|
|share backend|samba_share_backend|
|share:fake_fscaps|samba_share_fake_fscaps|
|shell_snap:check path command|samba_shell_snap_check_path_command|
|shell_snap:create command|samba_shell_snap_create_command|
|shell_snap:delete command|samba_shell_snap_delete_command|
|short preserve case|samba_short_preserve_case|
|show add printer wizard|samba_show_add_printer_wizard|
|shutdown script|samba_shutdown_script|
|smb encrypt|samba_smb_encrypt|
|smb passwd file|samba_smb_passwd_file|
|smb ports|samba_smb_ports|
|smb2 leases|samba_smb2_leases|
|smb2 max credits|samba_smb2_max_credits|
|smb2 max read|samba_smb2_max_read|
|smb2 max trans|samba_smb2_max_trans|
|smb2 max write|samba_smb2_max_write|
|smbd async dosmode|samba_smbd_async_dosmode|
|smbd getinfo ask sharemode|samba_smbd_getinfo_ask_sharemode|
|smbd max async dosmode|samba_smbd_max_async_dosmode|
|smbd profiling level|samba_smbd_profiling_level|
|smbd search ask sharemode|samba_smbd_search_ask_sharemode|
|socket address|samba_socket_address|
|socket options|samba_socket_options|
|spn update command|samba_spn_update_command|
|spoolss: architecture|samba_spoolss_architecture|
|spoolss: os_build|samba_spoolss_os_build|
|spoolss: os_major|samba_spoolss_os_major|
|spoolss: os_minor|samba_spoolss_os_minor|
|spoolss_client: os_build|samba_spoolss_client_os_build|
|spoolss_client: os_major|samba_spoolss_client_os_major|
|spoolss_client: os_minor|samba_spoolss_client_os_minor|
|spotlight|samba_spotlight|
|stat cache|samba_stat_cache|
|state directory|samba_state_directory|
|store dos attributes|samba_store_dos_attributes|
|streams_depot:delete_lost|samba_streams_depot_delete_lost|
|streams_depot:directory|samba_streams_depot_directory|
|streams_xattr:prefix|samba_streams_xattr_prefix|
|streams_xattr:store_stream_type|samba_streams_xattr_store_stream_type|
|strict allocate|samba_strict_allocate|
|strict locking|samba_strict_locking|
|strict rename|samba_strict_rename|
|strict sync|samba_strict_sync|
|svcctl list|samba_svcctl_list|
|sync always|samba_sync_always|
|syncops:disable|samba_syncops_disable|
|syncops:onclose|samba_syncops_onclose|
|syncops:onmeta|samba_syncops_onmeta|
|syslog|samba_syslog|
|syslog only|samba_syslog_only|
|template homedir|samba_template_homedir|
|template shell|samba_template_shell|
|time server|samba_time_server|
|time_audit:timeout|samba_time_audit_timeout|
|timestamp logs|samba_timestamp_logs|
|tls cafile|samba_tls_cafile|
|tls certfile|samba_tls_certfile|
|tls crlfile|samba_tls_crlfile|
|tls dh params file|samba_tls_dh_params_file|
|tls enabled|samba_tls_enabled|
|tls keyfile|samba_tls_keyfile|
|tls priority|samba_tls_priority|
|tls verify peer|samba_tls_verify_peer|
|tsmsm:dmapi attribute|samba_tsmsm_dmapi_attribute|
|tsmsm:dmapi value|samba_tsmsm_dmapi_value|
|tsmsm:hsm script|samba_tsmsm_hsm_script|
|tsmsm:online ratio|samba_tsmsm_online_ratio|
|unicode|samba_unicode|
|unityed_media:clientid|samba_unityed_media_clientid|
|unix charset|samba_unix_charset|
|unix extensions|samba_unix_extensions|
|unix password sync|samba_unix_password_sync|
|use client driver|samba_use_client_driver|
|use mmap|samba_use_mmap|
|use sendfile|samba_use_sendfile|
|username level|samba_username_level|
|username map|samba_username_map|
|username map cache time|samba_username_map_cache_time|
|username map script|samba_username_map_script|
|usershare allow guests|samba_usershare_allow_guests|
|usershare max shares|samba_usershare_max_shares|
|usershare owner only|samba_usershare_owner_only|
|usershare path|samba_usershare_path|
|usershare prefix allow list|samba_usershare_prefix_allow_list|
|usershare prefix deny list|samba_usershare_prefix_deny_list|
|usershare template share|samba_usershare_template_share|
|utmp|samba_utmp|
|utmp directory|samba_utmp_directory|
|valid users|samba_valid_users|
|veto files|samba_veto_files|
|veto oplock files|samba_veto_oplock_files|
|vfs object|samba_vfs_object|
|vfs objects|samba_vfs_objects|
|virusfilter:block access on error|samba_virusfilter_block_access_on_error|
|virusfilter:block suspected file|samba_virusfilter_block_suspected_file|
|virusfilter:cache entry limit|samba_virusfilter_cache_entry_limit|
|virusfilter:cache time limit|samba_virusfilter_cache_time_limit|
|virusfilter:connect timeout|samba_virusfilter_connect_timeout|
|virusfilter:exclude files|samba_virusfilter_exclude_files|
|virusfilter:infected file action|samba_virusfilter_infected_file_action|
|virusfilter:infected file command|samba_virusfilter_infected_file_command|
|virusfilter:infected file errno on close|samba_virusfilter_infected_file_errno_on_close|
|virusfilter:infected file errno on open|samba_virusfilter_infected_file_errno_on_open|
|virusfilter:io timeout|samba_virusfilter_io_timeout|
|virusfilter:max file size|samba_virusfilter_max_file_size|
|virusfilter:max nested scan archive|samba_virusfilter_max_nested_scan_archive|
|virusfilter:min file size|samba_virusfilter_min_file_size|
|virusfilter:quarantine directory|samba_virusfilter_quarantine_directory|
|virusfilter:quarantine directory mode|samba_virusfilter_quarantine_directory_mode|
|virusfilter:quarantine keep name|samba_virusfilter_quarantine_keep_name|
|virusfilter:quarantine keep tree|samba_virusfilter_quarantine_keep_tree|
|virusfilter:quarantine prefix|samba_virusfilter_quarantine_prefix|
|virusfilter:quarantine suffix|samba_virusfilter_quarantine_suffix|
|virusfilter:rename prefix|samba_virusfilter_rename_prefix|
|virusfilter:rename suffix|samba_virusfilter_rename_suffix|
|virusfilter:scan archive|samba_virusfilter_scan_archive|
|virusfilter:scan error command|samba_virusfilter_scan_error_command|
|virusfilter:scan error errno on close|samba_virusfilter_scan_error_errno_on_close|
|virusfilter:scan error errno on open|samba_virusfilter_scan_error_errno_on_open|
|virusfilter:scan mime|samba_virusfilter_scan_mime|
|virusfilter:scan on close|samba_virusfilter_scan_on_close|
|virusfilter:scan on open|samba_virusfilter_scan_on_open|
|virusfilter:scanner|samba_virusfilter_scanner|
|virusfilter:socket path|samba_virusfilter_socket_path|
|volume|samba_volume|
|web port|samba_web_port|
|wide links|samba_wide_links|
|winbind cache time|samba_winbind_cache_time|
|winbind enum groups|samba_winbind_enum_groups|
|winbind enum users|samba_winbind_enum_users|
|winbind expand groups|samba_winbind_expand_groups|
|winbind gid|samba_winbind_gid|
|winbind max clients|samba_winbind_max_clients|
|winbind max domain connections|samba_winbind_max_domain_connections|
|winbind nested groups|samba_winbind_nested_groups|
|winbind normalize names|samba_winbind_normalize_names|
|winbind nss info|samba_winbind_nss_info|
|winbind offline logon|samba_winbind_offline_logon|
|winbind reconnect delay|samba_winbind_reconnect_delay|
|winbind refresh tickets|samba_winbind_refresh_tickets|
|winbind request timeout|samba_winbind_request_timeout|
|winbind rpc only|samba_winbind_rpc_only|
|winbind scan trusted domains|samba_winbind_scan_trusted_domains|
|winbind sealed pipes|samba_winbind_sealed_pipes|
|winbind separator|samba_winbind_separator|
|winbind uid|samba_winbind_uid|
|winbind use default domain|samba_winbind_use_default_domain|
|winbind:ignore domains|samba_winbind_ignore_domains|
|winbindd socket directory|samba_winbindd_socket_directory|
|wins hook|samba_wins_hook|
|wins proxy|samba_wins_proxy|
|wins server|samba_wins_server|
|wins support|samba_wins_support|
|winsdb:dbnosync|samba_winsdb_dbnosync|
|winsdb:local_owner|samba_winsdb_local_owner|
|workgroup|samba_workgroup|
|worm:grace_period|samba_worm_grace_period|
|wreplsrv:periodic_interval|samba_wreplsrv_periodic_interval|
|wreplsrv:propagate name releases|samba_wreplsrv_propagate_name_releases|
|wreplsrv:scavenging_interval|samba_wreplsrv_scavenging_interval|
|wreplsrv:tombstone_extra_timeout|samba_wreplsrv_tombstone_extra_timeout|
|wreplsrv:tombstone_interval|samba_wreplsrv_tombstone_interval|
|wreplsrv:tombstone_timeout|samba_wreplsrv_tombstone_timeout|
|wreplsrv:verify_interval|samba_wreplsrv_verify_interval|
|writable|samba_writable|
|write cache size|samba_write_cache_size|
|write list|samba_write_list|
|write ok|samba_write_ok|
|write raw|samba_write_raw|
|writeable|samba_writeable|
|wtmp directory|samba_wtmp_directory|
|xattr_tdb:file|samba_xattr_tdb_file|
|access based share enum|samba_access_based_share_enum|
|acl allow execute always|samba_acl_allow_execute_always|
|acl check permissions|samba_acl_check_permissions|
|acl group control|samba_acl_group_control|
|acl map full control|samba_acl_map_full_control|
|acl_xattr:default acl style|samba_acl_xattr_default_acl_style|
|acl_xattr:ignore system acls|samba_acl_xattr_ignore_system_acls|
|admin users|samba_admin_users|
|administrative share|samba_administrative_share|
|afs share|samba_afs_share|
|aio read size|samba_aio_read_size|
|aio write behind|samba_aio_write_behind|
|aio write size|samba_aio_write_size|
|aio_pthread:aio open|samba_aio_pthread_aio_open|
|allocation roundup size|samba_allocation_roundup_size|
|allow hosts|samba_allow_hosts|
|audit:facility|samba_audit_facility|
|audit:priority|samba_audit_priority|
|available|samba_available|
|block size|samba_block_size|
|blocking locks|samba_blocking_locks|
|browsable|samba_browsable|
|browseable|samba_browseable|
|btrfs: manipulate snapshots|samba_btrfs_manipulate_snapshots|
|cacheprime:rsize|samba_cacheprime_rsize|
|case sensitive|samba_case_sensitive|
|casesignames|samba_casesignames|
|catia:mappings|samba_catia_mappings|
|ceph:config_file|samba_ceph_config_file|
|ceph:user_id|samba_ceph_user_id|
|check parent directory delete on close|samba_check_parent_directory_delete_on_close|
|comment|samba_comment|
|commit:dthresh|samba_commit_dthresh|
|copy|samba_copy|
|create mask|samba_create_mask|
|create mode|samba_create_mode|
|crossrename:sizelimit|samba_crossrename_sizelimit|
|csc policy|samba_csc_policy|
|cups options|samba_cups_options|
|default case|samba_default_case|
|default devmode|samba_default_devmode|
|default_quota:gid|samba_default_quota_gid|
|default_quota:gid nolimit|samba_default_quota_gid_nolimit|
|default_quota:uid|samba_default_quota_uid|
|default_quota:uid nolimit|samba_default_quota_uid_nolimit|
|delete readonly|samba_delete_readonly|
|delete veto files|samba_delete_veto_files|
|deny hosts|samba_deny_hosts|
|dfree cache time|samba_dfree_cache_time|
|dfree command|samba_dfree_command|
|directory|samba_directory|
|directory mask|samba_directory_mask|
|directory mode|samba_directory_mode|
|directory name cache size|samba_directory_name_cache_size|
|directory security mask|samba_directory_security_mask|
|dmapi support|samba_dmapi_support|
|dont descend|samba_dont_descend|
|dos filemode|samba_dos_filemode|
|dos filetime resolution|samba_dos_filetime_resolution|
|dos filetimes|samba_dos_filetimes|
|durable handles|samba_durable_handles|
|ea support|samba_ea_support|
|exec|samba_exec|
|fake directory create times|samba_fake_directory_create_times|
|fake oplocks|samba_fake_oplocks|
|fileid:algorithm|samba_fileid_algorithm|
|fileid:fstype allow|samba_fileid_fstype_allow|
|fileid:fstype deny|samba_fileid_fstype_deny|
|fileid:mapping|samba_fileid_mapping|
|fileid:mntdir allow|samba_fileid_mntdir_allow|
|fileid:mntdir deny|samba_fileid_mntdir_deny|
|fileid:nolockinode|samba_fileid_nolockinode|
|follow symlinks|samba_follow_symlinks|
|force create mode|samba_force_create_mode|
|force directory mode|samba_force_directory_mode|
|force directory security mode|samba_force_directory_security_mode|
|force group|samba_force_group|
|force printername|samba_force_printername|
|force security mode|samba_force_security_mode|
|force unknown acl user|samba_force_unknown_acl_user|
|force user|samba_force_user|
|fruit:delete_empty_adfiles|samba_fruit_delete_empty_adfiles|
|fruit:encoding|samba_fruit_encoding|
|fruit:locking|samba_fruit_locking|
|fruit:metadata|samba_fruit_metadata|
|fruit:posix_rename|samba_fruit_posix_rename|
|fruit:resource|samba_fruit_resource|
|fruit:time machine|samba_fruit_time_machine|
|fruit:time machine max size|samba_fruit_time_machine_max_size|
|fruit:veto_appledouble|samba_fruit_veto_appledouble|
|fruit:wipe_intentionally_left_blank_rfork|samba_fruit_wipe_intentionally_left_blank_rfork|
|fstype|samba_fstype|
|full_audit:facility|samba_full_audit_facility|
|full_audit:failure|samba_full_audit_failure|
|full_audit:log_secdesc|samba_full_audit_log_secdesc|
|full_audit:prefix|samba_full_audit_prefix|
|full_audit:priority|samba_full_audit_priority|
|full_audit:success|samba_full_audit_success|
|full_audit:syslog|samba_full_audit_syslog|
|glusterfs:logfile|samba_glusterfs_logfile|
|glusterfs:loglevel|samba_glusterfs_loglevel|
|glusterfs:volfile_server|samba_glusterfs_volfile_server|
|glusterfs:volume|samba_glusterfs_volume|
|gpfs:acl|samba_gpfs_acl|
|gpfs:check_fstype|samba_gpfs_check_fstype|
|gpfs:dfreequota|samba_gpfs_dfreequota|
|gpfs:getrealfilename|samba_gpfs_getrealfilename|
|gpfs:hsm|samba_gpfs_hsm|
|gpfs:leases|samba_gpfs_leases|
|gpfs:merge_writeappend|samba_gpfs_merge_writeappend|
|gpfs:prealloc|samba_gpfs_prealloc|
|gpfs:recalls|samba_gpfs_recalls|
|gpfs:refuse_dacl_protected|samba_gpfs_refuse_dacl_protected|
|gpfs:settimes|samba_gpfs_settimes|
|gpfs:sharemodes|samba_gpfs_sharemodes|
|gpfs:syncio|samba_gpfs_syncio|
|gpfs:winattr|samba_gpfs_winattr|
|group|samba_group|
|guest ok|samba_guest_ok|
|guest only|samba_guest_only|
|hide dot files|samba_hide_dot_files|
|hide files|samba_hide_files|
|hide new files timeout|samba_hide_new_files_timeout|
|hide special files|samba_hide_special_files|
|hide unreadable|samba_hide_unreadable|
|hide unwriteable files|samba_hide_unwriteable_files|
|hosts allow|samba_hosts_allow|
|hosts deny|samba_hosts_deny|
|include|samba_include|
|inherit acls|samba_inherit_acls|
|inherit owner|samba_inherit_owner|
|inherit permissions|samba_inherit_permissions|
|invalid users|samba_invalid_users|
|kernel oplocks|samba_kernel_oplocks|
|kernel share modes|samba_kernel_share_modes|
|level2 oplocks|samba_level2_oplocks|
|locking|samba_locking|
|lppause command|samba_lppause_command|
|lpq command|samba_lpq_command|
|lpresume command|samba_lpresume_command|
|lprm command|samba_lprm_command|
|magic output|samba_magic_output|
|magic script|samba_magic_script|
|mangled names|samba_mangled_names|
|mangling char|samba_mangling_char|
|map acl inherit|samba_map_acl_inherit|
|map archive|samba_map_archive|
|map hidden|samba_map_hidden|
|map readonly|samba_map_readonly|
|map system|samba_map_system|
|max connections|samba_max_connections|
|max print jobs|samba_max_print_jobs|
|max reported print jobs|samba_max_reported_print_jobs|
|min print space|samba_min_print_space|
|msdfs proxy|samba_msdfs_proxy|
|msdfs root|samba_msdfs_root|
|msdfs shuffle referrals|samba_msdfs_shuffle_referrals|
|nfs4:acedup|samba_nfs4_acedup|
|nfs4:chown|samba_nfs4_chown|
|nfs4:mode|samba_nfs4_mode|
|nfs4acl_xattr:default acl style|samba_nfs4acl_xattr_default_acl_style|
|nfs4acl_xattr:encoding|samba_nfs4acl_xattr_encoding|
|nfs4acl_xattr:version|samba_nfs4acl_xattr_version|
|nfs4acl_xattr:xattr_name|samba_nfs4acl_xattr_xattr_name|
|nt acl support|samba_nt_acl_support|
|ntvfs handler|samba_ntvfs_handler|
|only guest|samba_only_guest|
|oplocks|samba_oplocks|
|path|samba_path|
|posix locking|samba_posix_locking|
|postexec|samba_postexec|
|prealloc:EXT|samba_prealloc_ext|
|preexec|samba_preexec|
|preexec close|samba_preexec_close|
|preopen:helpers|samba_preopen_helpers|
|preopen:names|samba_preopen_names|
|preopen:num_bytes|samba_preopen_num_bytes|
|preopen:queuelen|samba_preopen_queuelen|
|preserve case|samba_preserve_case|
|print command|samba_print_command|
|print notify backchannel|samba_print_notify_backchannel|
|print ok|samba_print_ok|
|printable|samba_printable|
|printer|samba_printer|
|printer name|samba_printer_name|
|printing|samba_printing|
|printjob username|samba_printjob_username|
|public|samba_public|
|queuepause command|samba_queuepause_command|
|queueresume command|samba_queueresume_command|
|read list|samba_read_list|
|read only|samba_read_only|
|readahead:length|samba_readahead_length|
|readahead:offset|samba_readahead_offset|
|readdir_attr:aapl_finder_info|samba_readdir_attr_aapl_finder_info|
|readdir_attr:aapl_max_access|samba_readdir_attr_aapl_max_access|
|readdir_attr:aapl_rsize|samba_readdir_attr_aapl_rsize|
|readonly:period|samba_readonly_period|
|recycle:directory_mode|samba_recycle_directory_mode|
|recycle:exclude|samba_recycle_exclude|
|recycle:exclude_dir|samba_recycle_exclude_dir|
|recycle:keeptree|samba_recycle_keeptree|
|recycle:maxsize|samba_recycle_maxsize|
|recycle:minsize|samba_recycle_minsize|
|recycle:noversions|samba_recycle_noversions|
|recycle:repository|samba_recycle_repository|
|recycle:subdir_mode|samba_recycle_subdir_mode|
|recycle:touch|samba_recycle_touch|
|recycle:touch_mtime|samba_recycle_touch_mtime|
|recycle:versions|samba_recycle_versions|
|root postexec|samba_root_postexec|
|root preexec|samba_root_preexec|
|root preexec close|samba_root_preexec_close|
|security mask|samba_security_mask|
|shadow:basedir|samba_shadow_basedir|
|shadow:crossmountpoints|samba_shadow_crossmountpoints|
|shadow:delimiter|samba_shadow_delimiter|
|shadow:fixinodes|samba_shadow_fixinodes|
|shadow:format|samba_shadow_format|
|shadow:localtime|samba_shadow_localtime|
|shadow:mountpoint|samba_shadow_mountpoint|
|shadow:snapdir|samba_shadow_snapdir|
|shadow:snapdirseverywhere|samba_shadow_snapdirseverywhere|
|shadow:snapprefix|samba_shadow_snapprefix|
|shadow:snapsharepath|samba_shadow_snapsharepath|
|shadow:sort|samba_shadow_sort|
|shadow:sscanf|samba_shadow_sscanf|
|shell_snap:check path command|samba_shell_snap_check_path_command|
|shell_snap:create command|samba_shell_snap_create_command|
|shell_snap:delete command|samba_shell_snap_delete_command|
|short preserve case|samba_short_preserve_case|
|smb encrypt|samba_smb_encrypt|
|smbd async dosmode|samba_smbd_async_dosmode|
|smbd getinfo ask sharemode|samba_smbd_getinfo_ask_sharemode|
|smbd max async dosmode|samba_smbd_max_async_dosmode|
|smbd search ask sharemode|samba_smbd_search_ask_sharemode|
|spotlight|samba_spotlight|
|store dos attributes|samba_store_dos_attributes|
|streams_depot:delete_lost|samba_streams_depot_delete_lost|
|streams_depot:directory|samba_streams_depot_directory|
|streams_xattr:prefix|samba_streams_xattr_prefix|
|streams_xattr:store_stream_type|samba_streams_xattr_store_stream_type|
|strict allocate|samba_strict_allocate|
|strict locking|samba_strict_locking|
|strict rename|samba_strict_rename|
|strict sync|samba_strict_sync|
|sync always|samba_sync_always|
|syncops:disable|samba_syncops_disable|
|syncops:onclose|samba_syncops_onclose|
|syncops:onmeta|samba_syncops_onmeta|
|time_audit:timeout|samba_time_audit_timeout|
|tsmsm:dmapi attribute|samba_tsmsm_dmapi_attribute|
|tsmsm:dmapi value|samba_tsmsm_dmapi_value|
|tsmsm:hsm script|samba_tsmsm_hsm_script|
|tsmsm:online ratio|samba_tsmsm_online_ratio|
|unityed_media:clientid|samba_unityed_media_clientid|
|use client driver|samba_use_client_driver|
|use sendfile|samba_use_sendfile|
|valid users|samba_valid_users|
|veto files|samba_veto_files|
|veto oplock files|samba_veto_oplock_files|
|vfs object|samba_vfs_object|
|vfs objects|samba_vfs_objects|
|virusfilter:block access on error|samba_virusfilter_block_access_on_error|
|virusfilter:block suspected file|samba_virusfilter_block_suspected_file|
|virusfilter:cache entry limit|samba_virusfilter_cache_entry_limit|
|virusfilter:cache time limit|samba_virusfilter_cache_time_limit|
|virusfilter:connect timeout|samba_virusfilter_connect_timeout|
|virusfilter:exclude files|samba_virusfilter_exclude_files|
|virusfilter:infected file action|samba_virusfilter_infected_file_action|
|virusfilter:infected file command|samba_virusfilter_infected_file_command|
|virusfilter:infected file errno on close|samba_virusfilter_infected_file_errno_on_close|
|virusfilter:infected file errno on open|samba_virusfilter_infected_file_errno_on_open|
|virusfilter:io timeout|samba_virusfilter_io_timeout|
|virusfilter:max file size|samba_virusfilter_max_file_size|
|virusfilter:max nested scan archive|samba_virusfilter_max_nested_scan_archive|
|virusfilter:min file size|samba_virusfilter_min_file_size|
|virusfilter:quarantine directory|samba_virusfilter_quarantine_directory|
|virusfilter:quarantine directory mode|samba_virusfilter_quarantine_directory_mode|
|virusfilter:quarantine keep name|samba_virusfilter_quarantine_keep_name|
|virusfilter:quarantine keep tree|samba_virusfilter_quarantine_keep_tree|
|virusfilter:quarantine prefix|samba_virusfilter_quarantine_prefix|
|virusfilter:quarantine suffix|samba_virusfilter_quarantine_suffix|
|virusfilter:rename prefix|samba_virusfilter_rename_prefix|
|virusfilter:rename suffix|samba_virusfilter_rename_suffix|
|virusfilter:scan archive|samba_virusfilter_scan_archive|
|virusfilter:scan error command|samba_virusfilter_scan_error_command|
|virusfilter:scan error errno on close|samba_virusfilter_scan_error_errno_on_close|
|virusfilter:scan error errno on open|samba_virusfilter_scan_error_errno_on_open|
|virusfilter:scan mime|samba_virusfilter_scan_mime|
|virusfilter:scan on close|samba_virusfilter_scan_on_close|
|virusfilter:scan on open|samba_virusfilter_scan_on_open|
|virusfilter:scanner|samba_virusfilter_scanner|
|virusfilter:socket path|samba_virusfilter_socket_path|
|volume|samba_volume|
|wide links|samba_wide_links|
|worm:grace_period|samba_worm_grace_period|
|writable|samba_writable|
|write cache size|samba_write_cache_size|
|write list|samba_write_list|
|write ok|samba_write_ok|
|writeable|samba_writeable|
|xattr_tdb:file|samba_xattr_tdb_file|
|idmap config DOMAIN : OPTION|samba_idmap_configs - [see usage](#idmap-config)|

## Service/share options
|Samba option|Ansible property|
|------------|----------------|
|access based share enum|access_based_share_enum|
|acl allow execute always|acl_allow_execute_always|
|acl check permissions|acl_check_permissions|
|acl group control|acl_group_control|
|acl map full control|acl_map_full_control|
|acl_xattr:default acl style|acl_xattr_default_acl_style|
|acl_xattr:ignore system acls|acl_xattr_ignore_system_acls|
|admin users|admin_users|
|administrative share|administrative_share|
|afs share|afs_share|
|aio read size|aio_read_size|
|aio write behind|aio_write_behind|
|aio write size|aio_write_size|
|aio_pthread:aio open|aio_pthread_aio_open|
|allocation roundup size|allocation_roundup_size|
|allow hosts|allow_hosts|
|audit:facility|audit_facility|
|audit:priority|audit_priority|
|available|available|
|block size|block_size|
|blocking locks|blocking_locks|
|browsable|browsable|
|browseable|browseable|
|btrfs: manipulate snapshots|btrfs_manipulate_snapshots|
|cacheprime:rsize|cacheprime_rsize|
|case sensitive|case_sensitive|
|casesignames|casesignames|
|catia:mappings|catia_mappings|
|ceph:config_file|ceph_config_file|
|ceph:user_id|ceph_user_id|
|check parent directory delete on close|check_parent_directory_delete_on_close|
|comment|comment|
|commit:dthresh|commit_dthresh|
|copy|copy|
|create mask|create_mask|
|create mode|create_mode|
|crossrename:sizelimit|crossrename_sizelimit|
|csc policy|csc_policy|
|cups options|cups_options|
|default case|default_case|
|default devmode|default_devmode|
|default_quota:gid|default_quota_gid|
|default_quota:gid nolimit|default_quota_gid_nolimit|
|default_quota:uid|default_quota_uid|
|default_quota:uid nolimit|default_quota_uid_nolimit|
|delete readonly|delete_readonly|
|delete veto files|delete_veto_files|
|deny hosts|deny_hosts|
|dfree cache time|dfree_cache_time|
|dfree command|dfree_command|
|directory|directory|
|directory mask|directory_mask|
|directory mode|directory_mode|
|directory name cache size|directory_name_cache_size|
|directory security mask|directory_security_mask|
|dmapi support|dmapi_support|
|dont descend|dont_descend|
|dos filemode|dos_filemode|
|dos filetime resolution|dos_filetime_resolution|
|dos filetimes|dos_filetimes|
|durable handles|durable_handles|
|ea support|ea_support|
|exec|exec|
|fake directory create times|fake_directory_create_times|
|fake oplocks|fake_oplocks|
|fileid:algorithm|fileid_algorithm|
|fileid:fstype allow|fileid_fstype_allow|
|fileid:fstype deny|fileid_fstype_deny|
|fileid:mapping|fileid_mapping|
|fileid:mntdir allow|fileid_mntdir_allow|
|fileid:mntdir deny|fileid_mntdir_deny|
|fileid:nolockinode|fileid_nolockinode|
|follow symlinks|follow_symlinks|
|force create mode|force_create_mode|
|force directory mode|force_directory_mode|
|force directory security mode|force_directory_security_mode|
|force group|force_group|
|force printername|force_printername|
|force security mode|force_security_mode|
|force unknown acl user|force_unknown_acl_user|
|force user|force_user|
|fruit:delete_empty_adfiles|fruit_delete_empty_adfiles|
|fruit:encoding|fruit_encoding|
|fruit:locking|fruit_locking|
|fruit:metadata|fruit_metadata|
|fruit:posix_rename|fruit_posix_rename|
|fruit:resource|fruit_resource|
|fruit:time machine|fruit_time_machine|
|fruit:time machine max size|fruit_time_machine_max_size|
|fruit:veto_appledouble|fruit_veto_appledouble|
|fruit:wipe_intentionally_left_blank_rfork|fruit_wipe_intentionally_left_blank_rfork|
|fstype|fstype|
|full_audit:facility|full_audit_facility|
|full_audit:failure|full_audit_failure|
|full_audit:log_secdesc|full_audit_log_secdesc|
|full_audit:prefix|full_audit_prefix|
|full_audit:priority|full_audit_priority|
|full_audit:success|full_audit_success|
|full_audit:syslog|full_audit_syslog|
|glusterfs:logfile|glusterfs_logfile|
|glusterfs:loglevel|glusterfs_loglevel|
|glusterfs:volfile_server|glusterfs_volfile_server|
|glusterfs:volume|glusterfs_volume|
|gpfs:acl|gpfs_acl|
|gpfs:check_fstype|gpfs_check_fstype|
|gpfs:dfreequota|gpfs_dfreequota|
|gpfs:getrealfilename|gpfs_getrealfilename|
|gpfs:hsm|gpfs_hsm|
|gpfs:leases|gpfs_leases|
|gpfs:merge_writeappend|gpfs_merge_writeappend|
|gpfs:prealloc|gpfs_prealloc|
|gpfs:recalls|gpfs_recalls|
|gpfs:refuse_dacl_protected|gpfs_refuse_dacl_protected|
|gpfs:settimes|gpfs_settimes|
|gpfs:sharemodes|gpfs_sharemodes|
|gpfs:syncio|gpfs_syncio|
|gpfs:winattr|gpfs_winattr|
|group|group|
|guest ok|guest_ok|
|guest only|guest_only|
|hide dot files|hide_dot_files|
|hide files|hide_files|
|hide new files timeout|hide_new_files_timeout|
|hide special files|hide_special_files|
|hide unreadable|hide_unreadable|
|hide unwriteable files|hide_unwriteable_files|
|hosts allow|hosts_allow|
|hosts deny|hosts_deny|
|include|include|
|inherit acls|inherit_acls|
|inherit owner|inherit_owner|
|inherit permissions|inherit_permissions|
|invalid users|invalid_users|
|kernel oplocks|kernel_oplocks|
|kernel share modes|kernel_share_modes|
|level2 oplocks|level2_oplocks|
|locking|locking|
|lppause command|lppause_command|
|lpq command|lpq_command|
|lpresume command|lpresume_command|
|lprm command|lprm_command|
|magic output|magic_output|
|magic script|magic_script|
|mangled names|mangled_names|
|mangling char|mangling_char|
|map acl inherit|map_acl_inherit|
|map archive|map_archive|
|map hidden|map_hidden|
|map readonly|map_readonly|
|map system|map_system|
|max connections|max_connections|
|max print jobs|max_print_jobs|
|max reported print jobs|max_reported_print_jobs|
|min print space|min_print_space|
|msdfs proxy|msdfs_proxy|
|msdfs root|msdfs_root|
|msdfs shuffle referrals|msdfs_shuffle_referrals|
|nfs4:acedup|nfs4_acedup|
|nfs4:chown|nfs4_chown|
|nfs4:mode|nfs4_mode|
|nfs4acl_xattr:default acl style|nfs4acl_xattr_default_acl_style|
|nfs4acl_xattr:encoding|nfs4acl_xattr_encoding|
|nfs4acl_xattr:version|nfs4acl_xattr_version|
|nfs4acl_xattr:xattr_name|nfs4acl_xattr_xattr_name|
|nt acl support|nt_acl_support|
|ntvfs handler|ntvfs_handler|
|only guest|only_guest|
|oplocks|oplocks|
|path|path|
|posix locking|posix_locking|
|postexec|postexec|
|prealloc:EXT|prealloc_ext|
|preexec|preexec|
|preexec close|preexec_close|
|preopen:helpers|preopen_helpers|
|preopen:names|preopen_names|
|preopen:num_bytes|preopen_num_bytes|
|preopen:queuelen|preopen_queuelen|
|preserve case|preserve_case|
|print command|print_command|
|print notify backchannel|print_notify_backchannel|
|print ok|print_ok|
|printable|printable|
|printer|printer|
|printer name|printer_name|
|printing|printing|
|printjob username|printjob_username|
|public|public|
|queuepause command|queuepause_command|
|queueresume command|queueresume_command|
|read list|read_list|
|read only|read_only|
|readahead:length|readahead_length|
|readahead:offset|readahead_offset|
|readdir_attr:aapl_finder_info|readdir_attr_aapl_finder_info|
|readdir_attr:aapl_max_access|readdir_attr_aapl_max_access|
|readdir_attr:aapl_rsize|readdir_attr_aapl_rsize|
|readonly:period|readonly_period|
|recycle:directory_mode|recycle_directory_mode|
|recycle:exclude|recycle_exclude|
|recycle:exclude_dir|recycle_exclude_dir|
|recycle:keeptree|recycle_keeptree|
|recycle:maxsize|recycle_maxsize|
|recycle:minsize|recycle_minsize|
|recycle:noversions|recycle_noversions|
|recycle:repository|recycle_repository|
|recycle:subdir_mode|recycle_subdir_mode|
|recycle:touch|recycle_touch|
|recycle:touch_mtime|recycle_touch_mtime|
|recycle:versions|recycle_versions|
|root postexec|root_postexec|
|root preexec|root_preexec|
|root preexec close|root_preexec_close|
|security mask|security_mask|
|shadow:basedir|shadow_basedir|
|shadow:crossmountpoints|shadow_crossmountpoints|
|shadow:delimiter|shadow_delimiter|
|shadow:fixinodes|shadow_fixinodes|
|shadow:format|shadow_format|
|shadow:localtime|shadow_localtime|
|shadow:mountpoint|shadow_mountpoint|
|shadow:snapdir|shadow_snapdir|
|shadow:snapdirseverywhere|shadow_snapdirseverywhere|
|shadow:snapprefix|shadow_snapprefix|
|shadow:snapsharepath|shadow_snapsharepath|
|shadow:sort|shadow_sort|
|shadow:sscanf|shadow_sscanf|
|shell_snap:check path command|shell_snap_check_path_command|
|shell_snap:create command|shell_snap_create_command|
|shell_snap:delete command|shell_snap_delete_command|
|short preserve case|short_preserve_case|
|smb encrypt|smb_encrypt|
|smbd async dosmode|smbd_async_dosmode|
|smbd getinfo ask sharemode|smbd_getinfo_ask_sharemode|
|smbd max async dosmode|smbd_max_async_dosmode|
|smbd search ask sharemode|smbd_search_ask_sharemode|
|spotlight|spotlight|
|store dos attributes|store_dos_attributes|
|streams_depot:delete_lost|streams_depot_delete_lost|
|streams_depot:directory|streams_depot_directory|
|streams_xattr:prefix|streams_xattr_prefix|
|streams_xattr:store_stream_type|streams_xattr_store_stream_type|
|strict allocate|strict_allocate|
|strict locking|strict_locking|
|strict rename|strict_rename|
|strict sync|strict_sync|
|sync always|sync_always|
|syncops:disable|syncops_disable|
|syncops:onclose|syncops_onclose|
|syncops:onmeta|syncops_onmeta|
|time_audit:timeout|time_audit_timeout|
|tsmsm:dmapi attribute|tsmsm_dmapi_attribute|
|tsmsm:dmapi value|tsmsm_dmapi_value|
|tsmsm:hsm script|tsmsm_hsm_script|
|tsmsm:online ratio|tsmsm_online_ratio|
|unityed_media:clientid|unityed_media_clientid|
|use client driver|use_client_driver|
|use sendfile|use_sendfile|
|valid users|valid_users|
|veto files|veto_files|
|veto oplock files|veto_oplock_files|
|vfs object|vfs_object|
|vfs objects|vfs_objects|
|virusfilter:block access on error|virusfilter_block_access_on_error|
|virusfilter:block suspected file|virusfilter_block_suspected_file|
|virusfilter:cache entry limit|virusfilter_cache_entry_limit|
|virusfilter:cache time limit|virusfilter_cache_time_limit|
|virusfilter:connect timeout|virusfilter_connect_timeout|
|virusfilter:exclude files|virusfilter_exclude_files|
|virusfilter:infected file action|virusfilter_infected_file_action|
|virusfilter:infected file command|virusfilter_infected_file_command|
|virusfilter:infected file errno on close|virusfilter_infected_file_errno_on_close|
|virusfilter:infected file errno on open|virusfilter_infected_file_errno_on_open|
|virusfilter:io timeout|virusfilter_io_timeout|
|virusfilter:max file size|virusfilter_max_file_size|
|virusfilter:max nested scan archive|virusfilter_max_nested_scan_archive|
|virusfilter:min file size|virusfilter_min_file_size|
|virusfilter:quarantine directory|virusfilter_quarantine_directory|
|virusfilter:quarantine directory mode|virusfilter_quarantine_directory_mode|
|virusfilter:quarantine keep name|virusfilter_quarantine_keep_name|
|virusfilter:quarantine keep tree|virusfilter_quarantine_keep_tree|
|virusfilter:quarantine prefix|virusfilter_quarantine_prefix|
|virusfilter:quarantine suffix|virusfilter_quarantine_suffix|
|virusfilter:rename prefix|virusfilter_rename_prefix|
|virusfilter:rename suffix|virusfilter_rename_suffix|
|virusfilter:scan archive|virusfilter_scan_archive|
|virusfilter:scan error command|virusfilter_scan_error_command|
|virusfilter:scan error errno on close|virusfilter_scan_error_errno_on_close|
|virusfilter:scan error errno on open|virusfilter_scan_error_errno_on_open|
|virusfilter:scan mime|virusfilter_scan_mime|
|virusfilter:scan on close|virusfilter_scan_on_close|
|virusfilter:scan on open|virusfilter_scan_on_open|
|virusfilter:scanner|virusfilter_scanner|
|virusfilter:socket path|virusfilter_socket_path|
|volume|volume|
|wide links|wide_links|
|worm:grace_period|worm_grace_period|
|writable|writable|
|write cache size|write_cache_size|
|write list|write_list|
|write ok|write_ok|
|writeable|writeable|
|xattr_tdb:file|xattr_tdb_file|
## License
Licensed under [MIT](LICENSE.txt).
