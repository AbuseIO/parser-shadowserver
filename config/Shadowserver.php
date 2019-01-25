<?php

return [
    'parser' => [
        'name'          => 'Shadowserver',
        'enabled'       => true,
        'file_regex'    => "~(?:\d{4})-(?:\d{2})-(?:\d{2})-(.*)-[^\-]+-[^\-]+.csv~i",
        'sender_map'    => [
            '/autoreports@shadowserver.org/',
        ],
        'body_map'      => [
            //
        ],
    ],


    'feeds' => [
         'cisco_smart_install' => [
             'class'     => 'OPEN_SMARTINSTALL',
             'type'      => 'INFO',
             'enabled'   => true,
             'fields'    => [
                 'ip',
                 'timestamp',
                 'port',
             ],
             'filters'   => [
                 'asn',
                 'geo',
                 'region',
                 'city',
                 'naics',
                 'sic',
             ],
         ],

         'scan_hadoop' => [
             'class'     => 'OPEN_HADOOP_SERVER',
             'type'      => 'INFO',
             'enabled'   => true,
             'fields'    => [
                 'ip',
                 'timestamp',
                 'port',
                 'server_type',
                 'clisterid',
                 'total_disk',
                 'livenodes',
                 'namenodeaddress',
                 'volumeinfo',
             ],
             'filters'   => [
                 'asn',
                 'geo',
                 'region',
                 'city',
                 'naics',
                 'sic',
             ],
         ],

         'sinkhole6' => [
             'class'     => 'BOTNET_INFECTION',
             'type'      => 'ABUSE',
             'enabled'   => true,
             'fields'    => [
                 'src_ip',
                 'src_port',
                 'dst_ip',
                 'dst_port',
                 'timestamp',
                 'port',
             ],
            'aliasses' => [
                'ip' => 'src_ip',
            ],
             'filters'   => [
                 'asn',
                 'geo',
                 'region',
                 'city',
                 'naics',
                 'sic',
             ],
         ],

         'scan_vnc' => [
             'class'     => 'OPEN_VNC_SERVER',
             'type'      => 'INFO',
             'enabled'   => true,
             'fields'    => [
                 'ip',
                 'timestamp',
                 'port',
             ],
             'filters'   => [
                 'asn',
                 'geo',
                 'region',
                 'city',
                 'naics',
                 'sic',
             ],
         ],

         'scan_smb' => [
             'class'     => 'OPEN_SMB_SERVER',
             'type'      => 'INFO',
             'enabled'   => true,
             'fields'    => [
                 'ip',
                 'timestamp',
                 'port',
             ],
             'filters'   => [
                 'asn',
                 'geo',
                 'region',
                 'city',
                 'naics',
                 'sic',
             ],
         ],

         'scan_cwmp' => [
             'class'     => 'OPEN_CWMP_SERVER',
             'type'      => 'INFO',
             'enabled'   => true,
             'fields'    => [
                 'ip',
                 'timestamp',
                 'protocol',
                 'port',
             ],
             'filters'   => [
                 'asn',
                 'geo',
                 'region',
                 'city',
                 'naics',
                 'sic',
             ],
         ],
 
         'scan_telnet' => [
             'class'     => 'OPEN_TELNET_SERVER',
             'type'      => 'INFO',
             'enabled'   => true,
             'fields'    => [
                 'ip',
                 'timestamp',
                 'protocol',
                 'port',
             ],
             'filters'   => [
                 'asn',
                 'geo',
                 'region',
                 'city',
                 'naics',
                 'sic',
             ],
         ],
 
         'scan_ldap' => [
             'class'     => 'OPEN_LDAP_SERVER',
             'type'      => 'INFO',
             'enabled'   => true,
             'fields'    => [
                 'ip',
                 'timestamp',
                 'protocol',
                 'port',
             ],
             'filters'   => [
                 'asn',
                 'geo',
                 'region',
                 'city',
                 'naics',
                 'sic',
             ],
         ],
 
         'scan_ldap_tcp' => [
             'class'     => 'OPEN_LDAP_SERVER',
             'type'      => 'INFO',
             'enabled'   => true,
             'fields'    => [
                 'ip',
                 'timestamp',
                 'protocol',
                 'port',
             ],
             'filters'   => [
                 'asn',
                 'geo',
                 'region',
                 'city',
                 'naics',
                 'sic',
             ],
         ],
        
         'blacklist' => [
             'class'     => 'RBL_LISTED',
             'type'      => 'INFO',
             'enabled'   => true,
             'fields'    => [
                 'ip',
                 'timestamp',
                 'source',
             ],
             'filters'   => [
                 'asn',
                 'geo',
                 'region',
                 'city',
                 'naics',
                 'sic',
             ],
        ],

        'scan_isakmp' => [
            'class'     => 'ISAKMP_VULNERABLE_DEVICE',
            'type'      => 'INFO',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'timestamp',
                'protocol',
                'port',
            ],
            'filters'   => [
                'asn',
                'geo',
                'region',
                'city',
                'naics',
                'sic',
            ],
        ],

        'scan_rdp' => [
            'class'     => 'OPEN_RDP_SERVER',
            'type'      => 'INFO',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'timestamp',
                'port',
            ],
            'filters'   => [
                'asn',
                'geo',
                'region',
                'city',
                'naics',
                'sic',
                'sector',
            ],
        ],

        'scan_tftp' => [
            'class'     => 'OPEN_TFTP_SERVER',
            'type'      => 'INFO',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'timestamp',
                'protocol',
                'port',
            ],
            'filters'   => [
                'asn',
                'geo',
                'region',
                'city',
                'naics',
                'sic',
            ],
        ],

        'scan_mdns' => [
            'class'     => 'OPEN_MDNS_SERVICE',
            'type'      => 'INFO',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'timestamp',
                'protocol',
                'port',
                'hostname',
            ],
            'filters'   => [
                'asn',
                'geo',
                'region',
                'city',
                'naics',
                'sic',
            ],
        ],

        'scan_portmapper' => [
            'class'     => 'OPEN_PORTMAP_SERVER',
            'type'      => 'INFO',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'timestamp',
                'protocol',
                'port',
                'hostname',
                'programs',
                'mountd_port',
                'exports',
            ],
            'filters'   => [
                'asn',
                'geo',
                'region',
                'city',
                'naics',
                'sic',
            ],
        ],

        'scan_elasticsearch' => [
            'class'     => 'OPEN_ELASTICSEARCH_SERVER',
            'type'      => 'INFO',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'timestamp',
                'protocol',
                'port',
                'version',
                'name',
                'cluster_name',
            ],
            'filters'   => [
                'asn',
                'geo',
                'region',
                'city',
            ],
        ],

        'scan_qotd' => [
            'class'     => 'OPEN_QOTD_SERVER',
            'type'      => 'INFO',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'timestamp',
                'protocol',
                'port',
            ],
            'filters'   => [
                'asn',
                'geo',
                'region',
                'city',
            ],
        ],

        'spam_url' => [
            'class'     => 'SPAMVERTISED_WEBSITE',
            'type'      => 'ABUSE',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'timestamp',
                'url',
                'host',
            ],
            'filters'   => [
                'asn',
                'geo',
                'region',
                'city',
            ],
        ],

        'scan_mssql' => [
            'class'     => 'OPEN_MSSQL_SERVER',
            'type'      => 'INFO',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'timestamp',
                'protocol',
                'port',
                'version',
                'instance_name',
                'tcp_port',
                'named_pipe',
                'response_length',
                'amplification',
            ],
            'filters'   => [
                'asn',
                'geo',
                'region',
                'city',
            ],
        ],

        'scan_ssl_poodle' => [
            'class'     => 'SSLV3_VULNERABLE_SERVER',
            'type'      => 'INFO',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'timestamp',
                'port',
                'handshake',
                'cipher_suite',
                'subject_common_name',
                'issuer_common_name',
                'cert_expiration_date',
                'issuer_organization_name',
            ],
            'filters'   => [
                'asn',
                'geo',
                'region',
                'city',
            ],
        ],

        'ssl_scan' => [
            'class'     => 'SSLV3_VULNERABLE_SERVER',
            'type'      => 'INFO',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'timestamp',
                'port',
                'handshake',
                'cipher_suite',
                'subject_common_name',
                'issuer_common_name',
                'cert_expiration_date',
                'issuer_organization_name',
            ],
            'filters'   => [
                'asn',
                'geo',
                'region',
                'city',
            ],
        ],

        'scan_ssl_freak' => [
            'class'     => 'FREAK_VULNERABLE_SERVER',
            'type'      => 'INFO',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'timestamp',
                'port',
                'handshake',
                'cipher_suite',
                'freak_cipher_suite',
                'subject_common_name',
                'issuer_common_name',
                'cert_expiration_date',
            ],
            'filters'   => [
                'asn',
                'geo',
                'region',
                'city',
            ],
        ],

        'cc_ip' => [
            'class'     => 'BOTNET_CONTROLLER',
            'type'      => 'ABUSE',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'timestamp',
                'port',
                'channel',
            ],
            'filters'   => [
                'asn',
                'geo',
                'region',
                'city',
            ],
        ],

        'scan_ntpmonitor' => [
            'class'     => 'POSSIBLE_DDOS_SENDING_SERVER',
            'type'      => 'ABUSE',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'timestamp',
                'protocol',
                'port',
                'hostname',
                'packets',
                'size',
            ],
            'filters'   => [
                'asn',
                'geo',
                'region',
                'city',
            ],
        ],

        'compromised_website' => [
            'class'     => 'COMPROMISED_WEBSITE',
            'type'      => 'ABUSE',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'timestamp',
                'http_host',
                'category',
                'tag',
                'redirect_target',
            ],
            'filters'   => [
                'asn',
                'geo',
                'region',
                'city',
            ],
        ],

        'cwsandbox_url' => [
            'class'     => 'MALWARE_INFECTION',
            'type'      => 'ABUSE',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'timestamp',
                'md5hash',
                'url',
                'user_agent',
                'host',
                'method',
            ],
            'filters'   => [
                'asn',
                'geo',
                'region',
                'city',
            ],
        ],

        'sinkhole_http_drone' => [
            'class'     => 'BOTNET_INFECTION',
            'type'      => 'ABUSE',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'timestamp',
                'type',
                'url',
                'http_agent',
                'src_port',
                'dst_ip',
                'dst_port',
            ],
            'filters'   => [
                'asn',
                'geo',
                'region',
                'city',
            ],
        ],

        'microsoft_sinkhole' => [
            'class'     => 'BOTNET_INFECTION',
            'type'      => 'ABUSE',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'timestamp',
                'type',
                'url',
                'http_agent',
                'src_port',
                'dst_ip',
                'dst_port',
            ],
            'filters'   => [
                'asn',
                'geo',
                'region',
                'city',
            ],
        ],

        'botnet_drone' => [
            'class'     => 'BOTNET_INFECTION',
            'type'      => 'ABUSE',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'timestamp',
                'infection',
                'url',
                'agent',
                'cc_ip',
                'cc_port',
                'cc_dns',
            ],
            'aliasses' => [
                'cc' => 'cc_ip',
            ],
            'filters'   => [
                'asn',
                'geo',
                'region',
                'city',
            ],
        ],

        'dns_openresolver' => [
            'class'     => 'OPEN_DNS_RESOLVER',
            'type'      => 'INFO',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'timestamp',
                'protocol',
                'port',
                'min_amplification',
                'dns_version',
            ],
            'filters'   => [
                'asn',
                'geo',
                'region',
                'city',
            ],
        ],

        'scan_ntp' => [
            'class'     => 'OPEN_NTP_SERVER',
            'type'      => 'INFO',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'timestamp',
                'clock',
                'error',
                'frequency',
                'peer',
                'refid',
                'reftime',
                'stratum',
                'system',
            ],
            'filters'   => [
                'asn',
                'geo',
                'region',
                'city',
            ],
        ],

        'scan_snmp' => [
            'class'     => 'OPEN_SNMP_SERVER',
            'type'      => 'INFO',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'timestamp',
                'sysdesc',
                'sysname',
                'version',
            ],
            'filters'   => [
                'asn',
                'geo',
                'region',
                'city',
            ],
        ],

        'scan_netbios' => [
            'class'     => 'OPEN_NETBIOS_SERVER',
            'type'      => 'INFO',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'timestamp',
                'mac_address',
                'workgroup',
                'machine_name',
                'username',
            ],
            'filters'   => [
                'asn',
                'geo',
                'region',
                'city',
            ],
        ],

        'scan_ssdp' => [
            'class'     => 'OPEN_SSDP_SERVER',
            'type'      => 'INFO',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'timestamp',
                'systime',
                'location',
                'server',
                'unique_service_name',
            ],
            'filters'   => [
                'asn',
                'geo',
                'region',
                'city',
            ],
        ],

        'scan_chargen' => [
            'class'     => 'OPEN_CHARGEN_SERVER',
            'type'      => 'INFO',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'timestamp',
                'protocol',
                'port',
                'size',
            ],
            'filters'   => [
                'asn',
                'geo',
                'region',
                'city',
            ],
        ],

        'scan_ipmi' => [
            'class'     => 'OPEN_IMPI_SERVER',
            'type'      => 'INFO',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'timestamp',
                'port',
                'ipmi_version',
                'none_auth',
                'md2_auth',
                'md5_auth',
                'passkey_auth',
                'oem_auth',
                'defaultkg',
                'permessage_auth',
                'userlevel_auth',
                'usernames',
                'nulluser',
                'anon_login',
            ],
            'filters'   => [
                'asn',
                'geo',
                'region',
                'city',
            ],
        ],

        'scan_net_pmp' => [
            'class'     => 'OPEN_NATPMP_SERVER',
            'type'      => 'INFO',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'timestamp',
                'protocol',
                'port',
                'version',
                'uptime',
            ],
            'filters'   => [
                'asn',
                'geo',
                'region',
                'city',
            ],
        ],

        'scan_nat_pmp' => [
            'class'     => 'OPEN_NATPMP_SERVER',
            'type'      => 'INFO',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'timestamp',
                'protocol',
                'port',
                'version',
                'uptime',
            ],
            'filters'   => [
                'asn',
                'geo',
                'region',
                'city',
            ],
        ],

        'scan_redis' => [
            'class'     => 'OPEN_REDIS_SERVER',
            'type'      => 'INFO',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'timestamp',
                'protocol',
                'port',
                'version',
                'mode',
                'os',
                'process_id',
            ],
            'filters'   => [
                'asn',
                'geo',
                'region',
                'city',
            ],
        ],

        'wiki_file' => [
            //Apparently shadowserver used this one in error, keeping it for parsing history
            'class'     => 'OPEN_MEMCACHED_SERVER',
            'type'      => 'INFO',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'timestamp',
                'protocol',
                'port',
                'version',
                'uptime',
                'curr_connections',
                'total_connections',
            ],
            'filters'   => [
                'asn',
                'geo',
                'region',
                'city',
            ],
        ],

        'scan_memcached' => [
            'class'     => 'OPEN_MEMCACHED_SERVER',
            'type'      => 'INFO',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'timestamp',
                'protocol',
                'port',
                'version',
                'uptime',
                'curr_connections',
                'total_connections',
            ],
            'filters'   => [
                'asn',
                'geo',
                'region',
                'city',
            ],
        ],

        'scan_mongodb' => [
            'class'     => 'OPEN_MONGODB_SERVER',
            'type'      => 'INFO',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'timestamp',
                'protocol',
                'port',
                'version',
                'visible_databases',
            ],
            'filters'   => [
                'asn',
                'geo',
                'region',
                'city',
            ],
        ],
    ],
];
