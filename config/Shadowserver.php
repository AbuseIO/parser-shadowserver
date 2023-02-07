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

        'event6_sinkhole_http' => [
            'class'     => 'BOTNET_INFECTION',
            'type'      => 'ABUSE',
            'enabled'   => true,
            'fields'    => [
                'src_ip',
                'timestamp',
                'device_type',
                'http_url',
                'http_agent',
                'src_port',
                'dst_ip',
                'dst_port',
            ],
            'filters'   => [
                'src_asn',
                'src_geo',
                'src_region',
                'src_city',
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

         'scan6_smb' => [
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
        // https://www.shadowserver.org/what-we-do/network-reporting/accessible-telnet-report/
         'scan6_telnet' => [
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

        'scan6_rdp' => [
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
        // https://www.shadowserver.org/what-we-do/network-reporting/ssl-poodle-report/
        'scan6_ssl_poodle' => [
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
        // https://www.shadowserver.org/what-we-do/network-reporting/sinkhole-http-events-report/
        'event4_sinkhole_http' => [
            'class'     => 'BOTNET_INFECTION',
            'type'      => 'ABUSE',
            'enabled'   => true,
            'fields'    => [
                'src_ip',
                'timestamp',
                'device_type',
                'http_url',
                'http_agent',
                'src_port',
                'dst_ip',
                'dst_port',
            ],
            'filters'   => [
                'src_asn',
                'src_geo',
                'src_region',
                'src_city',
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

        'scan6_ntp' => [
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

        'scan_afp' => [
            'class'     => 'OPEN_AFP_SERVER',
            'type'      => 'INFO',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'timestamp',
                'protocol',
                'port',
                'machine_type',
                'afp_versions',
                'uams',
                'flags',
                'server_name',
                'directory_service',
                'network_address',
            ],
            'filters'   => [
                'asn',
                'geo',
                'region',
                'city',
            ],
        ],

        'scan_dns' => [
            'class'     => 'OPEN_DNS_RESOLVER',
            'type'      => 'INFO',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'timestamp',
                'protocol',
                'port',
                'min_amplification',
            ],
            'filters'   => [
                'asn',
                'geo',
                'region',
                'city',
            ],
        ],

        'scan6_dns' => [
            'class'     => 'OPEN_DNS_RESOLVER',
            'type'      => 'INFO',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'timestamp',
                'protocol',
                'port',
                'min_amplification',
            ],
            'filters'   => [
                'asn',
                'geo',
                'region',
                'city',
            ],
        ],

        'scan_ftp' => [
             'class'     => 'OPEN_FTP_SERVER',
             'type'      => 'INFO',
             'enabled'   => true,
             'fields'    => [
                 'ip',
                 'timestamp',
                 'port',
                 'hostname',
                 'banner',
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

        'scan6_ftp' => [
             'class'     => 'OPEN_FTP_SERVER',
             'type'      => 'INFO',
             'enabled'   => true,
             'fields'    => [
                 'ip',
                 'timestamp',
                 'port',
                 'hostname',
                 'banner',
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

        'scan_http' => [
             'class'     => 'OPEN_HTTP_SERVER',
             'type'      => 'INFO',
             'enabled'   => true,
             'fields'    => [
                 'ip',
                 'timestamp',
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

        // https://www.shadowserver.org/what-we-do/network-reporting/accessible-http-report/
        'scan6_http' =>  [
            'class'     => 'OPEN_HTTP_SERVER',
            'type'      => 'INFO',
            'enabled'   => 'true',
            'fields'    =>  [
                'timestamp',
                'ip',
                'hostname',
                'protocol',
                'port',
            ],
            'filters'   =>  [
                'asn',
                'geo',
                'region',
                'city',
                'naics',
            ],
        ],


        'scan_rsync' => [
             'class'     => 'OPEN_RSYNC_SERVER',
             'type'      => 'INFO',
             'enabled'   => true,
             'fields'    => [
                 'ip',
                 'timestamp',
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
        
        //https://www.shadowserver.org/what-we-do/network-reporting/open-proxy-report/
        'scan_open_proxy_report' => [
            'class'                =>'OPEN_PROXY_SERVER',
            'type'                 =>'INFO',
            'enabled'              => true,
            'fields'               =>  [
                'ip',
                'timestamp',
                'port'
            ],
            'filters'              => [
                'asn',
                'geo',
                'region',
                'city',
            ]
        ],

        //https://www.shadowserver.org/what-we-do/network-reporting/open-ubiquiti-report/
        'scan_ubiquiti' => [
            'class'                     =>'OPEN_UBIQUITI_SERVER',
            'type'                      =>'INFO',
            'enabled'                   => true,
            'fields'                    =>  [
                'ip',
                'timestamp',
                'protocol',
                'port',
                'hostname',
            ],
            'filters'               => [
                'asn',
                'geo',
                'region',
                'city',
                'naics',
                'sic',
            ],
        ],
        //https://www.shadowserver.org/what-we-do/network-reporting/brute-force-attack-report/
        'brute_force_attack_report' => [
            'class'     => 'BRUTE_FORCE_ATTACK',
            'type'      => 'INFO',
            'enabled'   => true,
            'fields'    =>  [
                'timestamp',
                'ip',
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
        // https://www.shadowserver.org/what-we-do/network-reporting/honeypot-amplification-ddos-events-report/
        'event4_honeypot_ddos_amp' => [
            'class'     => 'AMPLICATION_DDOS_VICTIM',
            'type'      => 'INFO',
            'enabled'   => true,
            'fields'    => [
                'timestamp',
                'dst_ip',
                'protocol',
                'dst_port',
                'dst_hostname',
            ],
            'filters'   => [
                'dst_asn',
                'dst_geo',
                'dst_region',
                'dst_city',
                'dst_naics',
            ],
        ],
        // https://www.shadowserver.org/what-we-do/network-reporting/honeypot-amplification-ddos-events-report/
        'event6_honeypot_ddos_amp' => [
            'class'     => 'AMPLICATION_DDOS_VICTIM',
            'type'      => 'INFO',
            'enabled'   => true,
            'fields'    => [
                'timestamp',
                'dst_ip',
                'protocol',
                'dst_port',
                'dst_hostname',
            ],
            'filters'   => [
                'dst_asn',
                'dst_geo',
                'dst_region',
                'dst_city',
                'dst_naics',
            ],
        ],

        
        //https://www.shadowserver.org/what-we-do/network-reporting/accessible-adb-report/
        'scan_adb' => [
            'class'     => 'ACCESSIBLE_ADB_REPORT',
            'type'      => 'INFO',
            'enabled'   =>  true,
            'fields'    =>  [
                'timestamp',
                'ip',
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
        //https://www.shadowserver.org/what-we-do/network-reporting/accessible-apple-remote-desktop-ard-report/
        'scan_ard' => [
            'class'     => 'ACCESSIBLE_APPLE_REMOTE_DESKTOP_ARD_REPORT',
            'type'      => 'INFO',
            'enabled'   => true,
            'fields'    =>  [
                'timestamp',
                'ip',
                'protocol',
                'port',
            ],
            'filters'   =>[
                'asn',
                'geo',
                'region',
                'city',
                'naics',
                'sic',
            ],
        ],

        //https://www.shadowserver.org/what-we-do/network-reporting/accessible-xdmcp-service-report/
        'scan_xdmcp' => [
            'class'     => 'ACCESSIBLE_XDMCP_SERVICE_REPORT',
            'type'      => 'INFO',
            'enabled'   =>  true,
            'fields'    =>  [
                'timestamp',
                'ip',
                'protocol',
                'port',
            ],
            'filters'   =>[
                'asn',
                'geo',
                'region',
                'city',
                'naics',
                'sic',
            ],
        ],
        //https://www.shadowserver.org/what-we-do/network-reporting/caida-ip-spoofer-report/
        'caida_ip_spoofer' => [
            'class'     => 'CAIDA_IP_SPOOFER_REPORT',
            'type'      => 'INFO',
            'enabled'   =>  true,
            'fields'    =>  [
                'timestamp',
                'ip',
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
       //https://www.shadowserver.org/what-we-do/network-reporting/drone-botnet-drone-report/
        'drone_brute_force' => [
            'class'     => 'DRONE_BOTNET_DRONE_REPORT',
            'type'      => 'INFO',
            'enabled'   =>  true,
            'fields'    =>  [
                'timestamp',
                'ip',
                'port',
            ],
            'filters'   =>[
                'asn',
                'geo',
                'region',
                'city',
                'naics',
                'sic',
            ],
        ],

        //https://www.shadowserver.org/what-we-do/network-reporting/netcore-netis-router-vulnerability-scan-report/
        'netis_router' => [
            'class'     => 'NETCORE_NETIS_ROUTER_VULNERABILITY_SCAN_REPORT',
            'type'      => 'INFO',
            'enabled'   =>  true,
            'fields'    =>  [
                'timestamp',
                'ip',
                'port',
            ],
            'filters'   =>[
                'asn',
                'geo',
                'region',
                'city',
            ],
        ],
        //https://www.shadowserver.org/what-we-do/network-reporting/open-db2-discovery-service-report/
        'scan_db2' => [
            'class'     => 'OPEN_DB2_DISCOVERY_SERVICE_REPORT',
            'type'      => 'INFO',
            'enabled'   =>  true,
            'fields'    =>  [
                'timestamp',
                'ip',
                'protocol',
                'port',
            ],
            'filters'   =>[
                'asn',
                'geo',
                'region',
                'city',
            ],
        ],
        //https://www.shadowserver.org/what-we-do/network-reporting/open-mqtt-report/
        'scan_mqtt' => [
            'class'     => 'OPEN_MQTT',
            'type'      => 'INFO',
            'enabled'   =>  true,
            'fields'    =>  [
                'timestamp',
                'ip',
                'protocol',
                'port',
            ],
            'filters'   =>[
                'asn',
                'geo',
                'region',
                'city',
                'naics',
            ],
        ],

        //https://www.shadowserver.org/what-we-do/network-reporting/open-mqtt-report/
        'scan6_mqtt' => [
            'class'     => 'OPEN_MQTT',
            'type'      => 'INFO',
            'enabled'   =>  true,
            'fields'    =>  [
                'timestamp',
                'ip',
                'protocol',
                'port',
            ],
            'filters'   =>[
                'asn',
                'geo',
                'region',
                'city',
                'naics',
            ],
        ],

        //https://www.shadowserver.org/what-we-do/network-reporting/accessible-coap-report/
        'scan_coap' => [
            'class'     => 'OPEN_COAP',
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
                'response',
            ],
        ],
        //https://www.shadowserver.org/what-we-do/network-reporting/open-ipp-report/
        'scan_ipp' => [
            'class'     => 'OPEN_IPP',
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
                'response',
            ],
        ],
        //https://www.shadowserver.org/what-we-do/network-reporting/accessible-radmin-report/
        'scan_radmin' => [
            'class'     => 'OPEN_RADMIN',
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
        //https://www.shadowserver.org/what-we-do/network-reporting/accessible-ms-rdpeudp/
        'scan_rdpeudp' => [
            'class'     => 'OPEN_RDPEUDP',
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
        //https://www.shadowserver.org/what-we-do/network-reporting/vulnerable-http-report/
        'scan_http_vulnerable' => [
            'class'     => 'OPEN_BASIC_AUTH_SERVICE',
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

        'scan6_http_vulnerable' => [
            'class'     => 'OPEN_BASIC_AUTH_SERVICE',
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

        //https://www.shadowserver.org/what-we-do/network-reporting/darknet-report/
        'darknet' => [
            'class'     => 'DARKNET',
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
        // https://www.shadowserver.org/what-we-do/network-reporting/blocklist-report/
        'blocklist' => [
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
        // https://www.shadowserver.org/what-we-do/network-reporting/vulnerable-smtp-report/
       'scan_smtp_vulnerable' => [
            'class'     => 'VULNERABLE_SMTP_SERVER',
            'type'      => 'INFO',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'timestamp',
                'port',
                'tag',
                'sector',
                'banner',
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
        // https://www.shadowserver.org/what-we-do/network-reporting/vulnerable-smtp-report/
        'scan6_smtp_vulnerable' => [
            'class'     => 'VULNERABLE_SMTP_SERVER',
            'type'      => 'INFO',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'timestamp',
                'port',
                'tag',
                'sector',
                'banner',
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

        // https://www.shadowserver.org/what-we-do/network-reporting/accessible-amqp-report/
        'scan_amqp' => [
            'class'     => 'OPEN_AMQP',
            'type'      => 'INFO',
            'enabled'   =>  true,
            'fields'    =>  [
                'timestamp',
                'ip',
                'hostname',
                'protocol',
                'port',
            ],
            'filters'   =>  [
                'asn',
                'geo',
                'region',
                'city',
                'naics',
            ],
        ],

        // https://www.shadowserver.org/what-we-do/network-reporting/accessible-ssh-report/
        'scan_ssh' => [
            'class'     => 'OPEN_SSH_SERVER',
            'type'      => 'INFO',
            'enabled'   => 'true',
            'fields'    =>  [
                'timestamp',
                'ip',
                'hostname',
                'protocol',
                'port',
            ],
            'filters'   =>  [
                'asn',
                'geo',
                'region',
                'city',
                'naics',
            ],
        ],

        // https://www.shadowserver.org/what-we-do/network-reporting/accessible-ssh-report/
        'scan6_ssh' => [
            'class'     => 'OPEN_SSH_SERVER',
            'type'      => 'INFO',
            'enabled'   =>  true,
            'fields'    =>  [
                'timestamp',
                'ip',
                'hostname',
                'protocol',
                'port',
            ],
            'filters'   =>  [
                'asn',
                'geo',
                'region',
                'city',
                'naics',
            ],
        ],

        // https://www.shadowserver.org/what-we-do/network-reporting/accessible-smtp-report/
        'scan_smtp' => [
            'class'     => 'OPEN_SMTP_SERVER',
            'type'      => 'INFO',
            'enabled'   =>  true,
            'fields'    =>  [
                'timestamp',
                'ip',
                'hostname',
                'protocol',
                'port',
            ],
            'filters'   =>  [
                'asn',
                'geo',
                'region',
                'city',
                'naics',
            ],
        ],

        // https://www.shadowserver.org/what-we-do/network-reporting/accessible-smtp-report/
        'scan6_smtp' => [
            'class'     => 'OPEN_SMTP_SERVER',
            'type'      => 'INFO',
            'enabled'   =>  true,
            'fields'    =>  [
                'timestamp',
                'ip',
                'hostname',
                'protocol',
                'port',
            ],
            'filters'   =>  [
                'asn',
                'geo',
                'region',
                'city',
                'naics',
            ],
        ],

        // https://www.shadowserver.org/what-we-do/network-reporting/accessible-stun-service-report/
        'scan_stun' =>  [
            'class'     => 'OPEN_STUN_SERVICE',
            'type'      => 'INFO',
            'enabled'   =>  true,
            'fields'    =>  [
                'timestamp',
                'ip',
                'hostname',
                'protocol',
                'port',
            ],
            'filters'   =>  [
                'asn',
                'geo',
                'region',
                'city',
                'naics',
            ],
        ],

        // https://www.shadowserver.org/what-we-do/network-reporting/accessible-stun-service-report/
        'scan6_stun' =>  [
            'class'     => 'OPEN_STUN_SERVICE',
            'type'      => 'INFO',
            'enabled'   =>  true,
            'fields'    =>  [
                'timestamp',
                'ip',
                'hostname',
                'protocol',
                'port',
            ],
            'filters'   =>  [
                'asn',
                'geo',
                'region',
                'city',
                'naics',
            ],
        ],

        // https://www.shadowserver.org/what-we-do/network-reporting/accessible-socks4-5-proxy-report/
        'scan_socks' => [
            'class'     => 'OPEN_SOCKS_PROXY',
            'type'      => 'INFO',
            'enabled'   =>  true,
            'fields'    =>  [
                'timestamp',
                'ip',
                'hostname',
                'protocol',
                'port',
            ],
            'filters'   =>  [
                'asn',
                'geo',
                'region',
                'city',
                'naics',
            ],
        ],

        // https://www.shadowserver.org/what-we-do/network-reporting/accessible-ics-report/
        'scan_ics' => [
            'class'     => 'OPEN_ICS',
            'type'      => 'INFO',
            'enabled'   =>  true,
            'fields'    =>  [
                'timestamp',
                'ip',
                'hostname',
                'protocol',
                'port',
                'device_vendor',
                'device_type',
                'device_model',
                'device_version',
                'device_id',
            ],
            'filters'   =>  [
                'asn',
                'geo',
                'region',
                'city',
                'naics',
            ],
        ],

        // https://www.shadowserver.org/what-we-do/network-reporting/accessible-postgresql-server-report/
        'scan_postgres' => [
            'class'     => 'OPEN_POSTGRESQL_SERVER',
            'type'      => 'INFO',
            'enabled'   =>  true,
            'fields'    =>  [
                'timestamp',
                'ip',
                'hostname',
                'protocol',
                'port',
            ],
            'filters'   =>  [
                'asn',
                'geo',
                'region',
                'city',
                'naics',
            ],
        ],

        // https://www.shadowserver.org/what-we-do/network-reporting/accessible-postgresql-server-report/
        'scan6_postgres' => [
            'class'     => 'OPEN_POSTGRESQL_SERVER',
            'type'      => 'INFO',
            'enabled'   =>  true,
            'fields'    =>  [
                'timestamp',
                'ip',
                'hostname',
                'protocol',
                'port',
            ],
            'filters'   =>  [
                'asn',
                'geo',
                'region',
                'city',
                'naics',
            ],
        ],

        // https://www.shadowserver.org/what-we-do/network-reporting/accessible-erlang-port-mapper-report-daemon/
        'scan_epmd' => [
            'class'     => 'OPEN_ERLANG_PORTMAPPER_DAEMON',
            'type'      => 'INFO',
            'enabled'   =>  true,
            'fields'    =>  [
                'timestamp',
                'ip',
                'hostname',
                'protocol',
                'port',
                'nodes',
            ],
            'filters'   =>  [
                'asn',
                'geo',
                'region',
                'city',
                'naics',
            ],
        ],

        // https://www.shadowserver.org/what-we-do/network-reporting/device-identification-report/
        'device_id' => [
            'class'     => 'DEVICE_IDENTIFICATION',
            'type'      => 'INFO',
            'enabled'   =>  false,
            'fields'    =>  [
                'timestamp',
                'ip',
                'hostname',
                'protocol',
                'port',
                'device_vendor',
                'device_type',
                'device_model',
            ],
            'filters'   =>  [
                'asn',
                'geo',
                'region',
                'city',
                'naics',
            ],
        ],

        'device_id6' => [
            'class'     => 'DEVICE_IDENTIFICATION',
            'type'      => 'INFO',
            'enabled'   =>  false,
            'fields'    =>  [
                'timestamp',
                'ip',
                'hostname',
                'protocol',
                'port',
                'device_vendor',
                'device_type',
                'device_model',
            ],
            'filters'   =>  [
                'asn',
                'geo',
                'region',
                'city',
                'naics',
            ],
        ],

        // https://www.shadowserver.org/what-we-do/network-reporting/vulnerable-exchange-server-report/
        'scan_http_vulnerable' => [
            'class'     => 'VULNERABLE_EXCHANGE_SERVER',
            'type'      => 'INFO',
            'enabled'   =>  true,
            'fields'    =>  [
                'timestamp',
                'ip',
                'hostname',
                'port',
                'version',
                'servername',
            ],
            'filters'   =>  [
                'asn',
                'geo',
                'region',
                'city',
                'naics',
            ],
        ],

        // https://www.shadowserver.org/what-we-do/network-reporting/vulnerable-exchange-server-report/
        'scan6_http_vulnerable' => [
            'class'     => 'VULNERABLE_EXCHANGE_SERVER',
            'type'      => 'INFO',
            'enabled'   =>  true,
            'fields'    =>  [
                'timestamp',
                'ip',
                'hostname',
                'port',
                'version',
                'servername',
            ],
            'filters'   =>  [
                'asn',
                'geo',
                'region',
                'city',
                'naics',
            ],
        ],
    ],
];
