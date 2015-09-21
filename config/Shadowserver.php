<?php

return [
    'parser' => [
        'name'          => 'Shadowserver',
        'enabled'       => true,
        'sender_map'    => [
            '/autoreports@shadowserver.org/',
        ],
        'body_map'      => [
            //
        ],
    ],

        
    'feeds' => [
        'scan_portmapper' => [
            'class'     => 'Open Portmapper Server',
            'type'      => 'Info',
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
            'class'     => 'Open ElasticSearch Server',
            'type'      => 'Info',
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
            'class'     => 'Open QOTD Server',
            'type'      => 'Info',
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
            'class'     => 'Spamvertised web site',
            'type'      => 'Abuse',
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
            'class'     => 'Open Microsoft SQL Server',
            'type'      => 'Info',
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
            'class'     => 'SSLv3 Vulnerable Server',
            'type'      => 'Info',
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
            'class'     => 'SSLv3 Vulnerable Server',
            'type'      => 'Info',
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
            'class'     => 'FREAK Vulnerable Server',
            'type'      => 'Info',
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
            'class'     => 'Command and control server',
            'type'      => 'Abuse',
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
            'class'     => 'Possible DDoS sending Server',
            'type'      => 'Abuse',
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
            'class'     => 'Compromised website',
            'type'      => 'Abuse',
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
            'class'     => 'Malware infection',
            'type'      => 'Abuse',
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
            'class'     => 'Botnet infection',
            'type'      => 'Abuse',
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
            'class'     => 'Botnet infection',
            'type'      => 'Abuse',
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
            'class'     => 'Botnet infection',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'timestamp',
                'infection',
                'url',
                'agent',
                'cc',
                'cc_port',
                'cc_dns',
            ],
            'filters'   => [
                'asn',
                'geo',
                'region',
                'city',
            ],
        ],

        'dns_openresolver' => [
            'class'     => 'Open DNS Resolver',
            'type'      => 'Info',
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
            'class'     => 'Open NTP Server',
            'type'      => 'Info',
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
            'class'     => 'Open SNMP Server',
            'type'      => 'Info',
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
            'class'     => 'Open Netbios Server',
            'type'      => 'Info',
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
            'class'     => 'Open SSDP Server',
            'type'      => 'Info',
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
            'class'     => 'Open Chargen Server',
            'type'      => 'Info',
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
            'class'     => 'Open IPMI Server',
            'type'      => 'Info',
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
            'class'     => 'Open NAT_PMP Server',
            'type'      => 'Info',
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
            'class'     => 'Open NAT_PMP Server',
            'type'      => 'Info',
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
            'class'     => 'Open REDIS Server',
            'type'      => 'Info',
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
            'class'     => 'Open MemCached Server',
            'type'      => 'Info',
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
            'class'     => 'Open MemCached Server',
            'type'      => 'Info',
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
            'class'     => 'Open MongoDB Server',
            'type'      => 'Info',
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
