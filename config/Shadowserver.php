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
                'sysInfo',
                'visible_databases',
            ],
        ],
    ],
];
