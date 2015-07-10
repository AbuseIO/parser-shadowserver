<?php

return
    [
        'parser' =>
        [
            'name'          => 'Shadowserver',
            'enabled'       => true,
            'sender_map'    =>
            [
                '/autoreports@shadowserver.org/',
            ],
            'body_map'      =>
            [
                //
            ],
            'default'      =>
            [
                'class'     => 'Unknown classification',
                'type'      => 'Abuse',
                'enabled'   => false,
            ],
        ],
        'feeds' =>
        [
            'scan_elasticsearch' =>
            [
                'class'     => 'Open ElasticSearch Server',
                'fields'    => 'protocol port version name cluster_name',
                'type'      => 'Info',
                'enabled'   => true,
            ],
            'scan_qotd' =>
            [
                'class'     => 'Open QOTD Server',
                'fields'    => 'protocol port',
                'type'      => 'Info',
                'enabled'   => true,
            ],
            'spam_url' =>
            [
                'class'     => 'Spamvertised web site',
                'fields'    => 'url host',
                'type'      => 'Abuse',
                'enabled'   => true,
            ],
            'scan_mssql' =>
            [
                'class'     => 'Open Microsoft SQL Server',
                'fields'    => 'protocol port version instance_name tcp_port named_pipe response_length amplification',
                'type'      => 'Info',
                'enabled'   => true,
            ],
            'scan_ssl_poodle' =>
            [
                'class'     => 'SSLv3 Vulnerable Server',
                'fields'    => 'port handshake cipher_suite subject_common_name issuer_common_name cert_expiration_date issuer_organization_name',
                'type'      => 'Info',
                'enabled'   => true,
            ],
            'ssl_scan' =>
            [
                'class'     => 'SSLv3 Vulnerable Server',
                'fields'    => 'port handshake cipher_suite subject_common_name issuer_common_name cert_expiration_date issuer_organization_name',
                'type'      => 'Info',
                'enabled'   => true,
            ],
            'scan_ssl_freak' =>
            [
                'class'     => 'FREAK Vulnerable Server',
                'fields'    => 'port handshake cipher_suite freak_cipher_suite subject_common_name issuer_common_name cert_expiration_date',
                'type'      => 'Info',
                'enabled'   => true,
            ],
            'cc_ip' =>
            [
                'class'     => 'Command and control server',
                'fields'    => 'port channel',
                'type'      => 'Abuse',
                'enabled'   => true,
            ],
            'scan_ntpmonitor' =>
            [
                'class'     => 'Possible DDOS sending NTP Server',
                'fields'    => 'protocol port hostname packets size',
                'type'      => 'Abuse',
                'enabled'   => true,
            ],
            'compromised_website' =>
            [
                'class'     => 'Compromised website',
                'fields'    => 'http_host category tag redirect_target',
                'type'      => 'Abuse',
                'enabled'   => true,
            ],
            'cwsandbox_url' =>
            [
                'class'     => 'Malware infection',
                'fields'    => 'md5hash url user_agent host method',
                'type'      => 'Abuse',
                'enabled'   => true,
            ],
            'sinkhole_http_drone' =>
            [
                'class'     => 'Botnet infection',
                'fields'    => 'type url http_agent src_port dst_ip dst_port',
                'type'      => 'Abuse',
                'enabled'   => true,
            ],
            'microsoft_sinkhole' =>
            [
                'class'     => 'Botnet infection',
                'fields'    => 'type url http_agent src_port dst_ip dst_port',
                'type'      => 'Abuse',
                'enabled'   => true,
            ],
            'botnet_drone' =>
            [
                'class'     => 'Botnet infection',
                'fields'    => 'infection url agent cc cc_port cc_dns',
                'type'      => 'Abuse',
                'enabled'   => true,
            ],
            'dns_openresolver' =>
            [
                'class'     => 'Open DNS Resolver',
                'fields'    => 'protocol port min_amplification dns_version',
                'type'      => 'Info',
                'enabled'   => true,
            ],
            'scan_ntp' =>
            [
                'class'     => 'Open NTP Server',
                'fields'    => 'clock error frequency peer refid reftime stratum system',
                'type'      => 'Info',
                'enabled'   => true,
            ],
            'scan_snmp' =>
            [
                'class'     => 'Open SNMP Server',
                'fields'    => 'sysdesc sysname version',
                'type'      => 'Info',
                'enabled'   => true,
            ],
            'scan_netbios' =>
            [
                'class'     => 'Open Netbios Server',
                'fields'    => 'mac_address workgroup machine_name username',
                'type'      => 'Info',
                'enabled'   => true,
            ],
            'scan_ssdp' =>
            [
                'class'     => 'Open SSDP Server',
                'fields'    => 'systime location server unique_service_name',
                'type'      => 'Info',
                'enabled'   => true,
            ],
            'scan_chargen' =>
            [
                'class'     => 'Open Chargen Server',
                'fields'    => 'protocol port size',
                'type'      => 'Info',
                'enabled'   => true,
            ],
            'scan_ipmi' =>
            [
                'class'     => 'Open IPMI Server',
                'fields'    => 'port ipmi_version none_auth md2_auth md5_auth passkey_auth oem_auth defaultkg permessage_auth userlevel_auth usernames nulluser anon_login',
                'type'      => 'Info',
                'enabled'   => true,
            ],
            'scan_net_pmp' =>
            [
                'class'     => 'Open NAT_PMP Server',
                'fields'    => 'protocol port version uptime',
                'type'      => 'Info',
                'enabled'   => true,
            ],
            'scan_nat_pmp' =>
            [
                'class'     => 'Open NAT_PMP Server',
                'fields'    => 'protocol port version uptime',
                'type'      => 'Info',
                'enabled'   => true,
            ],
            'scan_redis' =>
            [
                'class'     => 'Open REDIS Server',
                'fields'    => 'protocol port version mode os process_id',
                'type'      => 'Info',
                'enabled'   => true,
            ],
            'wiki_file' =>
            [
                //Apparently shadowserver used this one in error, keeping it for parsing history
                'class'     => 'Open MemCached Server',
                'fields'    => 'protocol port version uptime curr_connections total_connections',
                'type'      => 'Info',
                'enabled'   => true,
            ],
            'scan_memcached' =>
            [
                'class'     => 'Open MemCached Server',
                'fields'    => 'protocol port version uptime curr_connections total_connections',
                'type'      => 'Info',
                'enabled'   => true,
            ],
            'scan_mongodb' =>
            [
                'class'     => 'Open MongoDB Server',
                'fields'    => 'protocol port version sysInfo visible_databases',
                'type'      => 'Info',
                'enabled'   => true,
            ],
        ],
    ];
