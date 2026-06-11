import re
from typing import Optional, Tuple
from core.models import PortFinding, ServiceType

class BannerAnalyzer:
    SIGNATURES = {
        ServiceType.SSH: [
            re.compile(r'^SSH-2\.0-([^\s\r\n]+)', re.IGNORECASE),
            re.compile(r'^SSH-1\.99-', re.IGNORECASE),
        ],
        ServiceType.HTTP: [
            re.compile(r'^HTTP/1\.[01]', re.IGNORECASE),
            re.compile(r'^<\?xml', re.IGNORECASE),
            re.compile(r'^<html', re.IGNORECASE),
            re.compile(r'^<!DOCTYPE', re.IGNORECASE),
            re.compile(r'^\{.*\}$', re.DOTALL),
        ],
        ServiceType.FTP: [
            re.compile(r'^220 .*FTP', re.IGNORECASE),
            re.compile(r'^220-.*FTP', re.IGNORECASE),
            re.compile(r'^220 .*FileZilla', re.IGNORECASE),
        ],
        ServiceType.SMTP: [
            re.compile(r'^220 .*SMTP', re.IGNORECASE),
            re.compile(r'^220 .*ESMTP', re.IGNORECASE),
            re.compile(r'^220 .*Postfix', re.IGNORECASE),
        ],
        ServiceType.TELNET: [
            re.compile(r'^Welcome to', re.IGNORECASE),
            re.compile(r'^login:', re.IGNORECASE),
            re.compile(r'^Password:', re.IGNORECASE),
        ],
        ServiceType.MYSQL: [re.compile(r'mysql', re.IGNORECASE)],
        ServiceType.POSTGRESQL: [re.compile(r'postgresql', re.IGNORECASE)],
        ServiceType.RDP: [re.compile(r'^\x03\x00\x00', re.DOTALL)],
        ServiceType.VNC: [re.compile(r'^RFB ', re.IGNORECASE)],
    }
    
    PORT_MAP = {
        20: ServiceType.FTP,      # FTP-DATA
        21: ServiceType.FTP,       # FTP
        69: ServiceType.TFTP,      # TFTP
        115: ServiceType.SFTP,     # SFTP
        2049: ServiceType.NFS,     # NFS

        22: ServiceType.SSH,       # SSH
        23: ServiceType.TELNET,   # Telnet
        513: ServiceType.RLOGIN,  # rlogin
        514: ServiceType.RSH,     # rsh
        2222: ServiceType.SSH,    # SSH alternate
        8022: ServiceType.SSH,    # SSH alternate
        10000: ServiceType.WEBMIN, # Webmin

        25: ServiceType.SMTP,     # SMTP
        110: ServiceType.POP3,    # POP3
        143: ServiceType.IMAP,    # IMAP
        465: ServiceType.SMTPS,   # SMTPS (SSL)
        587: ServiceType.SMTP,    # SMTP submission
        993: ServiceType.IMAPS,   # IMAPS (SSL)
        995: ServiceType.POP3S,   # POP3S (SSL)

        53: ServiceType.DNS,      # DNS
        5353: ServiceType.MDNS,   # mDNS (Bonjour)

        80: ServiceType.HTTP,     # HTTP
        443: ServiceType.HTTPS,   # HTTPS
        3000: ServiceType.HTTP,   # Node.js / React dev
        5000: ServiceType.HTTP,   # Flask / dev
        8000: ServiceType.HTTP,   # Django / dev
        8008: ServiceType.HTTP,   # HTTP alternate
        8080: ServiceType.HTTP,   # HTTP proxy / dev
        8081: ServiceType.HTTP,   # HTTP alternate
        8443: ServiceType.HTTPS,  # HTTPS alternate
        8888: ServiceType.HTTP,   # Jupyter / dev
        9000: ServiceType.HTTP,   # PHP-FPM / dev
        9090: ServiceType.HTTP,   # Cockpit / dev

        135: ServiceType.MS_RPC,   # MS RPC
        139: ServiceType.NETBIOS,  # NetBIOS
        445: ServiceType.SMB,     # SMB / CIFS

        389: ServiceType.LDAP,    # LDAP
        636: ServiceType.LDAPS,   # LDAPS (SSL)
        3268: ServiceType.LDAP,   # Global Catalog
        3269: ServiceType.LDAPS,  # Global Catalog SSL

        1433: ServiceType.MSSQL,   # Microsoft SQL
        1521: ServiceType.ORACLE,  # Oracle
        1527: ServiceType.ORACLE,  # Oracle alternate
        1830: ServiceType.ORACLE,  # Oracle
        3306: ServiceType.MYSQL,   # MySQL / MariaDB
        3351: ServiceType.MYSQL,   # MySQL alternate
        5432: ServiceType.POSTGRESQL, # PostgreSQL
        5433: ServiceType.POSTGRESQL, # PostgreSQL alternate
        6379: ServiceType.REDIS,   # Redis
        6380: ServiceType.REDIS,   # Redis alternate
        7000: ServiceType.CASSANDRA, # Cassandra
        7001: ServiceType.CASSANDRA, # Cassandra SSL
        7199: ServiceType.CASSANDRA, # Cassandra JMX
        9042: ServiceType.CASSANDRA, # Cassandra CQL
        9160: ServiceType.CASSANDRA, # Cassandra Thrift
        9200: ServiceType.ELASTICSEARCH, # Elasticsearch HTTP
        9201: ServiceType.ELASTICSEARCH, # Elasticsearch
        9300: ServiceType.ELASTICSEARCH, # Elasticsearch transport
        11211: ServiceType.MEMCACHED, # Memcached
        27017: ServiceType.MONGODB, # MongoDB
        27018: ServiceType.MONGODB, # MongoDB shard
        27019: ServiceType.MONGODB, # MongoDB config
        28017: ServiceType.MONGODB, # MongoDB web

        3389: ServiceType.RDP,    # RDP
        3390: ServiceType.RDP,    # RDP alternate
        5900: ServiceType.VNC,    # VNC
        5901: ServiceType.VNC,    # VNC display :1
        5902: ServiceType.VNC,    # VNC display :2
        5800: ServiceType.VNC,    # VNC over HTTP
        5801: ServiceType.VNC,    # VNC over HTTP :1
        6000: ServiceType.X11,     # X11
        6001: ServiceType.X11,     # X11 :1

        5060: ServiceType.SIP,    # SIP
        5061: ServiceType.SIPS,   # SIP-TLS
        5160: ServiceType.SIP,    # SIP alternate

        500: ServiceType.IPSEC,    # IPsec IKE
        1701: ServiceType.L2TP,   # L2TP
        1723: ServiceType.PPTP,   # PPTP
        4500: ServiceType.IPSEC,  # IPsec NAT-T
        1194: ServiceType.OPENVPN, # OpenVPN

        515: ServiceType.LPD,     # LPD / LPR
        631: ServiceType.IPP,     # IPP (CUPS)
        9100: ServiceType.JETDIRECT, # HP JetDirect

        161: ServiceType.SNMP,    # SNMP
        162: ServiceType.SNMP,   # SNMP trap
        199: ServiceType.SMUX,    # SMUX
        10050: ServiceType.ZABBIX, # Zabbix agent
        10051: ServiceType.ZABBIX, # Zabbix server

        102: ServiceType.S7,      # Siemens S7
        502: ServiceType.MODBUS,  # Modbus TCP
        503: ServiceType.MODBUS,  # Modbus alternate
        1089: ServiceType.NFON,   # Nfon
        1090: ServiceType.NFON,   # Nfon
        1911: ServiceType.FOX,    # Fox
        2404: ServiceType.IEC104, # IEC 60870-5-104
        34962: ServiceType.ETHERNET_IP, # EtherNet/IP
        34963: ServiceType.ETHERNET_IP, # EtherNet/IP
        34964: ServiceType.ETHERNET_IP, # EtherNet/IP
        44818: ServiceType.ETHERNET_IP, # EtherNet/IP
        47808: ServiceType.BACNET, # BACnet

        6667: ServiceType.IRC,    # IRC
        6668: ServiceType.IRC,    # IRC
        6669: ServiceType.IRC,    # IRC
        6697: ServiceType.IRC,    # IRC SSL
        6881: ServiceType.BITTORRENT, # BitTorrent
        6882: ServiceType.BITTORRENT, # BitTorrent
        6883: ServiceType.BITTORRENT, # BitTorrent

        27015: ServiceType.STEAM,  # Source engine
        27016: ServiceType.STEAM,  # Source engine
        7777: ServiceType.GAME,    # Unreal / various
        7778: ServiceType.GAME,    # Unreal / various

        111: ServiceType.RPCBIND,  # RPCbind / portmapper
        113: ServiceType.IDENT,    # Ident
        179: ServiceType.BGP,     # BGP
        4433: ServiceType.VMWARE,  # VMware
        5001: ServiceType.VMWARE,  # VMware
        5984: ServiceType.COUCHDB, # CouchDB
        5985: ServiceType.WINRM,   # WinRM HTTP
        5986: ServiceType.WINRM,   # WinRM HTTPS
        6443: ServiceType.KUBERNETES, # Kubernetes API
        6444: ServiceType.KUBERNETES, # Kubernetes
        7474: ServiceType.NEO4J,   # Neo4j
        7687: ServiceType.NEO4J,   # Neo4j Bolt
        7473: ServiceType.NEO4J,   # Neo4j HTTPS
        8123: ServiceType.CLICKHOUSE, # ClickHouse
        8124: ServiceType.CLICKHOUSE, # ClickHouse
        9003: ServiceType.CLICKHOUSE, # ClickHouse
        9092: ServiceType.KAFKA,   # Kafka
        9093: ServiceType.KAFKA,   # Kafka SSL
        9094: ServiceType.KAFKA,   # Kafka SASL
        2181: ServiceType.ZOOKEEPER, # ZooKeeper
        2888: ServiceType.ZOOKEEPER, # ZooKeeper
        3888: ServiceType.ZOOKEEPER, # ZooKeeper
        2375: ServiceType.DOCKER,  # Docker (unencrypted)
        2376: ServiceType.DOCKER,  # Docker (TLS)
        4243: ServiceType.DOCKER,  # Docker alternate
        50000: ServiceType.DRBD,   # DRBD
        50070: ServiceType.HADOOP, # Hadoop NameNode
        50075: ServiceType.HADOOP, # Hadoop DataNode
        8088: ServiceType.HADOOP,  # Hadoop YARN
        19888: ServiceType.HADOOP, # Hadoop JobHistory
        8042: ServiceType.HADOOP,  # Hadoop NodeManager
        8889: ServiceType.JUPYTER, # JupyterHub
        8787: ServiceType.RSTUDIO, # RStudio
        5601: ServiceType.KIBANA,  # Kibana
        5044: ServiceType.LOGSTASH, # Logstash
        9600: ServiceType.LOGSTASH, # Logstash API
        8200: ServiceType.VAULT,   # HashiCorp Vault
        8201: ServiceType.VAULT,   # HashiCorp Vault
        8500: ServiceType.CONSUL,  # Consul
        8600: ServiceType.CONSUL,  # Consul DNS
        8300: ServiceType.CONSUL,  # Consul server RPC
        8301: ServiceType.CONSUL,  # Consul Serf LAN
        8302: ServiceType.CONSUL,  # Consul Serf WAN
        4646: ServiceType.NOMAD,   # Nomad
        4647: ServiceType.NOMAD,   # Nomad
        4648: ServiceType.NOMAD,   # Nomad
        3001: ServiceType.GRAFANA, # Grafana
        3002: ServiceType.GRAFANA, # Grafana alternate
        9093: ServiceType.ALERTMANAGER, # Prometheus Alertmanager
        9091: ServiceType.PUSHGATEWAY, # Prometheus Pushgateway
        9100: ServiceType.NODE_EXPORTER, # Prometheus Node Exporter
        9115: ServiceType.BLACKBOX, # Prometheus Blackbox
        9163: ServiceType.PROMETHEUS, # Prometheus
        8428: ServiceType.VICTORIAMETRICS, # VictoriaMetrics
        8429: ServiceType.VICTORIAMETRICS, # VictoriaMetrics
        2003: ServiceType.GRAPHITE, # Graphite
        2004: ServiceType.GRAPHITE, # Graphite
        8125: ServiceType.STATSD,  # StatsD
        8126: ServiceType.STATSD,  # StatsD
        5672: ServiceType.RABBITMQ, # RabbitMQ AMQP
        5671: ServiceType.RABBITMQ, # RabbitMQ AMQPS
        15672: ServiceType.RABBITMQ, # RabbitMQ Management
        15671: ServiceType.RABBITMQ, # RabbitMQ Management SSL
        25672: ServiceType.RABBITMQ, # RabbitMQ clustering
        4369: ServiceType.EPMD,    # Erlang Port Mapper
        5673: ServiceType.RABBITMQ, # RabbitMQ alternate
        61613: ServiceType.STOMP,  # STOMP
        61614: ServiceType.STOMP,  # STOMP SSL
        5674: ServiceType.RABBITMQ, # RabbitMQ alternate
        9418: ServiceType.GIT,    # Git daemon
        3690: ServiceType.SVN,    # SVN
        2947: ServiceType.GPSD,   # GPSD
        3240: ServiceType.ISCSI,   # iSCSI
        3260: ServiceType.ISCSI,   # iSCSI target
        860: ServiceType.ISCSI,    # iSCSI
        2409: ServiceType.OPENVMS, # OpenVMS
        1080: ServiceType.SOCKS,  # SOCKS proxy
        1081: ServiceType.SOCKS,  # SOCKS alternate
        3128: ServiceType.SQUID,  # Squid proxy
        808: ServiceType.SQUID,   # Squid alternate
        8118: ServiceType.PRIVACY, # Privoxy
        9050: ServiceType.TOR,     # Tor SOCKS
        9051: ServiceType.TOR,     # Tor control
        9150: ServiceType.TOR,     # Tor Browser
        4444: ServiceType.METASPLOIT, # Metasploit
        5555: ServiceType.ANDROID, # Android ADB
        5037: ServiceType.ANDROID, # Android ADB alternate
        5554: ServiceType.ANDROID, # Android emulator
        10001: ServiceType.UBIQUITI, # Ubiquiti
        10002: ServiceType.UBIQUITI, # Ubiquiti
        10003: ServiceType.UBIQUITI, # Ubiquiti
        8291: ServiceType.MIKROTIK, # MikroTik Winbox
        8728: ServiceType.MIKROTIK, # MikroTik API
        8729: ServiceType.MIKROTIK, # MikroTik API SSL
        8292: ServiceType.MIKROTIK, # MikroTik Neighbor
        1700: ServiceType.RADIUS,  # RADIUS accounting
        1812: ServiceType.RADIUS,  # RADIUS authentication
        1813: ServiceType.RADIUS,  # RADIUS accounting
        1645: ServiceType.RADIUS,  # RADIUS old
        1646: ServiceType.RADIUS,  # RADIUS old accounting
        2082: ServiceType.CPANEL,  # cPanel
        2083: ServiceType.CPANEL,  # cPanel SSL
        2086: ServiceType.CPANEL,  # cPanel WHM
        2087: ServiceType.CPANEL,  # cPanel WHM SSL
        2095: ServiceType.CPANEL,  # cPanel Webmail
        2096: ServiceType.CPANEL,  # cPanel Webmail SSL
        2077: ServiceType.CPANEL,  # cPanel alternate
        2078: ServiceType.CPANEL,  # cPanel alternate SSL
        2080: ServiceType.CPANEL,  # cPanel alternate
        2081: ServiceType.CPANEL,  # cPanel alternate SSL
        5431: ServiceType.PGADMIN, # pgAdmin
        5050: ServiceType.PGADMIN, # pgAdmin alternate
        7475: ServiceType.PGADMIN, # pgAdmin alternate
        4848: ServiceType.GLASSFISH, # GlassFish
        8686: ServiceType.GLASSFISH, # GlassFish
        3700: ServiceType.GLASSFISH, # GlassFish IIOP
        3820: ServiceType.GLASSFISH, # GlassFish IIOP SSL
        3920: ServiceType.GLASSFISH, # GlassFish IIOP
        7676: ServiceType.GLASSFISH, # GlassFish JMS
        8181: ServiceType.GLASSFISH, # GlassFish HTTP
        4849: ServiceType.GLASSFISH, # GlassFish admin
        9009: ServiceType.JBOSS,   # JBoss
        8447: ServiceType.JBOSS,   # JBoss
        9990: ServiceType.JBOSS,   # JBoss management
        9999: ServiceType.JBOSS,   # JBoss
        4447: ServiceType.JBOSS,   # JBoss remoting
        4712: ServiceType.JBOSS,   # JBoss
        4713: ServiceType.JBOSS,   # JBoss
        7600: ServiceType.JBOSS,   # JBoss clustering
        55200: ServiceType.JBOSS,   # JBoss
        45700: ServiceType.JBOSS,   # JBoss
        45688: ServiceType.JBOSS,   # JBoss
        4446: ServiceType.JBOSS,   # JBoss
        1098: ServiceType.JBOSS,   # JBoss naming
        1099: ServiceType.JBOSS,   # JBoss naming
        1100: ServiceType.JBOSS,   # JBoss
        1101: ServiceType.JBOSS,   # JBoss
        1102: ServiceType.JBOSS,   # JBoss
        1103: ServiceType.JBOSS,   # JBoss
        4445: ServiceType.JBOSS,   # JBoss
        8083: ServiceType.JBOSS,   # JBoss
        4443: ServiceType.JBOSS,   # JBoss
        4714: ServiceType.JBOSS,   # JBoss
        5445: ServiceType.JBOSS,   # JBoss
        5446: ServiceType.JBOSS,   # JBoss
        4457: ServiceType.JBOSS,   # JBoss
        4458: ServiceType.JBOSS,   # JBoss
        8082: ServiceType.JBOSS,   # JBoss
        9993: ServiceType.JBOSS,   # JBoss
        9994: ServiceType.JBOSS,   # JBoss
        9995: ServiceType.JBOSS,   # JBoss
        9996: ServiceType.JBOSS,   # JBoss
        9997: ServiceType.JBOSS,   # JBoss
        9998: ServiceType.JBOSS,   # JBoss
        17501: ServiceType.JBOSS,  # JBoss
        15001: ServiceType.JBOSS,  # JBoss
        15002: ServiceType.JBOSS,  # JBoss
        15003: ServiceType.JBOSS,  # JBoss
        15004: ServiceType.JBOSS,  # JBoss
        15005: ServiceType.JBOSS,  # JBoss
        15006: ServiceType.JBOSS,  # JBoss
        15007: ServiceType.JBOSS,  # JBoss
        15008: ServiceType.JBOSS,  # JBoss
        15009: ServiceType.JBOSS,  # JBoss
        15010: ServiceType.JBOSS,  # JBoss
    }

    @staticmethod
    def analyze(finding: PortFinding) -> PortFinding:
        banner = finding.banner or ""
        service = ServiceType.UNKNOWN
        version = None

        for svc, patterns in BannerAnalyzer.SIGNATURES.items():
            for pattern in patterns:
                match = pattern.search(banner)
                if match:
                    service = svc
                    if match.groups():
                        version = match.group(1)
                    break
            if service != ServiceType.UNKNOWN:
                break

        if service == ServiceType.UNKNOWN:
            service = BannerAnalyzer.PORT_MAP.get(finding.port, ServiceType.UNKNOWN)

        if service in (ServiceType.HTTP, ServiceType.HTTPS) and banner:
            server_match = re.search(r'Server:\s*([^\r\n]+)', banner, re.IGNORECASE) # ИСПРАВЛЕНО
            if server_match:
                version = server_match.group(1).strip()

        if service == ServiceType.SSH and banner:
            ssh_match = re.search(r'^SSH-2\.0-([^\s\r\n]+)', banner, re.IGNORECASE) # ИСПРАВЛЕНО
            if ssh_match:
                version = ssh_match.group(1)

        finding.service = service
        finding.service_version = version
        return finding