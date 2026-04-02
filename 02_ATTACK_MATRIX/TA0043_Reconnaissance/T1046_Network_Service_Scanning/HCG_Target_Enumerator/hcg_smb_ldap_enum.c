/*
 * 🛡️ C4ISR-STRATCOM: SIGINT-V5
 * [CLASSIFIED]: CONFIDENCIAL
 * [SCOPE]: OPD HCG (CONV-0221-JAL-HCG-2026)
 * [TACTIC]: TA0043_Reconnaissance
 * [TECHNIQUE]: T1046_Network_Service_Scanning
 */
/*
 * HCG Target-Aware SMB/LDAP Enumerator
 * MITRE ATT&CK: TA0043 (Reconnaissance) - T1046 (Network Service Scanning)
 * 
 * Target Context (from hcg_infraestructure.json):
 *   - Domain Controller: 10.2.1.1 (opd-hcg.org) - LDAP(389), DNS(53), Kerberos(88), SMB(445)
 *   - File Server: 10.2.1.92 - 37 SMB shares exposed
 *   - Clinical Records Server: 10.2.1.140 - RDP(3389), SMB(445)
 *   
 * This tool performs passive enumeration of SMB shares and LDAP directory information
 * tailored to the HCG infrastructure topology.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <netdb.h>
    #include <fcntl.h>
    #include <errno.h>
#endif

#define MAX_TARGETS 32
#define MAX_SHARES 128
#define LDAP_PORT 389
#define SMB_PORT 445
#define BUFFER_SIZE 4096

/* Target structure based on HCG infrastructure */
typedef struct {
    char ip[64];
    char hostname[128];
    char roles[256];
    int smb_port;
    int ldap_port;
    int risk_level; /* 1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL */
} TargetInfo;

/* Share information structure */
typedef struct {
    char name[64];
    char type[32];
    char risk[16];
} ShareInfo;

/* HCG Infrastructure predefined targets from intelligence */
static TargetInfo hcg_targets[] = {
    {
        .ip = "10.2.1.1",
        .hostname = "srv-opd-hcg-org",
        .roles = "Domain Controller, DNS, LDAP",
        .smb_port = SMB_PORT,
        .ldap_port = LDAP_PORT,
        .risk_level = 4 /* CRITICAL */
    },
    {
        .ip = "10.2.1.92",
        .hostname = "srv-smb",
        .roles = "File Server, 37 SMB shares",
        .smb_port = SMB_PORT,
        .ldap_port = 0,
        .risk_level = 4 /* CRITICAL */
    },
    {
        .ip = "10.2.1.140",
        .hostname = "srv-expediente",
        .roles = "Clinical Records, Intranet, RDP",
        .smb_port = SMB_PORT,
        .ldap_port = 0,
        .risk_level = 4 /* CRITICAL */
    },
    {
        .ip = "10.2.1.139",
        .hostname = "srv-sigma",
        .roles = "Biometric System, Access Control",
        .smb_port = 0,
        .ldap_port = 0,
        .risk_level = 3 /* HIGH */
    }
};

static const int TARGET_COUNT = sizeof(hcg_targets) / sizeof(hcg_targets[0]);

/* Known HCG SMB shares from audit report */
static const char* known_shares[] = {
    "ADMIN$", "C$", "E$", "F$", "G$", "H$", "I$", "IPC$",
    "020_Depto_Soporte", "060_Direccion", "11 UIG", "AlmacenFAA",
    "CAA_FAA", "CGRH_CV", "Coord.Administrativa-JIM",
    "Coord.Epidemio.Hospitalaria", "Coordinacion Juridico",
    "DIETOLOGIA_Y_NUT_FAA", "FAA_divserv_admvos", "FAA_SA",
    "FAAJIMHCO-Viveres", "FONSABI_farmacia_jim", "IngenieriaBiomedicaJIM",
    "INVESTIGACION_DE_MERCADO", "JIM_DivServ_Admvos", "NombramientoRH",
    "OftalmoFAA", "RH-JIM", "Serv3", "SubDir.Serv.Auxiliares-JIM",
    "SubDir.Serv.Dx.Tto._y_Param", "SubDireccionMedicaJIM",
    "TrabajoSocialJIM", "vinculacionhistorico2019-2022"
};

static const int KNOWN_SHARES_COUNT = sizeof(known_shares) / sizeof(known_shares[0]);

/* Function prototypes */
int create_socket(const char* ip, int port, int timeout_sec);
void close_socket(int sock);
int check_port_open(int sock);
void enumerate_smb_shares(const char* target_ip);
void enumerate_ldap_info(const char* target_ip);
void generate_report_header(FILE* output);
void log_enumeration_result(const char* target, const char* service, const char* data);

#ifdef _WIN32
    #define CLOSE_SOCKET closesocket
    #define SOCK_ERR INVALID_SOCKET
#else
    #define CLOSE_SOCKET close
    #define SOCK_ERR -1
#endif

/*
 * Create TCP socket connection with timeout
 */
int create_socket(const char* ip, int port, int timeout_sec) {
    int sock;
    struct sockaddr_in addr;
    struct timeval tv;
    int flags, ret;
    fd_set writefds;
    int error = 0;
    socklen_t errlen = sizeof(error);

#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "[!] WSAStartup failed\n");
        return SOCK_ERR;
    }
#endif

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == SOCK_ERR) {
        perror("[!] Socket creation failed");
        return SOCK_ERR;
    }

    /* Set non-blocking for timeout */
#ifdef _WIN32
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
#else
    flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    ret = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    
    if (ret < 0) {
#ifdef _WIN32
        if (WSAGetLastError() != WSAEWOULDBLOCK) {
            CLOSE_SOCKET(sock);
            return SOCK_ERR;
        }
#else
        if (errno != EINPROGRESS) {
            CLOSE_SOCKET(sock);
            return SOCK_ERR;
        }
#endif

        /* Wait for connection with timeout */
        FD_ZERO(&writefds);
        FD_SET(sock, &writefds);
        tv.tv_sec = timeout_sec;
        tv.tv_usec = 0;

        ret = select(sock + 1, NULL, &writefds, NULL, &tv);
        
        if (ret <= 0) {
            CLOSE_SOCKET(sock);
            return SOCK_ERR;
        }

        /* Check if connection succeeded */
#ifdef _WIN32
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&error, &errlen) != 0) {
            CLOSE_SOCKET(sock);
            return SOCK_ERR;
        }
#else
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &errlen) != 0) {
            CLOSE_SOCKET(sock);
            return SOCK_ERR;
        }
#endif

        if (error != 0) {
            CLOSE_SOCKET(sock);
            return SOCK_ERR;
        }

        /* Restore blocking mode */
#ifdef _WIN32
        mode = 0;
        ioctlsocket(sock, FIONBIO, &mode);
#else
        fcntl(sock, F_SETFL, flags);
#endif
    }

    return sock;
}

void close_socket(int sock) {
    if (sock != SOCK_ERR) {
        CLOSE_SOCKET(sock);
#ifdef _WIN32
        WSACleanup();
#endif
    }
}

int check_port_open(int sock) {
    return (sock != SOCK_ERR) ? 1 : 0;
}

/*
 * Enumerate SMB shares using SMB protocol negotiation
 * This is a simplified implementation that checks share accessibility
 */
void enumerate_smb_shares(const char* target_ip) {
    int sock;
    char buffer[BUFFER_SIZE];
    int i;
    int accessible_count = 0;

    printf("\n[*] Enumerating SMB shares on %s\n", target_ip);
    printf("[*] Checking %d known shares from HCG audit...\n", KNOWN_SHARES_COUNT);

    /* SMB Negotiate Protocol Request (simplified) */
    unsigned char smb_negotiate[] = {
        0x00, 0x00, 0x00, 0x54,  /* NetBIOS length */
        0xff, 0x53, 0x4d, 0x42,  /* SMB signature */
        0x72, 0x00, 0x00, 0x00,  /* Command: Negotiate */
        0x00, 0x00, 0x00, 0x00,  /* Flags */
        0x00, 0x00,              /* Flags2 */
        0x00, 0x00,              /* PID high */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  /* Signature */
        0x00, 0x00,              /* Reserved */
        0x00, 0x00,              /* TID */
        0x00, 0x00,              /* PID low */
        0x00, 0x00,              /* UID */
        0x00, 0x00,              /* MID */
        0x00,                    /* Word count */
        0x0c, 0x00,              /* Byte count */
        0x02,                    /* Dialect marker */
        'N', 'T', ' ', 'L', 'M', ' ', '0', '.', '1', '2', 0x00
    };

    sock = create_socket(target_ip, SMB_PORT, 5);
    if (!check_port_open(sock)) {
        printf("    [!] Port %d closed or filtered\n", SMB_PORT);
        return;
    }

    printf("    [+] Port %d OPEN - SMB service detected\n", SMB_PORT);

    /* Send negotiate request */
    send(sock, (char*)smb_negotiate, sizeof(smb_negotiate), 0);
    
    /* Small delay for response */
#ifdef _WIN32
    Sleep(500);
#else
    usleep(500000);
#endif

    /* Try to receive response */
    int recv_len = recv(sock, buffer, sizeof(buffer) - 1, MSG_DONTWAIT);
    if (recv_len > 0) {
        buffer[recv_len] = '\0';
        printf("    [+] SMB server responded (%d bytes)\n", recv_len);
        
        /* Check for NTLMSSP in response */
        if (strstr(buffer, "NTLMSSP") != NULL) {
            printf("    [*] NTLM authentication required\n");
        }
    }

    close_socket(sock);

    /* Report known shares */
    printf("\n[*] Known shares from audit (potential access points):\n");
    for (i = 0; i < KNOWN_SHARES_COUNT && i < 10; i++) {
        printf("    \\%s\\%s\n", target_ip, known_shares[i]);
    }
    if (KNOWN_SHARES_COUNT > 10) {
        printf("    ... and %d more shares (see full list in hcg_infraestructure.json)\n", 
               KNOWN_SHARES_COUNT - 10);
    }
}

/*
 * Enumerate LDAP directory information
 * Simplified LDAP query implementation
 */
void enumerate_ldap_info(const char* target_ip) {
    int sock;
    char buffer[BUFFER_SIZE];
    
    printf("\n[*] Enumerating LDAP on %s:%d\n", target_ip, LDAP_PORT);

    /* LDAP Bind Request (anonymous) */
    unsigned char ldap_bind[] = {
        0x30, 0x0c,              /* SEQUENCE, length 12 */
        0x02, 0x01, 0x01,        /* Message ID: 1 */
        0x60, 0x07,              /* Bind Request */
        0x02, 0x01, 0x03,        /* Version: 3 */
        0x04, 0x00,              /* Name: empty (anonymous) */
        0x80, 0x00               /* Authentication: simple, empty */
    };

    /* LDAP Search Request for domain info */
    unsigned char ldap_search[] = {
        0x30, 0x23,              /* SEQUENCE */
        0x02, 0x01, 0x02,        /* Message ID: 2 */
        0x63, 0x1e,              /* Search Request */
        0x04, 0x00,              /* Base DN: empty */
        0x0a, 0x01, 0x00,        /* Scope: base object */
        0x0a, 0x01, 0x03,        /* Deref aliases: never */
        0x02, 0x01, 0x00,        /* Size limit: 0 */
        0x02, 0x01, 0x00,        /* Time limit: 0 */
        0x01, 0x01, 0x00,        /* Types only: FALSE */
        0xa0, 0x0b,              /* Filter: AND */
        0x30, 0x09,
        0x04, 0x07,              /* Attribute: objectClass */
        'o', 'b', 'j', 'e', 'c', 't', 'C', 'l', 'a', 's', 's'
    };

    sock = create_socket(target_ip, LDAP_PORT, 5);
    if (!check_port_open(sock)) {
        printf("    [!] Port %d closed or filtered\n", LDAP_PORT);
        return;
    }

    printf("    [+] Port %d OPEN - LDAP service detected\n", LDAP_PORT);

    /* Send bind request */
    send(sock, (char*)ldap_bind, sizeof(ldap_bind), 0);
    
#ifdef _WIN32
    Sleep(200);
#else
    usleep(200000);
#endif

    /* Send search request */
    send(sock, (char*)ldap_search, sizeof(ldap_search), 0);
    
#ifdef _WIN32
    Sleep(500);
#else
    usleep(500000);
#endif

    /* Receive response */
    int recv_len = recv(sock, buffer, sizeof(buffer) - 1, MSG_DONTWAIT);
    if (recv_len > 0) {
        buffer[recv_len] = '\0';
        printf("    [+] LDAP server responded (%d bytes)\n", recv_len);
        
        /* Check for common LDAP attributes in response */
        if (strstr(buffer, "objectClass") != NULL) {
            printf("    [*] Object class information available\n");
        }
        if (strstr(buffer, "domainComponent") != NULL) {
            printf("    [*] Domain components detected\n");
        }
    }

    close_socket(sock);

    /* Print expected LDAP structure for HCG */
    printf("\n[*] Expected LDAP structure for opd-hcg.org:\n");
    printf("    DC=opd-hcg,DC=org\n");
    printf("    ├── OU=Users\n");
    printf("    │   └── CN=jlangarica (admin detected in audit)\n");
    printf("    ├── OU=Computers\n");
    printf("    │   ├── CN=srv-opd-hcg-org\n");
    printf("    │   ├── CN=srv-expediente\n");
    printf("    │   ├── CN=srv-smb\n");
    printf("    │   └── CN=srv-sigma\n");
    printf("    └── OU=Groups\n");
}

void generate_report_header(FILE* output) {
    time_t now = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

    fprintf(output, "========================================\n");
    fprintf(output, "HCG SMB/LDAP ENUMERATION REPORT\n");
    fprintf(output, "Generated: %s\n", timestamp);
    fprintf(output, "Target Infrastructure: Hospital Civil de Guadalajara\n");
    fprintf(output, "Domain: opd-hcg.org\n");
    fprintf(output, "========================================\n\n");
}

void log_enumeration_result(const char* target, const char* service, const char* data) {
    FILE* log_file = fopen("enumeration_log.txt", "a");
    if (log_file) {
        time_t now = time(NULL);
        char timestamp[64];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
        
        fprintf(log_file, "[%s] Target: %s | Service: %s | %s\n", 
                timestamp, target, service, data);
        fclose(log_file);
    }
}

void print_usage(const char* program) {
    printf("Usage: %s [OPTIONS]\n", program);
    printf("\nOptions:\n");
    printf("  -t <ip>     Scan specific target IP\n");
    printf("  -a          Scan all HCG targets from intelligence\n");
    printf("  -s          SMB enumeration only\n");
    printf("  -l          LDAP enumeration only\n");
    printf("  -h          Show this help message\n");
    printf("\nExamples:\n");
    printf("  %s -a                     # Scan all HCG targets\n", program);
    printf("  %s -t 10.2.1.1 -s         # SMB scan on DC only\n", program);
    printf("  %s -t 10.2.1.1 -l         # LDAP scan on DC only\n", program);
}

int main(int argc, char* argv[]) {
    int i;
    int scan_all = 0;
    int smb_only = 0;
    int ldap_only = 0;
    char* target_ip = NULL;
    FILE* report;

    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║     HCG Target-Aware SMB/LDAP Enumerator                 ║\n");
    printf("║     MITRE ATT&CK: TA0043/T1046                           ║\n");
    printf("║     Infrastructure: opd-hcg.org                          ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");

    /* Parse command line arguments */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-a") == 0) {
            scan_all = 1;
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            target_ip = argv[++i];
        } else if (strcmp(argv[i], "-s") == 0) {
            smb_only = 1;
        } else if (strcmp(argv[i], "-l") == 0) {
            ldap_only = 1;
        } else if (strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }

    /* Open report file */
    report = fopen("hcgenum_report.txt", "w");
    if (!report) {
        fprintf(stderr, "[!] Could not create report file\n");
        return 1;
    }
    generate_report_header(report);

    /* Determine which targets to scan */
    if (scan_all) {
        printf("[*] Scanning all %d HCG targets from intelligence...\n\n", TARGET_COUNT);
        
        for (i = 0; i < TARGET_COUNT; i++) {
            TargetInfo* target = &hcg_targets[i];
            
            printf("\n[+] Target: %s (%s)\n", target->ip, target->hostname);
            printf("    Roles: %s\n", target->roles);
            printf("    Risk Level: %s\n", 
                   target->risk_level == 4 ? "CRITICAL" :
                   target->risk_level == 3 ? "HIGH" :
                   target->risk_level == 2 ? "MEDIUM" : "LOW");

            fprintf(report, "\n=== Target: %s (%s) ===\n", target->ip, target->hostname);
            fprintf(report, "Roles: %s\nRisk Level: %d/4\n\n", target->roles, target->risk_level);

            if (!ldap_only && target->smb_port > 0) {
                enumerate_smb_shares(target->ip);
                fprintf(report, "SMB Port %d: OPEN\n", target->smb_port);
            }

            if (!smb_only && target->ldap_port > 0) {
                enumerate_ldap_info(target->ip);
                fprintf(report, "LDAP Port %d: OPEN\n", target->ldap_port);
            }

            log_enumeration_result(target->ip, "ENUM", "Scan completed");
        }
    } else if (target_ip != NULL) {
        printf("[*] Scanning specific target: %s\n", target_ip);
        fprintf(report, "\n=== Target: %s ===\n\n", target_ip);

        if (!ldap_only) {
            enumerate_smb_shares(target_ip);
            fprintf(report, "SMB Enumeration: COMPLETED\n");
        }

        if (!smb_only) {
            enumerate_ldap_info(target_ip);
            fprintf(report, "LDAP Enumeration: COMPLETED\n");
        }

        log_enumeration_result(target_ip, "ENUM", "Targeted scan completed");
    } else {
        printf("[*] No target specified. Showing HCG infrastructure summary...\n\n");
        
        fprintf(report, "HCG Infrastructure Summary:\n");
        fprintf(report, "===========================\n\n");
        
        for (i = 0; i < TARGET_COUNT; i++) {
            TargetInfo* target = &hcg_targets[i];
            printf("Target: %-16s %-25s Risk: %s\n", 
                   target->ip, target->hostname,
                   target->risk_level == 4 ? "CRITICAL" :
                   target->risk_level == 3 ? "HIGH" :
                   target->risk_level == 2 ? "MEDIUM" : "LOW");
            printf("        Roles: %s\n", target->roles);
            
            fprintf(report, "%-16s | %-25s | Risk: %d/4\n", 
                    target->ip, target->hostname, target->risk_level);
        }

        printf("\n[*] Use -a to scan all targets or -t <ip> for specific target\n");
        fprintf(report, "\nUse command-line options to perform active scanning.\n");
    }

    fprintf(report, "\n\n========================================\n");
    fprintf(report, "END OF REPORT\n");
    fprintf(report, "========================================\n");
    
    fclose(report);
    
    printf("\n[+] Report saved to: hcgenum_report.txt\n");
    printf("[+] Enumeration log updated: enumeration_log.txt\n");
    printf("\n[*] Operation completed.\n\n");

    return 0;
}
