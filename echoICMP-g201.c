/* 
 * Tema 8: ICMP-ECHO
 *
 * García Carbonero, Mario
 * Adán de la Fuente, Hugo
 */

#include "ip-icmp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

#define ICMP_ECHO 8
#define ICMP_ECHOREPLY 0

/* Función para obtener la descripción del error ICMP según el tipo y código */
char *
icmp_error_desc(uint8_t type, uint8_t code)
{
    switch (type) {
        case 3:
            switch (code) {
                case 0:  return "Destination Unreachable: Net Unreachable (Type 3, Code 0)";
                case 1:  return "Destination Unreachable: Host Unreachable (Type 3, Code 1)";
                case 2:  return "Destination Unreachable: Protocol Unreachable (Type 3, Code 2)";
                case 3:  return "Destination Unreachable: Port Unreachable (Type 3, Code 3)";
                case 4:  return "Destination Unreachable: Fragmentation Needed (Type 3, Code 4)";
                case 5:  return "Destination Unreachable: Source Route Failed (Type 3, Code 5)";
                case 6:  return "Destination Unreachable: Destination Network Unknown (Type 3, Code 6)";
                case 7:  return "Destination Unreachable: Destination Host Unknown (Type 3, Code 7)";
                case 8:  return "Destination Unreachable: Source Host Isolated (Type 3, Code 8)";
                case 11: return "Destination Unreachable: Destination Network Unreachable for Type of Service (Type 3, Code 11)";
                case 12: return "Destination Unreachable: Destination Host Unreachable for Type of Service (Type 3, Code 12)";
                case 13: return "Destination Unreachable: Communication Administratively Prohibited (Type 3, Code 13)";
                case 14: return "Destination Unreachable: Host Precedence Violation (Type 3, Code 14)";
                case 15: return "Destination Unreachable: Precedence Cutoff in Effect (Type 3, Code 15)";
                default: return "Destination Unreachable: Unknown Code";
            }

        case 5:
            switch (code) {
                case 1: return "Redirect: Redirect for Destination Host (Type 5, Code 1)";
                case 3: return "Redirect: Redirect for Destination Host Based on Type-of-Service (Type 5, Code 3)";
                default: return "Redirect: Unknown Code";
            }

        case 11:
            switch (code) {
                case 0: return "Time Exceeded: Time-to-Live Exceeded in Transit (Type 11, Code 0)";
                case 1: return "Time Exceeded: Fragment Reassembly Time Exceeded (Type 11, Code 1)";
                default: return "Time Exceeded: Unknown Code";
            }

        case 12:
            switch (code) {
                case 0: return "Parameter Problem: Pointer indicates the error (Type 12, Code 0)";
                case 1: return "Parameter Problem: Missing a Required Option (Type 12, Code 1)";
                case 2: return "Parameter Problem: Bad Length (Type 12, Code 2)";
                default: return "Parameter Problem: Unknown Code";
            }

        default:
            return "ICMP Error: Unknown Type";
    }
}

/* Función para calcular el checksum del datagrama ICMP */
int 
calculateChecksum(void *datagram, size_t len)
{
    uint32_t sum = 0;
    uint16_t *ptr = datagram;
    
    /* Sumar palabras de 16 bits */
    while (len > 1) {
        sum += *ptr;
        ptr++;
        len -= 2;
    }

    /* Si queda un byte, añadirlo */
    if (len == 1) {
        sum += *((uint8_t *)ptr);
    }

    /* Plegar los carries */
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    /* Complemento a uno */
    return ~sum;
}

int 
main(int argc, char *argv[])
{
    Echo echo_req;
    EchoReply echo_reply;
    struct sockaddr_in local_sockfd, dst_sockfd; 
    struct timeval send_time, recv_time, timeout;
    fd_set readfds;
    double rtt, total_time = 0.0, min_rtt = 0.0, max_rtt = 0.0, avg_rtt = 0.0;
    int sockfd;
    int packets_sent = 0, packets_received = 0;
    int ret;

    /* Comprobar número de argumentos */
    if (argc != 2) {
        fprintf(stderr, "Invalid Arguments\nUsage: sudo ./echoICMP <IPv4 Address>\n");
        return -1;
    }

    /* Convertir la dirección IP de formato texto a binario */
    struct in_addr dst_addr;
    if (inet_aton(argv[1], &dst_addr) == 0) {
        fprintf(stderr, "Invalid Arguments\nUsage: sudo ./echoICMP <IPv4 Address>\n");
        return -1;
    }

    /* Crear socket RAW para ICMP */
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
        perror("Socket Creation Failed");
        return -1;
    }
    
    /* Configurar dirección local para bind */
    memset(&local_sockfd, 0, sizeof(local_sockfd));
    local_sockfd.sin_family = AF_INET;
    local_sockfd.sin_addr.s_addr = INADDR_ANY;
    local_sockfd.sin_port = htons(0);

    /* Vincular socket a la interfaz local */
    if (bind(sockfd, (struct sockaddr *)&local_sockfd, sizeof(local_sockfd)) < 0) {
        perror("Socket Bind Failed");
        close(sockfd);
        return -1;
    }

    /* Preparar el mensaje ICMP Echo */
    memset(&echo_req, 0, sizeof(echo_req));
    echo_req.icmpHdr.type = ICMP_ECHO;
    echo_req.icmpHdr.code = 0;
    echo_req.icmpHdr.checksum = 0;
    echo_req.id = getpid();
    echo_req.sequence = 1; /* Inicializar a 1 según el enunciado */
    strcpy(echo_req.payload, "Echo to Check Availability");

    /* Calcular checksum */
    echo_req.icmpHdr.checksum = calculateChecksum(&echo_req, sizeof(echo_req));

    /* Configurar dirección destino */
    memset(&dst_sockfd, 0, sizeof(dst_sockfd));
    dst_sockfd.sin_family = AF_INET;
    dst_sockfd.sin_addr = dst_addr;
    dst_sockfd.sin_port = htons(0);

    printf("PING (%s): %lu bytes of data.\n", argv[1], sizeof(echo_req));

    /* Enviar 5 mensajes ICMP Echo */
    while (packets_sent < 5) {
        
        /* Registrar tiempo de envío */
        if (gettimeofday(&send_time, NULL) < 0) {
            perror("Getting Send Time Failed");
            close(sockfd);
            return -1;
        }

        /* Enviar mensaje ICMP Echo */
        if (sendto(sockfd, &echo_req, sizeof(echo_req), 0, 
                   (struct sockaddr *)&dst_sockfd, sizeof(dst_sockfd)) < 0) {
            perror("Send To Failed");
            close(sockfd);
            return -1;
        }
        
        packets_sent++;

        /* Configurar timeout de 5 segundos para select */
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        
        /* Configurar conjunto de descriptores para select */
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);

        /* Esperar respuesta con timeout */
        ret = select(sockfd + 1, &readfds, NULL, NULL, &timeout);

        if (ret < 0) {
            perror("Select Failed");
            close(sockfd);
            return -1;
        } else if (ret == 0) {
            /* Timeout: no se recibió respuesta */
            printf("Timeout Expired...\n");
            break;
        }

        /* Recibir respuesta */
        memset(&echo_reply, 0, sizeof(echo_reply));
        if (recvfrom(sockfd, &echo_reply, sizeof(echo_reply), 0, NULL, NULL) < 0) {
            perror("Receive From Failed");
            close(sockfd);
            return -1;
        }

        /* Registrar tiempo de recepción */
        if (gettimeofday(&recv_time, NULL) < 0) {
            perror("Getting Receive Time Failed");
            close(sockfd);
            return -1;
        }

        /* Calcular RTT en milisegundos */
        rtt = (recv_time.tv_sec - send_time.tv_sec) * 1000.0 + 
              (recv_time.tv_usec - send_time.tv_usec) / 1000.0;

        /* Procesar la respuesta según el tipo */
        if (echo_reply.echoMsg.icmpHdr.type == ICMP_ECHOREPLY && 
            echo_reply.echoMsg.icmpHdr.code == 0) {
            /* Echo Reply exitoso */
            packets_received++;
            total_time += rtt;
            
            if (packets_received == 1) {
                min_rtt = max_rtt = rtt;
            } else {
                if (rtt < min_rtt) min_rtt = rtt;
                if (rtt > max_rtt) max_rtt = rtt;
            }

            printf("%ld bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms\n",
                   sizeof(echo_reply),//.echoMsg),
                   inet_ntoa(echo_reply.IPHdr.srcAddr),
                   echo_reply.echoMsg.sequence,
                   echo_reply.IPHdr.ttl,
                   rtt);

        } else if (echo_reply.echoMsg.icmpHdr.type == ICMP_ECHO && 
                   echo_reply.echoMsg.icmpHdr.code == 0) {
            /* Caso especial: localhost o loopback sin procesar */
            printf("ICMP Datagram Not Processed...\n");
            break;

        } else {
            /* Error ICMP */
            printf("%s\n", icmp_error_desc(echo_reply.echoMsg.icmpHdr.type, 
                                          echo_reply.echoMsg.icmpHdr.code));
            break;
        }

        /* Incrementar número de secuencia */
        echo_req.sequence++;
        
        /* Recalcular checksum con nuevo sequence */
        echo_req.icmpHdr.checksum = 0;
        echo_req.icmpHdr.checksum = calculateChecksum(&echo_req, sizeof(echo_req));

        /* Esperar 1 segundo antes del siguiente envío (excepto en el último) */
        if (packets_sent < 5) {
            sleep(1);
        }
    }

    /* Mostrar estadísticas finales */
    printf("\n--- %s ping statistics ---\n", argv[1]);
    
    if (packets_received > 0) {
        avg_rtt = total_time / packets_received;
        printf("%d packet/s transmitted, %d received, %d packet loss, time %.3f ms\n",
               packets_sent, packets_received, packets_sent - packets_received, total_time);
        printf("rtt min/avg/max = %.3f/%.3f/%.3f ms\n", min_rtt, avg_rtt, max_rtt);
    } else {
        printf("%d packet/s transmitted, %d received, %d packet loss, time %.3f ms\n",
               packets_sent, packets_received, packets_sent - packets_received, 0.0);
    }

    close(sockfd);
    return 0;
}