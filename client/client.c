/*
 * NAME            : Yong-Sung Masuda
 *
 * HOMEWORK        : 8
 *
 * CLASS           : ICS 451
 *
 * INSTRUCTOR      : Ravi Narayan
 *
 * DATE            : November 19, 2022
 *
 * FILE            : client.c
 *
 * DESCRIPTION     : This file contains the client program that will start and complete a simulated TCP 3-way handshake and establish a connection to a server.
 *
 * REFERENCES      : https://www.gta.ufrj.br/ensino/eel878/sockets/sockaddr_inman.html
 *                   https://docs.oracle.com/cd/E19620-01/805-4041/6j3r8iu2l/index.html
 *                   https://agosta.faculty.polimi.it/lib/exe/socketfd74.pdf_%3B?id=teaching%3Apsrete&cache=cache&media=teaching:socket.pdf
 * */

#include <stdio.h> /* imports standard input and output functions */
#include <sys/socket.h> /* imports Posix socket api */
#include <netinet/in.h> /* imports protocols and socket address structure */
#include <unistd.h> /* imports close function */
#include <stdlib.h> /* imports atoi function to convert char array to int */
#include <time.h> /* imports time function that will be used to seed a pseudo-random sequence number */
#include <string.h>

/* creates the structure of the 20 byte TCP header */
struct tcp_header
{
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t sequence_number;
    uint32_t acknowledgement_number;
    unsigned int  data_offset:4;
    unsigned int  reserved:6;
    unsigned int flags:6; /* includes Header Length and Reserved bits */
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
};

/* provides readable values to be used for bit shifting */
enum FLAGS
{
    FIN,
    SYN,
    RST,
    PSH,
    ACK,
    URG
};

/* provides readable values to describe the state of the TCP connection */
enum STATES
{
    LISTEN,
    SYN_RECEIVED,
    SYN_SENT,
    ESTABLISHED
};

/* prints the TCP header in human-readable format */
void print_header_formatted(struct tcp_header *header)
{
    int spacing = 10;
    int i;
    char flags[23];
    for(i = 0; i < 23; i++)
    {
        flags[i] = '\0';
    }
    if(header->flags == 0)
    {
        strcpy(flags, "None");
    }
    else
    {
        if((header->flags & (0x01 << FIN)) == (0x01 << FIN))
        {
            strcpy(flags, " FIN");
        }
        if((header->flags & (0x01 << SYN)) == (0x01 << SYN))
        {
            strcat(flags, " SYN");
        }
        if((header->flags & (0x01 << RST)) == (0x01 << RST))
        {
            strcat(flags, " RST");
        }
        if((header->flags & (0x01 << PSH)) == (0x01 << PSH))
        {
            strcat(flags, " PSH");
        }
        if((header->flags & (0x01 << ACK)) == (0x01 << ACK))
        {
            strcat(flags, " ACK");
        }
        if((header->flags & (0x01 << URG)) == (0x01 << URG))
        {
            strcat(flags, " URG");
        }
    }
    printf("Source Port:            %*u\n", spacing, header->source_port);
    printf("Destination Port:       %*u\n", spacing, header->destination_port);
    printf("Sequence Number:        %*u\n", spacing, header->sequence_number);
    printf("Acknowledgement Number: %*u\n", spacing, header->acknowledgement_number);
    printf("Flags:                  %*s\n", spacing, flags);
    printf("\n");
}

/* prints the TCP header in hexadecimal */
void print_header_raw(struct tcp_header *header)
{
    int i;
    printf("Full header in hexadecimal:\n");
    for(i = 0; i < 20; i++)
    {
        printf("%02X ", *((unsigned char*)header + i));
    }
    printf("\n");
}

/* writes the outgoing TCP header based on the last received TCP header and current state */
void create_response(struct tcp_header *in, struct tcp_header *out, int *state)
{
    out->source_port = in->destination_port;
    out->destination_port = in->source_port;
    out->sequence_number = in->acknowledgement_number;
    out->acknowledgement_number = ++in->sequence_number;

    switch(*state) {
        case LISTEN:
            if (((in->flags >> SYN) & 0x01) == 0x01)
            {
                srand(time(NULL) + 5234); /* seeds with an arbitrary offset from time so as to make outgoing sequence number different from incoming */
                out->sequence_number = rand();
                out->data_offset = 0;
                out->reserved = 0;
                out->flags = ((0x01 << ACK) | (0x01 << SYN));
                out->window_size = 17520;
                out->checksum = 0xffff;
                out->urgent_pointer = 0;
                *state = SYN_RECEIVED;
            }
            break;
        case SYN_RECEIVED:
            if ((in->flags & ((0x01 << ACK))) == ((0x01 << ACK)))
            {
                out->flags = (0x00);
                *state = ESTABLISHED;
            }
            break;
        case SYN_SENT:
            if ((in->flags & ((0x01 << ACK) | (0X01 << SYN))) == ((0x01 << ACK) | (0X01 << SYN)))
            {
                out->flags = (0x01 << ACK);
                *state = ESTABLISHED;
            }
            break;
        case ESTABLISHED:
            if ((in->flags & (0x01 << FIN)) == 0x00)
            {
                out->flags = 0x00;
            }
    }
}

/* initializes a TCP header with actual ports, a random sequence number, a SYN flag, and filler values for window size, checksum, and urgent pointer */
void init_tcp_header(struct tcp_header *header, uint16_t source_port, uint16_t destination_port)
{
    srand(time(NULL));
    header->source_port = source_port;
    header->destination_port = destination_port;
    header->sequence_number = rand();
    header->acknowledgement_number = 0;
    header->data_offset = 0;
    header->reserved = 0;
    header->flags = 0x01 << SYN;
    header->window_size = 17520;
    header->checksum = 0xffff;
    header->urgent_pointer = 0;
}

int main(int argc, char const *argv[]) {
    /* ensures exactly one argument is passed to the program */
    if (argc != 2) {
        printf("port number must be specified\n");
    }

        /* ensures the argument is an integer not less than 1 and not greater than the maximum port number */
    else if (atoi(argv[1]) < 1 || atoi(argv[1])> 65535) {
        printf("port %s out of range\n", argv[1]);
    }

    /* main body of the client program */
    else {
        struct tcp_header *client_tcp_header = malloc(sizeof(struct tcp_header)); /* This memory will be reused for each outgoing TCP header */
        struct tcp_header *server_tcp_header; /* Will end up pointing to buffer */
        unsigned char *buffer = malloc(sizeof(struct tcp_header)); /* Server response will be recorded here  */
        int state;
        uint16_t source_port;
        uint16_t destination_port = atoi(argv[1]);
        int test_iterator = 0; /* Used in place of implementing a proper connection tear down */


        /* creates client socket */
        int my_socket = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);

        /* creating server address object for client socket to connect to */
        struct sockaddr_in server_address = {0};
        struct sockaddr_in client_address = {0};
        socklen_t len = sizeof(client_address);
        server_address.sin_family = AF_INET;
        server_address.sin_port = htons(destination_port);
        server_address.sin_addr.s_addr = htonl(INADDR_ANY);

        /* connecting client socket to remote socket */
        if(connect(my_socket, (struct sockaddr *) &server_address, sizeof(server_address)) == -1)
        {
            printf("There was an error making a connection to the remote socket \n\n");
        }
        else
        {
            printf("Successfully connected to remote socket\n\n");
        }

        /* Gets the source port number of the socket and stores it in source_port */
        if (getsockname(my_socket, (struct sockaddr *)&client_address, &len) == -1) {
            perror("There was an error getting the socket's name \n\n");
        }
        else {
            source_port = ntohs(client_address.sin_port);
        }

        /* initializes the first outgoing TCP header to be sent to the server */
        init_tcp_header(client_tcp_header, source_port, destination_port);
        state = SYN_SENT;

        /* This is where messages are sent to and received from the server */
        while(state < 4 && test_iterator < 3) {
            printf(">> Sending packet: \n");
            print_header_formatted(client_tcp_header);
            print_header_raw(client_tcp_header);
            printf("\n");

            /* Sends packet to server */
            if(send(my_socket, client_tcp_header, sizeof(struct tcp_header), 0) == -1)
            {
                printf("Error sending message to server\n");
            }
            else
            {
                printf("Message successfully sent to server\n");
            }

            /* Receives packet from server and writes it to buffer */
            if(recv(my_socket, buffer, sizeof(struct tcp_header), 0) == -1)
            {
                printf("Error receiving message from server\n");
            }
            else
            {
                printf("Message successfully received from server\n\n");
            }

            server_tcp_header = (struct tcp_header*)buffer;
            printf("<< Server packet: \n");
            print_header_formatted(server_tcp_header);
            print_header_raw(server_tcp_header);
            printf("\n");
            create_response(server_tcp_header, client_tcp_header, &state);
            test_iterator++;
        }

        /* closes client socket */
        close(my_socket);
    }
    return 0;
}