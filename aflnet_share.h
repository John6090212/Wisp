#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef _AFLNET_SHARE_H
#define _AFLNET_SHARE_H
#include <sys/mman.h>
#include <fcntl.h> // O_* constant
#include <sys/stat.h> // mode constants
#include <stdlib.h>
#include <stdio.h>  
#include <string.h>  
#include <unistd.h>  
#include <sys/types.h>  
#include <sys/socket.h>  
#include <netinet/in.h>  
#include <arpa/inet.h> 
#include <pthread.h>
#include <limits.h>

/* share_queue.h start */
#define min(a,b) (((a) < (b)) ? (a) : (b))
#define max(a,b) (((a) > (b)) ? (a) : (b))
#define MESSAGE_MAX_LENGTH 1500

typedef struct share_queue share_queue;
typedef struct buffer buffer;
typedef struct message_t message_t;

struct share_queue {
    int front, rear, capacity, current_size;
    // data start offset
    int message_start_offset;
};

struct buffer {
    char *buf;
    int length;
};

// for datagram
struct message_t {
    int length;
    char buf[MESSAGE_MAX_LENGTH];
};

int stream_enqueue(void *shm, share_queue *q, char *c, int len);
buffer *stream_dequeue(void *shm, share_queue *q, int len);

// for datagram
int datagram_enqueue(void *shm, share_queue *q, message_t m);
message_t *datagram_dequeue(void *shm, share_queue *q);

/* share_queue.h end */

/* socket.h start */

typedef struct mysocket mysocket;
#define LO_MSS 65496

struct mysocket {
    int domain;
    int type;
    int protocol;
    // check socket exist
    int in_use;
    // for getsockname
    int has_bind;
    struct sockaddr addr;
    // for getpeername
    struct sockaddr peer_addr;
    // for shutdown
    int shutdown_read;
    int shutdown_write;
    // for MSG_MORE
    // tcp
    char *msg_more_buf;
    int msg_more_size;
    // for share memory communication
    int share_unit_index;
    share_queue *request_queue;
    share_queue *response_queue;
    pthread_mutex_t *request_lock;
    pthread_mutex_t *response_lock;
    // GETFL and SETFL flags
    int file_status_flags;
    // for dnsmasq
    int pollfds_index;
    // for poll
    int is_accept_fd;
    int is_server;
};

/* socket.h end */

/* queue.h start */

typedef struct Queue Queue;

// A structure to represent a queue
struct Queue {
    int front, rear, size;
    unsigned capacity;
    int* array;
};

typedef struct int_array int_array;
struct int_array{
    int *arr;
    int length;
};

Queue* createQueue(unsigned capacity);
int isFullQueue(Queue* queue);
int isEmptyQueue(Queue* queue);
int enqueue(Queue* queue, int item);
int dequeue(Queue* queue);
void destroyQueue(Queue* queue);
int_array *getQueueArray(Queue* queue);

// connect queue
typedef struct connection connection;
struct connection{
    struct sockaddr addr;
    int client_fd; // for accept queue checking
};

typedef struct connect_queue connect_queue;

struct connect_queue {
    int front, rear, size;
    unsigned capacity;
    int queue_start_offset;
};

int isFullConnectQueue(connect_queue* queue);
int isEmptyConnectQueue(connect_queue* queue);
int Connect_enqueue(void *shm, connect_queue* queue, connection item);
connection* Connect_dequeue(void *shm, connect_queue* queue);

// accept queue
typedef struct acception acception;
struct acception{
    int client_fd;
    int share_unit_index;
};

typedef struct accept_queue accept_queue;

struct accept_queue {
    int front, rear, size;
    unsigned capacity;
    int queue_start_offset;
};

int isFullAcceptQueue(accept_queue* queue);
int isEmptyAcceptQueue(accept_queue* queue);
int Accept_enqueue(void *shm, accept_queue* queue, acception item);
acception* Accept_dequeue(void *shm, accept_queue* queue);

/* queue.h end */

/* share.h start */

#define STREAM_QUEUE_CAPACITY 30080
#define DATAGRAM_QUEUE_CAPACITY 20
#define CONNECT_QUEUE_CAPACITY 20
#define ACCEPT_QUEUE_CAPACITY 10
// share memory size for share unit
#define COMMUNICATE_SHM_SIZE 0x400000
// share memory size for connect and accept 
#define CONNECT_SHM_SIZE 0x5000
// share memory size for close
#define CLOSE_SHM_SIZE 0x4000
// share queue number in share memory, an upper bound of max connections at a time of server
#define SOCKET_NUM 10

// share memory for socket communication 
int shm_fd;
void *shm_ptr;

typedef struct share_unit share_unit;
struct share_unit {
    share_queue request_queue;
    share_queue response_queue;
    pthread_mutex_t request_lock;
    pthread_mutex_t response_lock;
    char request_buf[STREAM_QUEUE_CAPACITY];
    char response_buf[STREAM_QUEUE_CAPACITY];
};

// share memory for socket connection
int connect_shm_fd;
void *connect_shm_ptr;
connect_queue *connect_queue_ptr;
accept_queue *accept_queue_ptr;
pthread_mutex_t *connect_lock;
pthread_mutex_t *accept_lock;

typedef struct close_unit close_unit;
struct close_unit {
    int client_read;
    int client_write;
    int server_read;
    int server_write;
};

// share memory for socket close
int close_shm_fd;
void *close_shm_ptr;
close_unit *close_arr;

/* share.h end */

/* inet_client_shm.c start */

mysocket socket_cli;

ssize_t my_recv(int sockfd, void *buf, size_t len, int flags);
ssize_t my_send(int sockfd, const void *buf, size_t len, int flags);
int my_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int my_socket(int domain, int type, int protocol);
int my_close(int fd);

/* inet_client_shm.c end */

#endif