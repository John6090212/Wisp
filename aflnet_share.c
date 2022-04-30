#include "aflnet_share.h"

/* share_queue.c start */

int stream_enqueue(void *shm, share_queue *q, char *c, int len){
    char *m_arr = (char *)(shm+q->message_start_offset);

    // queue is full
    if(q->current_size == q->capacity){
        // printf("Queue is full!\n");
        return -1;
    }
    
    int add_len = min((q->capacity-q->current_size), len);
    // queue is empty
    if(q->front == -1){
        q->front = q->rear = 0;
        memcpy(&m_arr[q->rear], c, add_len*sizeof(char));
        q->rear = (add_len - 1) % q->capacity;
    }
    // normal condition
    else{
        q->rear = (q->rear + 1) % q->capacity;
        memcpy(&m_arr[q->rear], c, add_len*sizeof(char));
        q->rear = (q->rear + add_len - 1) % q->capacity;
        
    }
    q->current_size += add_len;

    return add_len;
}

// need to free buffer and char*
buffer *stream_dequeue(void *shm, share_queue *q, int len){
    char *m_arr = (char *)(shm+q->message_start_offset);

    int sub_len = min((q->current_size), len);
    char *m = (char *)malloc(sub_len*sizeof(char));
    buffer *b = (buffer *)malloc(sizeof(buffer));
    if(q->front == -1){
        // printf("Queue is empty!\n");
        free(m);
        m = NULL;
        b->buf = m;
        b->length = 0;
        return b;
    }
    
    memcpy(m, &m_arr[q->front], sub_len*sizeof(char));
    memset(&m_arr[q->front], 0, sub_len*sizeof(char));
    q->current_size -= sub_len;
    // reset front and rear if queue becomes empty
    if(q->current_size == 0){
        q->front = -1;
        q->rear = -1;
    }
    // normal condition
    else
        q->front = (q->front + sub_len) % q->capacity;
    
    b->buf = m;
    b->length = sub_len;

    return b;
}

int datagram_enqueue(void *shm, share_queue *q, message_t m){
    message_t *m_arr = (message_t *)(shm+q->message_start_offset);
    // queue is full
    if (q->current_size == q->capacity){
        return -1;
    }
    // queue is empty
    if(q->front == -1){
        q->front = q->rear = 0;
        memcpy(&m_arr[q->rear], &m, sizeof(message_t));
    }
    // normal condition
    else{
        q->rear = (q->rear + 1) % q->capacity;
        memcpy(&m_arr[q->rear], &m, sizeof(message_t));
    }
    q->current_size++;

    return 0;
}

message_t *datagram_dequeue(void *shm, share_queue *q){
    message_t *m_arr = (message_t *)(shm+q->message_start_offset);
    message_t *m = (message_t *)malloc(sizeof(message_t));
    if(q->front == -1){
        m->length = 0;
        return m;
    }
    
    memcpy(m, &m_arr[q->front], sizeof(message_t));
    m_arr[q->front].length = 0;
    // reset front and rear if queue becomes empty
    if(q->front == q->rear){
        q->front = -1;
        q->rear = -1;
    }
    // normal condition
    else
        q->front = (q->front + 1) % q->capacity;
    
    q->current_size--;

    return m;    
}

/* share_queue.c end */

/* queue.c start */

// function to create a queue
// of given capacity.
// It initializes size of queue as 0
Queue* createQueue(unsigned capacity)
{
    Queue* queue = (Queue*)malloc(
        sizeof(Queue));
    queue->capacity = capacity;
    queue->front = queue->size = 0;
 
    // This is important, see the enqueue
    queue->rear = capacity - 1;
    queue->array = (int*)malloc(
        queue->capacity * sizeof(int));
    return queue;
}
 
// Queue is full when size becomes
// equal to the capacity
int isFullQueue(Queue* queue)
{
    return (queue->size == queue->capacity);
}
 
// Queue is empty when size is 0
int isEmptyQueue(Queue* queue)
{
    return (queue->size == 0);
}
 
// Function to add an item to the queue.
// It changes rear and size
int enqueue(Queue* queue, int item)
{
    if (isFullQueue(queue))
        return -1;
    queue->rear = (queue->rear + 1)
                  % queue->capacity;
    queue->array[queue->rear] = item;
    queue->size = queue->size + 1;
    return 0;
}
 
// Function to remove an item from queue.
// It changes front and size
int dequeue(Queue* queue)
{
    if (isEmptyQueue(queue))
        return INT_MIN;
    int item = queue->array[queue->front];
    queue->front = (queue->front + 1)
                   % queue->capacity;
    queue->size = queue->size - 1;
    return item;
}

void destroyQueue(Queue* queue){
    if(queue != NULL){
        if(queue->array != NULL)
            free(queue->array);
        free(queue);
    }
}

int_array *getQueueArray(Queue* queue){
    if(queue == NULL || queue->size == 0)
        return NULL;

    int *arr = (int *)malloc(queue->size*sizeof(int));
    for(int i = 0; i < queue->size; i++){
        arr[i] = queue->array[(queue->front+i)%queue->capacity];
    }
    int_array *ia = (int_array *)malloc(sizeof(int_array));
    ia->arr = arr;
    ia->length = queue->size;

    return ia;
}

// connect queue function
connect_queue* createConnectQueue(unsigned capacity){
    connect_queue* queue = (connect_queue*)malloc(
        sizeof(struct connect_queue));
    queue->capacity = capacity;
    queue->front = queue->size = 0;
 
    // This is important, see the enqueue
    queue->rear = capacity - 1;
    return queue;
}

int isFullConnectQueue(connect_queue* queue){
    return (queue->size == queue->capacity);
}

int isEmptyConnectQueue(connect_queue* queue){
    return (queue->size == 0);
}

int Connect_enqueue(void *shm, connect_queue* queue, connection item){
    connection *array = (connection *)(shm+queue->queue_start_offset);
    if (isFullConnectQueue(queue))
        return -1;
    queue->rear = (queue->rear + 1)
                  % queue->capacity;
    memcpy(&array[queue->rear], &item, sizeof(connection));
    queue->size = queue->size + 1;
    return 0;
}

connection* Connect_dequeue(void *shm, connect_queue* queue){
    connection *array = (connection *)(shm+queue->queue_start_offset);
    if (isEmptyConnectQueue(queue))
        return NULL;
    connection *item = (connection*)malloc(sizeof(connection));
    memcpy(item, &array[queue->front], sizeof(connection));
    queue->front = (queue->front + 1)
                   % queue->capacity;
    queue->size = queue->size - 1;
    return item;
}

// accept queue function
accept_queue* createAcceptQueue(unsigned capacity){
    accept_queue* queue = (accept_queue*)malloc(
        sizeof(struct accept_queue));
    queue->capacity = capacity;
    queue->front = queue->size = 0;
 
    // This is important, see the enqueue
    queue->rear = capacity - 1;

    return queue;
}

int isFullAcceptQueue(accept_queue* queue){
    return (queue->size == queue->capacity);
}

int isEmptyAcceptQueue(accept_queue* queue){
    return (queue->size == 0);
}

int Accept_enqueue(void *shm, accept_queue* queue, acception item){
    acception *array = (acception *)(shm+queue->queue_start_offset);
    if (isFullAcceptQueue(queue))
        return -1;
    queue->rear = (queue->rear + 1)
                  % queue->capacity;
    memcpy(&array[queue->rear], &item, sizeof(acception));
    queue->size = queue->size + 1;
    return 0;
}

acception* Accept_dequeue(void *shm, accept_queue* queue){
    acception *array = (acception *)(shm+queue->queue_start_offset);
    if (isEmptyAcceptQueue(queue))
        return NULL;
    acception *item = (acception*)malloc(sizeof(acception));
    memcpy(item, &array[queue->front], sizeof(acception));
    queue->front = (queue->front + 1)
                   % queue->capacity;
    queue->size = queue->size - 1;
    return item;
}

/* queue.c end */

/* inet_client_shm.c start */
ssize_t my_recv(int sockfd, void *buf, size_t len, int flags){
    if(close_arr[socket_cli.share_unit_index].server_write)
        return 0;

    while(socket_cli.response_queue->current_size == 0){
        if(close_arr[socket_cli.share_unit_index].server_write)
            return 0;    
    }

    if(pthread_mutex_lock(socket_cli.response_lock) != 0) perror("pthread_mutex_lock failed");
    ssize_t count = 0;
    buffer *b = stream_dequeue(shm_ptr, socket_cli.response_queue, len);
    if(b->buf != NULL){
        memcpy(buf, b->buf, b->length *sizeof(char));
        count = b->length;
        free(b->buf); 
    }
    free(b);
    if(pthread_mutex_unlock(socket_cli.response_lock) != 0) perror("pthread_mutex_unlock failed");

    return count;
}

ssize_t my_send(int sockfd, const void *buf, size_t len, int flags){
    while(socket_cli.request_queue->current_size == socket_cli.request_queue->capacity){
        if(close_arr[socket_cli.share_unit_index].server_read)
            return 0;
    }

    if(pthread_mutex_lock(socket_cli.request_lock) != 0) perror("pthread_mutex_lock failed");
    ssize_t count = 0;
    count = stream_enqueue(shm_ptr, socket_cli.request_queue, (char *)buf, len);
    if(pthread_mutex_unlock(socket_cli.request_lock) != 0) perror("pthread_mutex_unlock failed");

    return count;
}

int my_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen){
    if(socket_cli.in_use != 1){
        printf("socket not initialized\n");
        return -1;
    }

    connection c = (connection){
        .client_fd = sockfd
    };
    memcpy(&c.addr, addr, sizeof(struct sockaddr));

    while(connect_queue_ptr->size == connect_queue_ptr->capacity);
    if(pthread_mutex_lock(connect_lock) != 0) perror("pthread_mutex_lock failed");
    if(Connect_enqueue(connect_shm_ptr, connect_queue_ptr, c) == -1)
        printf("connect queue enqueue failed\n");
    if(pthread_mutex_unlock(connect_lock) != 0) perror("pthread_mutex_unlock failed");
    
    while(accept_queue_ptr->size == 0);
    if(pthread_mutex_lock(accept_lock) != 0) perror("pthread_mutex_lock failed");
    acception *a = Accept_dequeue(connect_shm_ptr, accept_queue_ptr);
    if(pthread_mutex_unlock(accept_lock) != 0) perror("pthread_mutex_unlock failed");
    
    if(a != NULL){
        if(a->client_fd != sockfd){
            printf("fd is different\n");
            free(a);
            return -1;
        }
        socket_cli.share_unit_index = a->share_unit_index;
        socket_cli.request_queue = &(((share_unit *)shm_ptr)[socket_cli.share_unit_index].request_queue);
        socket_cli.response_queue = &(((share_unit *)shm_ptr)[socket_cli.share_unit_index].response_queue);
        socket_cli.request_lock = &(((share_unit *)shm_ptr)[socket_cli.share_unit_index].request_lock);
        socket_cli.response_lock = &(((share_unit *)shm_ptr)[socket_cli.share_unit_index].response_lock);
        free(a);
        return 0;
    }
    else{
        printf("accept queue dequeue failed\n");
        return -1;
    }
}

int my_socket(int domain, int type, int protocol){
    socket_cli = (mysocket){
        .domain = domain,
        .type = type,
        .protocol = protocol,
        .has_bind = 0,
        .in_use = 1,
        .shutdown_read = 0,
        .shutdown_write = 0,
        .msg_more_buf = NULL,
        .msg_more_size = 0,
        .share_unit_index = -1,
        .file_status_flags = 0
    };

    // return original_socket(domain, type, protocol);
    return 999;
}

int my_close(int fd){
    if(socket_cli.in_use != 1){
        printf("socket not in use\n");
        return -1;
    }
    if(socket_cli.share_unit_index >= 0){
        close_arr[socket_cli.share_unit_index].client_read = 1;
        close_arr[socket_cli.share_unit_index].client_write = 1;
    }
    // clear socket_cli
    memset(&socket_cli, 0, sizeof(mysocket));

    return 0;
}

/* inet_client_shm.c end */