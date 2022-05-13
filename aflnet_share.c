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

int datagram_enqueue(void *shm, share_queue *q, my_message_t m){
    my_message_t *m_arr = (my_message_t *)(shm+q->message_start_offset);
    // queue is full
    if (q->current_size == q->capacity){
        return -1;
    }
    // queue is empty
    if(q->front == -1){
        q->front = q->rear = 0;
        memcpy(&m_arr[q->rear], &m, sizeof(my_message_t));
    }
    // normal condition
    else{
        q->rear = (q->rear + 1) % q->capacity;
        memcpy(&m_arr[q->rear], &m, sizeof(my_message_t));
    }
    q->current_size++;

    return 0;
}

my_message_t *datagram_dequeue(void *shm, share_queue *q){
    my_message_t *m_arr = (my_message_t *)(shm+q->message_start_offset);
    my_message_t *m = (my_message_t *)malloc(sizeof(my_message_t));
    if(q->front == -1){
        m->length = 0;
        return m;
    }
    
    memcpy(m, &m_arr[q->front], sizeof(my_message_t));
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

int int_enqueue(void *shm, share_queue *q, int m){
    int *m_arr = (int *)(shm+q->message_start_offset);
    // queue is full
    if (q->current_size == q->capacity){
        return -1;
    }
    // queue is empty
    if(q->front == -1){
        q->front = q->rear = 0;
        m_arr[q->rear] = m;
    }
    // normal condition
    else{
        q->rear = (q->rear + 1) % q->capacity;
        m_arr[q->rear] = m;
    }
    q->current_size++;

    return 0;
}

int int_dequeue(void *shm, share_queue *q){
    int *m_arr = (int *)(shm+q->message_start_offset);
    int m;
    if(q->front == -1)
        return -1;
    
    m = m_arr[q->front];
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
void my_signal_handler(int signum){
    if(signum == SIGUSR2){
        __sync_val_compare_and_swap(&socket_cli.is_socket_timeout, 0, 1);
    }
}

int my_createtimer(timer_t *timer){
    struct sigevent evp = (struct sigevent){
        .sigev_value.sival_ptr = timer,
        .sigev_notify = SIGEV_SIGNAL,
        .sigev_signo = SIGUSR2
    };

    return timer_create(CLOCK_REALTIME, &evp, timer);
}

int my_settimer(int is_send){
    timer_t timer;
    struct timeval tv;
    if(is_send){
        timer = socket_cli.send_timer;
        tv = socket_cli.send_timeout;
    }
    else{
        timer = socket_cli.recv_timer;
        tv = socket_cli.recv_timeout;
    }

    struct itimerspec new_value = (struct itimerspec){
        .it_interval = (struct timespec){
            .tv_sec = 0,
            .tv_nsec = 0
        },
        .it_value = (struct timespec){
            .tv_sec = tv.tv_sec + (time_t)(tv.tv_usec / 1000000),
            .tv_nsec = (long)(tv.tv_usec % 1000000) * 1000
        }
    };
    if(timer_settime(timer, 0, &new_value, NULL) == -1){
        log_error("settimer failed, %s", strerror(errno));
        return -1;
    }

    return 0;
}

int my_stoptimer(int is_send){
    timer_t timer;
    if(is_send)
        timer = socket_cli.send_timer;
    else
        timer = socket_cli.recv_timer;

    struct itimerspec new_value = (struct itimerspec){
        .it_interval = (struct timespec){
            .tv_sec = 0,
            .tv_nsec = 0
        },
        .it_value = (struct timespec){
            .tv_sec = 0,
            .tv_nsec = 0
        }
    };    
    if(timer_settime(timer, TIMER_ABSTIME, &new_value, NULL) == -1){
        log_error("stoptimer failed");
        return -1;
    }

    return 0;
}

ssize_t my_recv(int sockfd, void *buf, size_t len, int flags){
    struct timespec start, finish, delta;
    clock_gettime(CLOCK_REALTIME, &start);
    if(socket_cli.in_use != 1){
        log_error("socket not in use\n");
        return -1;
    }

    if(close_arr[socket_cli.share_unit_index].server_write)
        return 0;

    bool need_timeout = false;

    while(__sync_bool_compare_and_swap(&socket_cli.response_queue->current_size, 0, 0)){
        if(close_arr[socket_cli.share_unit_index].server_write){
            if(need_timeout && my_stoptimer(false) == -1)
                return -1;    
            clock_gettime(CLOCK_REALTIME, &finish);
            sub_timespec(start, finish, &delta);
            log_info("recv (server close) time: %d.%.9ld", (int)delta.tv_sec, delta.tv_nsec);        
            return 0;    
        }

        if(!need_timeout && (socket_cli.recv_timeout.tv_sec > 0 || socket_cli.recv_timeout.tv_usec > 0)){
            if(socket_cli.recv_timer == NULL){
                if(my_createtimer(&socket_cli.recv_timer) == -1){
                    log_error("recv_timer create failed");
                    socket_cli.recv_timer = NULL;
                    return 0;
                }
            }

            socket_cli.is_socket_timeout = 0;
            if(my_settimer(false) == -1)
                return 0;

            need_timeout = true;
        }

        if(socket_cli.recv_timer == NULL)
            continue;

        if(__sync_bool_compare_and_swap(&socket_cli.is_socket_timeout, 1, 1)){
            socket_cli.is_socket_timeout = 0;
            errno = EWOULDBLOCK;
            clock_gettime(CLOCK_REALTIME, &finish);
            sub_timespec(start, finish, &delta);
            log_info("recv (timeout) time: %d.%.9ld", (int)delta.tv_sec, delta.tv_nsec);
            return -1;
        }
    }

    if(socket_cli.recv_timer != NULL && need_timeout){
        if(my_stoptimer(false) == -1){
            return -1;
        }
    }

    if(pthread_mutex_lock(socket_cli.response_lock) != 0) log_error("pthread_mutex_lock response_lock failed");
    ssize_t count = 0;
    buffer *b = stream_dequeue(shm_ptr, socket_cli.response_queue, len);
    if(b->buf != NULL){
        memcpy(buf, b->buf, b->length *sizeof(char));
        count = b->length;
        free(b->buf); 
    }
    free(b);
    if(pthread_mutex_unlock(socket_cli.response_lock) != 0) log_error("pthread_mutex_unlock response_lock failed");

    clock_gettime(CLOCK_REALTIME, &finish);
    sub_timespec(start, finish, &delta);
    log_info("recv (normal) time: %d.%.9ld", (int)delta.tv_sec, delta.tv_nsec);
    return count;
}

ssize_t my_send(int sockfd, const void *buf, size_t len, int flags){
    struct timespec start, finish, delta;
    clock_gettime(CLOCK_REALTIME, &start);
    if(socket_cli.in_use != 1){
        log_error("socket not in use");
        return -1;
    }
    
    bool need_timeout = false;
    if(__sync_bool_compare_and_swap(&socket_cli.request_queue->current_size, socket_cli.request_queue->capacity, socket_cli.request_queue->capacity))
        need_timeout = true;

    if(need_timeout && (socket_cli.send_timeout.tv_sec > 0 || socket_cli.send_timeout.tv_usec > 0)){
        if(socket_cli.send_timer == NULL){
            if(my_createtimer(&socket_cli.send_timer) == -1){
                log_error("send_timer create failed");
                return 0;
            }
        }

        socket_cli.is_socket_timeout = 0;

        if(my_settimer(true) == -1)
            return 0;
    }
    
    while(socket_cli.request_queue->current_size == socket_cli.request_queue->capacity){
        if(close_arr[socket_cli.share_unit_index].server_read){
            if(need_timeout && my_stoptimer(true) == -1)
                return -1; 
            clock_gettime(CLOCK_REALTIME, &finish);
            sub_timespec(start, finish, &delta);
            log_info("send (server close) time: %d.%.9ld", (int)delta.tv_sec, delta.tv_nsec);
            return 0;
        }
        
        if(socket_cli.send_timer == NULL)
            continue;

        if(__sync_bool_compare_and_swap(&socket_cli.is_socket_timeout, 1, 1)){
            socket_cli.is_socket_timeout = 0;
            errno = EWOULDBLOCK;
            clock_gettime(CLOCK_REALTIME, &finish);
            sub_timespec(start, finish, &delta);
            log_info("send (timeout) time: %d.%.9ld", (int)delta.tv_sec, delta.tv_nsec);
            return -1;
        }        
    }
    
    if(socket_cli.send_timer != NULL && need_timeout){
        if(my_stoptimer(true) == -1){
            return -1;
        }
    }
    
    if(pthread_mutex_lock(socket_cli.request_lock) != 0) log_error("pthread_mutex_lock request_lock failed");
    ssize_t count = 0;
    count = stream_enqueue(shm_ptr, socket_cli.request_queue, (char *)buf, len);
    if(pthread_mutex_unlock(socket_cli.request_lock) != 0) log_error("pthread_mutex_unlock request_lock failed");

    clock_gettime(CLOCK_REALTIME, &finish);
    sub_timespec(start, finish, &delta);
    log_info("send (normal) time: %d.%.9ld", (int)delta.tv_sec, delta.tv_nsec);
    return count;
}

int my_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen){
    struct timespec start, finish, delta;
    clock_gettime(CLOCK_REALTIME, &start);
    if(socket_cli.in_use != 1){
        log_error("socket not initialized");
        return -1;
    }

    connection c = (connection){
        .client_fd = sockfd
    };
    memcpy(&c.addr, addr, sizeof(struct sockaddr));
    log_trace("before my_connect while loop");
    while(connect_queue_ptr->size == connect_queue_ptr->capacity)
        usleep(0);
    log_trace("after my_connect while_loop");
    if(pthread_mutex_lock(connect_lock) != 0) perror("pthread_mutex_lock failed");
    if(Connect_enqueue(connect_shm_ptr, connect_queue_ptr, c) == -1)
        log_error("connect queue enqueue failed");
    if(pthread_mutex_unlock(connect_lock) != 0) perror("pthread_mutex_unlock failed");
    log_trace("before accept_queue while loop");
    while(accept_queue_ptr->size == 0)
        usleep(0);
    log_trace("after accept_queue while loop");
    if(pthread_mutex_lock(accept_lock) != 0) perror("pthread_mutex_lock failed");
    acception *a = Accept_dequeue(connect_shm_ptr, accept_queue_ptr);
    if(pthread_mutex_unlock(accept_lock) != 0) perror("pthread_mutex_unlock failed");
    
    if(a != NULL){
        if(a->client_fd != sockfd){
            log_error("fd is different");
            free(a);
            return -1;
        }
        socket_cli.share_unit_index = a->share_unit_index;
        socket_cli.request_queue = &(((share_unit *)shm_ptr)[socket_cli.share_unit_index].request_queue);
        socket_cli.response_queue = &(((share_unit *)shm_ptr)[socket_cli.share_unit_index].response_queue);
        socket_cli.request_lock = &(((share_unit *)shm_ptr)[socket_cli.share_unit_index].request_lock);
        socket_cli.response_lock = &(((share_unit *)shm_ptr)[socket_cli.share_unit_index].response_lock);
        socket_cli.response_su_index = a->response_su_index;
        socket_cli.res_len_queue = &(((share_unit *)shm_ptr)[socket_cli.response_su_index].request_queue);
        socket_cli.res_queue_lock = &(((share_unit *)shm_ptr)[socket_cli.response_su_index].request_lock);
        free(a);
        log_trace("connect success");
        clock_gettime(CLOCK_REALTIME, &finish);
        sub_timespec(start, finish, &delta);
        log_info("connect time: %d.%.9ld", (int)delta.tv_sec, delta.tv_nsec);
        return 0;
    }
    else{
        log_error("accept queue dequeue failed");
        return -1;
    }
}

int my_socket(int domain, int type, int protocol){
    struct timespec start, finish, delta;
    clock_gettime(CLOCK_REALTIME, &start);
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
        .response_su_index = -1,
        .file_status_flags = 0,
        .send_timeout = (struct timeval) {
            .tv_sec = 0,
            .tv_usec = 0
        },
        .recv_timeout = (struct timeval) {
            .tv_sec = 0,
            .tv_usec = 0
        },
        .send_timer = NULL,
        .recv_timer = NULL,
        .is_socket_timeout = 0,
        .poll_timer = NULL
    };
    clock_gettime(CLOCK_REALTIME, &finish);
    sub_timespec(start, finish, &delta);
    log_info("socket time: %d.%.9ld", (int)delta.tv_sec, delta.tv_nsec);
    // return original_socket(domain, type, protocol);
    return 999;
}

int my_close(int fd){
    struct timespec start, finish, delta;
    clock_gettime(CLOCK_REALTIME, &start);
    if(socket_cli.in_use != 1){
        log_error("socket not in use");
        return -1;
    }
    if(socket_cli.share_unit_index >= 0){
        close_arr[socket_cli.share_unit_index].client_read = 1;
        close_arr[socket_cli.share_unit_index].client_write = 1;
    }

    // close timer
    if(socket_cli.send_timer != NULL){
        timer_delete(socket_cli.send_timer);
        socket_cli.send_timer = NULL;
    }
    if(socket_cli.recv_timer != NULL){
        timer_delete(socket_cli.recv_timer);
        socket_cli.send_timer = NULL;
    }
    if(socket_cli.poll_timer != NULL){
        timer_delete(socket_cli.poll_timer);
        socket_cli.poll_timer = NULL;
    }

    // clear socket_cli
    memset(&socket_cli, 0, sizeof(mysocket));
    clock_gettime(CLOCK_REALTIME, &finish);
    sub_timespec(start, finish, &delta);
    log_info("close time: %d.%.9ld", (int)delta.tv_sec, delta.tv_nsec);
    return 0;
}

/* inet_client_shm.c end */

/* function needed in modified send_over_network */
int my_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen){
    log_fatal("my_bind is called!");
    exit(999);
    return 0;
}

int my_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen){
    if(socket_cli.in_use != 1){
        log_error("socket not in use");
        return -1;
    }
    
    if(optname == SO_SNDTIMEO){
        struct timeval *tv = (struct timeval *)optval;
        socket_cli.send_timeout.tv_sec = tv->tv_sec;
        socket_cli.send_timeout.tv_usec = tv->tv_usec;
    }

    if(optname == SO_RCVTIMEO){
        struct timeval *tv = (struct timeval *)optval;
        socket_cli.recv_timeout.tv_sec = tv->tv_sec;
        socket_cli.recv_timeout.tv_usec = tv->tv_usec;        
    }

    return 0;
}

int my_poll_settimer(int timeout){
    timer_t timer = socket_cli.poll_timer;
    
    struct itimerspec new_value = (struct itimerspec){
        .it_interval = (struct timespec){
            .tv_sec = 0,
            .tv_nsec = 0
        },
        .it_value = (struct timespec){
            .tv_sec = (time_t)(timeout / 1000),
            .tv_nsec = (long)(timeout % 1000) * 1000000
        }
    };

    if(timer_settime(timer, 0, &new_value, NULL) == -1){
        log_error("poll settimer failed, %s", strerror(errno));
        return -1;
    }

    return 0;
}

int my_poll_stoptimer(void){
    timer_t timer = socket_cli.poll_timer;

    struct itimerspec new_value = (struct itimerspec){
        .it_interval = (struct timespec){
            .tv_sec = 0,
            .tv_nsec = 0
        },
        .it_value = (struct timespec){
            .tv_sec = 0,
            .tv_nsec = 0
        }
    };    
    if(timer_settime(timer, TIMER_ABSTIME, &new_value, NULL) == -1){
        log_error("poll stoptimer failed");
        return -1;
    }

    return 0;
}

int my_poll(struct pollfd *fds, nfds_t nfds, int timeout){
    struct timespec start, finish, delta;
    clock_gettime(CLOCK_REALTIME, &start);
    if(socket_cli.in_use != 1){
        log_error("poll socket not in use");
        fds[0].revents = 32;
        return 1;
    }

    int rv = 0;
    fds[0].revents = 0;

    if(close_arr[socket_cli.share_unit_index].server_write || close_arr[socket_cli.share_unit_index].server_read){
        log_info("poll after server shutdown or close socket");
        fds[0].revents = fds[0].events;
        return 1;
    }

    if(timeout == -1){
        while(1){
            if(fds[0].events & POLLIN && socket_cli.response_queue->current_size > 0){
                fds[0].revents |= POLLIN;
                rv++;
                return rv;
            }   

            if(fds[0].events & POLLOUT && socket_cli.request_queue->current_size < socket_cli.request_queue->capacity){
                fds[0].revents |= POLLOUT;
                rv++;
                return rv;
            } 
            usleep(0);
        }
    }


    if(fds[0].events & POLLIN && socket_cli.response_queue->current_size > 0){
        fds[0].revents |= POLLIN;
        rv++;
    }

    if(fds[0].events & POLLOUT && socket_cli.request_queue->current_size < socket_cli.request_queue->capacity){
        fds[0].revents |= POLLOUT;
        rv++;
    }

    if(timeout == 0 || rv > 0){
        clock_gettime(CLOCK_REALTIME, &finish);
        sub_timespec(start, finish, &delta);
        log_info("poll (first rv>0) time: %d.%.9ld", (int)delta.tv_sec, delta.tv_nsec);    
        return rv;
    }
    
    if(timeout > 0){
        if(socket_cli.poll_timer == NULL && my_createtimer(&socket_cli.poll_timer) == -1){
            log_error("poll_timer create failed");
            return -1;
        }
        
        socket_cli.is_socket_timeout = 0;

        if(my_poll_settimer(timeout) == -1)
            return -1;
    }
    
    while(1){
        if(close_arr[socket_cli.share_unit_index].server_write || close_arr[socket_cli.share_unit_index].server_read){
            log_info("poll after server shutdown or close socket");
            if(my_poll_stoptimer() == -1)
                return -1;
            fds[0].revents = fds[0].events;
            clock_gettime(CLOCK_REALTIME, &finish);
            sub_timespec(share_start_time, finish, &delta);
            log_info("poll relative time: %d.%.9ld", (int)delta.tv_sec, delta.tv_nsec);
            log_info("poll clock time: %lld.%.9ld", finish.tv_sec, finish.tv_nsec);
            sub_timespec(start, finish, &delta);
            log_info("poll (server close) time: %d.%.9ld", (int)delta.tv_sec, delta.tv_nsec);            
            return 1;
        }

        if(fds[0].events & POLLIN && socket_cli.response_queue->current_size > 0){
            fds[0].revents |= POLLIN;
            rv++;
        }

        if(fds[0].events & POLLOUT && socket_cli.request_queue->current_size < socket_cli.request_queue->capacity){
            fds[0].revents |= POLLOUT;
            rv++;
        }

        if(rv > 0){
            if(my_poll_stoptimer() == -1)
                return -1;
            
            clock_gettime(CLOCK_REALTIME, &finish);
            sub_timespec(start, finish, &delta);
            log_info("poll (rv>0) time: %d.%.9ld", (int)delta.tv_sec, delta.tv_nsec);
            return rv;
        }

        if(__sync_bool_compare_and_swap(&socket_cli.is_socket_timeout, 1, 1)){
            socket_cli.is_socket_timeout = 0;
            clock_gettime(CLOCK_REALTIME, &finish);
            sub_timespec(share_start_time, finish, &delta);
            log_info("poll relative time: %d.%.9ld", (int)delta.tv_sec, delta.tv_nsec);
            log_info("poll clock time: %lld.%.9ld", finish.tv_sec, finish.tv_nsec);
            sub_timespec(start, finish, &delta);
            log_info("poll (timeout) time: %d.%.9ld", (int)delta.tv_sec, delta.tv_nsec);
            return 0;
        }
    }

    return rv;
}

int my_net_send(int sockfd, struct timeval timeout, char *mem, unsigned int len) {
  struct timespec start, finish, delta;
  clock_gettime(CLOCK_REALTIME, &start);
  unsigned int byte_count = 0;
  int n;
  struct pollfd pfd[1];
  pfd[0].fd = sockfd;
  pfd[0].events = POLLOUT;
  int rv = my_poll(pfd, 1, 1);

  my_setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));
  if (rv > 0) {
    if (pfd[0].revents & POLLOUT) {
      // send 2-byte dns query length for tcp
      unsigned char tcp_len[2] = {0};
      tcp_len[0] = len / 256;
      tcp_len[1] = len % 256;
      n = my_send(sockfd, tcp_len, 2, MSG_NOSIGNAL);
      log_debug("my_send end, n=%d", n);
      if (n == 0) return byte_count;
      if (n == -1) return -1;
      while (byte_count < len) {
        usleep(10);
        n = my_send(sockfd, &mem[byte_count], len - byte_count, MSG_NOSIGNAL);
        log_debug("my_send in while loop end, n=%d", n);
        if (n == 0) return byte_count;
        if (n == -1) return -1;
        byte_count += n;
      }
    }
  }
  clock_gettime(CLOCK_REALTIME, &finish);
  sub_timespec(start, finish, &delta);
  log_info("my_net_send time: %d.%.9ld", (int)delta.tv_sec, delta.tv_nsec);
  return byte_count;
}

int my_single_net_recv(int sockfd, struct timeval timeout, int poll_w, char **response_buf, unsigned int *len) {
  struct timespec start, finish, delta;
  clock_gettime(CLOCK_REALTIME, &start);
  char temp_buf[1000];
  int n;
  struct pollfd pfd[1];
  pfd[0].fd = sockfd;
  pfd[0].events = POLLIN;
  log_trace("my_poll start");
  int rv = my_poll(pfd, 1, poll_w);
  log_trace("my_poll end, rv=%d", rv);
  my_setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
  // data received
  if (rv > 0) {
    if (pfd[0].revents & POLLIN) {
      log_debug("my_recv start");
      n = my_recv(sockfd, temp_buf, sizeof(temp_buf), 0);
      if ((n < 0) && (errno != EAGAIN)) {
        clock_gettime(CLOCK_REALTIME, &finish);
        sub_timespec(start, finish, &delta);
        log_info("my_single_net_recv (error) time: %d.%.9ld", (int)delta.tv_sec, delta.tv_nsec);
        return 1;
      }
      log_debug("my_recv end, n=%d", n);
      if (n > 0) {
        *response_buf = (unsigned char *)ck_realloc(*response_buf, *len + n + 1);
        memcpy(&(*response_buf)[*len], temp_buf, n);
        (*response_buf)[(*len) + n] = '\0';
        *len = *len + n;
      }
    }
  } else
    if (rv < 0) // an error was returned
      return 1;

  clock_gettime(CLOCK_REALTIME, &finish);
  sub_timespec(start, finish, &delta);
  log_info("my_single_net_recv (normal) time: %d.%.9ld", (int)delta.tv_sec, delta.tv_nsec);
  // rv == 0 poll timeout or all data pending after poll has been received successfully
  return 0;
}

int my_net_recv(int sockfd, struct timeval timeout, int poll_w, char **response_buf, unsigned int *len) {
  struct timespec start, finish, delta;
  clock_gettime(CLOCK_REALTIME, &start);
  char temp_buf[1000];
  int n;
  struct pollfd pfd[1];
  pfd[0].fd = sockfd;
  pfd[0].events = POLLIN;
  log_trace("my_poll start");
  int rv = my_poll(pfd, 1, poll_w);
  log_trace("my_poll end, rv=%d", rv);
  my_setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
  // data received
  if (rv > 0) {
    if (pfd[0].revents & POLLIN) {
      log_debug("my_recv start");
      n = my_recv(sockfd, temp_buf, sizeof(temp_buf), 0);
      if ((n < 0) && (errno != EAGAIN)) {
        clock_gettime(CLOCK_REALTIME, &finish);
        sub_timespec(start, finish, &delta);
        log_info("my_net_recv (error) time: %d.%.9ld", (int)delta.tv_sec, delta.tv_nsec);
        return 1;
      }
      log_debug("my_recv end, n=%d", n);
      while (n > 0) {
        usleep(10);
        *response_buf = (unsigned char *)ck_realloc(*response_buf, *len + n + 1);
        memcpy(&(*response_buf)[*len], temp_buf, n);
        (*response_buf)[(*len) + n] = '\0';
        *len = *len + n;
        log_debug("start my_recv in while loop");
        n = my_recv(sockfd, temp_buf, sizeof(temp_buf), 0);
        log_debug("my_recv in while loop end, n=%d", n);
        if ((n < 0) && (errno != EAGAIN)) {
          clock_gettime(CLOCK_REALTIME, &finish);
          sub_timespec(start, finish, &delta);
          log_info("my_net_recv (error) time: %d.%.9ld", (int)delta.tv_sec, delta.tv_nsec);
          return 1;
        }
      }
      log_debug("while end");
    }
  } else
    if (rv < 0) // an error was returned
      return 1;

  clock_gettime(CLOCK_REALTIME, &finish);
  sub_timespec(start, finish, &delta);
  log_info("my_net_recv (normal) time: %d.%.9ld", (int)delta.tv_sec, delta.tv_nsec);
  // rv == 0 poll timeout or all data pending after poll has been received successfully
  return 0;  
}

/* for debug */

void my_log_hex(char *m, int length){
    for(int i = 0; i < length; i++){
        log_trace("%02x ", m[i]);
    }
}

void sub_timespec(struct timespec t1, struct timespec t2, struct timespec *td)
{
    td->tv_nsec = t2.tv_nsec - t1.tv_nsec;
    td->tv_sec  = t2.tv_sec - t1.tv_sec;
    if (td->tv_sec > 0 && td->tv_nsec < 0)
    {
        td->tv_nsec += NS_PER_SECOND;
        td->tv_sec--;
    }
    else if (td->tv_sec < 0 && td->tv_nsec > 0)
    {
        td->tv_nsec -= NS_PER_SECOND;
        td->tv_sec++;
    }
}