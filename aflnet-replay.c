#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include "alloc-inl.h"
#include "aflnet.h"
#include "aflnet_share.h"

#define server_wait_usecs 10000

unsigned int* (*extract_response_codes)(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref) = NULL;
u32 my_poll_wait_msecs = 0;

/* Expected arguments:
1. Path to the test case (e.g., crash-triggering input)
2. Application protocol (e.g., RTSP, FTP)
3. Server's network port
Optional:
4. First response timeout (ms), default 1
5. Follow-up responses timeout (us), default 1000
*/

static unsigned long long get_cur_time(void) {

  struct timeval tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000);

}

/* aflnet_share initialization */
__attribute__((constructor(101))) void aflnet_share_init(void){
  // initialize logging
  log_set_quiet(true);

  // initialize share memory
  char *use_share = getenv("USE_AFLNET_SHARE");
  if(use_share && memcmp(use_share, "1", 1) == 0)
    USE_AFLNET_SHARE = true;
  else
    USE_AFLNET_SHARE = false;

  char *profile_time = getenv("PROFILING_TIME");
  if(profile_time && memcmp(profile_time, "1", 1) == 0)
    PROFILING_TIME = true;
  else
    PROFILING_TIME = false;

  shm_name = NULL;
  connect_shm_name = NULL;
  close_shm_name = NULL;
  control_sock_name = NULL;

  unlink_first_time = true;

  if(USE_AFLNET_SHARE){
    /*
    time_t cur_t = time(0);
    struct tm* t = localtime(&cur_t);
    char log_name[100] = {0};
    snprintf(log_name, 100, "aflnet_replay_%04u-%02u-%02u-%02u:%02u:%02u.log", 
      t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);
    FILE *fp = fopen((const char *)log_name, "w+");
    if(fp == NULL){
      log_error("fopen failed");
      exit(999);
    }
    log_add_fp(fp, LOG_ERROR);
    */

    if(PROFILING_TIME)
      clock_gettime(CLOCK_REALTIME, &share_start_time);

    char *server_type = getenv("SERVER");
    if(server_type == NULL){
      log_error("SERVER getenv failed");
      exit(999);
    }

    if(!strncmp(server_type, "DNSMASQ", 7))
      server = DNSMASQ;
    else if(!strncmp(server_type, "TINYDTLS", 8))
      server = TINYDTLS;
    else if(!strncmp(server_type, "DCMQRSCP", 8))
      server = DCMQRSCP;
    else 
      server = OTHER;

    shm_name = (char *)malloc(50*sizeof(char));
    if(shm_name == NULL){
      log_error("shm_name malloc failed");
      exit(999);
    }
    snprintf(shm_name, 50, "message_sm_%llu", get_cur_time());
    setenv("AFLNET_SHARE_MESSAGE_SHM", shm_name, 1);
    shm_fd = shm_open((const char *)shm_name, O_CREAT | O_RDWR, 0666);
    if(shm_fd < 0){
      log_error("shm_open failed");
      exit(999);
    }
    ftruncate(shm_fd, COMMUNICATE_SHM_SIZE);

    shm_ptr = mmap(NULL, COMMUNICATE_SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if(shm_ptr == (void *)-1){
      log_error("mmap failed");
    }

    // initialize connect share memory
    connect_shm_name = (char *)malloc(50*sizeof(char));
    if(connect_shm_name == NULL){
      log_error("connect_shm_name malloc failed");
      exit(999);
    }
    snprintf(connect_shm_name, 50, "connect_sm_%llu", get_cur_time());
    setenv("AFLNET_SHARE_CONNECT_SHM", connect_shm_name, 1);
    connect_shm_fd = shm_open(connect_shm_name, O_CREAT | O_RDWR, 0666);
    if(connect_shm_fd < 0){
      log_error("connect_shm_open failed");
      exit(999);
    }
    ftruncate(connect_shm_fd, CONNECT_SHM_SIZE);

    connect_shm_ptr = mmap(NULL, CONNECT_SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, connect_shm_fd, 0);
    if(connect_shm_ptr == (void *)-1){
      log_error("mmap failed");
    }
    connect_queue_ptr = (connect_queue *)(connect_shm_ptr);
    accept_queue_ptr = (accept_queue *)(connect_shm_ptr+sizeof(connect_queue));
    connect_lock = (pthread_mutex_t *)(connect_shm_ptr+sizeof(connect_queue)+sizeof(accept_queue));
    accept_lock = (pthread_mutex_t *)(connect_shm_ptr+sizeof(connect_queue)+sizeof(accept_queue)+sizeof(pthread_mutex_t));

    // initialize socket_cli
    memset(&socket_cli, 0, sizeof(mysocket));

    // initialize close share memory
    close_shm_name = (char *)malloc(50*sizeof(char));
    if(close_shm_name == NULL){
      log_error("close_shm_name malloc failed");
      exit(999);
    }
    snprintf(close_shm_name, 50, "close_sm_%llu", get_cur_time());
    setenv("AFLNET_SHARE_CLOSE_SHM", close_shm_name, 1);    
    close_shm_fd = shm_open(close_shm_name, O_CREAT | O_RDWR, 0666);
    if(close_shm_fd < 0){
      log_error("shm_open failed");
      exit(999);
    }
    ftruncate(close_shm_fd, CLOSE_SHM_SIZE);

    close_shm_ptr = mmap(NULL, CLOSE_SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, close_shm_fd, 0);
    if(close_shm_ptr == (void *)-1){
      log_error("mmap failed");
    }
    close_arr = (close_unit *)close_shm_ptr;

    // set signal handler for recv and send timeout
    signal(SIGUSR2, my_signal_handler);

    control_sock_name = (char *)malloc(50*sizeof(char));
    if(control_sock_name == NULL){
      log_error("control_sock_name malloc failed");
      exit(999);
    }
    snprintf(control_sock_name, 50, "/tmp/control_sock_%llu", get_cur_time());
    setenv("CONTROL_SOCKET_NAME", control_sock_name, 1);

    memset(&control_serveraddr, 0, sizeof(control_serveraddr));
    control_serveraddr.sun_family = AF_UNIX;
    strncpy(control_serveraddr.sun_path, control_sock_name, sizeof(control_serveraddr.sun_path)); 

    if (server == DCMQRSCP)
      control_socket_timeout = 2300;
    else
      control_socket_timeout = 25000;
  }
}

__attribute__((destructor(101))) void aflnet_share_cleanup(void){
  if(USE_AFLNET_SHARE){
    // unlink all the share memory
    if(shm_name){
      shm_unlink(shm_name);
      free(shm_name);
    }

    if(connect_shm_name){
      shm_unlink(connect_shm_name);
      free(connect_shm_name);
    }

    if(close_shm_name){
      shm_unlink(close_shm_name);
      free(close_shm_name);
    }

    if(control_sock_name){
      unlink(control_sock_name);
      free(control_sock_name);
    }
  }
}

int main(int argc, char* argv[])
{
  FILE *fp;
  int portno, n;
  struct sockaddr_in serv_addr;
  char* buf = NULL, *response_buf = NULL;
  int response_buf_size = 0;
  unsigned int size, i, state_count, packet_count = 0;
  unsigned int *state_sequence;
  unsigned int socket_timeout = 1000;
  unsigned int poll_timeout = 1;


  if (argc < 4) {
    PFATAL("Usage: ./aflnet-replay packet_file protocol port [first_resp_timeout(us) [follow-up_resp_timeout(ms)]]");
  }

  fp = fopen(argv[1],"rb");

  if (!strcmp(argv[2], "RTSP")) extract_response_codes = &extract_response_codes_rtsp;
  else if (!strcmp(argv[2], "FTP")) extract_response_codes = &extract_response_codes_ftp;
  else if (!strcmp(argv[2], "DNS")) extract_response_codes = &extract_response_codes_dns;
  else if (!strcmp(argv[2], "DTLS12")) extract_response_codes = &extract_response_codes_dtls12;
  else if (!strcmp(argv[2], "DICOM")) extract_response_codes = &extract_response_codes_dicom;
  else if (!strcmp(argv[2], "SMTP")) extract_response_codes = &extract_response_codes_smtp;
  else if (!strcmp(argv[2], "SSH")) extract_response_codes = &extract_response_codes_ssh;
  else if (!strcmp(argv[2], "TLS")) extract_response_codes = &extract_response_codes_tls;
  else if (!strcmp(argv[2], "SIP")) extract_response_codes = &extract_response_codes_sip;
  else if (!strcmp(argv[2], "HTTP")) extract_response_codes = &extract_response_codes_http;
  else if (!strcmp(argv[2], "IPP")) extract_response_codes = &extract_response_codes_ipp;
  else {fprintf(stderr, "[AFLNet-replay] Protocol %s has not been supported yet!\n", argv[2]); exit(1);}

  portno = atoi(argv[3]);

  if (argc > 4) {
    poll_timeout = atoi(argv[4]);
    if (argc > 5) {
      socket_timeout = atoi(argv[5]);
    }
  }

  //Wait for the server to initialize
  usleep(server_wait_usecs);

  if (response_buf) {
    ck_free(response_buf);
    response_buf = NULL;
    response_buf_size = 0;
  }

  int sockfd;
  //if ((!strcmp(argv[2], "DTLS12")) || (!strcmp(argv[2], "DNS")) || (!strcmp(argv[2], "SIP"))) {
  if ((!strcmp(argv[2], "DTLS12")) || (!strcmp(argv[2], "SIP"))) {
    if(USE_AFLNET_SHARE)
      sockfd = my_socket(AF_INET, SOCK_DGRAM, 0);
    else
      sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  } else {
    if(USE_AFLNET_SHARE)
      sockfd = my_socket(AF_INET, SOCK_STREAM, 0);
    else
      sockfd = socket(AF_INET, SOCK_STREAM, 0);
  }

  if (sockfd < 0) {
    PFATAL("Cannot create a socket");
  }

  //Set timeout for socket data sending/receiving -- otherwise it causes a big delay
  //if the server is still alive after processing all the requests
  struct timeval timeout;

  timeout.tv_sec = 0;
  timeout.tv_usec = socket_timeout;

  if(USE_AFLNET_SHARE)
    my_setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));
  else
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));

  memset(&serv_addr, '0', sizeof(serv_addr));

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(portno);
  serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

  int control_server = -1;
  if(USE_AFLNET_SHARE){
    // create control socket and wait server to connect
    control_server = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if(control_server < 0) {
      log_error("control socket create failed");
    }

    // delete previous control socket
    if(unlink(control_sock_name) == -1)
      log_error("first time create or unlink previous control socket failed");

    if(bind(control_server, (struct sockaddr *)&control_serveraddr, sizeof(control_serveraddr)) == -1)
      log_error("control socket bind failed");

    if(listen(control_server, 1) < 0)
      log_error("control socket listen failed");

    if(my_connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
      //If it cannot connect to the server under test
      //try it again as the server initial startup time is varied
      for (n=0; n < 1; n++) {
        if (my_connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0) break;
        //usleep(1000);
      }
      if (n== 1) {
        my_close(sockfd);
        return 1;
      }
    }
  }
  else{
    if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
      //If it cannot connect to the server under test
      //try it again as the server initial startup time is varied
      for (n=0; n < 1000; n++) {
        if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0) break;
        usleep(1000);
      }
      if (n== 1000) {
        close(sockfd);
        return 1;
      }
    }
  }

  int control_sock = -1;
  if(USE_AFLNET_SHARE){
    control_sock = accept(control_server, NULL, NULL);
    if(control_sock == -1)
      log_error("control socket accept failed");
  }
  char control_buf[CONTROL_BUF_LEN];
  memset(control_buf, 0, CONTROL_BUF_LEN);

  // get share unit index from udp server through control socket
  if(socket_cli.type == SOCK_DGRAM){
    timeout.tv_sec = 0;
    timeout.tv_usec = control_socket_timeout;
    if(setsockopt(control_sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
      log_error("control socket setsockopt failed");
    // receive message from control socket
    if((n = recv(control_sock, control_buf, CONTROL_BUF_LEN, MSG_NOSIGNAL)) < 0){
      log_error("received share_unit_index failed, %s", strerror(errno));
      exit(999);
    }
    log_trace("control message length: %d", n);
    if(n > 0 && (memcmp(control_buf, "share_unit_index:", min(17,n)) == 0)){
      int share_unix_index;
      sscanf(control_buf, "share_unit_index:%d", &share_unix_index);
      log_trace("share_unit_index: %d", share_unix_index);
      socket_cli.share_unit_index = share_unix_index;
      socket_cli.request_queue = &(((share_unit *)shm_ptr)[socket_cli.share_unit_index].request_queue);
      socket_cli.response_queue = &(((share_unit *)shm_ptr)[socket_cli.share_unit_index].response_queue);
      socket_cli.request_lock = &(((share_unit *)shm_ptr)[socket_cli.share_unit_index].request_lock);
      socket_cli.response_lock = &(((share_unit *)shm_ptr)[socket_cli.share_unit_index].response_lock);
    }
  }

  //Send requests one by one
  //And save all the server responses
  while(!feof(fp)) {
    if (buf) {ck_free(buf); buf = NULL;}
    if (fread(&size, sizeof(unsigned int), 1, fp) > 0) {
      packet_count++;
    	fprintf(stderr,"\nSize of the current packet %d is  %d\n", packet_count, size);

      buf = (char *)ck_alloc(size);
      fread(buf, size, 1, fp);

      if(USE_AFLNET_SHARE){
        //if (my_net_recv(sockfd, timeout, poll_timeout, &response_buf, &response_buf_size)) break;
        n = my_net_send(sockfd, timeout, buf,size);
        if (n != size) break;
        timeout.tv_sec = 0;
        timeout.tv_usec = control_socket_timeout;
        if(setsockopt(control_sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
          log_error("control socket setsockopt failed");
        // receive message from control socket
        if((n = recv(control_sock, control_buf, CONTROL_BUF_LEN, MSG_NOSIGNAL)) < 0){ 
          log_error("control socket recv failed, %s", strerror(errno));
          break;
        }
        if(server == DCMQRSCP){
          if (my_net_recv(sockfd, timeout, my_poll_wait_msecs, &response_buf, &response_buf_size)) break;
        }
        if (my_single_net_recv(sockfd, timeout, my_poll_wait_msecs, &response_buf, &response_buf_size)) break;
      }
      else{
        if (net_recv(sockfd, timeout, poll_timeout, &response_buf, &response_buf_size)) break;
        n = net_send(sockfd, timeout, buf,size);
        if (n != size) break;

        if (net_recv(sockfd, timeout, poll_timeout, &response_buf, &response_buf_size)) break;
      }
    }
  }

  fclose(fp);
  if(USE_AFLNET_SHARE)
    my_close(sockfd);
  else
    close(sockfd);

  //Extract response codes
  state_sequence = (*extract_response_codes)(response_buf, response_buf_size, &state_count);

  fprintf(stderr,"\n--------------------------------");
  fprintf(stderr,"\nResponses from server:");

  for (i = 0; i < state_count; i++) {
    fprintf(stderr,"%d-",state_sequence[i]);
  }

  fprintf(stderr,"\n++++++++++++++++++++++++++++++++\nResponses in details:\n");
  for (i=0; i < response_buf_size; i++) {
    fprintf(stderr,"%c",response_buf[i]);
  }
  fprintf(stderr,"\n--------------------------------");

  //Free memory
  ck_free(state_sequence);
  if (buf) ck_free(buf);
  ck_free(response_buf);

  return 0;
}

