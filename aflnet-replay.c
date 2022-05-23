#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include "alloc-inl.h"
#include "aflnet.h"
#include "aflnet_share.h"

#define server_wait_usecs 10000

unsigned int* (*extract_response_codes)(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref) = NULL;

/* Expected arguments:
1. Path to the test case (e.g., crash-triggering input)
2. Application protocol (e.g., RTSP, FTP)
3. Server's network port
Optional:
4. First response timeout (ms), default 1
5. Follow-up responses timeout (us), default 1000
*/

/* aflnet_share initialization */
__attribute__((constructor(101))) void aflnet_share_init(void){
  // initialize logging
  log_set_quiet(true);
  /*
  char *log_name = getenv("aflnet_share_log");
  if(log_name){
      FILE *fp = fopen((const char *)log_name, "a+");
      log_add_fp(fp, LOG_TRACE);
  }*/
  // initialize share memory
  if(USE_AFLNET_SHARE){
    shm_fd = shm_open("message_sm", O_CREAT | O_RDWR, 0666);
    if (shm_fd < 0){
        log_error("shm_open failed");
        exit(999);
    }
    ftruncate(shm_fd, COMMUNICATE_SHM_SIZE);

    shm_ptr = mmap(NULL, COMMUNICATE_SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if(shm_ptr == (void *)-1){
        log_error("mmap failed");
    }

    // initialize connect share memory
    connect_shm_fd = shm_open("connect_sm", O_CREAT | O_RDWR, 0666);
    if (connect_shm_fd < 0){
        log_error("shm_open failed");
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
    close_shm_fd = shm_open("close_sm", O_CREAT | O_RDWR, 0666);
    if (close_shm_fd < 0){
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

    struct sockaddr_un serveraddr;
    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sun_family = AF_UNIX;
    strncpy(serveraddr.sun_path, CONTROL_SOCKET_NAME, sizeof(serveraddr.sun_path)); 

    // delete previous control socket
    if(unlink(CONTROL_SOCKET_NAME) == -1)
      log_error("first time create or unlink previous control socket failed");

    if(bind(control_server, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) == -1)
      log_error("control socket bind failed");

    if(listen(control_server, 1) < 0)
      log_error("control socket listen failed");

    if(my_connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
      //If it cannot connect to the server under test
      //try it again as the server initial startup time is varied
      for (n=0; n < 1000; n++) {
        if (my_connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0) break;
        usleep(1000);
      }
      if (n== 1000) {
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
        timeout.tv_usec = CONTROL_SOCKET_TIMEOUT;
        if(setsockopt(control_sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
          log_error("control socket setsockopt failed");
        // receive message from control socket
        if((n = recv(control_sock, control_buf, CONTROL_BUF_LEN, MSG_NOSIGNAL)) < 0) break;
        if (my_single_net_recv(sockfd, timeout, poll_timeout, &response_buf, &response_buf_size)) break;
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

