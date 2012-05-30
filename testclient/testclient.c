
#include "mongoose_ex.h"
#include "mongoose_sys_porting.h"


char * HOST = "127.0.0.1";
unsigned short PORT = 8081;
static const char * RESOURCE[] = { 
	"/ajax/echo.cgi",
	"/imagetest/00.png",
	"/args.cgi",
	"/_stat",
	"/_echo"
};

#define CLIENTCOUNT 20
#define TESTCYCLES 5


int sockvprintf(SOCKET soc, const char * fmt, va_list vl) {

  char buf[1024*8];
  int len = vsprintf_s(buf, sizeof(buf), fmt, vl);
  int ret = send(soc, buf, len, 0);
  return ret;
}


int sockprintf(SOCKET soc, const char * fmt, ...) {

  int ret = -1;
  va_list vl;
  va_start(vl, fmt);
  ret = sockvprintf(soc, fmt, vl);
  va_end(vl);
  return ret;
}

static char *source_data_buffer = NULL;
static size_t source_data_size = 0;
static char *source_query_data_buffer = NULL;
static size_t source_query_data_size = 0;

static void send_dummy_data(SOCKET soc, size_t len)
{
	size_t i, l;

	for (i = len; i > 0; ) 
	{
		int rv;

		l = i;
		if (l > source_data_size)
			l = source_data_size;
		rv = send(soc, source_data_buffer, l, 0);
		if (rv <= 0)
		{
			printf("**BONK**! in send_dummy_data(): %d/%d\a\n", rv, GetLastError());
			return;
		}
		i -= rv;
	} 
}

static void send_dummy_query_data(SOCKET soc, size_t len)
{
	size_t i, l;

	for (i = len; i > 0; ) 
	{
		int rv;

		l = i;
		if (l > source_query_data_size)
			l = source_query_data_size;
		rv = send(soc, source_query_data_buffer, l, 0);
		if (rv <= 0)
		{
			printf("**BONK**! in send_dummy_query_data()\a\n");
			return;
		}
		i -= l;
	} 
}

static struct sockaddr_in target = {0};
static CRITICAL_SECTION cs = {0};
static size_t expectedData = 0;
static DWORD_PTR availableCPUs = 1;
static DWORD_PTR totalCPUs = 1;
static unsigned good = 0;
static unsigned bad = 0;
static unsigned long postSize = 0;
static int verbose = 1;
static int volatile bugger_off = 0;
static int testcase = 35;


int WINAPI ClientMain(void * clientNo) {

  SOCKET soc;
  time_t lastData;
  size_t totalData = 0;
  int isBody = 0;
  int isTest = (clientNo == 0);
  int cpu = ((int)clientNo) % 64; /* Win32: max 64 processors possible for affinity mask!!! See the Win32 API docs. */
  int timeOut = 10;

  if ((!isTest) && (((1ULL<<cpu) & availableCPUs)!=0)) {
    SetThreadAffinityMask(GetCurrentThread(), 1ULL<<cpu);
  }

  soc = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (soc==INVALID_SOCKET) {
    EnterCriticalSection(&cs);
    printf("\r\nClient %u cannot create socket\a\r\n", (int)clientNo);
    LeaveCriticalSection(&cs);
    return 1;
  }

  if (connect(soc, (SOCKADDR*)&target, sizeof(target))) {
    EnterCriticalSection(&cs);
    printf("\r\nClient %u cannot connect to server %s:%u\a\r\n", (int)clientNo, HOST, PORT);
    LeaveCriticalSection(&cs);
    return 2;
  }

  {
	const int tcpbuflen = 1 * 1024 * 1024;

	setsockopt(soc, SOL_SOCKET, SO_RCVBUF, (const void *)&tcpbuflen, sizeof(tcpbuflen));
	setsockopt(soc, SOL_SOCKET, SO_SNDBUF, (const void *)&tcpbuflen, sizeof(tcpbuflen));
  }

  // Comment in just one of these test cases
  switch (testcase)
  {
  case 1:
  case 2:
  case 3:
  case 4:
  case 5:
	  // "GET"
	  sockprintf(soc, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: Close\r\n\r\n", RESOURCE[(testcase - 1) % ARRAY_SIZE(RESOURCE)], HOST);
	  break;

  case 11:
  case 12:
  case 13:
  case 14:
  case 15:
	  // "GET" with <postSize> bytes extra head data
	  sockprintf(soc, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: Close\r\n", RESOURCE[(testcase - 1) % ARRAY_SIZE(RESOURCE)], HOST);
	  send_dummy_data(soc, postSize);
	  sockprintf(soc, "BuggerIt: Millennium-Hand-And-Shrimp!\r\n\r\n");
	  break;

  case 21:
  case 22:
  case 23:
  case 24:
  case 25:
	  // "GET" with <postSize> bytes of query string
	  sockprintf(soc, "GET %s?", RESOURCE[(testcase - 1) % ARRAY_SIZE(RESOURCE)]);
	  send_dummy_query_data(soc, postSize);
	  sockprintf(soc, " HTTP/1.1\r\nHost: %s\r\nConnection: Close\r\n\r\n", HOST);
	  break;

  case 31:
  case 32:
  case 33:
  case 34:
  case 35:
	  // "POST <postSize> bytes"
	  sockprintf(soc, "POST %s HTTP/1.1\r\nHost: %s\r\nConnection: Close\r\nContent-Length: %u\r\n\r\n", RESOURCE[(testcase - 1) % ARRAY_SIZE(RESOURCE)], HOST, postSize);
	  send_dummy_data(soc, postSize);
	  timeOut += postSize/10000;
	  break;

  case 41:
  case 42:
  case 43:
  case 44:
  case 45:
	  // "POST" with <postSize> bytes of query string
	  sockprintf(soc, "POST %s?", RESOURCE[(testcase - 1) % ARRAY_SIZE(RESOURCE)]);
	  send_dummy_query_data(soc, postSize);
	  sockprintf(soc, " HTTP/1.1\r\nHost: %s\r\nConnection: Close\r\nContent-Length: 0\r\n\r\n", HOST);
	  break;
  }

  if (verbose == 1) fputc('>', stdout);

  /*
  You MUST flush the TCP write buffer or mongoose to receive the transmitted data -- or part or whole of
  it will sit in your own TX buffer for EVER, or rather, until the socket 'times out'.

  The classic approach here is to do a half-close, but you can be nasty and disable Nagle, i.e. act
  like you're telnet.

  When sending multiple requests to the HTTP server over a single connection (HTTP keep-alive), it is
  generally assumed that:

  - request A+1 is not directly dependent on the response to request A (as that would make the entire 
    thing half-duplex anyway, while we strive for full-duplex comm), or
  - both sides flush their TCP buffers after each request (no-Nagle or some other way)
  */
  (void) shutdown(soc, SHUT_WR);
  //mg_set_non_blocking_mode(soc, 1);

  lastData = time(0);
  for (;;) {
    char buf[2048];
    int chunkSize = 0;
    unsigned long dataReady = 0;
	FD_SET fds;
	struct timeval tv;
	int srv;

	tv.tv_sec = 10;
	tv.tv_usec = 0;

	FD_ZERO(&fds);
	FD_SET(soc, &fds);
	srv = select(1, &fds, 0, 0, &tv);
	if (bugger_off)
	{
		if (verbose <= 1) fputc('~', stdout);
		else if (verbose > 1) printf("Closing prematurely: server is taking too long to our taste: client %i --> %u/%u\r\n", (int)clientNo, (unsigned int)totalData, (unsigned int)postSize);
		break;
	}

    if (ioctlsocket(soc, FIONREAD, &dataReady) < 0) 
	{
		if (verbose || 1) fputc('@', stdout);
		break;
	}
    if (dataReady) {
	  if (verbose > 1) fputc('+', stdout); // see a bit of action around here...
      chunkSize = recv(soc, buf, sizeof(buf), 0);
      if (chunkSize<0) {
        printf("Error: recv failed for client %i: %d/%d\r\n", (int)clientNo, chunkSize, GetLastError());
        break;
      } else if (!isBody) {
        char * headEnd = strstr(buf,"\xD\xA\xD\xA");
        if (headEnd) {
          headEnd+=4;
          chunkSize -= ((int)headEnd - (int)buf);
          if (chunkSize>0) {
            totalData += chunkSize;
			if (verbose > 2) printf("r:%d/%d\n", (int)chunkSize, (int)totalData);
            lastData = time(0);
            //fwrite(headEnd,1,got,STORE);
          }
          isBody=1;
        }
      } else {
        totalData += chunkSize;
		if (verbose > 2) printf("R:%d/%d\n", (int)chunkSize, (int)totalData);
        lastData = time(0);
        //fwrite(buf,1,got,STORE);
      }
    } else {
      time_t current = time(0);
	  if (verbose > 1) fputc('.', stdout); // see a bit of action around here...
      if (difftime(current, lastData) > timeOut) 
	  {
        printf("Error: request timed out for client %i\r\n", (int)clientNo);
		break;
	  }
	  if (srv == 1)
	  {
		  // server closed connection:
		  if (verbose <= 1) fputc('#', stdout);
		  else if (verbose > 1) printf("Server close: client %i --> %u/%u\r\n", (int)clientNo, (unsigned int)totalData, (unsigned int)postSize);
		break;
	  }
	  else 
	  {
		  // server crash / abortus provocatus?
        printf("Abortus Provocatus?: client %i --> %u/%u\r\n", (int)clientNo, (unsigned int)totalData, (unsigned int)postSize);
		break;
	  }
    }
  }

  closesocket(soc);

  EnterCriticalSection(&cs);
  if (isTest) {
	if (verbose > 2) printf("RR:%d\n", (int)totalData);
    expectedData = totalData;
  } else if (totalData != expectedData) {
    printf("Error: Client %i got %u bytes instead of %u\r\n", (int)clientNo, (unsigned int)totalData, (unsigned int)expectedData);
    bad++;
  } else {
    good++;
  }
  LeaveCriticalSection(&cs);

  return 0;
}


void RunMultiClientTest(int loop) {

  HANDLE hThread[CLIENTCOUNT] = {0};
  int i;
  DWORD res;

  for (i=0;i<CLIENTCOUNT;i++) {
    DWORD dummy;
    hThread[i] = CreateThread(NULL, 1024*32, (LPTHREAD_START_ROUTINE)ClientMain, (void*)(1000*loop+i), 0, &dummy);
  }

  res = WaitForMultipleObjects(CLIENTCOUNT, hThread, TRUE, 15000);
  if (res != WAIT_OBJECT_0 + CLIENTCOUNT - 1 && res != 0 /* all threads already terminated by themselves as they were done */)
  {
      printf("WaitForMultipleObjects() --> $%08x%s / $%08x\r\n", res, (res == STATUS_TIMEOUT ? " (STATUS_TIMEOUT)" : ""), GetLastError());
  }
  for (i=0;i<CLIENTCOUNT;i++) {
    res = WaitForSingleObject(hThread[i], 0);
	if (res == WAIT_OBJECT_0) {
      CloseHandle(hThread[i]);
      hThread[i]=0;
    }
	else
	{
      printf("Thread %i WaitForSingleObject() --> $%08x%s / $%08x\r\n", i, res, (res == STATUS_TIMEOUT ? " (STATUS_TIMEOUT)" : ""), GetLastError());
	}
  }
  for (i=0;i<CLIENTCOUNT;i++) {
    if (hThread[i]) {
      EnterCriticalSection(&cs);
#if 0
	  SuspendThread(hThread[i]); // -> check this thread in the debugger
#else
	  bugger_off = 1;

		res = WaitForSingleObject(hThread[i], 2 * 1000); // wait for a maximum of 2 select() poll periods to make sure that the thread had a chance to see 'bugger_off'...
		if (res == WAIT_OBJECT_0) {
			CloseHandle(hThread[i]);
			hThread[i]=0;
		}
#endif
		printf("Thread %i did not finish in time!\r\n", (int)(1000*loop+i));

      LeaveCriticalSection(&cs);
    }
  }
  EnterCriticalSection(&cs);
  printf("Test cycle %u completed\r\n\r\n", loop);
  LeaveCriticalSection(&cs);
}


int MultiClientTestAutomatic(unsigned long initialPostSize) {

  FILE        * log;
  int           cycle;

  postSize = initialPostSize;

  do {
    printf("Preparing test with %u bytes of data ...", postSize);
    ClientMain(0);
    if (expectedData==0) {
      printf(" Error: Could not read any data\a\r\n");
      return 1;
    }
    printf(" OK: %u bytes of data\r\n", expectedData);
    printf("Starting multi client test: %i cycles, %i clients each\r\n\r\n", (int)TESTCYCLES, (int)CLIENTCOUNT);
    good=bad=0;

    for (cycle=1;cycle<=TESTCYCLES;cycle++) {
      RunMultiClientTest(cycle);
    }

    printf("\r\n--------\r\n%u errors\r\n%u OK\r\n--------\r\n\r\n", bad, good);
    log = fopen("testclient.log", "at");
    if (log) {
      fprintf(log, "%u\t%u\t%u\r\n", postSize, good, bad);
      fclose(log);
    }
	Sleep(1000);

    postSize = (postSize!=0) ? (postSize<<1) : 1;

  } while (postSize!=0);

  return 0;
}


int SingleClientTestAutomatic(void) {

  FILE        * log;
  int           cycle;
  int           i;

  postSize = 0;
  for (cycle=0;;cycle++) {
    good=bad=0;
    for (i=0;i<1000;i++) {
      expectedData=3;
      ClientMain((void*)1);
    }
    log = fopen("testclient.log", "at");
    if (log) {
      fprintf(log, "Cycle<%u>\t%u\t%u\r\n", cycle, good, bad);
      fclose(log);
    }
    printf("test cycle %u: %u good, %u bad\r\n", cycle, good, bad);
  }

  return 0;
}


int main(int argc, char * argv[]) {

  WSADATA       wsaData = {0};
  HOSTENT     * lpHost = 0;

  if (WSAStartup(MAKEWORD(2,2), &wsaData) != NO_ERROR) {
    printf("\r\nCannot init WinSock\a\r\n");
    return 1;
  }

  lpHost = gethostbyname(HOST);
  if (lpHost == NULL) {
    printf("\r\nCannot find host %s\a\r\n",HOST);
    return 2;
  }

  target.sin_family = AF_INET;
  target.sin_addr.s_addr = *((u_long FAR *) (lpHost->h_addr));
  target.sin_port = htons(PORT);

  GetProcessAffinityMask(GetCurrentProcess(), &availableCPUs, &totalCPUs);
  printf("CPUs (bit masks): process=%x, system=%x\r\n", availableCPUs, totalCPUs);

  InitializeCriticalSectionAndSpinCount(&cs, 100000);

  /* set up the data buffer for fast I/O */
  source_data_size = 1024 * 1024;
  source_data_buffer = (char *)malloc(source_data_size);
  {
	  int i;
	  char *d = source_data_buffer;

	  for (i = source_data_size; i >= 80; )
	  {
		  _snprintf(d, i, "Comment%04u: 1234567890\r\n", i % 10000);
		  i -= strlen(d);
		  d += strlen(d);
	  }
	  memset(d, '.', i);
  }
  /* and another one for the fake query data */
  source_query_data_size = 2 * 1024;
  source_query_data_buffer = (char *)malloc(source_query_data_size);
  {
	  int i;
	  char *d = source_query_data_buffer;

	  for (i = source_query_data_size; i >= 80; )
	  {
		  _snprintf(d, i, "Comment%04u=1234567890-%i&", i % 10000, i);
		  i -= strlen(d);
		  d += strlen(d);
	  }
	  memcpy(d, "FaulOlRon=NoMatchFerYeSkunnersIllSay123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890", i);
	  source_query_data_buffer[source_query_data_size - 1] = '&';
  }

  /* Do the actual test here */
  MultiClientTestAutomatic(200);
  //SingleClientTestAutomatic();

  /* Cleanup */
  DeleteCriticalSection(&cs);
  WSACleanup();
  return 0;
}
