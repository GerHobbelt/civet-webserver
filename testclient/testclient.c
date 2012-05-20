#include <WinSock2.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>

char * HOST = "127.0.0.1";
unsigned short PORT = 80;
char * RESOURCE = "/";
#define CLIENTCOUNT 20
#define TESTCYCLES 20


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


static struct sockaddr_in target = {0};
static CRITICAL_SECTION cs = {0};
static size_t expectedData = 0;
static DWORD availableCPUs = 1;
static DWORD totalCPUs = 1;
static unsigned good = 0;
static unsigned bad = 0;


int WINAPI ClientMain(void * clientNo) {

  SOCKET soc;
  time_t lastData;
  size_t totalData = 0;
  int isBody = 0;
  int isTest = (clientNo == 0);
  int cpu = ((int)clientNo) % 1000;
  
  if ((!isTest) && (((1<<cpu) & availableCPUs)!=0)) {
    SetThreadAffinityMask(GetCurrentThread(), 1<<cpu);
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

  sockprintf(soc, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: Close\r\n\r\n", RESOURCE, HOST);

  lastData = time(0);
  for (;;) {
    char buf[2048];
    int chunkSize = 0;
    unsigned long dataReady = 0;

    Sleep(1);

    if (ioctlsocket(soc, FIONREAD, &dataReady) < 0) break;
    if (dataReady) {
      chunkSize = recv(soc, buf, sizeof(buf), 0);
      if (!isBody) {
        char * headEnd = strstr(buf,"\xD\xA\xD\xA");
        if (headEnd) {
          headEnd+=4;
          chunkSize -= ((int)headEnd - (int)buf);
          if (chunkSize>0) {
            totalData += chunkSize;
            lastData = time(0);
            //fwrite(headEnd,1,got,STORE);
          }
          isBody=1;
        }
      } else {
        totalData += chunkSize;
        lastData = time(0);
        //fwrite(buf,1,got,STORE);
      }
    } else {
      time_t current = time(0);
      if (difftime(current, lastData) > 10) break;
    }
  }

  closesocket(soc);

  EnterCriticalSection(&cs);
  if (isTest) {
    expectedData = totalData;
  } else if (totalData != expectedData) {
    printf("Error: Client %u got %u bytes instead of %u\r\n", (int)clientNo, totalData, expectedData);
    bad++;
  } else {
    good++;
  }
  LeaveCriticalSection(&cs);

  return 0;
}


void RunTest(int loop) {

  HANDLE hThread[CLIENTCOUNT] = {0};
  int i;

  for (i=0;i<CLIENTCOUNT;i++) {
    DWORD dummy;
    hThread[i] = CreateThread(NULL, 1024*32, (LPTHREAD_START_ROUTINE)ClientMain, (void*)(1000*loop+i), 0, &dummy);
  }

  WaitForMultipleObjects(CLIENTCOUNT, hThread, TRUE, 15000);
  for (i=0;i<CLIENTCOUNT;i++) {
    if (WaitForSingleObject(hThread[i], 0)==WAIT_OBJECT_0) {
      CloseHandle(hThread[i]);
      hThread[i]=0;
    }
  }
  for (i=0;i<CLIENTCOUNT;i++) {
    if (hThread[i]) {
      EnterCriticalSection(&cs);
      SuspendThread(hThread[i]); // -> check this thread in the debugger
      printf("Thread %i did not finish!\r\n", (int)(1000*loop+i));
      LeaveCriticalSection(&cs);
    }
  }
  EnterCriticalSection(&cs);
  printf("Test cylce %u completed\r\n\r\n", loop);
  LeaveCriticalSection(&cs);
}


int main(int argc, char * argv[]) {

  WSADATA       wsaData = {0};
  HOSTENT     * lpHost = 0;
  int           i;

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

  printf("Preparing test ...");  
  ClientMain(0);
  if (expectedData==0) {
    printf(" Error: Could not read any data\a\r\n");
    return 3;
  }
  printf(" OK: %u bytes of data\r\n", expectedData);
  printf("Starting multi client test: %i cycles, %i clients each\r\n\r\n", (int)TESTCYCLES, (int)CLIENTCOUNT);
  
  for (i=1;i<=TESTCYCLES;i++) {
    RunTest(i);
  }

  printf("\r\n--------\r\n%u errors\r\n%u OK\r\n--------\r\n\r\n", bad, good);

  DeleteCriticalSection(&cs);

  WSACleanup();
  return 0;
}
