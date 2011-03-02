#define CONFIGURE_MINIMUM_TASK_STACK_SIZE (8*1024)
#define CONFIGURE_INIT_TASK_STACK_SIZE (8*1024)
#define CONFIGURE_STACK_CHECKER_ENABLED

#define CONFIGURE_MAXIMUM_DRIVERS 4

#define CONFIGURE_APPLICATION_NEEDS_CLOCK_DRIVER
#define CONFIGURE_APPLICATION_NEEDS_CONSOLE_DRIVER
#define CONFIGURE_APPLICATION_NEEDS_LIBBLOCK   /* for telnet shell */
#define CONFIGURE_APPLICATION_NEEDS_NULL_DRIVER  /* pty here! */

#define CONFIGURE_LIBIO_MAXIMUM_FILE_DESCRIPTORS 8

#define CONFIGURE_EXECUTIVE_RAM_SIZE        (256*1024)

#define CONFIGURE_MAXIMUM_MESSAGE_QUEUES    16
#define CONFIGURE_MAXIMUM_TASKS             16
#define CONFIGURE_MAXIMUM_POSIX_TIMERS      16  /* tbd gds: XXX */
#define CONFIGURE_MAXIMUM_TIMERS            16
#define CONFIGURE_MAXIMUM_POSIX_THREADS              16
#define CONFIGURE_MAXIMUM_POSIX_CONDITION_VARIABLES  16
#define CONFIGURE_MAXIMUM_POSIX_MUTEXES              16
#define CONFIGURE_MAXIMUM_POSIX_SEMAPHORES           16
#define CONFIGURE_MAXIMUM_PTYS 4

#define CONFIGURE_POSIX_INIT_THREAD_TABLE
#define CONFIGURE_USE_IMFS_AS_BASE_FILESYSTEM

#define CONFIGURE_INIT

#define USE_DHCP 0  /* XXX Need to fix. */


#include <rtems.h>
#include <rtems/rtems_bsdnet.h>

#if USE_DHCP
#include <rtems/dhcp.h>
#include <rtems/rtems_dhcp_failsafe.h>
#endif


/* Network configuration
 */
extern int rtems_smc91111_driver_attach_mpc5554(struct rtems_bsdnet_ifconfig *, int);


struct rtems_bsdnet_ifconfig bsdnet_ifconfig = {
    "smc0",                         /* name */
    rtems_smc91111_driver_attach_mpc5554, /* attach function */
    NULL,                           /* link to next interface */
#if USE_DHCP == 0
    "192.168.240.17",               /* IP address */
    "255.255.255.0",                /* IP net mask */
#else
    0,                              /* IP address */
    0,                               /* IP net mask */
#endif
    0,                              /* hardware_address */
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    NULL
};

struct rtems_bsdnet_config rtems_bsdnet_config = {
    &bsdnet_ifconfig,       /* Network interface */
#if USE_DHCP
#if 1
    rtems_bsdnet_do_dhcp
#else
    rtems_bsdnet_do_dhcp_failsafe
#endif
#else
    0
#endif
};

int main(int ac, char *av[]);

void * POSIX_Init(void);
void * POSIX_Init(void)
{
    char *av[] = {"mongoose", 0};

    rtems_bsdnet_initialize_network();

	return (void *)main(1, av);
}


#include <rtems/confdefs.h>
#include <rtems/shellconfig.h>
