#include <sys/ptrace.h>
#include <wait.h>
#include <errno.h>
#include <unistd.h>

#include <msg/msg.h>
#include <xbt.h>

int main(int argc, char *argv[])
{
  MSG_init(&argc, argv);


  const char *platform_file = argv[optind];
  const char *application_file = argv[optind + 1];

  MSG_create_environment(platform_file);
  init_host_list();

  MSG_function_register_default(runner);
  MSG_launch_application(application_file);

  msg_error_t res = MSG_main();
  XBT_INFO("Simulated time: %g", MSG_get_clock());

  if (res == MSG_OK)
    return 0;
  else
    return 1;
}

static int runner(int argc, char *argv[])
{
  int status;
  int tracked_pid = fork();
  if (tracked_pid == 0) {
    // in child
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
      perror("ptrace traceme");
      exit(1);
    }

    xbt_dynar_t cmdline_dynar = xbt_dynar_new(sizeof(char *), NULL);
    int i;
    for (i = 0; i < argc; i++)
      xbt_dynar_push(cmdline_dynar, &argv[i]);
    char *cmdline_str = xbt_str_join(cmdline_dynar, " ");
    char **cmdline_array = (char **) xbt_dynar_to_array(cmdline_dynar);

    XBT_INFO("Process %d is starting child: %s", getpid(), cmdline_str);

    process_set_descriptor(process_descriptor_new(MSG_host_get_name(MSG_host_self()), getpid()));

    execv(cmdline_array[0], cmdline_array);     // If successful, the execution flow does not go any further here

    fprintf(stderr, "Error while starting %s: %s (full cmdline: %s)", cmdline_array[0], strerror(errno), cmdline_str);
    exit(1);
  }
  // We are still in simterpose, so we are the thread that is the representative of the external process

  // Wait for the traceme to apply (ie, for the child to start)
  waitpid(tracked_pid, &status, 0);
  process_set_descriptor(process_descriptor_new(MSG_host_get_name(MSG_host_self()), tracked_pid));

  // Trace the child and all upcoming granchilds
  if (ptrace(PTRACE_SETOPTIONS, tracked_pid, NULL,
             PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEVFORKDONE)
      == -1) {
    perror("Error setoptions");
    exit(1);
  }

  process_descriptor_t *proc = MSG_process_get_data(MSG_process_self());

  // Main loop where we track our external process and do the simcall that represent its syscalls
  while (1) {

  }
  return 0;
}
