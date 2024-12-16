
#include <errno.h>

#include "main.skel.h"

#include "common.h"

static int print_fn(enum libbpf_print_level level, const char *format,
                    va_list args) {
  return vfprintf(stderr, format, args);
}

static int handle_buf(void *ctx, void *data, size_t size) {
  const struct stack_trace_t *trace = data;
  printf("file=%s\n", trace->fname);

  printf("stack_size=%lld\n", trace->size);
  for (size_t i = 0; i < trace->size; ++i) {
    printf("  %016llx\n", trace->ip[i]);
  }

  return 0;
}

static int handle_event(void *ctx, void *data, size_t size) {
  const struct set_event_t *event = data;
  printf("state=%d\n", event->state);
  return 0;
}

int main() {
  libbpf_set_print(print_fn);
  int err = 0;

  struct main_bpf *skel = main_bpf__open_and_load();
  if (!skel) {
    (void)fprintf(stderr, "Failed to open and load BPF skeleton\n");
    return 1;
  }

  err = main_bpf__attach(skel);
  if (err) {
    (void)fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }

  struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
                                            handle_event, NULL, NULL);
  // ring_buffer__new(bpf_map__fd(skel->maps.stacks), handle_buf, NULL, NULL);

  if (!rb) {
    err = -1;
    (void)fprintf(stderr, "Failed to create ring buffer\n");
    goto cleanup;
  }

  (void)fprintf(stderr, "Monitoring...\n");

  while (true) {
    err = ring_buffer__poll(rb, 1000);
    if (err == -EINTR) {
      err = 0;
      break;
    }
    if (err < 0) {
      (void)fprintf(stderr, "Failed to poll ring buffer\n");
      break;
    }
  }

cleanup:
  main_bpf__destroy(skel);
  return -err;
}
