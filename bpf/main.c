
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

static const char *const pci_power_names[] = {
    "error", "D0", "D1", "D2", "D3hot", "D3cold", "unknown",
};

static int handle_event(void *ctx, void *data, size_t size) {
  const struct set_event_t *event = data;
  printf("acpi_pci_set_power_state('%s', PCI_%s)\n", event->name,
         pci_power_names[1 + event->state]);
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

  struct ring_buffer *rb =
#if 0
      ring_buffer__new(bpf_map__fd(skel->maps.stacks), handle_buf, NULL, NULL);
#else
      ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL,
                       NULL);
#endif

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
