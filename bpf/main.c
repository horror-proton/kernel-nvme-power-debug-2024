
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>

#if __has_include("blazesym.h")
#include "blazesym.h"
#define HAS_BLAZESYM 1
#endif

#include "main.skel.h"

#include "common.h"

static int print_fn(enum libbpf_print_level level, const char *format,
                    va_list args) {
  return vfprintf(stderr, format, args);
}

static struct blaze_symbolizer *g_symbolizer = NULL;

static int print_stack(struct stack_trace_t const *st) {
#ifdef HAS_BLAZESYM
  const struct blaze_symbolize_inlined_fn *inlined = NULL;

  struct blaze_symbolize_src_kernel src = {
      .type_size = sizeof(src),
  };

  const size_t stack_size = st->size;
  const uintptr_t *stack = (const uintptr_t *)st->ip;
  const struct blaze_syms *syms =
      blaze_symbolize_kernel_abs_addrs(g_symbolizer, &src, stack, stack_size);

  if (!syms) {
    (void)fprintf(stderr, "  failed to symbolize addresses: %s\n",
                  blaze_err_str(blaze_err_last()));
    return -1;
  }

  int no_sym_cnt = 0;
  for (size_t i = 0; i < stack_size; ++i) {
    if (syms->cnt <= i || syms->syms[i].name == NULL) {
      if (no_sym_cnt == 0)
        printf("\t%016lx: <no-symbol>\n", stack[i]);
      ++no_sym_cnt;
      continue;
    }
    no_sym_cnt = 0;

    const struct blaze_sym *sym = &syms->syms[i];
    printf("\t%016lx: %s\n", stack[i], sym->name);
  }

  blaze_syms_free(syms);
#endif

  return 0;
}

static int handle_buf(void *ctx, void *data, size_t size) {
  const struct unlinkat_info *trace = data;
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

  const char *expected_name = (const char *)ctx;

  if (expected_name && strcmp(event->dev_name, expected_name) != 0)
    return 0;

  printf("acpi_pci_set_power_state( '%s', PCI_%s )\n", event->dev_name,
         pci_power_names[1 + event->state]);
  print_stack(&event->st);
  return 0;
}

static volatile sig_atomic_t g_exiting = 0;
static void sig_handler(int signo) { g_exiting = 1; }

int main(int argc, char **argv) {
  libbpf_set_print(print_fn);
  g_symbolizer = blaze_symbolizer_new();
  (void)setvbuf(stdout, NULL, _IONBF, 0);
  int err = 0;

  if (signal(SIGINT, sig_handler) == SIG_ERR ||
      signal(SIGTERM, sig_handler) == SIG_ERR) {
    (void)fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
    goto cleanup;
  }

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

  const char *ctx = NULL;
  if (argc > 1)
    ctx = argv[1];

  struct ring_buffer *rb =
#if 0
      ring_buffer__new(bpf_map__fd(skel->maps.stacks), handle_buf, NULL, NULL);
#else
      ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event,
                       (void *)ctx, NULL);
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
      (void)fprintf(stderr, "Interrupted\n");
      err = 0;
      if (g_exiting)
        break;
    }
    if (err < 0) {
      (void)fprintf(stderr, "Failed to poll ring buffer\n");
      break;
    }
  }

cleanup:
  main_bpf__destroy(skel);
  blaze_symbolizer_free(g_symbolizer);
  return -err;
}
