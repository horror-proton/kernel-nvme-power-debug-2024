#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "common.h"

char LICENSE[] SEC("license") = "GPL";

#if 0
// testing kprobe with do_unlinkat

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} stacks SEC(".maps");

SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name) {
  pid_t pid = (pid_t)(bpf_get_current_pid_tgid() >> 32U);
  const char *filename = BPF_CORE_READ(name, name);

  struct stack_trace_t *st = bpf_ringbuf_reserve(&stacks, sizeof(*st), 0);
  if (!st)
    return 0;

  st->fname[0] = '\n';
  bpf_probe_read_kernel_str(st->fname, sizeof(st->fname), filename);
  // BPF_CORE_READ_STR_INTO(&st->fname, name, name);

  bpf_get_current_comm(&st->comm, sizeof(st->comm));
  st->size = bpf_get_stack(ctx, &st->ip, sizeof(st->ip), 0);
  bpf_ringbuf_submit(st, 0);

  return 0;
}
#endif

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);

} events SEC(".maps");

SEC("kprobe/acpi_pci_set_power_state")
int BPF_KPROBE(acpi_pci_set_power_state, struct pci_dev *dev,
               pci_power_t state) {
  struct acpi_device *adev = container_of(&dev->dev, struct acpi_device, dev);

  struct set_event_t *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (!event)
    return 0;

  event->state = state;

  {
    const char *init_name = BPF_CORE_READ(dev, dev.init_name);
    if (init_name)
      bpf_probe_read_str(&event->name, sizeof(event->name), init_name);
    else {
      const char *kobj_name = BPF_CORE_READ(dev, dev.kobj.name);
      bpf_probe_read_kernel_str(&event->name, sizeof(event->name), kobj_name);
      // not working, why?
      // BPF_CORE_READ_STR_INTO(&event->name, dev, dev.kobj.name);
    }
  }
  bpf_ringbuf_submit(event, 0);

  return 0;
}
