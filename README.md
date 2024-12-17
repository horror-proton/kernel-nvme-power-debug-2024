For some reason a nvme SSD on my laptop would sometimes stall with a message like:
```
nvme nvme0: controller is down; will reset: CSTS=0xffffffff, PCI_STATUS=0xffff
nvme nvme0: Does your device have a fauty power saving mode enabled?
...
```

I have put something like `nvme_core.default_ps_max_latency_us=0 pcie_aspm=off pcie_port_pm=off`
in the kernel command line, but it doesn't help.

It seems that some other power saving feature is still on implicitly[^1].

Perhaps disabling D3cold would help:
```ini
# /etc/tmpfiles.d/nvme-disable-d3cold.conf
w /sys/class/nvme/nvme*/device/d3cold_allowed - - - - 0
```

This repo stores some temporary shit code for debugging

---
## bpf
A BPF program for pci power state monitoring.

## tmpfiles.d
Tmpfiles config for systemd-tmpfiles.

```

[^1]:https://bbs.archlinux.org/viewtopic.php?pid=2206758#p2206758
