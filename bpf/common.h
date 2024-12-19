#pragma once

struct unlinkat_info {
  char comm[63];
  __s64 size;
  __u64 ip[16];
  char fname[255];
};

struct stack_trace_t {
  __s64 size;
  __u64 ip[16];
};

struct set_event_t {
  int state;
  char dev_name[64];
  char drv_name[64];
  struct stack_trace_t st;
};
