#pragma once

struct stack_trace_t {
  char comm[63];
  __s64 size;
  __u64 ip[16];
  char fname[255];
};

struct set_event_t {
  int state;
};
