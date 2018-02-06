#include <linux/init.h>
#include <linux/module.h>
#include <linux/sched.h>

MODULE_LICENSE("GPL");

#define WORK_COUNT 8

struct work_struct odptest_work[WORK_COUNT];

void odptest_work_func(struct work_struct *work)
{
    int index = work - odptest_work;
    unsigned long cpu_flags;
    size_t size;
    void *ptr;

    cpu_flags = -1;
#if __x86_64__
    asm volatile ("pushf\n"
                  "pop %0\n"
                  : "=r" (cpu_flags)
                   );
#endif

    printk(KERN_DEBUG "odptest work[%d] start on pid %d cpu_flags=0x%0lx\n",
           index, task_pid_nr(current), cpu_flags);

    size = 2ul * 1024 * 1024 * 1024;
    ptr  = vmalloc(size);

    printk(KERN_DEBUG "odptest work[%d] zero memory\n", index);

    memset(ptr, 0, size);

    vfree(ptr);

    printk(KERN_DEBUG "odptest work[%d] odptest work end\n", index);
}

static int odptest_init(void)
{
    int i;

    for (i = 0; i < WORK_COUNT; ++i) {
        INIT_WORK(&odptest_work[i], odptest_work_func);
        schedule_work(&odptest_work[i]);
    }
    return 0;
}

static void odptest_exit(void)
{
    int i;

    for (i = 0; i < WORK_COUNT; ++i) {
        flush_work(&odptest_work[i]);
    }
}

module_init(odptest_init);
module_exit(odptest_exit);
