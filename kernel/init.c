
#include <kanawha/init.h>

#ifdef CONFIG_DEBUG_INIT_STAGES
#define DEBUG
#endif

#include <kanawha/printk.h>

#include <kanawha/stdint.h>
#include <kanawha/errno.h>

int
handle_init_stage_generic(
        const char *stage_name, 
        size_t num_events, 
        struct init_stage_event events[num_events])
{
    dprintk("Running Init Stage \"%s\" with %d init events...\n", stage_name, (int)num_events);
    size_t total_complete = 0;
    size_t total_failed = 0;
    size_t total_deferrals = 0;
    size_t num_complete;
    size_t num_failed;
    size_t num_deferred;

    do {
      num_complete = 0;
      num_failed = 0;
      num_deferred = 0;
      for(size_t i = 0; i < num_events; i++) {
          struct init_stage_event *event = &events[i];
          init_f *func = event->func;
          if(func != NULL) {
              if(event->desc_name != NULL) {
                  printk("%s...\n", event->desc_name);
              }
              int res = (*func)();
              switch(res) {
                  case -EDEFER:
                    num_deferred++;
                    if(event->desc_name) {
                        printk("%s [DEFERRED]\n", event->desc_name);
                    }
                    break;
                  case 0:
                    num_complete++;
                    event->func = NULL;
                    if(event->desc_name) {
                        printk("%s [COMPLETE]\n", event->desc_name);
                    }
                    break;
                  default:
                    num_failed++;
                    event->func = NULL;
                    if(event->desc_name) {
                        printk("%s [FAILED]\n", event->desc_name);
                    } else {
                        printk("init %p [FAILED]\n", event->func);
                    }
                    break;
              }
          }
      }
      total_complete += num_complete;
      total_failed += num_failed;
      total_deferrals += num_deferred;
    } while(num_deferred > 0 && ((num_complete + num_failed) > 0));

    dprintk("Finished Init Stage \"%s\" (complete=%lu, failed=%lu, total_deferrals=%lu)\n",
            stage_name,
            (unsigned long)total_complete,
            (unsigned long)total_failed,
            (unsigned long)total_deferrals);

    size_t num_outstanding = num_events - (total_complete + total_failed);

    if(total_failed > 0)
    {
        eprintk("Init Stage \"%s\" had %lu Failed functions!\n",
                stage_name,
                (unsigned long)total_failed);

        return -EINVAL;
    }
    if(num_outstanding > 0) 
    {
        eprintk("Init Stage \"%s\" still has %lu Incomplete functions! (Possible Dependency Loop?)\n",
                stage_name,
                (unsigned long)num_outstanding);

        return -EINVAL;
    }

    return 0;
}

#define DEFINE_INIT_STAGE_HANDLER(STAGE, ...)\
int handle_init_stage__ ## STAGE(void) \
{\
    extern struct init_stage_event __init_stage_ ## STAGE ## __init_start[];\
    extern struct init_stage_event __init_stage_ ## STAGE ## __init_end[];\
    \
    size_t num_events = (\
            (uintptr_t)__init_stage_ ## STAGE ## __init_end - \
            (uintptr_t)__init_stage_ ## STAGE ## __init_start)\
        / sizeof(struct init_stage_event);\
    \
    return handle_init_stage_generic(\
            #STAGE,\
            num_events,\
            __init_stage_ ## STAGE ## __init_start);\
}

XFOR_INIT_STAGE(DEFINE_INIT_STAGE_HANDLER)

