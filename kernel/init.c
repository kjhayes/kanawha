
#include <kanawha/init.h>

#ifdef CONFIG_DEBUG_INIT_STAGES
#define DEBUG
#endif

#ifdef CONFIG_LOG_INIT_STAGES
#define LOG(...) printk(__VA_ARGS__)
#else
#define LOG(...)
#endif

#include <kanawha/printk.h>

#include <kanawha/assert.h>
#include <kanawha/errno.h>
#include <kanawha/types.h>
#include <kanawha/vmem.h>

int
handle_init_stage_generic(const char *stage_name,
                          size_t num_events,
                          struct init_stage_event events[num_events])
{
    dprintk("Running Init Stage \"%s\" with %d init events...\n",
            stage_name,
            (int)num_events);
    size_t total_complete = 0;
    size_t total_failed = 0;
    __maybe_unused size_t total_deferrals = 0;
    size_t num_complete;
    size_t num_failed;
    size_t num_deferred;

    do
    {
        num_complete = 0;
        num_failed = 0;
        num_deferred = 0;
        for(size_t i = 0; i < num_events; i++)
        {
            struct init_stage_event *event = &events[i];
            DEBUG_ASSERT(KERNEL_ADDR(event));
            init_f *func = event->func;
            if(func != NULL)
            {
                if(event->desc_name != NULL)
                {
                    LOG("%s...\n", event->desc_name);
                }
                int res = (*func)();
                switch(res)
                {
                case -EDEFER:
                    num_deferred++;
                    if(event->desc_name)
                    {
                        LOG("%s [DEFERRED]\n", event->desc_name);
                    }
                    break;
                case 0:
                    num_complete++;
                    event->func = NULL;
                    if(event->desc_name)
                    {
                        LOG("%s [COMPLETE]\n", event->desc_name);
                    }
                    break;
                default:
                    num_failed++;
                    if(event->desc_name)
                    {
                        LOG("%s [FAILED]\n", event->desc_name);
                    }
                    else
                    {
                        LOG("init %p [FAILED]\n", event->func);
                    }
                    event->func = NULL;
                    break;
                }
            }
        }
        total_complete += num_complete;
        total_failed += num_failed;
        total_deferrals += num_deferred;
    } while(num_deferred > 0 && ((num_complete + num_failed) > 0));

    dprintk("Finished Init Stage \"%s\" (complete=%lu, failed=%lu, "
            "total_deferrals=%lu)\n",
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
        eprintk("Init Stage \"%s\" still has %lu Incomplete functions! "
                "(Possible Dependency Loop?)\n",
                stage_name,
                (unsigned long)num_outstanding);

        return -EINVAL;
    }

    return 0;
}

#define DEFINE_INIT_STAGE_CHECKS(STAGE, ...)                                   \
    static int __started_init_stage_##STAGE = 0;                               \
    static int __completed_init_stage_##STAGE = 0;                             \
    int started_init_stage_##STAGE(void)                                       \
    {                                                                          \
        return __started_init_stage_##STAGE;                                   \
    }                                                                          \
    int completed_init_stage_##STAGE(void)                                     \
    {                                                                          \
        return __completed_init_stage_##STAGE;                                 \
    }

XFOR_INIT_STAGE(DEFINE_INIT_STAGE_CHECKS)

#define DEFINE_INIT_STAGE_HANDLER(STAGE, ...)                                  \
    int handle_init_stage__##STAGE(void)                                       \
    {                                                                          \
        int res;                                                               \
                                                                               \
        extern struct init_stage_event __init_stage_##STAGE##__init_start[];   \
        extern struct init_stage_event __init_stage_##STAGE##__init_end[];     \
                                                                               \
        size_t num_events = ((uintptr_t)__init_stage_##STAGE##__init_end -     \
                             (uintptr_t)__init_stage_##STAGE##__init_start) /  \
                            sizeof(struct init_stage_event);                   \
                                                                               \
        __started_init_stage_##STAGE = 1;                                      \
        res = handle_init_stage_generic(#STAGE,                                \
                                        num_events,                            \
                                        __init_stage_##STAGE##__init_start);   \
        __completed_init_stage_##STAGE = 1;                                    \
        return res;                                                            \
    }

XFOR_INIT_STAGE(DEFINE_INIT_STAGE_HANDLER)
