#ifndef __KANAWHA__UAPI_SND_H__
#define __KANAWHA__UAPI_SND_H__

// "Notes" encoded by hz
// (Native endianness)
#define SND_FORMAT_FREQ_HZ_8  (1)
#define SND_FORMAT_FREQ_HZ_16 (2)
#define SND_FORMAT_FREQ_HZ_32 (3)
#define SND_FORMAT_FREQ_HZ_64 (4)

// PCM formats
#define SND_FORMAT_PCM_FLOAT32 (5)
#define SND_FORMAT_PCM_FLOAT64 (6)
#define SND_FORMAT_PCM_U8      (7)
#define SND_FORMAT_PCM_U16     (8)
#define SND_FORMAT_PCM_U32     (9)
#define SND_FORMAT_PCM_S8      (10)
#define SND_FORMAT_PCM_S16     (11)
#define SND_FORMAT_PCM_S32     (12)

// Only "off" -> 0 and "on" -> non-zero
#define SND_VOLUME_FORMAT_BINARY (1)

struct snd_mode_info
{
    unsigned long sampling_hz;

    unsigned long format;

    unsigned long volume_format;
    unsigned long volume_min;
    unsigned long volume_max;
};

#endif
