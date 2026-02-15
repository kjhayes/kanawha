
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#define REST (0)

#define C8  (4186)
#define CS8 (4435)
#define D8  (4699)
#define DS8 (4978)
#define E8  (5274)
#define F8  (5588)
#define FS8 (5920)
#define G8  (6272)
#define GS8 (6645)
#define A8  (7040)
#define AS8 (7459)
#define B8  (7902)

#define C7  ((4186) / 2)
#define CS7 ((4435) / 2)
#define D7  ((4699) / 2)
#define DS7 ((4978) / 2)
#define E7  ((5274) / 2)
#define F7  ((5588) / 2)
#define FS7 ((5920) / 2)
#define G7  ((6272) / 2)
#define GS7 ((6645) / 2)
#define A7  ((7040) / 2)
#define AS7 ((7459) / 2)
#define B7  ((7902) / 2)

#define C6  ((4186) / 4)
#define CS6 ((4435) / 4)
#define D6  ((4699) / 4)
#define DS6 ((4978) / 4)
#define E6  ((5274) / 4)
#define F6  ((5588) / 4)
#define FS6 ((5920) / 4)
#define G6  ((6272) / 4)
#define GS6 ((6645) / 4)
#define A6  ((7040) / 4)
#define AS6 ((7459) / 4)
#define B6  ((7902) / 4)

#define C5  ((4186) / 8)
#define CS5 ((4435) / 8)
#define D5  ((4699) / 8)
#define DS5 ((4978) / 8)
#define E5  ((5274) / 8)
#define F5  ((5588) / 8)
#define FS5 ((5920) / 8)
#define G5  ((6272) / 8)
#define GS5 ((6645) / 8)
#define A5  ((7040) / 8)
#define AS5 ((7459) / 8)
#define B5  ((7902) / 8)

#define C4  ((4186) / 16)
#define CS4 ((4435) / 16)
#define D4  ((4699) / 16)
#define DS4 ((4978) / 16)
#define E4  ((5274) / 16)
#define F4  ((5588) / 16)
#define FS4 ((5920) / 16)
#define G4  ((6272) / 16)
#define GS4 ((6645) / 16)
#define A4  ((7040) / 16)
#define AS4 ((7459) / 16)
#define B4  ((7902) / 16)

#define C3  ((4186) / 32)
#define CS3 ((4435) / 32)
#define D3  ((4699) / 32)
#define DS3 ((4978) / 32)
#define E3  ((5274) / 32)
#define F3  ((5588) / 32)
#define FS3 ((5920) / 32)
#define G3  ((6272) / 32)
#define GS3 ((6645) / 32)
#define A3  ((7040) / 32)
#define AS3 ((7459) / 32)
#define B3  ((7902) / 32)

#define _QUARTER(NOTE) NOTE, NOTE, NOTE, NOTE,
#define _HALF(NOTE) _QUARTER(NOTE) _QUARTER(NOTE) 
#define _FULL(NOTE) _HALF(NOTE) _HALF(NOTE)
#define _DOUBLE(NOTE) _FULL(NOTE) _FULL(NOTE)
#define _QUAD(NOTE) _DOUBLE(NOTE) _DOUBLE(NOTE)

#define QUARTER(NOTE) _QUARTER(NOTE) _QUARTER(REST)
#define HALF(NOTE)    _HALF(NOTE) _QUARTER(REST)
#define FULL(NOTE)    _FULL(NOTE) _QUARTER(REST)
#define DOUBLE(NOTE)  _DOUBLE(NOTE) _QUARTER(REST)
#define QUAD(NOTE)    _QUAD(NOTE) _QUARTER(REST)

uint16_t
tune_0[] =
{
    FULL(A3)
    FULL(B3)
    FULL(D4)
    FULL(B3)

    DOUBLE(F4)
    QUARTER(REST)
    DOUBLE(F4)
    QUARTER(REST)
    DOUBLE(E4)

    QUAD(REST)

    FULL(A3)
    FULL(B3)
    FULL(D4)
    FULL(B3)

    DOUBLE(E4)
    QUARTER(REST)
    DOUBLE(E4)
    QUARTER(REST)
    DOUBLE(D4)
    FULL(CS4)
    DOUBLE(B3)

    QUAD(REST)

    FULL(A3)
    FULL(B3)
    FULL(D4)
    FULL(B3)

    DOUBLE(D4)
    DOUBLE(E4)
    QUAD(CS4)
    QUARTER(REST)
    FULL(A3)
    DOUBLE(E4)
    DOUBLE(D4)
};

int main(int argc, const char **argv)
{
    FILE *file = fopen("/dev/snd/pc-speaker", "a");
    if(file == NULL) {
        printf("Failed to open /dev/snd/pc-speaker!\n");
        exit(-1);
    }

    uint16_t *tune = tune_0;
    int num_notes = sizeof(tune_0) / 2;

    printf("Playing tune of length %d\n", num_notes);
    ssize_t res = fwrite(tune, 2, num_notes, file);
    if(res < 0) {
        printf("Failed to write to /dev/snd/pc-speaker!\n");
        exit(res);
    }
    printf("Finished playing\n");

    return 0;
}

