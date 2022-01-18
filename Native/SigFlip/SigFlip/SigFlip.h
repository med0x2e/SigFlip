#ifndef _SIG_FLIP
#define _SIG_FLIP

#include <stdio.h>
#include <windows.h>
#include <WinTrust.h>
#include <time.h>


enum MODE {
	CUSTOM_SCRIPT, // Added
	BIT_FLIP,
	INJECT,
	HELP
};

#define MAX_PATH_LENGTH 255
#define MAX_KEY_SIZE 16

extern void usage(char* _file);
extern BOOL checkConfig();


#endif 