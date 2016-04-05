#define MAX_EVENT	100

typedef struct {
	int time ;
	char type[64];
	char data[1024];
} Event;
